#!/usr/bin/env bash

# github.com/xtarlit/wg-killswitch-nft
# Paranoid Wireguard killswitch designed specifically for nftables. 
#
# Usage: /path/to/wg-killswitch-nft {up|down} <wg-interface>

# BSD 3-Clause License
# 
# Copyright (c) 2025, xtarlit
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# prevent more than one instance of the script from running at the same time
exec 200>"/tmp/wg-killswitch.lock" || { echo "Failed to create lock file" >&2; exit 1; }
flock -x 200 || { echo "Another instance is running" >&2; exit 1; }

set -euo pipefail

# --- Configuration ---
readonly PRIORITY="-200"          # A high priority to preempt other rules.
readonly POLL_ATTEMPTS="10"        # How many times to check for a live endpoint.
readonly POLL_INTERVAL="0.5"        # Seconds to wait between poll attempts.
readonly ALLOW_LAN="false"        # Set to "true" to allow traffic to/from private RFC1918/ULA ranges.
readonly ENABLE_LOGGING="false"    # Set to "true" to log and count dropped packets.

# --- Script setup ---
# Set a sane, secure PATH and check for required commands.
export PATH="/usr/sbin:/sbin:/usr/bin:/bin"
readonly CMDS=(nft ip wg awk sed tr grep sleep flock)
for cmd in "${CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null; then
        echo "ERROR: Required command '$cmd' is not installed or not in PATH." >&2
        exit 1
    fi
done

# --- Functions ---
log_error() {
    echo "ERROR: $*" >&2
}

log_info() {
    echo "INFO: $*"
}

cleanup() {
    if [[ -n "${SANITIZED_IF:-}" ]]; then
        log_info "Running cleanup for interface '$IF' (table: vpn_killswitch_${SANITIZED_IF})..."
        # Delete the specific table for this interface, leaving other rules untouched.
        nft delete table inet "vpn_killswitch_${SANITIZED_IF}" 2>/dev/null || true
    fi
}

usage() {
    echo "Usage: $0 {up|down} <wg-interface>"
    exit 1
}

# --- Main Script ---

if [[ $# -ne 2 ]]; then
    usage
fi

readonly MODE="$1"
readonly IF="$2"

if ! [[ "$IF" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
    log_error "Invalid interface name specified: '$IF'"
    exit 1
fi
readonly SANITIZED_IF=$(echo "$IF" | tr -c 'a-zA-Z0-9_' '_')

readonly TABLE="vpn_killswitch_${SANITIZED_IF}"
readonly SET4="ep4_${SANITIZED_IF}"
readonly SET6="ep6_${SANITIZED_IF}"

trap cleanup EXIT INT TERM HUP

if [[ "$MODE" == "down" ]]; then
    log_info "Deactivating killswitch for '$IF'..."
    trap - EXIT INT TERM HUP
    cleanup
    log_info "Killswitch for '$IF' is now deactivated."
    exit 0
fi

if [[ "$MODE" != "up" ]]; then
    log_error "Invalid mode: '$MODE'. Must be 'up' or 'down'."
    usage
fi

# === MODE=up ===

if (( EUID != 0 )); then
    log_error "This script must be run as root to modify firewall rules."
    exit 1
fi

# Run cleanup first to remove any stale rules from a previous run.
cleanup

# --- Endpoint Discovery ---
declare -a addrs4=()
declare -a addrs6=()
EP_PORT=""

log_info "Attempting to discover live WireGuard endpoint for '$IF'..."
for ((i=1; i<=POLL_ATTEMPTS; i++)); do
    endpoint_data=$(wg show "$IF" endpoints)
    if [[ -n "$endpoint_data" ]]; then
        log_info "Live endpoint data found. Parsing and validating..."
        while read -r line; do
            peer_endpoint=$(echo "$line" | awk '{print $2}')
            if [[ -z "$peer_endpoint" || "$peer_endpoint" == "(none)" ]]; then
                continue
            fi
            # strip port & square-brackets, then validate via ip route get
            ip_raw=${peer_endpoint%:*}           # drop “:PORT”
            ip_raw=${ip_raw#\[}; ip_raw=${ip_raw%\]}  # drop leading ‘[’ and trailing ‘]’
            port_raw=${peer_endpoint##*:}        # grab port
            if ip -4 route get "$ip_raw" &>/dev/null; then
              addrs4+=("$ip_raw")
            elif ip -6 route get "$ip_raw" &>/dev/null; then
              addrs6+=("$ip_raw")
            else
                log_error "Parsed IP '$ip_raw' is not a valid IPv4 or IPv6 address. Skipping."
                continue
            fi
            EP_PORT=$port_raw
        done <<< "$endpoint_data"
        # If we found any valid addresses, we can stop polling.
        if (( ${#addrs4[@]} > 0 || ${#addrs6[@]} > 0 )); then
            break
        fi
    fi
    if (( i < POLL_ATTEMPTS )); then
        sleep "$POLL_INTERVAL"
    fi
done

if [[ ${#addrs4[@]} -eq 0 && ${#addrs6[@]} -eq 0 ]]; then
    log_error "Failed to determine any live endpoint IP for '$IF' after $POLL_ATTEMPTS attempts."
    exit 1
fi

log_info "Discovered IPv4 endpoints: ${addrs4[*]:-(none)}"
log_info "Discovered IPv6 endpoints: ${addrs6[*]:-(none)}"

if ! [[ "$EP_PORT" =~ ^[0-9]+$ && "$EP_PORT" -ge 1 && "$EP_PORT" -le 65535 ]]; then
    log_error "Invalid endpoint port parsed: '$EP_PORT'"
    exit 1
fi
log_info "Discovered endpoint port: $EP_PORT"

# --- Uplink Discovery (Better Method) ---
log_info "Detecting physical uplink interfaces via endpoint routes..."
UPLINK_IF4=""   # avoid unbound-variable under set -u
UPLINK_IF6=""

# helper to pick dev from an `ip route get` output
_pick_dev() {
  awk '/ dev/ {
    for(i=1;i<=NF;i++) if($i=="dev") print $(i+1);
    exit
  }'
}

if (( ${#addrs4[@]} > 0 )); then
  # try direct route-get first
  candidate=$(ip -4 route get "${addrs4[0]}" 2>/dev/null | _pick_dev)
  # if it pointed at our WG iface (or is empty), fall back to the default-gateway
  if [[ -z "$candidate" || "$candidate" == "$IF" ]]; then
    UPLINK_IF4=$(
      ip -4 route show table main default \
        | grep -v "dev $IF" \
        | _pick_dev
    )
  else
    UPLINK_IF4=$candidate
  fi
fi

if (( ${#addrs6[@]} > 0 )); then
  candidate=$(ip -6 route get "${addrs6[0]}" 2>/dev/null | _pick_dev)
  if [[ -z "$candidate" || "$candidate" == "$IF" ]]; then
    UPLINK_IF6=$(
      ip -6 route show table main default \
        | grep -v "dev $IF" \
        | _pick_dev
    )
  else
    UPLINK_IF6=$candidate
  fi
fi

if [[ -z "$UPLINK_IF4" && -z "$UPLINK_IF6" ]]; then
    log_error "Could not determine any uplink interface for endpoints. Cannot apply killswitch."
    exit 1
fi
[[ -n "$UPLINK_IF4" ]] && log_info "Detected IPv4 uplink: '$UPLINK_IF4'"
[[ -n "$UPLINK_IF6" ]] && log_info "Detected IPv6 uplink: '$UPLINK_IF6'"

# --- Build and apply nftables ruleset ---
v4_eps=$(IFS=,; echo "${addrs4[*]}")
v6_eps=$(IFS=,; echo "${addrs6[*]}")

NFT_RULES=$(cat <<EOF
add table inet $TABLE
add set inet $TABLE $SET4 { type ipv4_addr; flags interval; }
add set inet $TABLE $SET6 { type ipv6_addr; flags interval; }
$( [[ -n "$v4_eps" ]] && echo "add element inet $TABLE $SET4 { $v4_eps }" )
$( [[ -n "$v6_eps" ]] && echo "add element inet $TABLE $SET6 { $v6_eps }" )

add chain inet $TABLE input   { type filter hook input   priority $PRIORITY; policy drop; }
add chain inet $TABLE output  { type filter hook output  priority $PRIORITY; policy drop; }
add chain inet $TABLE forward { type filter hook forward priority $PRIORITY; policy drop; }

# Base rules: Always allow loopback and traffic on the WG interface itself
add rule inet $TABLE input  iifname "lo" accept
add rule inet $TABLE output oifname "lo" accept
add rule inet $TABLE input  iifname "$IF" accept
add rule inet $TABLE output oifname "$IF" accept

# Uplink rules (IPv4)
$( if [[ -n "$UPLINK_IF4" ]]; then
    # Allow essential ICMP
    echo "add rule inet $TABLE input iifname $UPLINK_IF4 icmp type { destination-unreachable, echo-reply, time-exceeded } accept"
    # Allow outbound WG traffic
    echo "add rule inet $TABLE output oifname $UPLINK_IF4 ip daddr @$SET4 udp dport $EP_PORT accept"
    # Allow inbound WG traffic
    echo "add rule inet $TABLE input iifname $UPLINK_IF4 ip saddr @$SET4 udp sport $EP_PORT accept"
fi )

# Uplink rules (IPv6)
$( if [[ -n "$UPLINK_IF6" ]]; then
    # Allow essential ICMPv6 (especially NDP)
    echo "add rule inet $TABLE input iifname $UPLINK_IF6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept"
    # Allow outbound WG traffic
    echo "add rule inet $TABLE output oifname $UPLINK_IF6 ip6 daddr @$SET6 udp dport $EP_PORT accept"
    # allow outgoing NDP/RS so we can resolve MACs
    echo "add rule inet $TABLE output oifname $UPLINK_IF6 icmpv6 type { nd-neighbor-solicit, nd-router-solicit } accept"
    # Allow inbound WG traffic
    echo "add rule inet $TABLE input iifname $UPLINK_IF6 ip6 saddr @$SET6 udp sport $EP_PORT accept"
fi )

# Optional: Allow LAN traffic
$( if [[ "$ALLOW_LAN" == "true" ]]; then
    echo "add rule inet $TABLE output ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept"
    echo "add rule inet $TABLE input  ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept"
    echo "add rule inet $TABLE output ip6 daddr fc00::/7 accept"
    echo "add rule inet $TABLE input  ip6 saddr fc00::/7 accept"
fi )

# Optional: Log and count any packets that are about to be dropped by the policy
# Now ratelimited
$( if [[ "$ENABLE_LOGGING" == "true" ]]; then
  echo "add rule inet $TABLE input   limit rate 5/second burst 10 log prefix \"[killswitch drop in]: \" counter"
  echo "add rule inet $TABLE output  limit rate 5/second burst 10 log prefix \"[killswitch drop out]: \" counter"
  echo "add rule inet $TABLE forward limit rate 5/second burst 10 log prefix \"[killswitch drop fwd]: \" counter"
fi )
EOF
)

log_info "Applying atomic nftables ruleset..."
if ! printf '%s\n' "$NFT_RULES" | nft -f -; then
    log_error "Failed to apply nftables ruleset. No firewall changes were made."
    exit 1
fi

log_info "Killswitch for '$IF' is now ACTIVE."

trap - EXIT INT TERM HUP
exit 0
