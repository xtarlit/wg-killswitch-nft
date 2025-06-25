#!/usr/bin/env bash
#
# A robust, secure killswitch for WireGuard using nftables.

set -euo pipefail

# --- Configuration ---
readonly PRIORITY="-200"          # A high priority to preempt other rules.
readonly POLL_ATTEMPTS=10         # How many times to check for a live endpoint.
readonly POLL_INTERVAL=0.5        # Seconds to wait between poll attempts.
readonly ALLOW_LAN="false"        # Set to "true" to allow traffic to/from private RFC1918/ULA ranges.
readonly ENABLE_LOGGING="false"    # Set to "true" to log and count dropped packets.

# --- Script setup ---
# Set a sane, secure PATH and check for required commands.
export PATH="/usr/sbin:/sbin:/usr/bin:/bin"
readonly CMDS=(nft ip wg awk sed tr)
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
            ip_raw=$(echo "$peer_endpoint" | sed -E 's/\[|\]//g; s/:[0-9]+$//')
            port_raw=$(echo "$peer_endpoint" | awk -F: '{print $NF}')

            # Validate IP format before adding to array.
            if [[ "$ip_raw" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                addrs4+=("$ip_raw")
            elif [[ "$ip_raw" == *:* ]]; then
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

# --- Uplink Discovery (Robust Method) ---
# Now that we have the endpoint IPs, we can find the exact route to them.
# This is the most reliable way to find the physical uplink interface.
log_info "Detecting physical uplink interfaces via endpoint routes..."
UPLINK_IF4=""
UPLINK_IF6=""
if (( ${#addrs4[@]} > 0 )); then
  # look in the "main" table (ID 254) for the default gateway
  UPLINK_IF4=$(
    ip -4 route show table main default \
      | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}'
  )
fi
if (( ${#addrs6[@]} > 0 )); then
  UPLINK_IF6=$(
    ip -6 route show table main default \
      | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}'
  )
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

# Optional: Allow LAN traffic
$( if [[ "$ALLOW_LAN" == "true" ]]; then
    echo "add rule inet $TABLE output ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept"
    echo "add rule inet $TABLE input  ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept"
    echo "add rule inet $TABLE output ip6 daddr fc00::/7 accept"
    echo "add rule inet $TABLE input  ip6 saddr fc00::/7 accept"
fi )

# Uplink rules (IPv4)
$( if [[ -n "$UPLINK_IF4" ]]; then
    # Allow essential ICMP
    echo "add rule inet $TABLE input iifname $UPLINK_IF4 icmp type { destination-unreachable, echo-reply, time-exceeded } accept"
    # Allow outbound WG traffic
    echo "add rule inet $TABLE output oifname $UPLINK_IF4 ip daddr @$SET4 udp dport $EP_PORT accept"
    # CRITICAL: Allow inbound WG traffic
    echo "add rule inet $TABLE input iifname $UPLINK_IF4 ip saddr @$SET4 udp sport $EP_PORT accept"
fi )

# Uplink rules (IPv6)
$( if [[ -n "$UPLINK_IF6" ]]; then
    # Allow essential ICMPv6 (especially NDP)
    echo "add rule inet $TABLE input iifname $UPLINK_IF6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept"
    # Allow outbound WG traffic
    echo "add rule inet $TABLE output oifname $UPLINK_IF6 ip6 daddr @$SET6 udp dport $EP_PORT accept"
    # CRITICAL: Allow inbound WG traffic
    echo "add rule inet $TABLE input iifname $UPLINK_IF6 ip6 saddr @$SET6 udp sport $EP_PORT accept"
fi )

# Optional: Log and count any packets that are about to be dropped by the policy
$( if [[ "$ENABLE_LOGGING" == "true" ]]; then
    echo "add rule inet $TABLE input   log prefix \"[killswitch drop in]: \" counter"
    echo "add rule inet $TABLE output  log prefix \"[killswitch drop out]: \" counter"
    echo "add rule inet $TABLE forward log prefix \"[killswitch drop fwd]: \" counter"
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
