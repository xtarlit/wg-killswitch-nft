# wg-killswitch-nft
An over-engineered Wireguard killswitch designed specifically for the modern "nftables" netfilter project for Linux machines. It's developed for use with commercial consumer-oriented VPN services in mind, but can be used for or adapted to any Wireguard config. 

# What does it do? 
The scope of this project is to provide a script that will prevent internet access if the VPN tunnel unexpectedly fails (interfering, misconfigured, or misbehaving software, buggy wireguard implementation, etc.) and block applications from sending traffic to any interface that isn't your VPN tunnel. (as an example, qBittorrent may attempt to bind to multiple interfaces by default. This can cause traffic to "leak" out of the VPN tunnel by going directly to your physical interface.) 

# Features
 - Option to allow LAN traffic (disabled by default).
 - Option to log dropped packets (disabled by default).
 - No hard-coded path to your configs.
 - Full IPv6 compatibility and connectivity via the VPN interface if provided.
 - Blocks almost everything (aside from the bare minimum required to maintain any connectivity) going to your physical interface(s) on both IPv4 and IPv6.
 - Allows for loopback/localhost connectivity. 
 - Follows many security best practices (examples: set -euo pipefail, readonly variables, input validation, nftables with a default-drop policy) 
 - Avoids sending DNS requests outside of the tunnel for hostname lookup in your VPN config.
 - Relatively paranoid.

# "Anti-features"
 - The script resolves the VPN endpoint's domain name to an IP address once upon execution. If the server's IP address changes (due to load balancing, DDoS mitigation, or server migration), the killswitch will block the connection because the new IP is not in the nftables set.
   
    Possible solution: run a background process that periodically re-resolves the endpoint and updates the nftables set.
 - The script doesn’t handle multiple peers on different ports: we overwrite $EP_PORT on every loop iteration. If you ever wire up two peers, your rules will only allow the last peer’s port, silently dropping the other.
   
    Possible solution: either assert that there’s only one peer, or build a per-port set (or require uniform ports).
 - The script sets our three chains (input, output, forward) to policy drop but don’t install any ARP rules. ARP lives in the arp family, not inet, so still allowed by default. Usually good, but be aware you’re implicitly trusting link-layer.
 - We don’t allow any DNS queries to go out the physical uplink, which is intentional, but you must be 100% sure every process is pointed at an internal DNS resolver or your VPN's internal resolver. Otherwise DNS simply fails rather than “leaks.”

# Usage
 - In your Wireguard config: 
```
[Interface]
PostUp   =  /path/to/wg-killswitch-nft.sh up %i
PostDown = /path/to/wg-killswitch-nft.sh down %i
```
- The %i is important, that's how the script knows what our interface is called.

# BSD 3-Clause License

Copyright (c) 2025, xtarlit

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Wireguard
- "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.
