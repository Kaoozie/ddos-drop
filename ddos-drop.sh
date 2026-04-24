#!/bin/sh
# =============================================================================
# Anti-DDoS nftables script for OpenWrt 23.05 x86 (IPv4-only)
# =============================================================================

# ===========================================================================
# CONFIG
# ===========================================================================

wan_device=""            # Leave empty for auto-detection via UCI.
                         # For multiple interfaces: "eth0,eth1"

bogon="1"                # Bogon filter: "1" enable, "0" disable

forward_router=""        # Upstream router IP/network (used with bogon filter).
                         # Leave empty if not applicable.
                         # Multiple entries: "192.168.1.1,10.0.0.0/24"

syn_flood="1"            # SYN flood protection: "1" enable, "0" disable

icmp_flood="1"           # ICMP flood protection: "1" enable, "0" disable

udp_flood="1"            # UDP flood protection: "1" enable, "0" disable

port_scan_detection="1"  # Port scan detection: "1" enable, "0" disable

arp_limit_enable="1"     # ARP rate limiting: "1" enable, "0" disable

wan_input_drop="0"       # Drop all input on WAN interface: "1" enable, "0" disable

wireguard_input_drop="0" # Drop all input on WireGuard interfaces: "1" enable, "0" disable

reject_with_icmp="0"     # Reject WAN/WG input with ICMP unreachable instead of drop

ragnarok_protection="1"  # Ragnarok Online port protection (6900/6121/5121): "1" enable, "0" disable

ssh_protection="1"       # SSH brute-force protection: "1" enable, "0" disable

# ===========================================================================
# PARAMETERS
# ===========================================================================

arp_limit="1"              # Max ARP requests/sec per MAC address

syn_flood_limit="300"      # SYN packets/sec limit
syn_flood_burst="500"      # Burst allowance above SYN limit

icmp_flood_limit="15"      # ICMP packets/sec limit
icmp_flood_burst="10"      # Burst allowance above ICMP limit

udp_flood_limit="20"       # UDP packets/sec limit (RO is TCP-only; UDP from WAN is mostly noise)
udp_flood_burst="10"       # Burst allowance above UDP limit

portscan_limit="15"        # Packets before source is blocked
portscan_drop_time="24h"   # Block duration (s=seconds, m=minutes, h=hours)
portscan_src_ports="22"    # Source ports exempt from portscan detection
portscan_dst_ports="{ 22, 6900, 6121, 5121 }" # Destination ports exempt from portscan detection

ragnarok_login_rate="2"    # Login server (6900): new connections/sec per IP
ragnarok_login_burst="10"
ragnarok_char_rate="3"     # Char server (6121): new connections/sec per IP
ragnarok_char_burst="15"
ragnarok_map_rate="5"      # Map server (5121): new connections/sec per IP
ragnarok_map_burst="30"
ragnarok_conn_limit="10"   # Max simultaneous connections per IP to RO ports (~3 clients + margin)

# Login brute-force (hashlimit per IP on port 6900)
ragnarok_login_bf_rate="1/minute"  # Max login attempts per IP per minute
ragnarok_login_bf_burst="5"        # Initial burst before rate limiting kicks in

ssh_port="22"                # SSH port (change if you moved SSH to a non-standard port)
ssh_rate="3/minute"          # Max new SSH connections per IP per minute
ssh_burst="5"                # Burst before rate limit kicks in
ssh_ban_time="1h"            # How long to block an IP after exceeding the limit

log_prefix="DDOS"          # Prefix for kernel log messages

# ===========================================================================
# BOGON ADDRESS LIST (IPv4 only)
# ===========================================================================

bogon_addresses="\
0.0.0.0/8, \
10.0.0.0/8, \
100.64.0.0/10, \
127.0.0.0/8, \
169.254.0.0/16, \
172.16.0.0/12, \
192.0.0.0/24, \
192.0.2.0/24, \
192.168.0.0/16, \
198.18.0.0/15, \
198.51.100.0/24, \
203.0.113.0/24, \
224.0.0.0/4, \
240.0.0.0/4, \
255.255.255.255/32"

# ===========================================================================
# INIT & VALIDATION
# ===========================================================================

log() { logger -t ddos-protect "$1"; echo "[ddos-protect] $1"; }
die() { log "ERROR: $1"; exit 1; }

# Resolve WAN device
if [ -z "$wan_device" ]; then
    wan_device=$(uci -q get network.wan.device) || die "Could not detect WAN device via UCI."
    # Also check for wan6 or multiple uplinks if defined
    wan6=$(uci -q get network.wan6.device)
    [ -n "$wan6" ] && wan_device="${wan_device},${wan6}"
fi
[ -z "$wan_device" ] && die "wan_device is empty. Set it manually in the config section."

# Validate numeric burst values are >= 1
for var in syn_flood_burst icmp_flood_burst udp_flood_burst ssh_burst ragnarok_login_bf_burst; do
    eval val=\$$var
    [ "$val" -ge 1 ] 2>/dev/null || die "$var must be a number >= 1 (got: '$val')"
done

log "Starting with WAN device(s): $wan_device"

# ===========================================================================
# BUILD RULESET
# ===========================================================================

RULES=$(mktemp /tmp/ddos_rules.XXXXXX.nft)
trap 'rm -f "$RULES"' EXIT

# ---------------------------------------------------------------------------
# Flush existing tables
# ---------------------------------------------------------------------------
cat >> "$RULES" <<EOF
# Flush previous rules
flush table inet DDOS
flush table inet tcp_portscan
flush table arp ARP
EOF

# nft will error on flush of non-existent tables on first run; handle that:
nft list ruleset | grep -q 'table inet DDOS'       || sed -i '/flush table inet DDOS/d'       "$RULES"
nft list ruleset | grep -q 'table inet tcp_portscan' || sed -i '/flush table inet tcp_portscan/d' "$RULES"
nft list ruleset | grep -q 'table arp ARP'          || sed -i '/flush table arp ARP/d'          "$RULES"

# ---------------------------------------------------------------------------
# ARP rate limiting
# ---------------------------------------------------------------------------
if [ "$arp_limit_enable" = "1" ]; then
cat >> "$RULES" <<EOF

table arp ARP {
    chain arp_limit {
        type filter hook input priority 0; policy accept;
        arp operation 1 meter per_mac { ether saddr limit rate ${arp_limit}/second burst 2 packets } counter accept
        arp operation 1 counter drop
    }
}
EOF
fi

# ---------------------------------------------------------------------------
# reject_drop chain (shared target for input drop rules)
# ---------------------------------------------------------------------------
if [ "$reject_with_icmp" = "1" ]; then
cat >> "$RULES" <<EOF

table inet DDOS {
    chain reject_drop {
        counter reject with icmp type port-unreachable
    }
}
EOF
else
cat >> "$RULES" <<EOF

table inet DDOS {
    chain reject_drop {
        counter drop
    }
}
EOF
fi

# ---------------------------------------------------------------------------
# Flood protection chains
# ---------------------------------------------------------------------------

# SYN flood
if [ "$syn_flood" = "1" ]; then
cat >> "$RULES" <<EOF

table inet DDOS {
    chain syn_flood {
        limit rate ${syn_flood_limit}/second burst ${syn_flood_burst} packets return comment "Accept SYN below rate limit"
        counter drop comment "Drop excess SYN"
    }
}
EOF
else
cat >> "$RULES" <<EOF

table inet DDOS {
    chain syn_flood {
        return
    }
}
EOF
fi

# ICMP flood
if [ "$icmp_flood" = "1" ]; then
cat >> "$RULES" <<EOF

table inet DDOS {
    chain icmp_flood {
        limit rate ${icmp_flood_limit}/second burst ${icmp_flood_burst} packets return
        counter drop comment "Drop excess ICMP"
    }
}
EOF
else
cat >> "$RULES" <<EOF

table inet DDOS {
    chain icmp_flood {
        return
    }
}
EOF
fi

# UDP flood
if [ "$udp_flood" = "1" ]; then
cat >> "$RULES" <<EOF

table inet DDOS {
    chain udp_flood {
        limit rate ${udp_flood_limit}/second burst ${udp_flood_burst} packets return
        counter drop comment "Drop excess UDP"
    }
}
EOF
else
cat >> "$RULES" <<EOF

table inet DDOS {
    chain udp_flood {
        return
    }
}
EOF
fi

# ---------------------------------------------------------------------------
# Main DDoS filter — flags, invalid packets, flood dispatch
# (priority -495: runs before fw4's prerouting at -300)
# ---------------------------------------------------------------------------
cat >> "$RULES" <<EOF

table inet DDOS {
    chain filter_ddos {
        type filter hook prerouting priority -495; policy accept;

        # Only process packets arriving on WAN
        iifname != { ${wan_device} } return

EOF

# Bogon source filter (before anything else on WAN)
if [ "$bogon" = "1" ]; then
    if [ -n "$forward_router" ]; then
cat >> "$RULES" <<EOF
        # Allow configured upstream router(s) before bogon check
        ip saddr { ${forward_router} } counter accept
EOF
    fi
cat >> "$RULES" <<EOF
        # Drop bogon source addresses
        ip saddr { ${bogon_addresses} } counter drop comment "${log_prefix}: bogon src"
EOF
fi

cat >> "$RULES" <<EOF
        # Drop IPv4 fragments
        ip frag-off & 0x1fff != 0 counter drop comment "${log_prefix}: fragment"

        # Drop tiny MSS (common in SYN amplification)
        tcp flags syn tcp option maxseg size 1-535 counter drop comment "${log_prefix}: tiny MSS"

        # Valid TCP flag combinations — anything else is dropped below
        meta l4proto tcp tcp flags syn   / fin,syn,rst,urg,ack,psh accept
        meta l4proto tcp tcp flags fin   / fin,syn,rst,urg,ack,psh accept
        meta l4proto tcp tcp flags rst   / fin,syn,rst,urg,ack,psh accept
        meta l4proto tcp tcp flags ack   / fin,syn,rst,urg,ack,psh accept
        meta l4proto tcp tcp flags syn,ack   / fin,syn,rst,urg,ack,psh accept
        meta l4proto tcp tcp flags fin,ack   / fin,syn,rst,urg,ack,psh accept
        meta l4proto tcp tcp flags rst,ack   / fin,syn,rst,urg,ack,psh accept
        meta l4proto tcp tcp flags ack,psh   / fin,syn,rst,urg,ack,psh accept
        meta l4proto tcp tcp flags fin,psh   / fin,syn,rst,urg,ack,psh accept
        meta l4proto tcp tcp flags ack,fin,psh / fin,syn,rst,urg,ack,psh accept
        meta l4proto tcp counter log prefix "${log_prefix} invalid-flags: " drop

        # Dispatch ICMP to flood chain
        ip protocol icmp icmp type {
            echo-reply, destination-unreachable, source-quench, redirect,
            echo-request, time-exceeded, parameter-problem,
            timestamp-request, timestamp-reply, info-request, info-reply,
            address-mask-request, address-mask-reply,
            router-advertisement, router-solicitation
        } jump icmp_flood

        # Dispatch SYN to flood chain
        tcp flags syn / fin,syn,rst,ack jump syn_flood comment "${log_prefix}: rate limit SYN"
    }
}
EOF

# ---------------------------------------------------------------------------
# Secondary filter — CT state, UDP flood, Ragnarok, WAN/WG input drop
# (priority -155: runs after conntrack at -200)
# ---------------------------------------------------------------------------
cat >> "$RULES" <<EOF

table inet DDOS {
    chain drop_ddos {
        type filter hook prerouting priority -155; policy accept;

        # Drop invalid conntrack state
        ct state invalid counter drop comment "${log_prefix}: ct invalid"

        # New UDP from WAN -> flood chain
        iifname { ${wan_device} } udp sport 1-65535 ct state new jump udp_flood

        # Drop new TCP that doesn't have only SYN set (post-CT, non-established)
        tcp flags & (fin|syn|rst|ack) != syn ct state new counter drop comment "${log_prefix}: bad new TCP"

        # Allow established/related
        ct state established,related counter accept

EOF

# Ragnarok Online protection
if [ "$ragnarok_protection" = "1" ]; then
cat >> "$RULES" <<EOF
        # --- Ragnarok Online port protection ---
        # Login server (6900)
        tcp dport 6900 ct state new limit rate over ${ragnarok_login_rate}/second burst ${ragnarok_login_burst} packets counter drop
        # Char server (6121)
        tcp dport 6121 ct state new limit rate over ${ragnarok_char_rate}/second burst ${ragnarok_char_burst} packets counter drop
        # Map server (5121) — higher tolerance for fast map changes
        tcp dport 5121 ct state new limit rate over ${ragnarok_map_rate}/second burst ${ragnarok_map_burst} packets counter drop
        # Max simultaneous connections per IP across all RO ports (anti-Slowloris)
        tcp dport { 6900, 6121, 5121 } meter ro_conn_limit { ip saddr ct count over ${ragnarok_conn_limit} } counter drop

EOF
fi

# WAN input drop
if [ "$wan_input_drop" = "1" ]; then
cat >> "$RULES" <<EOF
        # Drop all new input on WAN
        iifname { ${wan_device} } goto reject_drop

EOF
fi

# WireGuard input drop
if [ "$wireguard_input_drop" = "1" ]; then
cat >> "$RULES" <<EOF
        # Drop all input on WireGuard interfaces
        iifname { wg0, wg1, wg2, wg3, wg4, wg5, wg6, wg7, wg8, wg9 } goto reject_drop

EOF
fi

cat >> "$RULES" <<EOF
    }
}
EOF

# ---------------------------------------------------------------------------
# SSH brute-force protection
# ---------------------------------------------------------------------------
if [ "$ssh_protection" = "1" ]; then
cat >> "$RULES" <<EOF

table inet DDOS {
    set ssh_banned {
        type ipv4_addr
        flags dynamic, timeout
        timeout ${ssh_ban_time}
    }

    chain ssh_guard {
        type filter hook input priority filter -5; policy accept;

        # Fast-path drop for already-banned IPs trying SSH
        tcp dport ${ssh_port} ip saddr @ssh_banned counter drop comment "${log_prefix}: ssh banned"

        # Allow established SSH sessions through without touching the rate limit
        tcp dport ${ssh_port} ct state established,related counter accept

        # New connections: apply per-IP rate limit
        # Exceeding burst -> ban the source IP for ssh_ban_time
        tcp dport ${ssh_port} ct state new \
            meter ssh_rate { ip saddr limit rate ${ssh_rate} burst ${ssh_burst} packets } \
            counter accept

        # If we reach here the meter rejected the packet -> ban and drop
        tcp dport ${ssh_port} ct state new \
            log prefix "${log_prefix} ssh-ban: " \
            update @ssh_banned { ip saddr } \
            counter drop
    }
}
EOF
fi

# ---------------------------------------------------------------------------
# Ragnarok Login Server brute-force (hashlimit per IP)
# ---------------------------------------------------------------------------
if [ "$ragnarok_protection" = "1" ]; then
cat >> "$RULES" <<EOF

table inet DDOS {
    set ro_login_banned {
        type ipv4_addr
        flags dynamic, timeout
        timeout ${portscan_drop_time}
    }

    chain ro_login_guard {
        type filter hook prerouting priority -154; policy accept;

        # Fast-path drop for already-banned IPs on login port
        tcp dport 6900 ip saddr @ro_login_banned counter drop comment "${log_prefix}: ro-login banned"

        # Per-IP rate limit on new connections to Login Server
        tcp dport 6900 ct state new \
            meter ro_login_bf { ip saddr limit rate ${ragnarok_login_bf_rate} burst ${ragnarok_login_bf_burst} packets } \
            counter accept

        # Exceeded -> ban IP and drop
        tcp dport 6900 ct state new \
            log prefix "${log_prefix} ro-login-ban: " \
            update @ro_login_banned { ip saddr } \
            counter drop
    }
}
EOF
fi


if [ "$port_scan_detection" = "1" ]; then
cat >> "$RULES" <<EOF

table inet tcp_portscan {
    set enemies4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout ${portscan_drop_time}
    }

    # Drop known scanners early (priority -500, before everything)
    chain portscan_drop {
        type filter hook prerouting priority -500; policy accept;

        # Fast-path drop for already-flagged IPs
        meta nfproto ipv4 ip saddr @enemies4 update @enemies4 { ip saddr } counter drop

        # XMAS and NULL scans on WAN
        iifname { ${wan_device} } tcp flags fin,psh,urg / fin,psh,urg jump input_limit
        iifname { ${wan_device} } tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 jump input_limit
    }

    # Detect port scans (priority -160, after conntrack setup at -200)
    chain portscan_detection {
        type filter hook prerouting priority -160; policy accept;

        iifname { ${wan_device} } ct state established,related counter accept

EOF

    if [ -n "$forward_router" ]; then
cat >> "$RULES" <<EOF
        # Exempt upstream router from portscan detection
        iifname { ${wan_device} } ip saddr { ${forward_router} } counter accept

EOF
    fi

cat >> "$RULES" <<EOF
        # Flag sources sending unusual TCP flag combos to non-exempt ports
        iifname { ${wan_device} } tcp sport != { ${portscan_src_ports} } \
            tcp flags syn,fin,ack,rst \
            tcp dport != ${portscan_dst_ports} \
            jump input_limit

        # Flag new UDP to all ports
        iifname { ${wan_device} } udp dport 1-65535 ct state new jump input_limit
    }

    chain input_limit {
        limit rate ${portscan_limit}/second counter return
        meta nfproto ipv4 log prefix "${log_prefix} portscan: " update @enemies4 { ip saddr } counter drop
    }
}
EOF
fi

# ---------------------------------------------------------------------------
# Bogon forward/postrouting filters
# ---------------------------------------------------------------------------
if [ "$bogon" = "1" ]; then
cat >> "$RULES" <<EOF

table inet DDOS {
    chain drop_forward {
        type filter hook forward priority filter -5; policy accept;

EOF
    if [ -n "$forward_router" ]; then
cat >> "$RULES" <<EOF
        ip daddr { ${forward_router} } counter accept
EOF
    fi
cat >> "$RULES" <<EOF
        oifname { ${wan_device} } ip daddr { ${bogon_addresses} } counter reject with icmp type host-unreachable
    }

    chain drop_postrouting {
        type filter hook postrouting priority filter +5; policy accept;

EOF
    if [ -n "$forward_router" ]; then
cat >> "$RULES" <<EOF
        ip daddr { ${forward_router} } counter accept
EOF
    fi
cat >> "$RULES" <<EOF
        oifname { ${wan_device} } ip daddr { ${bogon_addresses} } counter drop
    }
}
EOF
fi

# ===========================================================================
# APPLY
# ===========================================================================

log "Validating ruleset..."
if ! nft -c -f "$RULES"; then
    log "Ruleset validation FAILED. No changes applied."
    log "Inspect /tmp/ddos_rules.*.nft for details (file kept for debug)."
    trap - EXIT   # Don't delete the file so user can inspect it
    exit 1
fi

log "Applying ruleset..."
if ! nft -f "$RULES"; then
    log "Failed to apply ruleset. Check 'logread | grep ddos' for details."
    exit 1
fi

log "DDoS protection active on: ${wan_device}"
exit 0
