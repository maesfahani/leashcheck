#!/bin/sh
# Runs as root for a moment with a few capabilities, sets up the firewall and
# the user, then drops every privilege for good and starts the real command.
set -eu

: "${LEASH_UID:?leash: LEASH_UID not set}" "${LEASH_GID:?leash: LEASH_GID not set}"

firewall() {
    # Internet stays open. The host, the local network and cloud metadata do not.
    iptables -w -A OUTPUT -o lo -j ACCEPT || return 1
    # the configured DNS servers may sit in a private range (home router, Docker)
    for ns in $(awk '$1 == "nameserver" { print $2 }' /etc/resolv.conf); do
        case "$ns" in *:*) continue ;; esac
        iptables -w -A OUTPUT -d "$ns" -p udp --dport 53 -j ACCEPT || return 1
        iptables -w -A OUTPUT -d "$ns" -p tcp --dport 53 -j ACCEPT || return 1
    done
    for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10; do
        iptables -w -A OUTPUT -d "$net" -j REJECT || return 1
    done
    # IPv6 is off in Docker by default; block local ranges if it is on
    if ip6tables -w -L OUTPUT >/dev/null 2>&1; then
        ip6tables -w -A OUTPUT -o lo -j ACCEPT || return 1
        for net in fc00::/7 fe80::/10; do
            ip6tables -w -A OUTPUT -d "$net" -j REJECT || return 1
        done
    fi
}

if ! firewall; then
    echo "leash: could not set up the firewall; refusing to start." >&2
    exit 1
fi

# a passwd entry, so tools that look up the current user do not fail
if ! grep -q "^[^:]*:[^:]*:${LEASH_UID}:" /etc/passwd; then
    echo "agent:x:${LEASH_UID}:${LEASH_GID}:agent:/home/agent:/bin/bash" >> /etc/passwd
fi

# the home volume is root-owned on first use
if [ "$(stat -c %u /home/agent)" != "$LEASH_UID" ]; then
    chown -R "${LEASH_UID}:${LEASH_GID}" /home/agent
fi

exec setpriv --reuid "$LEASH_UID" --regid "$LEASH_GID" --clear-groups \
    --inh-caps=-all --bounding-set=-all --no-new-privs -- "$@"
