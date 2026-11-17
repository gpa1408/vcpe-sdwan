
#!/bin/sh
# ==========================================================
# SD-WAN GNS3 CI - Linux Namespace Setup
#
# CPE-1: ci-ns1 / 10.0.1.1
# CPE-2: ci-ns2 / 10.0.2.1
#
# Run INSIDE the selected Alpine Linux CPE.
# This script does not modify GNS3 projects.
# ==========================================================

set -eu

# 1. Select the correct CPE configuration
case "${1:-}" in
    cpe1)
        NS="ci-ns1"
        HOST_VETH="veth-ci1"
        NS_VETH="veth-ns1"
        GATEWAY="10.0.1.1"
        ;;
    cpe2)
        NS="ci-ns2"
        HOST_VETH="veth-ci2"
        NS_VETH="veth-ns2"
        GATEWAY="10.0.2.1"
        ;;
    *)
        echo "Usage: sh setup_namespace.sh cpe1|cpe2"
        exit 1
        ;;
esac

BRIDGE="br-lan"

echo "========================================="
echo " SD-WAN Namespace CI Setup"
echo "========================================="
echo "Namespace : $NS"
echo "Bridge    : $BRIDGE"
echo "Gateway   : $GATEWAY"

# 2. Validate environment
if [ "$(id -u)" -ne 0 ]; then
    echo "FAIL: Root privileges required."
    exit 1
fi

for cmd in ip grep udhcpc ping; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "FAIL: Missing command: $cmd"
        exit 1
    fi
done

if ! ip link show dev "$BRIDGE" >/dev/null 2>&1; then
    echo "FAIL: br-lan does not exist."
    exit 1
fi

if ! ip -4 addr show dev "$BRIDGE" |
        grep -Fq "$GATEWAY/24"; then
    echo "FAIL: Unexpected br-lan IP address."
    exit 1
fi

# 3. Detect an existing namespace
if ip netns list | grep -q "^${NS}\([[:space:]]\|$\)"; then
    echo "INFO: Namespace already exists."

    # Do not overwrite an existing configuration.
    if ! ip link show dev "$HOST_VETH" \
        >/dev/null 2>&1; then
        echo "FAIL: Host veth is missing."
        exit 1
    fi

    if ! ip netns exec "$NS" \
        ip link show dev "$NS_VETH" \
        >/dev/null 2>&1; then
        echo "FAIL: Namespace veth is missing."
        exit 1
    fi

    if ! ip -o link show dev "$HOST_VETH" |
        grep -Fq "master $BRIDGE"; then
        echo "FAIL: Host veth is not on br-lan."
        exit 1
    fi

    if ! ip netns exec "$NS" \
        ip -4 addr show dev "$NS_VETH" |
        grep -q "inet "; then
        echo "FAIL: Namespace has no IPv4 address."
        exit 1
    fi

else
    echo "INFO: Creating new namespace."

    # Prevent collision with an existing interface
    if ip link show dev "$HOST_VETH" \
        >/dev/null 2>&1; then
        echo "FAIL: Host veth already exists."
        exit 1
    fi

    # 4. Create namespace and virtual cable
    ip netns add "$NS"

    ip link add "$HOST_VETH" \
        type veth peer name "$NS_VETH"

    # 5. Move one end into namespace
    ip link set "$NS_VETH" netns "$NS"

    # 6. Attach host side to LAN bridge
    ip link set "$HOST_VETH" master "$BRIDGE"
    ip link set "$HOST_VETH" up

    # 7. Activate namespace interfaces
    ip netns exec "$NS" \
        ip link set "$NS_VETH" up

    ip netns exec "$NS" \
        ip link set lo up

    # 8. DHCP helper:
    # Assign IP and route without changing host DNS.
    DHCP_SCRIPT="/tmp/ci-netns-udhcpc.sh"

    cat > "$DHCP_SCRIPT" <<'DHCP_EOF'
#!/bin/sh
case "$1" in
    bound|renew)
        if [ "${subnet:-}" != "255.255.255.0" ]; then
            echo "FAIL: Unexpected DHCP subnet mask."
            exit 1
        fi
        ip -4 addr replace "$ip/24" dev "$interface"
        if [ -n "${router:-}" ]; then
            set -- $router
            ip -4 route replace default \
                via "$1" dev "$interface"
        fi
        ;;
esac
DHCP_EOF

    chmod 700 "$DHCP_SCRIPT"

    echo "INFO: Requesting DHCP address..."

    ip netns exec "$NS" \
        udhcpc -i "$NS_VETH" \
        -n -q -t 3 -T 3 -s "$DHCP_SCRIPT"
fi

# 9. Show namespace address
echo ""
echo "----- Namespace IP -----"

ip netns exec "$NS" \
    ip -br addr

# 10. Test local gateway connectivity
echo ""
echo "----- Gateway Connectivity Test -----"

if ip netns exec "$NS" \
    ping -c 3 -W 2 "$GATEWAY"; then

    echo ""
    echo "========================================="
    echo " PASS: Namespace connectivity successful"
    echo "========================================="
    exit 0
else
    echo ""
    echo "========================================="
    echo " FAIL: Gateway is unreachable"
    echo "========================================="
    exit 1
fi
