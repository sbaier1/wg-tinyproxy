#!/bin/bash

# Ensure a config file is provided
if [[ -z "$1" ]]; then
    echo "Usage: $0 <wg0.conf>"
    exit 1
fi

WG_CONF="$1"

# Detect base64 decode flag based on OS (macOS uses -D, Linux uses -d)
if [[ "$(uname)" == "Darwin" ]]; then
    BASE64_DECODE="base64 -D"
else
    BASE64_DECODE="base64 -d"
fi

# Extract values from wg0.conf
WG_PRIVATE_KEY=$(grep -E "^PrivateKey" "$WG_CONF" | awk -F' = ' '{print $2}' | $BASE64_DECODE | xxd -p -c 256)
WG_PUBLIC_KEY=$(grep -E "^PublicKey" "$WG_CONF" | awk -F' = ' '{print $2}' | $BASE64_DECODE | xxd -p -c 256)
WG_ADDRESS=$(grep -E "^Address" "$WG_CONF" | awk -F' = ' '{print $2}')
WG_ALLOWED_IP=$(grep -E "^AllowedIPs" "$WG_CONF" | awk -F' = ' '{print $2}')
WG_ENDPOINT=$(grep -E "^Endpoint" "$WG_CONF" | awk -F' = ' '{print $2}')
if [[ -z "$WG_KEEPALIVE" ]]; then
    WG_KEEPALIVE=$(grep -E "^PersistentKeepalive" "$WG_CONF" | awk -F' = ' '{print $2}')
fi

# Output the environment mappings
cat <<EOF
export WG_PRIVATE_KEY="$WG_PRIVATE_KEY"
export WG_PUBLIC_KEY="$WG_PUBLIC_KEY"
export WG_ADDRESS="$WG_ADDRESS"
export WG_ALLOWED_IP="$WG_ALLOWED_IP"
export WG_ENDPOINT="$WG_ENDPOINT"
export WG_KEEPALIVE="${WG_KEEPALIVE:-0}"
EOF
