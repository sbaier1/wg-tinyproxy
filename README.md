# wg-tinyproxy

A super simple wireguard proxy that uses the wireguard-go userspace implementation.

The main use-case for this tool is to allow exposing individual downstream services within a Wireguard network.

By leveraging a userspace implementation and proxying directly from that userspace implementation, we can expose services within the confines of a container, allowing us to just run this as a regular, very small sidecar container, without running as root and without adding `NET_ADMIN` capabilities.

Currently only supports proxying to TCP services.

The concrete use-case i intend it for: Reverse tunneling to a K8s gateway controller

## Configuration

Requires these env variables:

```shell
# Typical conf params, no DNS because we won't connect to anything on the tunnel
# client key, NOTE: wireguard-go expects both keys in hex format. you can convert it by piping it into base64 -d | xxd -p -c 256
WG_PRIVATE_KEY
# server key
WG_PUBLIC_KEY
# Interface.Address. We will also bind the listener to this address.
WG_ADDRESS
# AllowedIPs CIDR
WG_ALLOWED_IP
# server endpoint+port
WG_ENDPOINT
# PersistentKeepalive
WG_KEEPALIVE
# local bind port
LOCAL_PORT
# target host+port to proxy to
TARGET_HOST
TARGET_PORT
```

There's a small script [here](wg_conf_to_env.sh) that will convert a typical wg.conf into an env mapping as expected by the tool.