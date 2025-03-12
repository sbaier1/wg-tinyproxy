# wg-tinyproxy

A super simple wireguard proxy that uses the wireguard-go userspace implementation.

The main use-case for this tool is to allow exposing individual downstream services within a Wireguard network.

By leveraging a userspace implementation and proxying directly from that userspace implementation, we can expose services within the confines of a container, allowing us to just run this as a regular, very small sidecar container, without running as root and without adding `NET_ADMIN` capabilities.

Currently only supports proxying to TCP services.

The concrete use-case i intend it for: Reverse tunneling to a K8s gateway controller

## Configuration

Requires these env variables:

```shell
# Regular conf params, no DNS because we won't connect to anything on the tunnel
# client key
WG_PRIVATE_KEY
# server key
WG_PUBLIC_KEY
# allowedip CIDR
WG_ALLOWED_IP
# server endpoint+port
WG_ENDPOINT
WG_LISTEN_PORT
# PersistentKeepalive
WG_KEEPALIVE
# local bind addr+port
LOCAL_IP
LOCAL_PORT
# target host+port
TARGET_HOST
TARGET_PORT
```
