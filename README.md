# wg-tinyproxy

A super simple wireguard proxy that uses the wireguard-go userspace implementation.

The main use-case for this tool is to allow exposing individual downstream services within a Wireguard network.

By leveraging a userspace implementation and proxying directly from that userspace implementation, we can expose services within the confines of a container, allowing us to just run this as a regular, very small sidecar container, without running as root and without adding `NET_ADMIN` capabilities.

Currently only supports proxying to TCP services.

The concrete use-case i intend it for: Reverse tunneling to a K8s gateway controller