# wg-tinyproxy

A super simple wireguard proxy that uses the wireguard-go userspace implementation.

A bit like socat but completely userspace and only intended for a simple point-to-point `tcp->wg->VPN->wg->tcp` connection.

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

Optional conf:

```shell
# healthcheck port, will provide a /health endpoint for readiness (or startup probe) checking (no continuous liveness check)
HEALTH_PORT
# MTU for the WireGuard interface (default: 1420)
WG_MTU
# Proxy mode: "egress" (default) or "ingress"
PROXY_MODE
# Listen address for ingress mode (default: 0.0.0.0)
LISTEN_ADDR
```

## Proxy Modes

### Egress (default)

Listens on the WireGuard tunnel and forwards to the regular network. Use this when you want to expose a service from outside the tunnel to clients inside the tunnel.

```
[WG tunnel] --> [wg-tinyproxy] --> [TARGET_HOST:TARGET_PORT]
```

### Ingress

Listens on the regular network and forwards through the WireGuard tunnel. Use this when you want to expose a service inside the tunnel to clients outside.

```
[LISTEN_ADDR:LOCAL_PORT] --> [wg-tinyproxy] --> [WG tunnel] --> [TARGET_HOST:TARGET_PORT]
```

Example:
```shell
PROXY_MODE=ingress
LISTEN_ADDR=0.0.0.0
LOCAL_PORT=8080
TARGET_HOST=10.0.0.5
TARGET_PORT=80
```

## Health Check

The `/health` endpoint supports different validation modes via query parameters:

| Mode | URL | Description |
|------|-----|-------------|
| Default | `/health` | Checks if proxy is ready (startup check only) |
| TCP | `/health?mode=tcp` | TCP connect to target through tunnel |
| HTTP | `/health?mode=http&path=/healthz` | HTTP GET to target through tunnel |

Additional parameters:
- `timeout` - connection timeout (default: `5s`), e.g. `timeout=3s`

### Kubernetes examples

```yaml
# Default (startup only)
readinessProbe:
  httpGet:
    port: 9091
    path: /health

# TCP validation through tunnel
readinessProbe:
  httpGet:
    port: 9091
    path: /health?mode=tcp

# HTTP validation through tunnel
readinessProbe:
  httpGet:
    port: 9091
    path: /health?mode=http&path=/healthz
```

### wg config conversion

There's a small script [here](wg_conf_to_env.sh) that will convert a typical wg.conf into an env mapping as expected by the tool.
