package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// PortMapping represents a single port forwarding rule
type PortMapping struct {
	ListenPort int
	TargetPort int
}

// parsePortMappings parses a comma-separated list of port mappings in format "src:dst,src:dst"
// If a single number is provided (e.g., "8080"), it maps to the same port (8080:8080)
func parsePortMappings(mappings string) ([]PortMapping, error) {
	var result []PortMapping
	for _, mapping := range strings.Split(mappings, ",") {
		mapping = strings.TrimSpace(mapping)
		if mapping == "" {
			continue
		}

		parts := strings.Split(mapping, ":")
		var listenPort, targetPort int
		var err error

		switch len(parts) {
		case 1:
			// Single port: use same port for both
			listenPort, err = strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", parts[0], err)
			}
			targetPort = listenPort
		case 2:
			listenPort, err = strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid listen port %q: %w", parts[0], err)
			}
			targetPort, err = strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid target port %q: %w", parts[1], err)
			}
		default:
			return nil, fmt.Errorf("invalid port mapping %q: expected format 'listen:target' or 'port'", mapping)
		}

		result = append(result, PortMapping{ListenPort: listenPort, TargetPort: targetPort})
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no valid port mappings found")
	}

	return result, nil
}

var (
	proxyReady    = false
	tunnelUpMutex = sync.Mutex{}

	// Health check dependencies (set after tunnel is up)
	healthTnet       *netstack.Net
	healthDev        *device.Device
	healthTargetHost string
	healthTargetPort string
)

// checkTunnel verifies the WireGuard tunnel has a recent handshake with the peer.
// maxAge is the oldest acceptable handshake age. WireGuard rekeys every ~2min, so
// a handshake older than ~3min indicates the tunnel is wedged or the peer is gone.
func checkTunnel(maxAge time.Duration) error {
	if healthDev == nil {
		return fmt.Errorf("tunnel not initialized")
	}

	cfg, err := healthDev.IpcGet()
	if err != nil {
		return fmt.Errorf("IpcGet failed: %w", err)
	}

	var sec, nsec int64
	var sawPeer bool
	for _, line := range strings.Split(cfg, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			sawPeer = true
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if !sawPeer {
		return fmt.Errorf("no peer configured")
	}
	if sec == 0 && nsec == 0 {
		return fmt.Errorf("no handshake yet")
	}
	age := time.Since(time.Unix(sec, nsec))
	if age > maxAge {
		return fmt.Errorf("last handshake %s ago (max %s)", age.Truncate(time.Second), maxAge)
	}
	return nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getRequiredEnv(key string) (string, error) {
	if value, exists := os.LookupEnv(key); exists {
		return value, nil
	}
	return "", fmt.Errorf("required environment variable %s is not set", key)
}

func checkTCP(timeout time.Duration) error {
	if healthTnet == nil {
		return fmt.Errorf("tunnel not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addr := net.JoinHostPort(healthTargetHost, healthTargetPort)
	conn, err := healthTnet.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("TCP connect failed: %w", err)
	}
	conn.Close()
	return nil
}

func checkHTTP(path string, timeout time.Duration) error {
	if healthTnet == nil {
		return fmt.Errorf("tunnel not initialized")
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: healthTnet.DialContext,
		},
	}

	url := fmt.Sprintf("http://%s:%s%s", healthTargetHost, healthTargetPort, path)
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	return nil
}

func startHealthCheckListener(port string) {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		tunnelUpMutex.Lock()
		ready := proxyReady
		tunnelUpMutex.Unlock()

		if !ready {
			http.Error(w, "WireGuard tunnel is down", http.StatusServiceUnavailable)
			return
		}

		mode := r.URL.Query().Get("mode")
		timeoutStr := r.URL.Query().Get("timeout")
		timeout := 5 * time.Second
		if timeoutStr != "" {
			if d, err := time.ParseDuration(timeoutStr); err == nil {
				timeout = d
			}
		}

		switch mode {
		case "tcp":
			if err := checkTCP(timeout); err != nil {
				log.Printf("Health check (tcp) failed: %v", err)
				http.Error(w, fmt.Sprintf("TCP check failed: %v", err), http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK (tcp)"))

		case "tunnel":
			maxAge := 3 * time.Minute
			if s := r.URL.Query().Get("max_age"); s != "" {
				if d, err := time.ParseDuration(s); err == nil {
					maxAge = d
				}
			}
			if err := checkTunnel(maxAge); err != nil {
				log.Printf("Health check (tunnel) failed: %v", err)
				http.Error(w, fmt.Sprintf("Tunnel check failed: %v", err), http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK (tunnel)"))

		case "http":
			path := r.URL.Query().Get("path")
			if path == "" {
				path = "/"
			}
			if err := checkHTTP(path, timeout); err != nil {
				log.Printf("Health check (http) failed: %v", err)
				http.Error(w, fmt.Sprintf("HTTP check failed: %v", err), http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK (http)"))

		default:
			// Default: just check if proxy is ready (original behavior)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	})

	log.Printf("Health check listener started on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start health check listener: %v", err)
	}
}

func main() {
	// Get WireGuard configuration from environment variables
	privateKey, err := getRequiredEnv("WG_PRIVATE_KEY")
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := getRequiredEnv("WG_PUBLIC_KEY")
	if err != nil {
		log.Fatal(err)
	}

	allowedIP, err := getRequiredEnv("WG_ALLOWED_IP")
	if err != nil {
		log.Fatal(err)
	}

	endpoint, err := getRequiredEnv("WG_ENDPOINT")
	if err != nil {
		log.Fatal(err)
	}

	keepAlive := getEnvOrDefault("WG_KEEPALIVE", "25")

	// Get proxy configuration
	localAddrStr, err := getRequiredEnv("WG_ADDRESS")
	if err != nil {
		log.Fatal(err)
	}

	targetAddrStr, err := getRequiredEnv("TARGET_HOST")
	if err != nil {
		log.Fatal(err)
	}

	// Parse port mappings: either PORT_MAPPINGS or legacy LOCAL_PORT/TARGET_PORT
	var portMappings []PortMapping
	if mappingsStr := getEnvOrDefault("PORT_MAPPINGS", ""); mappingsStr != "" {
		portMappings, err = parsePortMappings(mappingsStr)
		if err != nil {
			log.Fatalf("Invalid PORT_MAPPINGS: %v", err)
		}
	} else {
		// Legacy single-port mode
		localPort, err := getRequiredEnv("LOCAL_PORT")
		if err != nil {
			log.Fatal(err)
		}
		targetPort, err := getRequiredEnv("TARGET_PORT")
		if err != nil {
			log.Fatal(err)
		}
		listenPortInt, err := strconv.Atoi(localPort)
		if err != nil {
			log.Fatal("Invalid LOCAL_PORT:", err)
		}
		targetPortInt, err := strconv.Atoi(targetPort)
		if err != nil {
			log.Fatal("Invalid TARGET_PORT:", err)
		}
		portMappings = []PortMapping{{ListenPort: listenPortInt, TargetPort: targetPortInt}}
	}

	healthPort := getEnvOrDefault("HEALTH_PORT", "")
	mtu := getEnvOrDefault("WG_MTU", "1420")
	proxyMode := getEnvOrDefault("PROXY_MODE", "egress")
	listenAddr := getEnvOrDefault("LISTEN_ADDR", "0.0.0.0")

	// Parse MTU
	mtuInt, err := strconv.Atoi(mtu)
	if err != nil {
		log.Fatal("Invalid MTU value:", err)
	}

	// Start health check listener if HEALTH_PORT is set
	if healthPort != "" {
		go startHealthCheckListener(healthPort)
	}

	// We won't be makign any DNS queries, we only listen on the tunnel
	dnsServers := []netip.Addr{}

	// Create the WireGuard TUN device with netstack
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(localAddrStr)},
		dnsServers,
		mtuInt,
	)
	if err != nil {
		log.Fatal("Failed to create TUN device:", err)
	}

	// Create and configure the WireGuard device
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard: "))

	// Convert base64 keys to hex for WireGuard IPC
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		log.Fatal("Failed to decode private key:", err)
	}
	privateKeyHex := hex.EncodeToString(privateKeyBytes)

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		log.Fatal("Failed to decode public key:", err)
	}
	publicKeyHex := hex.EncodeToString(publicKeyBytes)

	// Configure WireGuard using IPC
	wgConfig := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s
persistent_keepalive_interval=%s
endpoint=%s
`, privateKeyHex, publicKeyHex, allowedIP, keepAlive, endpoint)

	err = dev.IpcSet(wgConfig)
	if err != nil {
		log.Fatal("Failed to configure WireGuard:", err)
	}

	// Bring up WireGuard interface
	err = dev.Up()
	if err != nil {
		log.Fatal("Failed to bring up WireGuard interface:", err)
	}

	// Set health check dependencies (use first mapping for health check target)
	healthTnet = tnet
	healthDev = dev
	healthTargetHost = targetAddrStr
	healthTargetPort = strconv.Itoa(portMappings[0].TargetPort)

	// Validate proxy mode
	if proxyMode != "egress" && proxyMode != "ingress" {
		log.Fatalf("Invalid PROXY_MODE: %s (must be 'egress' or 'ingress')", proxyMode)
	}

	// Start listeners for each port mapping
	var wg sync.WaitGroup
	for _, mapping := range portMappings {
		wg.Add(1)
		go func(m PortMapping) {
			defer wg.Done()
			switch proxyMode {
			case "egress":
				runEgressListener(tnet, localAddrStr, targetAddrStr, m)
			case "ingress":
				runIngressListener(tnet, listenAddr, targetAddrStr, m)
			}
		}(mapping)
	}

	proxyReady = true
	log.Printf("TCP proxy (%s) started with %d port mapping(s)", proxyMode, len(portMappings))
	wg.Wait()
}

func runEgressListener(tnet *netstack.Net, localAddr, targetHost string, mapping PortMapping) {
	listener, err := tnet.ListenTCP(&net.TCPAddr{Port: mapping.ListenPort})
	if err != nil {
		log.Fatalf("Failed to listen on tunnel port %d: %v", mapping.ListenPort, err)
	}

	log.Printf("  [egress] %s:%d -> %s:%d", localAddr, mapping.ListenPort, targetHost, mapping.TargetPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection on port %d: %v", mapping.ListenPort, err)
			continue
		}
		go handleEgressConnection(conn, targetHost, strconv.Itoa(mapping.TargetPort))
	}
}

func runIngressListener(tnet *netstack.Net, listenAddr, targetHost string, mapping PortMapping) {
	listenAddress := net.JoinHostPort(listenAddr, strconv.Itoa(mapping.ListenPort))
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddress, err)
	}

	log.Printf("  [ingress] %s -> %s:%d (via tunnel)", listenAddress, targetHost, mapping.TargetPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection on %s: %v", listenAddress, err)
			continue
		}
		go handleIngressConnection(conn, targetHost, strconv.Itoa(mapping.TargetPort), tnet)
	}
}

func handleEgressConnection(clientConn net.Conn, targetHost, targetPort string) {
	defer clientConn.Close()

	// Connect to the target via regular network
	targetAddr := net.JoinHostPort(targetHost, targetPort)
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	log.Printf("Proxying connection from %s to %s", clientConn.RemoteAddr(), targetAddr)
	proxyData(clientConn, targetConn)
}

func handleIngressConnection(clientConn net.Conn, targetHost, targetPort string, tnet *netstack.Net) {
	defer clientConn.Close()

	// Connect to the target via WireGuard tunnel
	targetAddr := net.JoinHostPort(targetHost, targetPort)
	targetConn, err := tnet.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s via tunnel: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	log.Printf("Proxying connection from %s to %s (via tunnel)", clientConn.RemoteAddr(), targetAddr)
	proxyData(clientConn, targetConn)
}

func proxyData(clientConn, targetConn net.Conn) {
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(targetConn, clientConn)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(clientConn, targetConn)
		errCh <- err
	}()

	// Wait for either direction to close
	err := <-errCh
	if err != nil && err != io.EOF {
		log.Printf("Connection error: %v", err)
	}
}
