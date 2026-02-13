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
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	proxyReady    = false
	tunnelUpMutex = sync.Mutex{}

	// Health check dependencies (set after tunnel is up)
	healthTnet       *netstack.Net
	healthTargetHost string
	healthTargetPort string
)

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

	localPort, err := getRequiredEnv("LOCAL_PORT")
	if err != nil {
		log.Fatal(err)
	}

	targetAddrStr, err := getRequiredEnv("TARGET_HOST")
	if err != nil {
		log.Fatal(err)
	}

	targetPort, err := getRequiredEnv("TARGET_PORT")
	if err != nil {
		log.Fatal(err)
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

	// Parse listen port
	listenPortInt, err := strconv.Atoi(localPort)
	if err != nil {
		log.Fatal("Invalid local port:", err)
	}

	// Set health check dependencies
	healthTnet = tnet
	healthTargetHost = targetAddrStr
	healthTargetPort = targetPort

	switch proxyMode {
	case "egress":
		// Egress mode: listen on tunnel, forward to regular network
		listener, err := tnet.ListenTCP(&net.TCPAddr{Port: listenPortInt})
		if err != nil {
			log.Fatal("Failed to listen on tunnel port:", err)
		}

		proxyReady = true
		log.Printf("TCP proxy (egress) listening on tunnel %s:%s", localAddrStr, localPort)
		log.Printf("Forwarding to %s:%s", targetAddrStr, targetPort)

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}
			go handleEgressConnection(conn, targetAddrStr, targetPort)
		}

	case "ingress":
		// Ingress mode: listen on regular network, forward through tunnel
		listenAddress := net.JoinHostPort(listenAddr, localPort)
		listener, err := net.Listen("tcp", listenAddress)
		if err != nil {
			log.Fatal("Failed to listen on address:", err)
		}

		proxyReady = true
		log.Printf("TCP proxy (ingress) listening on %s", listenAddress)
		log.Printf("Forwarding to %s:%s via tunnel", targetAddrStr, targetPort)

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}
			go handleIngressConnection(conn, targetAddrStr, targetPort, tnet)
		}

	default:
		log.Fatalf("Invalid PROXY_MODE: %s (must be 'egress' or 'ingress')", proxyMode)
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
