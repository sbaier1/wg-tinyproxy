package main

import (
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

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	proxyReady    = false
	tunnelUpMutex = sync.Mutex{}
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

func startHealthCheckListener(port string) {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		tunnelUpMutex.Lock()
		defer tunnelUpMutex.Unlock()
		if proxyReady {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		} else {
			http.Error(w, "WireGuard tunnel is down", http.StatusServiceUnavailable)
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
		1420,
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

	// Start TCP listener
	listener, err := tnet.ListenTCP(&net.TCPAddr{Port: listenPortInt})
	if err != nil {
		log.Fatal("Failed to listen on port:", err)
	}
	proxyReady = true
	log.Printf("TCP proxy listening on %s:%s", localAddrStr, localPort)
	log.Printf("Forwarding to %s:%s", targetAddrStr, targetPort)

	// Accept and handle connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		// Handle each connection in a separate goroutine
		go handleConnection(conn, targetAddrStr, targetPort)
	}
}

func handleConnection(clientConn net.Conn, targetHost, targetPort string) {
	defer clientConn.Close()

	// Connect to the target
	targetAddr := net.JoinHostPort(targetHost, targetPort)
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	log.Printf("Proxying connection from %s to %s", clientConn.RemoteAddr(), targetAddr)

	// Copy data in both directions simultaneously
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
	err = <-errCh
	if err != nil && err != io.EOF {
		log.Printf("Connection error: %v", err)
	}
}
