package main

/*
 * AXIS 2.0 P2P Relay Configuration
 */

const (
	RelayListenAddr = "0.0.0.0:6969"
	MaxUsers        = 100
)

var seedPeers = []string{
	"1.2.3.4:49152",
	"5.6.7.8:49152",
	"9.10.11.12:49152",
}

var validUsers = map[string]string{
	"admin": "admin123",
	"user1": "password1",
	"user2": "password2",
}
