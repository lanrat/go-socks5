package main

import (
	"context"
	"net"

	"github.com/lanrat/go-socks5"
)

func main() {
	conf := &socks5.Config{
		BindIP:   net.IPv4(127, 0, 0, 1),
		BindPort: 8000,
		// Optional: Configure UDP settings
		// UDPPacketSize:    4096,              // Custom UDP packet size (default: 2048)
		// UDPSessionTimeout: 10 * time.Minute, // Custom UDP session timeout (default: 5 minutes)
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe(context.Background(), "127.0.0.1:8000"); err != nil {
		panic(err)
	}
}
