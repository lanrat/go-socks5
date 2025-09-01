package socks5

import (
	"context"
	"net"
)

// NameResolver defines the interface for resolving hostnames to IP addresses.
// Custom implementations can provide alternative resolution strategies.
type NameResolver interface {
	// Resolve resolves a hostname to an IP address, returning the updated context and IP
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// DNSResolver uses the system's default DNS resolver to resolve hostnames.
// This is the default resolver used when no custom resolver is provided.
type DNSResolver struct{}

// Resolve uses the system DNS to resolve a hostname to an IP address.
func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.IP, err
}
