package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

/******************************************************
    Requests of client:

    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
*******************************************************/

// SOCKS5 command constants as defined in RFC 1928
const (
	// CommandConnect requests a TCP connection to the target (X'01')
	CommandConnect = uint8(1)
	// CommandBind requests the server to bind to a port for incoming connections (X'02')
	CommandBind = uint8(2)
	// CommandAssociate requests UDP association for relaying UDP datagrams (X'03')
	CommandAssociate = uint8(3)
)

// Address type constants as defined in RFC 1928
const (
	// AddressIPv4 indicates an IPv4 address follows (X'01')
	AddressIPv4 = uint8(1)
	// AddressDomainName indicates a domain name follows (X'03')
	AddressDomainName = uint8(3)
	// AddressIPv6 indicates an IPv6 address follows (X'04')
	AddressIPv6 = uint8(4)
)

/******************************************************
    Response of server:

    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
*******************************************************/

// Reply constants for server responses as defined in RFC 1928
const (
	// ReplySucceeded indicates the request was successful (X'00')
	ReplySucceeded uint8 = iota
	// ReplyServerFailure indicates a general server failure (X'01')
	ReplyServerFailure
	// ReplyRuleFailure indicates the connection was blocked by rules (X'02')
	ReplyRuleFailure
	// ReplyNetworkUnreachable indicates the network is unreachable (X'03')
	ReplyNetworkUnreachable
	// ReplyHostUnreachable indicates the host is unreachable (X'04')
	ReplyHostUnreachable
	// ReplyConnectionRefused indicates the connection was refused (X'05')
	ReplyConnectionRefused
	// ReplyTTLExpired indicates the TTL expired (X'06')
	ReplyTTLExpired
	// ReplyCommandNotSupported indicates the command is not supported (X'07')
	ReplyCommandNotSupported
	// ReplyAddrTypeNotSupported indicates the address type is not supported (X'08')
	ReplyAddrTypeNotSupported
)

// errUnrecognizedAddrType is returned when an invalid address type is encountered
var errUnrecognizedAddrType = fmt.Errorf("unrecognized address type")

// zeroBindAddr is used for TCP CONNECT responses where bind address is not meaningful
var zeroBindAddr = AddrSpec{IP: net.IPv4zero, Port: 1080}

// AddressRewriter is used to rewrite a destination address transparently.
// This can be used for implementing features like traffic routing, load balancing,
// or address translation. The returned context can contain additional metadata.
type AddressRewriter interface {
	// Rewrite takes a request and returns a potentially modified destination address.
	// The context may be modified to include additional routing information.
	Rewrite(ctx context.Context, request *Request) (context.Context, *AddrSpec)
}

// AddrSpec represents a SOCKS5 address specification.
// It can contain either an IP address (IPv4/IPv6) or a fully qualified domain name (FQDN).
type AddrSpec struct {
	// FQDN is the fully qualified domain name (empty if IP is used)
	FQDN string
	// IP is the IP address (nil if FQDN is used)
	IP net.IP
	// Port is the port number
	Port int
}

// String returns a human-readable representation of the address specification.
func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable for dialing, preferring IP over FQDN.
func (a AddrSpec) Address() string {
	if len(a.IP) != 0 {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// Request represents a SOCKS5 request received from a client.
// It contains the parsed command, destination address, and authentication context.
type Request struct {
	// Version is the SOCKS protocol version (should be 5)
	Version uint8
	// Command is the requested SOCKS command (CONNECT, BIND, ASSOCIATE)
	Command uint8
	// AuthContext contains authentication information from negotiation
	AuthContext *AuthContext
	// RemoteAddr is the address of the client that sent the request
	RemoteAddr *AddrSpec
	// DestAddr is the desired destination address from the client
	DestAddr *AddrSpec
	// realDestAddr is the actual destination (may be modified by rewriters)
	realDestAddr *AddrSpec
	// bufConn is the buffered connection for reading additional data
	bufConn io.Reader
}

// NewRequest parses a SOCKS5 request from the given reader.
// It reads and validates the request header and destination address.
// Returns an error if the request format is invalid or unsupported.
func NewRequest(bufConn io.Reader) (*Request, error) {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		return nil, fmt.Errorf("failed to get command version: %v", err)
	}

	// Ensure we are compatible
	if header[0] != socks5Version {
		return nil, fmt.Errorf("unsupported command version: %v", header[0])
	}

	// Read in the destination address
	dest, err := readAddrSpec(bufConn)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Version:  socks5Version,
		Command:  header[1],
		DestAddr: dest,
		bufConn:  bufConn,
	}

	return request, nil
}

// handleRequest processes a client request after authentication is complete.
// It resolves addresses, applies rewrites, and dispatches to the appropriate command handler.
func (s *Server) handleRequest(ctx context.Context, req *Request, conn net.Conn) error {
	// Resolve the address if we have a FQDN
	dest := req.DestAddr
	newCtx, err := s.resolveDestination(ctx, dest)
	if err != nil {
		if err := sendReply(conn, ReplyHostUnreachable, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return err
	}
	ctx = newCtx

	// Apply any address rewrites
	req.realDestAddr = req.DestAddr
	if s.config.Rewriter != nil {
		ctx, req.realDestAddr = s.config.Rewriter.Rewrite(ctx, req)
	}

	// Switch on the command
	switch req.Command {
	case CommandConnect:
		return s.handleConnect(ctx, conn, req)
	case CommandBind:
		return s.handleBind(ctx, conn, req)
	case CommandAssociate:
		return s.handleAssociate(ctx, conn, req)
	default:
		if err := sendReply(conn, ReplyCommandNotSupported, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("unsupported command: %v", req.Command)
	}
}

// handleConnect processes a CONNECT command by establishing a TCP connection to the target.
// It performs access control checks, connects to the destination, and proxies data bidirectionally.
func (s *Server) handleConnect(ctx context.Context, conn net.Conn, req *Request) error {
	// Check if this is allowed
	_ctx, ok := s.config.Rules.Allow(ctx, req)
	if !ok {
		if err := sendReply(conn, ReplyRuleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("failed to connect to %v: blocked by rules", req.DestAddr)
	}
	ctx = _ctx

	// Attempt to connect
	dial := s.config.Dial
	if dial == nil {
		dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
			return net.Dial(net_, addr)
		}
	}
	target, err := dial(ctx, "tcp", req.realDestAddr.Address())
	if err != nil {
		msg := err.Error()
		resp := ReplyHostUnreachable
		if strings.Contains(msg, "refused") {
			resp = ReplyConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = ReplyNetworkUnreachable
		}
		if err := sendReply(conn, resp, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("failed to connect to %v: %v", req.DestAddr, err)
	}
	defer func() {
		_ = target.Close() // Ignore close errors in defer
	}()

	// Send success
	if err := sendReply(conn, ReplySucceeded, &zeroBindAddr); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	// Start proxying
	errCh := make(chan error, 2)
	go proxy(ctx, target, req.bufConn, errCh)
	go proxy(ctx, conn, target, errCh)

	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			// return from this function closes target (and conn).
			return e
		}
	}
	return nil
}

// handleBind processes a BIND command (currently not implemented).
// The BIND command is used for protocols that require the client to accept incoming connections.
func (s *Server) handleBind(ctx context.Context, conn net.Conn, req *Request) error {
	// Check if this is allowed
	ctx, ok := s.config.Rules.Allow(ctx, req)
	if !ok {
		if err := sendReply(conn, ReplyRuleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("failed to bind to %v: blocked by rules", req.DestAddr)
	}
	_ = ctx // TODO: Use this context when BIND is implemented

	// TODO: Support bind
	if err := sendReply(conn, ReplyCommandNotSupported, nil); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}
	return nil
}

// handleAssociate processes an ASSOCIATE command for UDP proxying.
// It registers a UDP session and waits for the control connection to close.
func (s *Server) handleAssociate(ctx context.Context, conn net.Conn, req *Request) error {
	// Check if this is allowed
	ctx, ok := s.config.Rules.Allow(ctx, req)
	if !ok {
		if err := sendReply(conn, ReplyRuleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("failed to associate with %v: blocked by rules", req.DestAddr)
	}

	// Use the configured bind IP (guaranteed to be set during server creation)
	bindAddr := AddrSpec{IP: s.config.BindIP, Port: s.config.BindPort}

	if err := sendReply(conn, ReplySucceeded, &bindAddr); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	// Register UDP session for this client
	clientAddr := conn.RemoteAddr().String()
	s.udpSessionMgr.RegisterSession(clientAddr, ctx, req)

	// Ensure session cleanup when connection closes
	defer s.udpSessionMgr.UnregisterSession(clientAddr)

	// Wait for connection to close or context to be cancelled
	// This blocks until the client closes the connection
	done := make(chan error, 1)
	go func() {
		// This blocks until connection is closed (EOF) or an error occurs
		_, err := io.Copy(io.Discard, conn)
		done <- err
	}()

	select {
	case err := <-done:
		// Connection closed (EOF) or error occurred
		if err != nil && err != io.EOF {
			return fmt.Errorf("connection monitoring failed: %v", err)
		}
		return nil
	case <-ctx.Done():
		// Context cancelled (server shutdown, timeout, etc.)
		return ctx.Err()
	}
}

/***********************************
    Requests of client:

    +------+----------+----------+
    | ATYP | DST.ADDR | DST.PORT |
    +------+----------+----------+
    |  1   | Variable |    2     |
    +------+----------+----------+
************************************/

// readAddrSpec reads a SOCKS5 address specification from the given reader.
// It handles IPv4, IPv6, and domain name address types.
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case AddressIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case AddressIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case AddressDomainName:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, errUnrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

// resolveDestination resolves a domain name to an IP address if needed.
// If the AddrSpec contains an FQDN, it uses the configured resolver to get the IP.
func (s *Server) resolveDestination(ctx context.Context, addr *AddrSpec) (context.Context, error) {
	if addr.FQDN == "" {
		return ctx, nil // No FQDN to resolve
	}

	newCtx, ip, err := s.config.Resolver.Resolve(ctx, addr.FQDN)
	if err != nil {
		return ctx, fmt.Errorf("failed to resolve destination '%v': %v", addr.FQDN, err)
	}

	addr.IP = ip
	return newCtx, nil
}

// sendReply sends a SOCKS5 reply message with the given response code and address.
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = AddressIPv4
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = AddressDomainName
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = AddressIPv4
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = AddressIPv6
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}

// closeWriter defines an interface for connections that support half-close
type closeWriter interface {
	// CloseWrite closes the write side of the connection
	CloseWrite() error
}

// proxy copies data from src to dst in a goroutine, respecting context cancellation.
// It sends any errors through the provided error channel and attempts graceful connection shutdown.
func proxy(ctx context.Context, dst io.Writer, src io.Reader, errCh chan error) {
	done := make(chan error, 1)

	go func() {
		_, err := io.Copy(dst, src)
		if tcpConn, ok := dst.(closeWriter); ok {
			_ = tcpConn.CloseWrite() // Ignore close errors in proxy cleanup
		}
		done <- err
	}()

	select {
	case err := <-done:
		errCh <- err
	case <-ctx.Done():
		errCh <- ctx.Err()
	}
}
