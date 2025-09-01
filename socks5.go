// Package socks5 provides a complete implementation of a SOCKS5 server as defined in RFC 1928.
//
// This package includes support for:
//   - TCP CONNECT command for proxying TCP connections
//   - UDP ASSOCIATE command for proxying UDP datagrams
//   - Multiple authentication methods (no auth, username/password)
//   - Configurable address resolution and connection handling
//   - Rule-based access control
//   - Address rewriting capabilities
//   - Graceful server shutdown
//   - Connection timeouts and context-based cancellation
//
// The server is designed to be flexible and extensible, allowing custom implementations
// of authentication, name resolution, access rules, and address rewriting.
//
// Basic usage:
//
//	config := &socks5.Config{}
//	server, err := socks5.New(config)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	if err := server.ListenAndServe(context.Background(), ":1080"); err != nil {
//		log.Fatal(err)
//	}
//
// For more advanced configurations, see the Config struct and its various interface types.
package socks5

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

const (
	// socks5Version defines the SOCKS protocol version (5) as per RFC 1928
	socks5Version = uint8(5)
)

// contextKey is used as a type for context keys to avoid key collisions
type contextKey string

const (
	// ClientAddrKey is the context key for storing the client's remote address
	ClientAddrKey contextKey = "client_addr"
	// ServerAddrKey is the context key for storing the server's local address
	ServerAddrKey contextKey = "server_addr"
	// ConnTimeKey is the context key for storing the connection start time
	ConnTimeKey contextKey = "conn_time"
)

// ErrorLogger is an error handler interface compatible with the standard library logger.
// It is used by the SOCKS5 server to log errors and diagnostic information.
type ErrorLogger interface {
	// Printf formats and prints a log message similar to fmt.Printf
	Printf(format string, v ...interface{})
}

// Config is used to setup and configure a SOCKS5 Server.
// It provides options for authentication, networking, logging, and connection handling.
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is nil, then "auth-less" mode is enabled.
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// BindPort is the port used for bind or UDP associate operations.
	// If set to 0, UDP support is disabled.
	BindPort int

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger ErrorLogger

	// ConnTimeout is the maximum time a connection can be active.
	// If zero (default), connections have no timeout.
	ConnTimeout time.Duration

	// Dial is an optional function for making outbound TCP connections.
	// If nil, net.Dial is used.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// DialUDP is an optional function for making outbound UDP connections.
	// If nil, net.DialUDP is used with a zero source address.
	DialUDP func(ctx context.Context, network string, udpClientSrcAddr, targetUDPAddr *net.UDPAddr) (net.Conn, error)

	// UDPPacketSize sets the maximum size for UDP packets.
	// If zero, defaults to 2048 bytes.
	UDPPacketSize int

	// UDPSessionTimeout sets how long UDP sessions remain active without traffic.
	// If zero, defaults to 5 minutes.
	UDPSessionTimeout time.Duration
}

// Server is responsible for accepting connections and handling the details of the SOCKS5 protocol.
// It supports TCP CONNECT, UDP ASSOCIATE commands, and provides graceful shutdown capabilities.
type Server struct {
	config        *Config
	authMethods   map[uint8]Authenticator
	udpSessionMgr *UDPSessionManager

	// Shutdown coordination
	mu           sync.RWMutex
	listeners    []net.Listener
	udpConns     []net.PacketConn
	shutdown     chan struct{}
	shutdownOnce sync.Once
}

// New creates a new SOCKS5 server with the given configuration.
// It validates the configuration and sets up default values for any missing required fields.
// Returns an error if the configuration is invalid.
func New(conf *Config) (*Server, error) {
	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	// Ensure we have a log target
	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	// Ensure we have a bind IP (set default if not provided)
	if len(conf.BindIP) == 0 || conf.BindIP.IsUnspecified() {
		conf.BindIP = net.ParseIP("127.0.0.1")
	}

	// Set default UDP packet size if not provided
	if conf.UDPPacketSize == 0 {
		conf.UDPPacketSize = 2048 // 2KB default
	}

	// Set default UDP session timeout if not provided
	if conf.UDPSessionTimeout == 0 {
		conf.UDPSessionTimeout = 5 * time.Minute // 5 minutes default
	}

	server := &Server{
		config:        conf,
		udpSessionMgr: NewUDPSessionManager(conf.UDPSessionTimeout),
		shutdown:      make(chan struct{}),
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

// Shutdown gracefully shuts down the server without interrupting any active connections.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownOnce.Do(func() {
		close(s.shutdown)
	})

	// Stop UDP session manager
	s.udpSessionMgr.Stop()

	// Close all listeners
	s.mu.Lock()
	for _, listener := range s.listeners {
		_ = listener.Close()
	}
	for _, conn := range s.udpConns {
		_ = conn.Close()
	}
	s.mu.Unlock()

	// Wait for context cancellation or return immediately
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// ListenAndServe creates a network listener on the given address and serves SOCKS5 connections.
// It blocks until the context is cancelled or an error occurs.
// The network parameter should be "tcp", "tcp4", or "tcp6".
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, l)
}

// Serve accepts incoming connections from a listener and handles SOCKS5 protocol negotiations.
// It starts a UDP server if BindPort is configured, and spawns a goroutine for each TCP connection.
// This method blocks until the context is cancelled or an error occurs.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	// Track this listener for graceful shutdown
	s.mu.Lock()
	s.listeners = append(s.listeners, l)
	s.mu.Unlock()

	// Monitor context cancellation and close listener when cancelled
	go func() {
		select {
		case <-ctx.Done():
			// Context cancelled, close listener to unblock Accept()
			l.Close()
		case <-s.shutdown:
			// Server shutdown was called, close listener
			l.Close()
		}
	}()

	// open a UDP server if specified in config
	if s.config.BindPort > 0 {
		ip, _, _ := net.SplitHostPort(l.Addr().String())
		addr := net.UDPAddr{
			Port: s.config.BindPort,
			IP:   net.ParseIP(ip),
		}

		c, err := net.ListenUDP("udp", &addr)
		if err != nil {
			return err
		}

		// Track UDP connection for graceful shutdown
		s.mu.Lock()
		s.udpConns = append(s.udpConns, c)
		s.mu.Unlock()

		go s.handleUDP(ctx, c)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.shutdown:
			return nil
		default:
		}

		conn, err := l.Accept()
		if err != nil {
			// Check if error is due to context cancellation or shutdown
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-s.shutdown:
				return nil
			default:
				return err
			}
		}
		go func(c net.Conn) {
			if err := s.ServeConn(ctx, c); err != nil {
				s.config.Logger.Printf("failed to serve connection: %v", err)
			}
		}(conn)
	}
}

// ServeConn handles the SOCKS5 protocol for a single client connection.
// It performs authentication, parses the client request, and handles the requested command.
// The connection is automatically closed when this method returns.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) error {
	defer func() {
		_ = conn.Close() // Ignore close errors in defer
	}()

	// Create per-connection context with optional timeout and connection metadata
	var connCtx context.Context
	var cancel context.CancelFunc

	if s.config.ConnTimeout > 0 {
		connCtx, cancel = context.WithTimeout(ctx, s.config.ConnTimeout)
	} else {
		connCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	// Add connection metadata to context
	connCtx = context.WithValue(connCtx, ClientAddrKey, conn.RemoteAddr().String())
	connCtx = context.WithValue(connCtx, ServerAddrKey, conn.LocalAddr().String())
	connCtx = context.WithValue(connCtx, ConnTimeKey, time.Now())
	bufConn := bufio.NewReader(conn)

	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		s.config.Logger.Printf("socks: Failed to get version byte: %v", err)
		return err
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		err := fmt.Errorf("unsupported SOCKS version: %v", version)
		s.config.Logger.Printf("socks: %v", err)
		return err
	}

	// Authenticate the connection
	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		err = fmt.Errorf("failed to authenticate: %v", err)
		s.config.Logger.Printf("socks: %v", err)
		return err
	}

	request, err := NewRequest(bufConn)
	if err != nil {
		if err == errUnrecognizedAddrType {
			if err := sendReply(conn, ReplyAddrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("failed to read destination address: %v", err)
	}
	request.AuthContext = authContext
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	// Process the client request
	if err := s.handleRequest(connCtx, request, conn); err != nil {
		err = fmt.Errorf("failed to handle request: %v", err)
		s.config.Logger.Printf("socks: %v", err)
		return err
	}

	return nil
}
