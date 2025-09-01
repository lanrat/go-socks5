package socks5

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

const (
	socks5Version = uint8(5)
)

// Context keys for connection metadata
type contextKey string

const (
	ClientAddrKey contextKey = "client_addr"
	ServerAddrKey contextKey = "server_addr"
	ConnTimeKey   contextKey = "conn_time"
)

// ErrorLogger error handler, compatible with std logger
type ErrorLogger interface {
	Printf(format string, v ...interface{})
}

// Config is used to setup and configure a Server
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

	// BindIP is used for bind or udp associate
	BindPort int

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger ErrorLogger

	// ConnTimeout is the maximum time a connection can be active.
	// If zero (default), connections have no timeout.
	ConnTimeout time.Duration

	// Optional function for dialing out
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	DialUDP func(ctx context.Context, network string, udpClientSrcAddr, targetUDPAddr *net.UDPAddr) (net.Conn, error)
}

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config         *Config
	authMethods    map[uint8]Authenticator
	udpSessionMgr  *UDPSessionManager
}

// New creates a new Server and potentially returns an error
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

	server := &Server{
		config:        conf,
		udpSessionMgr: NewUDPSessionManager(),
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(ctx context.Context, network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
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
		go s.handleUDP(c)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
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
			connCtx = context.WithValue(connCtx, ClientAddrKey, c.RemoteAddr().String())
			connCtx = context.WithValue(connCtx, ServerAddrKey, c.LocalAddr().String())
			connCtx = context.WithValue(connCtx, ConnTimeKey, time.Now())
			
			if err := s.ServeConn(connCtx, c); err != nil {
				s.config.Logger.Printf("failed to serve connection: %v", err)
			}
		}(conn)
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) error {
	defer func() {
		_ = conn.Close() // Ignore close errors in defer
	}()
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
	if err := s.handleRequest(ctx, request, conn); err != nil {
		err = fmt.Errorf("failed to handle request: %v", err)
		s.config.Logger.Printf("socks: %v", err)
		return err
	}

	return nil
}
