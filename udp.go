package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const maxUDPPacketSize = 2 * 1024
const udpSessionIdleTimeout = 5 * time.Minute

var udpClientSrcAddrZero = &net.UDPAddr{IP: net.IPv4zero, Port: 0}

// UDPSession represents a UDP association session
type UDPSession struct {
	// Context from the ASSOCIATE command, with any rule modifications
	Context context.Context
	// Client's control connection address for session identification
	ClientAddr string
	// Time when session was created
	CreatedAt time.Time
	// Time of last UDP packet activity
	LastActivity time.Time
	// Request that created this session
	Request *Request
}

// UDPSessionManager manages UDP sessions
type UDPSessionManager struct {
	mu           sync.RWMutex
	sessions     map[string]*UDPSession // key: client address string (IP:port)
	sessionsByIP map[string]*UDPSession // key: client IP string (for fast IP-only lookup)
	cleanup      chan struct{}
	cleanupOnce  sync.Once
}

// NewUDPSessionManager creates a new UDP session manager
func NewUDPSessionManager() *UDPSessionManager {
	mgr := &UDPSessionManager{
		sessions:     make(map[string]*UDPSession),
		sessionsByIP: make(map[string]*UDPSession),
		cleanup:      make(chan struct{}),
	}

	// Start cleanup goroutine
	go mgr.cleanupExpiredSessions()

	return mgr
}

// RegisterSession registers a new UDP session
func (m *UDPSessionManager) RegisterSession(clientAddr string, ctx context.Context, req *Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	session := &UDPSession{
		Context:      ctx,
		ClientAddr:   clientAddr,
		CreatedAt:    now,
		LastActivity: now,
		Request:      req,
	}

	// Store in both indexes
	m.sessions[clientAddr] = session

	// Extract IP for IP-only index
	if host, _, err := net.SplitHostPort(clientAddr); err == nil {
		m.sessionsByIP[host] = session
	}
}

// GetSession retrieves a UDP session by client address
func (m *UDPSessionManager) GetSession(clientAddr string) (*UDPSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[clientAddr]
	return session, exists
}

// GetSessionByIP retrieves a UDP session by client IP (without port)
func (m *UDPSessionManager) GetSessionByIP(clientIP string) *UDPSession {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.sessionsByIP[clientIP]
}

// UpdateActivity updates the last activity time for a session
func (m *UDPSessionManager) UpdateActivity(clientAddr string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[clientAddr]; exists {
		session.LastActivity = time.Now()
	}
}

// UpdateActivityByIP updates the last activity time for a session by IP
func (m *UDPSessionManager) UpdateActivityByIP(clientIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session := m.sessionsByIP[clientIP]; session != nil {
		session.LastActivity = time.Now()
	}
}

// UnregisterSession removes a UDP session
func (m *UDPSessionManager) UnregisterSession(clientAddr string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from both indexes
	delete(m.sessions, clientAddr)

	// Extract IP and remove from IP index
	if host, _, err := net.SplitHostPort(clientAddr); err == nil {
		delete(m.sessionsByIP, host)
	}
}

// Stop gracefully stops the session manager
func (m *UDPSessionManager) Stop() {
	m.cleanupOnce.Do(func() {
		close(m.cleanup)
	})
}

// cleanupExpiredSessions removes expired UDP sessions
func (m *UDPSessionManager) cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.cleanup:
			return
		case <-ticker.C:
			now := time.Now()
			m.mu.Lock()
			for addr, session := range m.sessions {
				if now.Sub(session.LastActivity) > udpSessionIdleTimeout {
					// Remove from both indexes
					delete(m.sessions, addr)
					if host, _, err := net.SplitHostPort(addr); err == nil {
						delete(m.sessionsByIP, host)
					}
				}
			}
			m.mu.Unlock()
		}
	}
}

var udpPacketBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, maxUDPPacketSize)
		return &buf
	},
}

func getUDPPacketBuffer() []byte {
	return *udpPacketBufferPool.Get().(*[]byte)
}

func putUDPPacketBuffer(p []byte) {
	p = p[:cap(p)]
	udpPacketBufferPool.Put(&p)
}

//FIXME: insecure implementation of UDP server, anyone could send package here without authentication

func (s *Server) handleUDP(ctx context.Context, udpConn *net.UDPConn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		buffer := getUDPPacketBuffer()
		n, src, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			select {
			case <-ctx.Done():
				putUDPPacketBuffer(buffer)
				return // Context cancelled, this is expected
			default:
				s.config.Logger.Printf("udp socks: Failed to accept udp traffic: %v", err)
				putUDPPacketBuffer(buffer)
				continue
			}
		}
		buffer = buffer[:n]
		go func() {
			defer putUDPPacketBuffer(buffer)
			if err := s.serveUDPConn(buffer, src, func(data []byte) error {
				_, err := udpConn.WriteToUDP(data, src)
				return err
			}); err != nil {
				s.config.Logger.Printf("failed to serve UDP connection: %v", err)
			}
		}()
	}
}

/*********************************************************
    UDP PACKAGE to proxy
    +----+------+------+----------+----------+----------+
    |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    +----+------+------+----------+----------+----------+
    | 2  |  1   |  1   | Variable |    2     | Variable |
    +----+------+------+----------+----------+----------+
**********************************************************/

// ErrUDPFragmentNoSupported indicates that UDP fragmentation is not supported
var ErrUDPFragmentNoSupported = errors.New("UDP fragmentation not supported")

func (s *Server) serveUDPConn(udpPacket []byte, srcAddr *net.UDPAddr, reply func([]byte) error) error {
	// RSV  Reserved X'0000'
	// FRAG Current fragment number, do not support fragment here
	if len(udpPacket) < 3 {
		err := fmt.Errorf("failed to parse UDP header: packet too short (%d bytes)", len(udpPacket))
		s.config.Logger.Printf("udp socks: Failed to get UDP package header: %v", err)
		return err
	}

	// Read header from the actual packet
	header := udpPacket[:3]
	if header[0] != 0x00 || header[1] != 0x00 {
		err := fmt.Errorf("failed to parse UDP header: unsupported header values %+v", header[:2])
		s.config.Logger.Printf("udp socks: Failed to parse UDP package header: %v", err)
		return err
	}
	if header[2] != 0x00 {
		s.config.Logger.Printf("udp socks: %+v", ErrUDPFragmentNoSupported)
		return ErrUDPFragmentNoSupported
	}

	// Read in the destination address
	targetAddrRaw := udpPacket[3:]
	targetAddrSpec := &AddrSpec{}
	targetAddrRawSize := 0
	errShortAddrRaw := func() error {
		err := fmt.Errorf("failed to parse UDP address: packet too short (%d bytes)", len(targetAddrRaw))
		s.config.Logger.Printf("udp socks: Failed to get UDP package header: %v", err)
		return err
	}
	if len(targetAddrRaw) < 1+4+2 /* ATYP + DST.ADDR.IPV4 + DST.PORT */ {
		return errShortAddrRaw()
	}
	targetAddrRawSize = 1
	switch targetAddrRaw[0] {
	case AddressIPv4:
		targetAddrSpec.IP = net.IP(targetAddrRaw[targetAddrRawSize : targetAddrRawSize+4])
		targetAddrRawSize += 4
	case AddressIPv6:
		if len(targetAddrRaw) < 1+16+2 {
			return errShortAddrRaw()
		}
		targetAddrSpec.IP = net.IP(targetAddrRaw[1 : 1+16])
		targetAddrRawSize += 16
	case AddressDomainName:
		addrLen := int(targetAddrRaw[1])
		if len(targetAddrRaw) < 1+1+addrLen+2 {
			return errShortAddrRaw()
		}
		targetAddrSpec.FQDN = string(targetAddrRaw[1+1 : 1+1+addrLen])
		targetAddrRawSize += (1 + addrLen)
	default:
		s.config.Logger.Printf("udp socks: Failed to get UDP package header: %v", errUnrecognizedAddrType)
		return errUnrecognizedAddrType
	}
	targetAddrSpec.Port = (int(targetAddrRaw[targetAddrRawSize]) << 8) | int(targetAddrRaw[targetAddrRawSize+1])
	targetAddrRawSize += 2
	targetAddrRaw = targetAddrRaw[:targetAddrRawSize]

	// Try to get context from UDP session, fallback to background context
	ctx := context.Background()
	if session, exists := s.udpSessionMgr.GetSession(srcAddr.String()); exists {
		ctx = session.Context
		// Update activity timestamp for exact match
		s.udpSessionMgr.UpdateActivity(srcAddr.String())
	} else {
		// Try to find session by IP only (fallback for port mismatch)
		srcIP := srcAddr.IP.String()
		if ipSession := s.udpSessionMgr.GetSessionByIP(srcIP); ipSession != nil {
			ctx = ipSession.Context
			// Update activity timestamp for IP match
			s.udpSessionMgr.UpdateActivityByIP(srcIP)
		} else {
			// Only log error if no session found by IP either
			s.config.Logger.Printf("udp socks: UDP packet from %v has no associated session", srcAddr)
		}
	}

	// resolve addr.
	_, err := s.resolveDestination(ctx, targetAddrSpec)
	if err != nil {
		s.config.Logger.Printf("udp socks: %+v", err)
		return err
	}

	// make a writer and write to dst
	targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddrSpec.Address())
	if err != nil {
		err := fmt.Errorf("failed to resolve UDP address '%v': %v", targetAddrSpec.Address(), err)
		return err
	}

	dialUDP := s.config.DialUDP
	if dialUDP == nil {
		dialUDP = func(ctx context.Context, _net string, laddr, raddr *net.UDPAddr) (net.Conn, error) {
			return net.DialUDP(_net, udpClientSrcAddrZero, raddr)
		}
	}

	udpClientSrcAddr := &net.UDPAddr{IP: net.IPv4zero, Port: srcAddr.Port}

	target, err := dialUDP(ctx, "udp", udpClientSrcAddr, targetUDPAddr)
	if err != nil {
		err = fmt.Errorf("failed to connect to %v: %v", targetUDPAddr, err)
		s.config.Logger.Printf("udp socks: %+v\n", err)
		return err
	}

	var isEConn bool
	defer func() {
		if !isEConn {
			_ = target.Close() // Ignore close errors in defer cleanup
		}
	}()

	// write data to target and read the response back
	if _, err := target.Write(udpPacket[len(header)+len(targetAddrRaw):]); err != nil {
		s.config.Logger.Printf("udp socks: fail to write udp data to dest %s: %+v",
			targetUDPAddr.String(), err)
		return err
	}
	respBuffer := getUDPPacketBuffer()
	defer putUDPPacketBuffer(respBuffer)
	copy(respBuffer[0:len(header)], header)
	copy(respBuffer[len(header):len(header)+len(targetAddrRaw)], targetAddrRaw)
	n, err := target.Read(respBuffer[len(header)+len(targetAddrRaw):])
	if err != nil {
		s.config.Logger.Printf("udp socks: fail to read udp resp from dest %s: %+v",
			targetUDPAddr.String(), err)
		return err
	}
	if n < 0 { // a way to identify EConn, and handle it separately
		isEConn = true
		return nil
	}
	respBuffer = respBuffer[:len(header)+len(targetAddrRaw)+n]

	if err := reply(respBuffer); err != nil {
		s.config.Logger.Printf("udp socks: fail to send udp resp back: %+v", err)
		return err
	}
	return nil
}
