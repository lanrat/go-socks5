package socks5

import (
	"fmt"
	"io"
)

/*********************************
    Clients Negotiation:

    +----+----------+----------+
    |VER | NMETHODS | METHODS  |
    +----+----------+----------+
    | 1  |    1     | 1 to 255 |
    +----+----------+----------+
**********************************/

// Authentication method constants as defined in RFC 1928
const (
	// AuthMethodNoAuth indicates no authentication is required (X'00')
	AuthMethodNoAuth = uint8(0)

	// X'01' GSSAPI

	// AuthMethodUserPass indicates username/password authentication (X'02')
	AuthMethodUserPass = uint8(2)

	// X'03' to X'7F' IANA ASSIGNED

	// X'80' to X'FE' RESERVED FOR PRIVATE METHODS

	// AuthMethodNoAcceptable indicates no acceptable authentication methods (X'FF')
	AuthMethodNoAcceptable = uint8(255)
)

/************************************************
    rfc1929 client user/pass negotiation req
    +----+------+----------+------+----------+
    |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    +----+------+----------+------+----------+
    | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    +----+------+----------+------+----------+
************************************************/
/************************************************
    rfc1929 server user/pass negotiation resp
                +----+--------+
                |VER | STATUS |
                +----+--------+
                | 1  |   1    |
                +----+--------+
************************************************/

const (
	// AuthUserPassVersion is the version field for username/password sub-negotiation (X'01')
	AuthUserPassVersion = uint8(1)
	// AuthUserPassStatusSuccess indicates successful username/password authentication (X'00')
	AuthUserPassStatusSuccess = uint8(0)
	// AuthUserPassStatusFailure indicates failed username/password authentication (X'01')
	AuthUserPassStatusFailure = uint8(1)
)

var (
	// ErrUserAuthFailed is returned when username/password authentication fails
	ErrUserAuthFailed = fmt.Errorf("user authentication failed")
	// ErrNoSupportedAuth is returned when no mutually supported authentication method exists
	ErrNoSupportedAuth = fmt.Errorf("no supported authentication mechanism")
)

// AuthContext encapsulates authentication state provided during negotiation.
// It contains the authentication method used and any associated payload data.
type AuthContext struct {
	// Method is the authentication method code that was used
	Method uint8
	// Payload contains method-specific authentication data.
	// For UserPassAuth, contains "Username" key with the authenticated username.
	Payload map[string]string
}

// Authenticator defines the interface for SOCKS5 authentication methods.
// Implementations handle the authentication negotiation for specific methods.
type Authenticator interface {
	// Authenticate performs the authentication handshake with the client
	Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error)
	// GetCode returns the authentication method code for this authenticator
	GetCode() uint8
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct{}

// GetCode returns the authentication method code for no authentication.
func (a NoAuthAuthenticator) GetCode() uint8 {
	return AuthMethodNoAuth
}

// Authenticate performs the no-auth handshake by simply confirming the method.
func (a NoAuthAuthenticator) Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error) {
	_, err := writer.Write([]byte{socks5Version, AuthMethodNoAuth})
	return &AuthContext{AuthMethodNoAuth, nil}, err
}

// UserPassAuthenticator is used to handle username/password based
// authentication
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

// GetCode returns the authentication method code for username/password authentication.
func (a UserPassAuthenticator) GetCode() uint8 {
	return AuthMethodUserPass
}

// Authenticate performs username/password authentication as per RFC 1929.
// It reads the username and password from the client and validates them using the credential store.
func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error) {
	// Tell the client to use user/pass auth
	if _, err := writer.Write([]byte{socks5Version, AuthMethodUserPass}); err != nil {
		return nil, err
	}

	// Get the version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return nil, err
	}

	// Ensure we are compatible
	if header[0] != AuthUserPassVersion {
		return nil, fmt.Errorf("unsupported auth version: %v", header[0])
	}

	// Get the user name
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return nil, err
	}

	// Get the password length
	if _, err := reader.Read(header[:1]); err != nil {
		return nil, err
	}

	// Get the password
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return nil, err
	}

	// Verify the password
	if a.Credentials.Valid(string(user), string(pass)) {
		if _, err := writer.Write([]byte{AuthUserPassVersion, AuthUserPassStatusSuccess}); err != nil {
			return nil, err
		}
	} else {
		if _, err := writer.Write([]byte{AuthUserPassVersion, AuthUserPassStatusFailure}); err != nil {
			return nil, err
		}
		return nil, ErrUserAuthFailed
	}

	// Done
	return &AuthContext{AuthMethodUserPass, map[string]string{"Username": string(user)}}, nil
}

// authenticate is used to handle connection authentication
// authenticate handles the SOCKS5 authentication negotiation phase.
// It reads the client's supported authentication methods and selects a compatible one.
func (s *Server) authenticate(conn io.Writer, bufConn io.Reader) (*AuthContext, error) {
	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth methods: %v", err)
	}

	// Select a usable method
	for _, method := range methods {
		auth, found := s.authMethods[method]
		if found {
			return auth.Authenticate(bufConn, conn)
		}
	}

	// No usable method found
	return nil, noAcceptableAuth(conn)
}

// noAcceptableAuth is used to handle when we have no eligible
// authentication mechanism
// noAcceptableAuth sends a "no acceptable authentication methods" response
// to the client and returns an appropriate error.
func noAcceptableAuth(conn io.Writer) error {
	if _, err := conn.Write([]byte{socks5Version, AuthMethodNoAcceptable}); err != nil {
		return err
	}
	return ErrNoSupportedAuth
}

// readMethods is used to read the number of methods
// and proceeding auth methods
// readMethods reads the client's list of supported authentication methods
// from the initial SOCKS5 negotiation packet.
func readMethods(r io.Reader) ([]byte, error) {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(r, methods, numMethods)
	return methods, err
}
