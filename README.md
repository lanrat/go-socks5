# go-socks5

[![Go Report Card](https://goreportcard.com/badge/github.com/lanrat/go-socks5)](https://goreportcard.com/report/github.com/lanrat/go-socks5)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/lanrat/go-socks5)](https://pkg.go.dev/github.com/lanrat/go-socks5)

A complete implementation of a [SOCKS5 server](https://tools.ietf.org/html/rfc1928) in Go. SOCKS (Secure Sockets) is used to route traffic between a client and server through an intermediate proxy layer, enabling functionality such as firewall traversal and traffic anonymization.

## Fork History

This library is based on the following forks:

* [Xmader/go-socks5](https://github.com/Xmader/go-socks5)
* [haxii/socks5](https://github.com/haxii/socks5)
* [armon/go-socks5](https://github.com/armon/go-socks5)

## Features

* **Authentication Methods**
  * No authentication required
  * Username/password authentication (RFC 1929)
* **Commands**
  * TCP CONNECT command for proxying TCP connections
  * UDP ASSOCIATE command for proxying UDP datagrams
* **Flexible Configuration**
  * Custom DNS resolution
  * Rule-based access control
  * Address rewriting capabilities
  * Configurable connection timeouts
  * Custom UDP packet sizes and session timeouts
* **Production Ready**
  * Graceful server shutdown
  * Context-based cancellation
  * Comprehensive error handling
  * Extensive test coverage

## Installation

```bash
go get github.com/lanrat/go-socks5
```

## Usage

### Basic Server

```go
package main

import (
    "context"
    "log"
    
    "github.com/lanrat/go-socks5"
)

func main() {
    // Create a SOCKS5 server with default configuration
    conf := &socks5.Config{}
    server, err := socks5.New(conf)
    if err != nil {
        log.Fatal(err)
    }

    // Listen on localhost:1080
    if err := server.ListenAndServe(context.Background(), ":1080"); err != nil {
        log.Fatal(err)
    }
}
```

### Server with Authentication

```go
package main

import (
    "context"
    "log"
    
    "github.com/lanrat/go-socks5"
)

func main() {
    // Create credentials store
    creds := socks5.StaticCredentials{
        "user":  "password",
        "admin": "secret123",
    }

    conf := &socks5.Config{
        Credentials: creds,
    }
    
    server, err := socks5.New(conf)
    if err != nil {
        log.Fatal(err)
    }

    if err := server.ListenAndServe(context.Background(), ":1080"); err != nil {
        log.Fatal(err)
    }
}
```

### Server with UDP Support

UDP support in SOCKS5 works through the ASSOCIATE command, which establishes a UDP relay session. Here's how to configure it:

```go
package main

import (
    "context"
    "log"
    "net"
    "time"
    
    "github.com/lanrat/go-socks5"
)

func main() {
    conf := &socks5.Config{
        // Enable UDP by setting a bind IP and port
        BindIP:   net.IPv4(127, 0, 0, 1),
        BindPort: 8080, // UDP server will listen on this port
        
        // Optional: Configure UDP settings
        UDPPacketSize:     4096,              // Max UDP packet size (default: 2048)
        UDPSessionTimeout: 10 * time.Minute,  // Session idle timeout (default: 5 minutes)
    }
    
    server, err := socks5.New(conf)
    if err != nil {
        log.Fatal(err)
    }

    // TCP server on :1080, UDP relay on :8080
    if err := server.ListenAndServe(context.Background(), ":1080"); err != nil {
        log.Fatal(err)
    }
}
```

**How UDP ASSOCIATE Works:**

1. Client connects to TCP port (1080) and sends ASSOCIATE command
2. Server responds with UDP relay address (127.0.0.1:8080)
3. Client sends UDP packets to relay address with SOCKS5 UDP header
4. Server forwards packets to destination and returns responses
5. Session remains active until TCP connection closes or timeout expires

### Advanced Configuration

```go
package main

import (
    "context"
    "log"
    "net"
    "os"
    "time"
    
    "github.com/lanrat/go-socks5"
)

func main() {
    conf := &socks5.Config{
        // Custom authentication
        AuthMethods: []socks5.Authenticator{
            &socks5.NoAuthAuthenticator{},
            &socks5.UserPassAuthenticator{
                Credentials: socks5.StaticCredentials{
                    "user": "pass",
                },
            },
        },
        
        // Custom resolver
        Resolver: &socks5.DNSResolver{},
        
        // Access control rules
        Rules: socks5.PermitAll(), // or PermitNone(), or custom RuleSet
        
        // Custom logger
        Logger: log.New(os.Stdout, "socks5: ", log.LstdFlags),
        
        // Connection timeout
        ConnTimeout: 30 * time.Second,
        
        // UDP configuration
        BindIP:            net.IPv4(0, 0, 0, 0),
        BindPort:          0, // Set to 0 to disable UDP support
        UDPPacketSize:     2048,
        UDPSessionTimeout: 5 * time.Minute,
    }
    
    server, err := socks5.New(conf)
    if err != nil {
        log.Fatal(err)
    }

    if err := server.ListenAndServe(context.Background(), ":1080"); err != nil {
        log.Fatal(err)
    }
}
```

## Configuration Options

The `Config` struct provides extensive customization options:

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `AuthMethods` | `[]Authenticator` | Authentication methods | No-auth |
| `Credentials` | `CredentialStore` | Username/password store | None |
| `Resolver` | `NameResolver` | DNS resolver | System DNS |
| `Rules` | `RuleSet` | Access control rules | Permit all |
| `Rewriter` | `AddressRewriter` | Address rewriting | None |
| `BindIP` | `net.IP` | UDP bind address | 127.0.0.1 |
| `BindPort` | `int` | UDP bind port (0 = disabled) | 0 |
| `Logger` | `ErrorLogger` | Error logger | Stdout |
| `ConnTimeout` | `time.Duration` | Connection timeout | None |
| `UDPPacketSize` | `int` | Max UDP packet size | 2048 |
| `UDPSessionTimeout` | `time.Duration` | UDP session timeout | 5 minutes |

## Limitations

* **BIND Command**: Not yet implemented (returns "command not supported")
* **UDP Security**: Current UDP implementation accepts packets from any source (see security note in code)

## Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific test
go test -run TestSOCKS5_Connect
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request
