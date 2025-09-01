# Socks5

[![Go Report Card](https://goreportcard.com/badge/github.com/lanrat/go-socks5)](https://goreportcard.com/report/github.com/lanrat/go-socks5)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/lanrat/go-socks5)](https://pkg.go.dev/github.com/lanrat/go-socks5)

Provides the `socks5` package that implements a [SOCKS5 server](http://en.wikipedia.org/wiki/SOCKS).
SOCKS (Secure Sockets) is used to route traffic between a client and server through
an intermediate proxy layer. This can be used to bypass firewalls or NATs.

This library is based on the following forks:

* [Xmader/go-socks5](https://github.com/Xmader/go-socks5)
* [haxii/socks5](https://github.com/haxii/socks5)
* [armon/go-socks5](https://github.com/armon/go-socks5)

## Features

The package has the following features:

* "No Auth" mode
* User/Password authentication
* Support for the CONNECT command
* Support for the ASSOCIATE command
* Rules to do granular filtering of commands
* Custom DNS resolution
* Unit tests

## TODO

The package still needs the following:

* Support for the BIND command

## Example

Below is a simple example of usage:

```go
// Create a SOCKS5 server
conf := &socks5.Config{}
server, err := socks5.New(conf)
if err != nil {
  panic(err)
}

// Create SOCKS5 proxy on localhost port 8000
if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
  panic(err)
}
```
