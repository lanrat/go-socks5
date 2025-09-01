package socks5

import (
	"context"
)

// RuleSet defines the interface for implementing access control rules.
// Custom implementations can provide fine-grained control over which requests are allowed.
type RuleSet interface {
	// Allow determines if a request should be permitted, returning updated context and decision
	Allow(ctx context.Context, req *Request) (context.Context, bool)
}

// PermitAll returns a RuleSet that allows all SOCKS5 commands (CONNECT, BIND, ASSOCIATE).
func PermitAll() RuleSet {
	return &PermitCommand{true, true, true}
}

// PermitNone returns a RuleSet that disallows all SOCKS5 commands.
func PermitNone() RuleSet {
	return &PermitCommand{false, false, false}
}

// PermitCommand implements RuleSet to allow or deny specific SOCKS5 commands.
// It provides granular control over which operations are permitted.
type PermitCommand struct {
	// EnableConnect allows or denies CONNECT commands for TCP proxying
	EnableConnect bool
	// EnableBind allows or denies BIND commands for incoming connections
	EnableBind bool
	// EnableAssociate allows or denies ASSOCIATE commands for UDP proxying
	EnableAssociate bool
}

// Allow checks if the requested command is enabled in this rule set.
func (p *PermitCommand) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	switch req.Command {
	case CommandConnect:
		return ctx, p.EnableConnect
	case CommandBind:
		return ctx, p.EnableBind
	case CommandAssociate:
		return ctx, p.EnableAssociate
	}

	return ctx, false
}
