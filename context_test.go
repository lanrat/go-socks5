package socks5

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestServer_ContextCancellation(t *testing.T) {
	// Create a server
	conf := &Config{}
	server, err := New(conf)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create a listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Start the server in a goroutine
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx, l)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Cancel the context
	cancel()

	// Wait for the server to stop with a timeout
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("Expected context.Canceled, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Server did not stop within timeout after context cancellation")
	}
}

func TestServer_ContextTimeout(t *testing.T) {
	// Create a server
	conf := &Config{}
	server, err := New(conf)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create a listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Create a context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Start the server
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx, l)
	}()

	// Wait for the context to timeout and server to stop
	select {
	case err := <-done:
		if err != context.DeadlineExceeded {
			t.Errorf("Expected context.DeadlineExceeded, got: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Server did not stop within timeout after context deadline")
	}
}

func TestListenAndServe_ContextCancellation(t *testing.T) {
	// Create a server
	conf := &Config{}
	server, err := New(conf)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Start the server in a goroutine
	done := make(chan error, 1)
	go func() {
		done <- server.ListenAndServe(ctx, "127.0.0.1:0")
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Cancel the context
	cancel()

	// Wait for the server to stop with a timeout
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("Expected context.Canceled, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not stop within timeout after context cancellation")
	}
}
