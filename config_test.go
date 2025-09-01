package socks5

import (
	"testing"
	"time"
)

func TestConfig_UDPDefaults(t *testing.T) {
	// Test that defaults are applied correctly
	conf := &Config{}
	server, err := New(conf)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Check that defaults were applied
	if conf.UDPPacketSize != 2048 {
		t.Errorf("Expected default UDPPacketSize to be 2048, got %d", conf.UDPPacketSize)
	}

	if conf.UDPSessionTimeout != 5*time.Minute {
		t.Errorf("Expected default UDPSessionTimeout to be 5 minutes, got %v", conf.UDPSessionTimeout)
	}

	// Check that session manager got the correct timeout
	if server.udpSessionMgr.sessionTimeout != 5*time.Minute {
		t.Errorf("Expected session manager timeout to be 5 minutes, got %v", server.udpSessionMgr.sessionTimeout)
	}
}

func TestConfig_UDPCustomValues(t *testing.T) {
	// Test that custom values are respected
	customPacketSize := 4096
	customTimeout := 10 * time.Minute

	conf := &Config{
		UDPPacketSize:     customPacketSize,
		UDPSessionTimeout: customTimeout,
	}

	server, err := New(conf)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Check that custom values were preserved
	if conf.UDPPacketSize != customPacketSize {
		t.Errorf("Expected UDPPacketSize to be %d, got %d", customPacketSize, conf.UDPPacketSize)
	}

	if conf.UDPSessionTimeout != customTimeout {
		t.Errorf("Expected UDPSessionTimeout to be %v, got %v", customTimeout, conf.UDPSessionTimeout)
	}

	// Check that session manager got the custom timeout
	if server.udpSessionMgr.sessionTimeout != customTimeout {
		t.Errorf("Expected session manager timeout to be %v, got %v", customTimeout, server.udpSessionMgr.sessionTimeout)
	}
}
