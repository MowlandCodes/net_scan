package config

import (
	"testing"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c == nil {
		t.Fatal("Default() returned nil")
	}
	if c.Concurrency != 50 {
		t.Errorf("expected concurrency 50, got %d", c.Concurrency)
	}
	if len(c.Ports) == 0 {
		t.Error("expected non-empty default ports")
	}
}

func TestAllPortsNoCustom(t *testing.T) {
	c := Default()
	ports := c.AllPorts()
	if len(ports) != len(DefaultPorts) {
		t.Errorf("expected %d ports, got %d", len(DefaultPorts), len(ports))
	}
}

func TestAllPortsWithCustom(t *testing.T) {
	c := Default()
	c.CustomSSHPorts = []int{2222, 22222}
	ports := c.AllPorts()
	expected := len(DefaultPorts) + 1
	if len(ports) != expected {
		t.Errorf("expected %d ports (2222 dup), got %d", expected, len(ports))
	}
}

func TestResolveTargetsSingleIP(t *testing.T) {
	c := Default()
	c.Targets = []string{"192.168.1.1"}
	ips, err := c.ResolveTargets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != "192.168.1.1" {
		t.Errorf("expected [192.168.1.1], got %v", ips)
	}
}

func TestResolveTargetsCIDR(t *testing.T) {
	c := Default()
	c.Targets = []string{"192.168.1.0/30"}
	ips, err := c.ResolveTargets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 4 {
		t.Errorf("expected 4 IPs for /30, got %d: %v", len(ips), ips)
	}
}

func TestResolutionFails(t *testing.T) {
	c := Default()
	c.Targets = []string{"not.an.ip.or.host"}
	_, err := c.ResolveTargets()
	if err == nil {
		t.Error("expected error for invalid target")
	}
}
