package scanner

import (
	"testing"
)

func TestIdentifyServiceByPort(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{22, "SSH"},
		{80, "HTTP"},
		{443, "HTTPS"},
		{3389, "RDP"},
		{3306, "MySQL"},
		{5432, "PostgreSQL"},
		{6379, "Redis"},
		{12345, "Unknown"},
	}
	for _, tc := range tests {
		got := identifyService(tc.port, "")
		if got != tc.want {
			t.Errorf("identifyService(%d, '') = %q, want %q", tc.port, got, tc.want)
		}
	}
}

func TestIdentifyServiceByBanner(t *testing.T) {
	tests := []struct {
		port   int
		banner string
		want   string
	}{
		{2222, "SSH-2.0-OpenSSH_8.9", "SSH"},
		{8080, "HTTP/1.1 200 OK", "HTTP"},
		{8443, "nginx/1.24", "HTTP"},
		{9090, "Apache/2.4.57", "HTTP"},
		{25, "220 mx.example.com ESMTP", "SMTP"},
		{21, "220 ProFTPD", "FTP"},
	}
	for _, tc := range tests {
		got := identifyService(tc.port, tc.banner)
		if got != tc.want {
			t.Errorf("identifyService(%d, %q) = %q, want %q",
				tc.port, tc.banner, got, tc.want)
		}
	}
}

func TestIdentifyServiceBannerOverridesPort(t *testing.T) {
	got := identifyService(2222, "SSH-2.0-OpenSSH_8.9")
	if got != "SSH" {
		t.Errorf("expected SSH from banner, got %q", got)
	}
}

func TestCanRaw(t *testing.T) {
	_ = canRaw()
}

func TestRemoveDupes(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b"}
	got := removeDupes(input)
	expected := []string{"a", "b", "c"}
	if len(got) != len(expected) {
		t.Errorf("expected %d items, got %d: %v", len(expected), len(got), got)
		return
	}
	for i, v := range expected {
		if got[i] != v {
			t.Errorf("index %d: expected %q, got %q", i, v, got[i])
		}
	}
}

func TestFormatProgressLabel(t *testing.T) {
	tests := []struct {
		name string
		r    ScanResult
		want string
	}{
		{
			name: "single tcp port",
			r: ScanResult{Alive: true, Methods: []MethodResult{
				{Method: "tcp", Alive: true, Port: 80},
			}},
			want: "TCP(80)",
		},
		{
			name: "multiple tcp ports",
			r: ScanResult{Alive: true, Methods: []MethodResult{
				{Method: "tcp", Alive: true, Port: 22},
				{Method: "tcp", Alive: true, Port: 80},
				{Method: "tcp", Alive: true, Port: 443},
			}},
			want: "TCP(22), TCP(80), TCP(443)",
		},
		{
			name: "mixed methods with and without ports",
			r: ScanResult{Alive: true, Methods: []MethodResult{
				{Method: "tcp", Alive: true, Port: 80},
				{Method: "arp", Alive: true},
				{Method: "icmp", Alive: true},
				{Method: "dns", Alive: true},
			}},
			want: "TCP(80), ARP, ICMP, DNS",
		},
		{
			name: "filters out dead methods",
			r: ScanResult{Alive: true, Methods: []MethodResult{
				{Method: "tcp", Alive: true, Port: 22},
				{Method: "tcp", Alive: false, Port: 80},
				{Method: "arp", Alive: false},
			}},
			want: "TCP(22)",
		},
		{
			name: "no methods",
			r:    ScanResult{Alive: false},
			want: "",
		},
		{
			name: "all dead methods",
			r: ScanResult{Alive: true, Methods: []MethodResult{
				{Method: "tcp", Alive: false, Port: 80},
				{Method: "arp", Alive: false},
			}},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatProgressLabel(tc.r)
			if got != tc.want {
				t.Errorf("formatProgressLabel() = %q, want %q", got, tc.want)
			}
		})
	}
}
