package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/MowlandCodes/net_scan/internal/scanner"
)

func TestWriteTable(t *testing.T) {
	results := []scanner.ScanResult{
		{
			IP:    "192.168.1.1",
			Alive: true,
			Methods: []scanner.MethodResult{
				{Method: "tcp", Alive: true, Port: 80},
				{Method: "icmp", Alive: true},
			},
			Services: []scanner.ServiceResult{
				{Port: 80, Protocol: "tcp", Service: "HTTP", Banner: "nginx"},
			},
			Latency:  time.Second,
			Hostname: "router.local",
		},
		{
			IP:    "192.168.1.2",
			Alive: false,
			Methods: []scanner.MethodResult{
				{Method: "tcp", Alive: false, Port: 80},
				{Method: "icmp", Alive: false},
			},
			Latency: 3 * time.Second,
		},
	}

	var buf bytes.Buffer
	WriteTable(&buf, results)

	output := buf.String()
	if !strings.Contains(output, "ALIVE") {
		t.Error("expected ALIVE in table output")
	}
	if !strings.Contains(output, "DEAD") {
		t.Error("expected DEAD in table output")
	}
	if !strings.Contains(output, "192.168.1.1") {
		t.Error("expected 192.168.1.1 in table output")
	}
	if !strings.Contains(output, "router.local") {
		t.Error("expected hostname in table output")
	}
	if !strings.Contains(output, "1 alive") {
		t.Errorf("summary line missing, got:\n%s", output)
	}
}

func TestWriteJSON(t *testing.T) {
	results := []scanner.ScanResult{
		{
			IP:    "10.0.0.1",
			Alive: true,
			Methods: []scanner.MethodResult{
				{Method: "tcp", Alive: true, Port: 443},
			},
			Services: []scanner.ServiceResult{
				{Port: 443, Protocol: "tcp", Service: "HTTPS"},
			},
			Latency: 500 * time.Millisecond,
		},
	}

	var buf bytes.Buffer
	err := WriteJSON(&buf, results)
	if err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "10.0.0.1") {
		t.Error("expected 10.0.0.1 in JSON output")
	}
	if !strings.Contains(output, "HTTPS") {
		t.Error("expected HTTPS in JSON output")
	}
	if !strings.Contains(output, `"alive": 1`) {
		t.Error("expected alive count in JSON output")
	}
}

func TestWriteJSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, []scanner.ScanResult{})
	if err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, `"total": 0`) {
		t.Error("expected total: 0 in JSON output")
	}
}
