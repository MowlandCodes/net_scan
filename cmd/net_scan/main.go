package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/MowlandCodes/net_scan/internal/config"
	"github.com/MowlandCodes/net_scan/internal/output"
	"github.com/MowlandCodes/net_scan/internal/scanner"
)

func main() {
	fs := flag.NewFlagSet("net_scan", flag.ExitOnError)

	methods := fs.String("methods", "tcp,icmp,dns", "Comma-separated scan methods (tcp,icmp,dns,arp,syn)")
	ports := fs.String("ports", "", "Comma-separated port list (overrides default)")
	timeout := fs.Duration("timeout", 3_000_000_000, "Per-target timeout")
	concurrency := fs.Int("concurrency", 50, "Max concurrent targets")
	format := fs.String("format", "table", "Output format: table or json")
	outputFile := fs.String("output", "", "Write output to file instead of stdout")
	customSSH := fs.String("custom-ssh", "", "Extra SSH port numbers to add (comma-separated)")
	portRange := fs.String("port-range", "", "Port range like 1-1024 (overrides --ports)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: net_scan scan [flags] <target> [<target>...]\n\n")
		fmt.Fprintf(os.Stderr, "Targets can be IPs, CIDR ranges (192.168.1.0/24), or hostnames.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if len(os.Args) < 2 {
		fs.Usage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "scan":
		if err := fs.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		fs.Usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		fs.Usage()
		os.Exit(1)
	}

	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Error: at least one target is required")
		fs.Usage()
		os.Exit(1)
	}

	cfg := config.Default()
	cfg.Targets = fs.Args()
	cfg.Timeout = *timeout
	cfg.Concurrency = *concurrency
	cfg.Format = *format
	cfg.OutputFile = *outputFile

	if *methods != "" {
		cfg.Methods = strings.Split(*methods, ",")
		for i, m := range cfg.Methods {
			cfg.Methods[i] = strings.TrimSpace(m)
		}
	}

	if *ports != "" {
		cfg.Ports = parsePorts(*ports)
	}

	if *customSSH != "" {
		cfg.CustomSSHPorts = parsePorts(*customSSH)
	}

	if *portRange != "" {
		cfg.Ports = parsePortRange(*portRange)
	}

	s := scanner.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nReceived interrupt, stopping scan...")
		cancel()
	}()

	results := s.Scan(ctx)

	if results == nil {
		os.Exit(1)
	}

	w := os.Stdout
	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	switch cfg.Format {
	case "json":
		if err := output.WriteJSON(w, results); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
			os.Exit(1)
		}
	default:
		output.WriteTable(w, results)
	}
}

func parsePorts(s string) []int {
	parts := strings.Split(s, ",")
	var ports []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		var port int
		if _, err := fmt.Sscanf(p, "%d", &port); err == nil && port > 0 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	return ports
}

func parsePortRange(s string) []int {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return nil
	}
	var lo, hi int
	if _, err := fmt.Sscanf(parts[0], "%d", &lo); err != nil || lo < 1 {
		return nil
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &hi); err != nil || hi > 65535 || hi < lo {
		return nil
	}
	var ports []int
	for p := lo; p <= hi; p++ {
		ports = append(ports, p)
	}
	return ports
}
