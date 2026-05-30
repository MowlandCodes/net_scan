package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/MowlandCodes/net_scan/internal/config"
)

type MethodResult struct {
	Method string `json:"method"`
	Alive  bool   `json:"alive"`
	Port   int    `json:"port,omitempty"`
	Error  string `json:"error,omitempty"`
}

type ServiceResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Banner   string `json:"banner"`
}

type ScanResult struct {
	IP       string          `json:"ip"`
	Alive    bool            `json:"alive"`
	Methods  []MethodResult  `json:"methods"`
	Services []ServiceResult `json:"services"`
	Latency  time.Duration   `json:"latency"`
	Hostname string          `json:"hostname,omitempty"`
}

type Scanner struct {
	cfg    *config.Config
	pinger Pinger
}

type Pinger interface {
	Ping(ctx context.Context, ip string) bool
}

func New(cfg *config.Config) *Scanner {
	return &Scanner{cfg: cfg}
}

func (s *Scanner) Scan(ctx context.Context) []ScanResult {
	ips, err := s.cfg.ResolveTargets()
	if err != nil {
		fmt.Printf("Error resolving targets: %v\n", err)
		return nil
	}
	if len(ips) == 0 {
		fmt.Println("No targets to scan.")
		return nil
	}
	ips = removeDupes(ips)

	prog := NewProgress(len(ips))
	defer prog.Done()

	var mu sync.Mutex
	results := make([]ScanResult, 0, len(ips))
	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return results
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			res := s.scanTarget(ctx, ip)
			prog.AddResult(res)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return results
}

func (s *Scanner) scanTarget(ctx context.Context, ip string) ScanResult {
	start := time.Now()
	hostname, _ := net.LookupAddr(ip)
	var methods []MethodResult
	var services []ServiceResult
	alive := false

	methodsMap := make(map[string]bool)
	for _, m := range s.cfg.Methods {
		methodsMap[m] = true
	}

	if methodsMap["tcp"] {
		for _, port := range s.cfg.AllPorts() {
			select {
			case <-ctx.Done():
				return ScanResult{IP: ip}
			default:
			}
			open, banner := probeTCP(ctx, ip, port, s.cfg.Timeout)
			if open {
				alive = true
				methods = append(methods, MethodResult{
					Method: "tcp", Alive: true, Port: port,
				})
				svc := identifyService(port, banner)
				services = append(services, ServiceResult{
					Port: port, Protocol: "tcp",
					Service: svc, Banner: banner,
				})
			}
		}
	}

	if methodsMap["syn"] && canRaw() {
		for _, port := range s.cfg.AllPorts() {
			select {
			case <-ctx.Done():
				return ScanResult{IP: ip}
			default:
			}
			open := synScan(ctx, ip, port, s.cfg.Timeout)
			if open {
				alive = true
				methods = append(methods, MethodResult{
					Method: "syn", Alive: true, Port: port,
				})
				svc := identifyService(port, "")
				services = append(services, ServiceResult{
					Port: port, Protocol: "tcp",
					Service: svc, Banner: "",
				})
			}
		}
	}

	if methodsMap["icmp"] {
		reachable := icmpEcho(ctx, ip, s.cfg.Timeout)
		if reachable {
			alive = true
		}
		methods = append(methods, MethodResult{
			Method: "icmp", Alive: reachable,
		})
	}

	if methodsMap["arp"] && canRaw() {
		found := arpScan(ctx, ip, s.cfg.Timeout)
		if found {
			alive = true
		}
		methods = append(methods, MethodResult{
			Method: "arp", Alive: found,
		})
	}

	if methodsMap["dns"] {
		_, dnsErr := net.LookupAddr(ip)
		hasDNS := dnsErr == nil
		if hasDNS && !alive {
			alive = true
		}
		methods = append(methods, MethodResult{
			Method: "dns", Alive: hasDNS,
			Error: func() string {
				if dnsErr != nil {
					return dnsErr.Error()
				}
				return ""
			}(),
		})
	}

	hn := ""
	if len(hostname) > 0 {
		hn = hostname[0]
	}
	return ScanResult{
		IP:       ip,
		Alive:    alive,
		Methods:  methods,
		Services: services,
		Latency:  time.Since(start),
		Hostname: hn,
	}
}

func removeDupes(items []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}
