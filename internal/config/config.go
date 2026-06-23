package config

import (
	"fmt"
	"net"
	"time"
)

type Config struct {
	Targets        []string
	Ports          []int
	CustomSSHPorts []int
	Methods        []string
	Concurrency    int
	Timeout        time.Duration
	Format         string
	OutputFile     string
	PortRange      string
}

var DefaultPorts = []int{
	22, 80, 443, 2222, 19261, 3389, 445,
	8080, 8443, 21, 25, 53, 123, 161,
	3306, 5432, 6379, 27017, 8006, 5900, 6379, 11211, 9200, 27017,
}

var DefaultCustomSSH = []int{2222, 19261, 2022, 22222}

var DefaultMethods = []string{"tcp", "icmp", "dns", "arp", "syn"}

func Default() *Config {
	return &Config{
		Targets:        nil,
		Ports:          DefaultPorts,
		CustomSSHPorts: nil,
		Methods:        DefaultMethods,
		Concurrency:    50,
		Timeout:        3 * time.Second,
		Format:         "table",
		OutputFile:     "",
	}
}

func (c *Config) ResolveTargets() ([]string, error) {
	var ips []string
	for _, t := range c.Targets {
		if ip := net.ParseIP(t); ip != nil {
			ips = append(ips, ip.String())
			continue
		}
		_, cidr, err := net.ParseCIDR(t)
		if err != nil {
			addr, err2 := net.ResolveIPAddr("ip", t)
			if err2 != nil {
				return nil, fmt.Errorf("cannot resolve %q: %v / %v", t, err, err2)
			}
			ips = append(ips, addr.IP.String())
			continue
		}
		ip := cidr.IP.Mask(cidr.Mask)
		for ip2 := ip; cidr.Contains(ip2); incIP(ip2) {
			ips = append(ips, ip2.String())
		}
	}
	return ips, nil
}

func (c *Config) AllPorts() []int {
	if len(c.CustomSSHPorts) > 0 {
		seen := map[int]bool{}
		var merged []int
		for _, p := range c.Ports {
			if !seen[p] {
				seen[p] = true
				merged = append(merged, p)
			}
		}
		for _, p := range c.CustomSSHPorts {
			if !seen[p] {
				seen[p] = true
				merged = append(merged, p)
			}
		}
		return merged
	}
	return c.Ports
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
