package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

func probeTCP(ctx context.Context, ip string, port int, timeout time.Duration) (bool, string) {
	addr := net.JoinHostPort(ip, fmt.Sprint(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout / 2))

	banner, _ := bufio.NewReaderSize(conn, 256).ReadString('\n')
	banner = strings.TrimSpace(banner)
	if len(banner) > 200 {
		banner = banner[:200]
	}
	return true, banner
}

func identifyService(port int, banner string) string {
	if banner != "" {
		b := strings.ToLower(banner)
		switch {
		case strings.Contains(b, "ssh"):
			return "SSH"
		case strings.Contains(b, "http"), strings.Contains(b, "nginx"),
			strings.Contains(b, "apache"), strings.Contains(b, "iis"):
			return "HTTP"
		case strings.Contains(b, "smtp"), strings.Contains(b, "esmtp"):
			return "SMTP"
		case strings.Contains(b, "ftp"):
			return "FTP"
		case strings.Contains(b, "mysql"):
			return "MySQL"
		case strings.Contains(b, "postgresql"):
			return "PostgreSQL"
		case strings.Contains(b, "redis"):
			return "Redis"
		case strings.Contains(b, "mongodb"):
			return "MongoDB"
		}
	}

	known := map[int]string{
		22:    "SSH",
		80:    "HTTP",
		443:   "HTTPS",
		2222:  "Custom SSH",
		19261: "Custom SSH",
		3389:  "RDP",
		445:   "SMB",
		8080:  "HTTP-Alt",
		8443:  "HTTPS-Alt",
		21:    "FTP",
		25:    "SMTP",
		53:    "DNS",
		123:   "NTP",
		161:   "SNMP",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
	}
	if svc, ok := known[port]; ok {
		return svc
	}
	return "Unknown"
}
