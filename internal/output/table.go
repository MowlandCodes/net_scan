package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/MowlandCodes/net_scan/internal/scanner"
)

func WriteTable(w io.Writer, results []scanner.ScanResult) {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)

	aliveCount := 0
	for _, r := range results {
		if r.Alive {
			aliveCount++
		}
	}

	fmt.Fprintf(tw, "Results: %d total, %d alive, %d dead\n\n",
		len(results), aliveCount, len(results)-aliveCount)

	fmt.Fprintln(tw, "IP\tStatus\tMethods\tServices\tHostname\tLatency")
	fmt.Fprintln(tw, "--\t------\t-------\t--------\t--------\t-------")

	for _, r := range results {
		status := "DEAD"
		if r.Alive {
			status = "ALIVE"
		}

		var methodNames []string
		for _, m := range r.Methods {
			if m.Alive {
				label := strings.ToUpper(m.Method)
				if m.Port > 0 {
					label = fmt.Sprintf("%s(%d)", strings.ToUpper(m.Method), m.Port)
				}
				methodNames = append(methodNames, label)
			}
		}
		methods := "-"
		if len(methodNames) > 0 {
			methods = strings.Join(methodNames, ", ")
		}

		var svcStrs []string
		for _, s := range r.Services {
			svc := s.Service
			if s.Banner != "" {
				svc = fmt.Sprintf("%s (%s)", svc, s.Banner)
			}
			svcStrs = append(svcStrs, fmt.Sprintf("%d/tcp->%s", s.Port, svc))
		}
		services := "-"
		if len(svcStrs) > 0 {
			services = strings.Join(svcStrs, ", ")
		}

		hostname := "-"
		if r.Hostname != "" {
			hostname = r.Hostname
		}

		latency := r.Latency.Truncate(100 * time.Microsecond).String()

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.IP, status, methods, services, hostname, latency)
	}
	tw.Flush()
}
