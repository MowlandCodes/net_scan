package scanner

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Progress struct {
	total     int
	completed atomic.Int64
	alive     atomic.Int64
	start     time.Time
	mu        sync.Mutex
	w         io.Writer
}

func NewProgress(total int) *Progress {
	return &Progress{
		total: total,
		start: time.Now(),
		w:     os.Stderr,
	}
}

func (p *Progress) AddResult(r ScanResult) {
	completed := p.completed.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()

	if r.Alive {
		p.alive.Add(1)
		label := formatProgressLabel(r)
		fmt.Fprintf(p.w, "\033[2K\r[+] %s — %s\n", r.IP, label)
	}

	p.render(completed)
}

func formatProgressLabel(r ScanResult) string {
	var parts []string
	for _, m := range r.Methods {
		if !m.Alive {
			continue
		}
		s := strings.ToUpper(m.Method)
		if m.Port > 0 {
			s += fmt.Sprintf("(%d)", m.Port)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

func (p *Progress) render(completed int64) {
	alive := p.alive.Load()
	barWidth := 24
	filled := int(completed * int64(barWidth) / int64(p.total))
	bar := strings.Repeat("=", filled) + strings.Repeat("-", barWidth-filled)
	pct := completed * 100 / int64(p.total)
	elapsed := time.Since(p.start).Round(100 * time.Millisecond)
	fmt.Fprintf(p.w, "\r\033[KScanning: [%s] %d/%d (%d%%) | %d alive | %s",
		bar, completed, p.total, pct, alive, elapsed)
}

func (p *Progress) Done() {
	p.mu.Lock()
	fmt.Fprintln(p.w)
	p.mu.Unlock()
}
