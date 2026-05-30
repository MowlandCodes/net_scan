package scanner

import (
	"context"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func icmpEcho(ctx context.Context, ip string, timeout time.Duration) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("net_scan"),
		},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	dst, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return false
	}

	if _, err := conn.WriteTo(wire, dst); err != nil {
		return false
	}

	reply := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		n, peer, err := conn.ReadFrom(reply)
		if err != nil {
			return false
		}
		parsed, err := icmp.ParseMessage(1, reply[:n])
		if err != nil {
			continue
		}
		if parsed.Type == ipv4.ICMPTypeEchoReply {
			echo, ok := parsed.Body.(*icmp.Echo)
			if !ok {
				continue
			}
			if echo.ID == (os.Getpid()&0xffff) && peer.String() == dst.String() {
				return true
			}
		}
	}
}
