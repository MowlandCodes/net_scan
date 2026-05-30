package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func synScan(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	iface, err := findInterface()
	if err != nil {
		return false
	}

	handle, err := pcap.OpenLive(iface.Name, 65536, true, timeout/2)
	if err != nil {
		return false
	}
	defer handle.Close()

	srcIP := ifaceIP(iface)
	if srcIP == nil {
		return false
	}
	srcMAC := iface.HardwareAddr
	if len(srcMAC) == 0 {
		return false
	}

	dstIP := net.ParseIP(ip)
	if dstIP == nil {
		return false
	}

	gatewayMAC, err := resolveGatewayMAC(iface, srcIP, srcMAC, handle)
	if err != nil {
		return false
	}
	if gatewayMAC == nil {
		if ipIsLocal(iface, dstIP) {
			gatewayMAC = fakeMAC(dstIP)
		} else {
			return false
		}
	}

	srcPort := rand.Intn(65535-1024) + 1024
	seq := rand.Uint32()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       gatewayMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(port),
		Seq:     seq,
		SYN:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, tcp); err != nil {
		return false
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return false
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		packet, err := ps.NextPacket()
		if err != nil {
			return false
		}
		if packet == nil {
			continue
		}
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcpResp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}
		if tcpResp.DstPort == layers.TCPPort(srcPort) && tcpResp.SYN && tcpResp.ACK {
			return true
		}
	}
}

func resolveGatewayMAC(iface *net.Interface, srcIP net.IP, srcMAC net.HardwareAddr, handle *pcap.Handle) (net.HardwareAddr, error) {
	routes, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	_ = routes

	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	gatewayIP := guessGateway(srcIP)

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       broadcastMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress:    gatewayIP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return nil, err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	for i := 0; i < 30; i++ {
		packet, err := ps.NextPacket()
		if err != nil {
			return nil, fmt.Errorf("no arp reply")
		}
		if packet == nil {
			continue
		}
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arpResp, ok := arpLayer.(*layers.ARP)
		if !ok || arpResp.Operation != layers.ARPReply {
			continue
		}
		if string(arpResp.SourceProtAddress) == string(gatewayIP.To4()) {
			return arpResp.SourceHwAddress, nil
		}
	}
	return nil, fmt.Errorf("no arp reply from gateway")
}

func guessGateway(srcIP net.IP) net.IP {
	ip4 := srcIP.To4()
	if ip4 == nil {
		return nil
	}
	gateway := make(net.IP, 4)
	copy(gateway, ip4)
	gateway[3] = 1
	return gateway
}

func fakeMAC(ip net.IP) net.HardwareAddr {
	ip4 := ip.To4()
	if ip4 == nil {
		return net.HardwareAddr{0, 0, 0, 0, 0, 0}
	}
	return net.HardwareAddr{0x02, 0x00, ip4[0], ip4[1], ip4[2], ip4[3]}
}

func ipIsLocal(iface *net.Interface, ip net.IP) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if ok && ipnet.Contains(ip) {
			return true
		}
	}
	return false
}
