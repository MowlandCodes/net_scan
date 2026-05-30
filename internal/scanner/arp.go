package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func arpScan(ctx context.Context, ip string, timeout time.Duration) bool {
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
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
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
		DstProtAddress:    dstIP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
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
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arpResp, ok := arpLayer.(*layers.ARP)
		if !ok || arpResp.Operation != layers.ARPReply {
			continue
		}
		if string(arpResp.SourceProtAddress) == string(dstIP.To4()) {
			return true
		}
	}
}

func findInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok && ipnet.IP.To4() != nil {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no suitable network interface found")
}

func ifaceIP(iface *net.Interface) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if ok && ipnet.IP.To4() != nil {
			return ipnet.IP
		}
	}
	return nil
}
