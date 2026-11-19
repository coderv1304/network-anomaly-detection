package ingest

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
)

func TestDecodeTCPFlagsAndPorts(t *testing.T) {
	packet := buildPacket(t,
		&gplayers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
			DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
			EthernetType: gplayers.EthernetTypeIPv4,
		},
		&gplayers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: gplayers.IPProtocolTCP,
			SrcIP:    net.ParseIP("192.0.2.10"),
			DstIP:    net.ParseIP("198.51.100.20"),
		},
		&gplayers.TCP{
			SrcPort: 51515,
			DstPort: 443,
			SYN:     true,
			ACK:     true,
			PSH:     true,
			Window:  64240,
		},
	)
	decoded, ok := FromGopacket(packet)
	if !ok {
		t.Fatal("packet was not decoded")
	}
	if decoded.Proto != ProtoTCP || decoded.SrcPort != 51515 || decoded.DstPort != 443 {
		t.Fatalf("unexpected tuple: %+v", decoded)
	}
	if !decoded.HasFlag(TCPFlagSYN) || !decoded.HasFlag(TCPFlagACK) || !decoded.HasFlag(TCPFlagPSH) {
		t.Fatalf("flags not preserved: %#x", decoded.TCPFlags)
	}
	if decoded.HasFlag(TCPFlagFIN) || decoded.HasFlag(TCPFlagRST) {
		t.Fatalf("unexpected extra flags: %#x", decoded.TCPFlags)
	}
	if decoded.TCPWindow != 64240 {
		t.Fatalf("window not preserved: %d", decoded.TCPWindow)
	}
	if decoded.HeaderLen != 20 {
		t.Fatalf("TCP header length should be the IP header length, got %d", decoded.HeaderLen)
	}
	if decoded.Length != 40 {
		t.Fatalf("expected 40-byte IP length, got %d", decoded.Length)
	}
}

func TestDecodeUDPAndICMPv4(t *testing.T) {
	udp := buildPacket(t,
		&gplayers.Ethernet{EthernetType: gplayers.EthernetTypeIPv4},
		&gplayers.IPv4{Version: 4, TTL: 64, Protocol: gplayers.IPProtocolUDP, SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2")},
		&gplayers.UDP{SrcPort: 53, DstPort: 5353, Length: 12},
	)
	decodedUDP, ok := FromGopacket(udp)
	if !ok || decodedUDP.Proto != ProtoUDP || decodedUDP.SrcPort != 53 || decodedUDP.DstPort != 5353 {
		t.Fatalf("UDP decode failed: %+v", decodedUDP)
	}
	if decodedUDP.HeaderLen != 8 {
		t.Fatalf("expected 8-byte transport header for UDP, got %d", decodedUDP.HeaderLen)
	}

	icmp := buildPacket(t,
		&gplayers.Ethernet{EthernetType: gplayers.EthernetTypeIPv4},
		&gplayers.IPv4{Version: 4, TTL: 64, Protocol: gplayers.IPProtocolICMPv4, SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2")},
		&gplayers.ICMPv4{TypeCode: gplayers.CreateICMPv4TypeCode(8, 0)},
	)
	decodedICMP, ok := FromGopacket(icmp)
	if !ok || decodedICMP.Proto != ProtoICMP {
		t.Fatalf("ICMP decode failed: %+v", decodedICMP)
	}
	if decodedICMP.SrcPort != 0 || decodedICMP.DstPort != 0 {
		t.Fatalf("ICMP must use zero ports, got %d/%d", decodedICMP.SrcPort, decodedICMP.DstPort)
	}
}

func TestDecodeIPv6TCPAndICMPv6(t *testing.T) {
	tcp := buildPacket(t,
		&gplayers.Ethernet{EthernetType: gplayers.EthernetTypeIPv6},
		&gplayers.IPv6{
			Version:    6,
			NextHeader: gplayers.IPProtocolTCP,
			HopLimit:   64,
			SrcIP:      net.ParseIP("2001:db8::1"),
			DstIP:      net.ParseIP("2001:db8::2"),
		},
		&gplayers.TCP{SrcPort: 1234, DstPort: 80, SYN: true},
	)
	decodedTCP, ok := FromGopacket(tcp)
	if !ok || !decodedTCP.IsIPv6 || decodedTCP.Proto != ProtoTCP {
		t.Fatalf("IPv6 TCP decode failed: %+v", decodedTCP)
	}
	if decodedTCP.Length != 60 {
		t.Fatalf("expected 60-byte IPv6 packet, got %d", decodedTCP.Length)
	}

	icmp := buildPacket(t,
		&gplayers.Ethernet{EthernetType: gplayers.EthernetTypeIPv6},
		&gplayers.IPv6{
			Version:    6,
			NextHeader: gplayers.IPProtocolICMPv6,
			HopLimit:   64,
			SrcIP:      net.ParseIP("2001:db8::1"),
			DstIP:      net.ParseIP("2001:db8::2"),
		},
		&gplayers.ICMPv6{TypeCode: gplayers.CreateICMPv6TypeCode(128, 0)},
	)
	decodedICMP, ok := FromGopacket(icmp)
	if !ok || !decodedICMP.IsIPv6 || decodedICMP.Proto != ProtoICMPv6 {
		t.Fatalf("ICMPv6 decode failed: %+v", decodedICMP)
	}
}

func TestDecodeSkipsNonIP(t *testing.T) {
	arp := buildPacket(t,
		&gplayers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
			DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
			EthernetType: gplayers.EthernetTypeARP,
		},
		&gplayers.ARP{
			AddrType:          gplayers.LinkTypeEthernet,
			Protocol:          gplayers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         uint16(gplayers.ARPRequest),
			SourceHwAddress:   []byte{0, 1, 2, 3, 4, 5},
			SourceProtAddress: []byte{192, 0, 2, 1},
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    []byte{192, 0, 2, 2},
		},
	)
	if _, ok := FromGopacket(arp); ok {
		t.Fatal("ARP frame must not produce an IP packet")
	}
}

func buildPacket(t *testing.T, serializable ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	if len(serializable) > 0 {
		if eth, ok := serializable[0].(*gplayers.Ethernet); ok {
			if len(eth.SrcMAC) == 0 {
				eth.SrcMAC = net.HardwareAddr{0, 1, 2, 3, 4, 5}
			}
			if len(eth.DstMAC) == 0 {
				eth.DstMAC = net.HardwareAddr{6, 7, 8, 9, 10, 11}
			}
		}
	}
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buffer, options, serializable...); err != nil {
		t.Fatalf("serialize layers: %v", err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), gplayers.LinkTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = time.Unix(1767225600, 123000000)
	return packet
}
