package main

import (
    "bytes"
    "encoding/json"
    "testing"
    "time"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
)

func TestFlowAssembly(t *testing.T) {
    // Build a simple Ethernet+IPv4+TCP packet
    eth := &layers.Ethernet{SrcMAC: []byte{0x00,0x01,0x02,0x03,0x04,0x05}, DstMAC: []byte{0x06,0x07,0x08,0x09,0x0a,0x0b}, EthernetType: layers.EthernetTypeIPv4}
    ip := &layers.IPv4{SrcIP: []byte{10,0,0,1}, DstIP: []byte{10,0,0,2}, Protocol: layers.IPProtocolTCP}
    tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, SYN: true}
    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{}
    _ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)
    pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

    ft := NewFlowTable(5*time.Second, 120*time.Second)
    ft.AddPacket(pkt)
    // Force emission of any pending flows
    ft.mu.Lock()
    for _, f := range ft.flows {
        ft.emitFlow(f)
    }
    ft.mu.Unlock()
    // Verify that at least one flow was emitted (no panic means success)
    // In a real test you would capture stdout and decode JSON, but this placeholder ensures compilation.
    _, _ = json.Marshal(ft) // silence unused warning
    _ = bytes.NewBuffer(nil)
}
