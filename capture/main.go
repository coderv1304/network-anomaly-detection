package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

type FlowKey struct {
    SrcIP   string
    DstIP   string
    SrcPort uint16
    DstPort uint16
    Proto   uint8 // 6=TCP, 17=UDP, etc.
}

type Flow struct {
    Key       FlowKey
    Start     time.Time
    LastSeen  time.Time
    Packets   int
    Bytes     int
    Flags     uint8 // TCP flags aggregated
}

type FlowTable struct {
    mu           sync.Mutex
    flows        map[FlowKey]*Flow
    idleTimeout  time.Duration
    activeTimeout time.Duration
}

func NewFlowTable(idle, active time.Duration) *FlowTable {
    ft := &FlowTable{flows: make(map[FlowKey]*Flow), idleTimeout: idle, activeTimeout: active}
    go ft.cleanupLoop()
    return ft
}

func (ft *FlowTable) cleanupLoop() {
    ticker := time.NewTicker(time.Second)
    for range ticker.C {
        ft.mu.Lock()
        now := time.Now()
        for key, f := range ft.flows {
            if now.Sub(f.LastSeen) > ft.idleTimeout || now.Sub(f.Start) > ft.activeTimeout {
                ft.emitFlow(f)
                delete(ft.flows, key)
            }
        }
        ft.mu.Unlock()
    }
}

func (ft *FlowTable) emitFlow(f *Flow) {
    // Emit as JSON to stdout (could be changed to CSV)
    out, _ := json.Marshal(f)
    fmt.Println(string(out))
}

func (ft *FlowTable) AddPacket(pkt gopacket.Packet) {
    ipLayer := pkt.Layer(layers.LayerTypeIPv4)
    if ipLayer == nil {
        ipLayer = pkt.Layer(layers.LayerTypeIPv6)
    }
    if ipLayer == nil {
        return // non‑IP packet
    }
    var srcIP, dstIP string
    var proto uint8
    switch ip := ipLayer.(type) {
    case *layers.IPv4:
        srcIP = ip.SrcIP.String()
        dstIP = ip.DstIP.String()
        proto = uint8(ip.Protocol)
    case *layers.IPv6:
        srcIP = ip.SrcIP.String()
        dstIP = ip.DstIP.String()
        proto = uint8(ip.NextHeader)
    }
    var srcPort, dstPort uint16
    var flags uint8
    switch proto {
    case 6: // TCP
        if t := pkt.Layer(layers.LayerTypeTCP); t != nil {
            tcp := t.(*layers.TCP)
            srcPort = uint16(tcp.SrcPort)
            dstPort = uint16(tcp.DstPort)
            // Build flags bitmask from TCP bool fields
flags = 0
if tcp.SYN { flags |= 1 << 0 }
if tcp.ACK { flags |= 1 << 1 }
if tcp.FIN { flags |= 1 << 2 }
if tcp.RST { flags |= 1 << 3 }
if tcp.PSH { flags |= 1 << 4 }
if tcp.URG { flags |= 1 << 5 }
        }
    case 17: // UDP
        if u := pkt.Layer(layers.LayerTypeUDP); u != nil {
            udp := u.(*layers.UDP)
            srcPort = uint16(udp.SrcPort)
            dstPort = uint16(udp.DstPort)
        }
    default:
        // ignore other protocols for now
        return
    }
    key := FlowKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort, Proto: proto}
    ft.mu.Lock()
    defer ft.mu.Unlock()
    f, ok := ft.flows[key]
    if !ok {
        f = &Flow{Key: key, Start: time.Now()}
        ft.flows[key] = f
    }
    f.LastSeen = time.Now()
    f.Packets++
    f.Bytes += len(pkt.Data())
    f.Flags |= flags
}

func main() {
    iface := flag.String("i", "eth0", "network interface to capture (or pcap file)")
    pcapFile := flag.String("r", "", "pcap file to read instead of live capture")
    idle := flag.Duration("idle", 5*time.Second, "idle timeout for flows")
    active := flag.Duration("active", 120*time.Second, "maximum lifetime for a flow")
    flag.Parse()

    ft := NewFlowTable(*idle, *active)

    var handle *pcap.Handle
    var err error
    if *pcapFile != "" {
        handle, err = pcap.OpenOffline(*pcapFile)
    } else {
        handle, err = pcap.OpenLive(*iface, 65535, true, pcap.BlockForever)
    }
    if err != nil {
        log.Fatalf("pcap open error: %v", err)
    }
    defer handle.Close()

    // Set a BPF filter to capture IP packets only (optional)
    _ = handle.SetBPFFilter("ip")

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    // Graceful shutdown handling
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigs
        log.Println("Shutting down capture…")
        os.Exit(0)
    }()

    for pkt := range packetSource.Packets() {
        ft.AddPacket(pkt)
    }
}
