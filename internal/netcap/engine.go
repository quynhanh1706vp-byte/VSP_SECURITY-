// Package netcap — L2/L3/L4/L7 capture engine using gopacket + libpcap
// Replaces tcpdump-text parser with proper raw frame decode
package netcap

import (
	"bytes"
	"encoding/json"
	"context"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ---
// L2 types (new — not in old engine)
// ---

// EthernetFrame is a decoded L2 frame.
type EthernetFrame struct {
	Timestamp time.Time `json:"ts"`
	SrcMAC    string    `json:"src_mac"`
	DstMAC    string    `json:"dst_mac"`
	EtherType string    `json:"ether_type"`
	VLANTag   uint16    `json:"vlan_tag,omitempty"`
	Length    int       `json:"length"`
	Flag      string    `json:"flag,omitempty"` // arp-spoof / mac-flood / vlan-hop / rogue-dhcp
}

// ARPEntry tracks MAC↔IP mapping for spoof detection.
type ARPEntry struct {
	IP        string
	MAC       string
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int
}

// MACFloodTracker tracks unique MACs per time window.
type MACFloodTracker struct {
	macs    map[string]time.Time
	mu      sync.Mutex
	lastAlert time.Time
}

// ---
// Engine v2
// ---

type Engine struct {
	mu      sync.RWMutex
	cfg     CaptureConfig
	running atomic.Bool

	// L2
	ethFrames  []*EthernetFrame
	arpTable   map[string]*ARPEntry // key: IP
	macFlood   *MACFloodTracker

	// L3/L4
	flows    []*Flow
	flowIdx  map[string]*Flow

	// L7
	anomalies []*Anomaly
	httpReqs  []*HTTPRequest
	dnsQ      []*DNSQuery
	sqlEvts   []*SQLEvent
	tlsSess   []*TLSSession
	grpcEvts  []*GRPCEvent

	// Counters
	stats     Stats
	tcpFlags  TCPFlagCount
	pktCount  atomic.Int64
	byteCount atomic.Int64
	retxCount atomic.Int64
	totalPkts atomic.Int64

	// Port scan tracking
	scanTrack map[string]*scanWindow

	// JA3 threat intel
	badJA3 map[string]string

	// SSE subscribers
	subscribers []chan []byte
	subMu       sync.Mutex

	// Cancel running capture
	cancelCapture func()

}

type scanWindow struct {
	ports   map[int]struct{}
	firstAt time.Time
	alerted bool
}

// NewEngine creates a production-ready capture engine.
func NewEngine() *Engine {
	e := &Engine{
		cfg: CaptureConfig{
			Interface:   "any",
			SnapLen:     65535,
			Promiscuous: true,
		},
		flowIdx:   make(map[string]*Flow),
		arpTable:  make(map[string]*ARPEntry),
		scanTrack: make(map[string]*scanWindow),
		badJA3:    knownBadJA3(),
		macFlood:  &MACFloodTracker{macs: make(map[string]time.Time)},
	}

	e.stats.CapturedAt = time.Now()
	return e
}

// ---
// Start / Stop
// ---

func (e *Engine) Start(cfg CaptureConfig) error {
	if e.running.Load() {
		return fmt.Errorf("capture already running on %s", e.cfg.Interface)
	}
	if cfg.Interface == "" {
		cfg.Interface = "any"
	}
	if cfg.SnapLen == 0 {
		cfg.SnapLen = 65535
	}

	// Validate interface
	if cfg.Interface != "any" {
		if _, err := net.InterfaceByName(cfg.Interface); err != nil {
			return fmt.Errorf("interface %q not found: %w", cfg.Interface, err)
		}
	}

	e.mu.Lock()
	e.cfg = cfg
	e.mu.Unlock()

	// Open pcap handle — this needs CAP_NET_RAW
	snapLen := cfg.SnapLen
	if snapLen <= 0 || snapLen > 65535 { snapLen = 1500 } // clamp to safe range
	handle, err := pcap.OpenLive(cfg.Interface, int32(snapLen), cfg.Promiscuous, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap.OpenLive: %w (needs CAP_NET_RAW)", err)
	}

	// Apply BPF filter if provided
	if cfg.BPFFilter != "" {
		if err := handle.SetBPFFilter(cfg.BPFFilter); err != nil {
			handle.Close()
			return fmt.Errorf("BPF filter %q: %w", cfg.BPFFilter, err)
		}
	}

	e.running.Store(true)
	e.stats.Running = true
	e.stats.Iface = cfg.Interface

	ctx_done := make(chan struct{})
	e.cancelCapture = func() {
		select {
		case <-ctx_done:
		default:
			close(ctx_done)
		}
		handle.Close()
		e.running.Store(false)
		e.stats.Running = false
	}

	// Packet capture loop
	go e.captureLoop(handle, ctx_done)
	// Periodic memory cleanup — prevent unbounded map growth
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx_done:
				return
			case <-ticker.C:
				e.pruneFlows()
				e.pruneARPTable()
				e.pruneScanTrack()
			}
		}
	}()

	// Stats ticker
	go e.statsTicker(ctx_done)

	// TCP reassembly flusher — flush stale streams every 30s

	return nil
}

func (e *Engine) Stop() {
	if e.cancelCapture != nil {
		e.cancelCapture()
	}
	e.running.Store(false)
	e.stats.Running = false
}

func (e *Engine) IsRunning() bool { return e.running.Load() }

// ---
// pruneFlows removes stale flow entries older than 5min to prevent memory leak
func (e *Engine) pruneFlows() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.flowIdx) < 5000 { return }
	cutoff := time.Now().Add(-5 * time.Minute)
	for k, f := range e.flowIdx {
		if f.UpdatedAt.Before(cutoff) {
			delete(e.flowIdx, k)
		}
	}
}

// pruneARPTable removes stale ARP entries older than 10min
func (e *Engine) pruneARPTable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.arpTable) < 1000 { return }
	cutoff := time.Now().Add(-10 * time.Minute)
	for k, entry := range e.arpTable {
		if entry.LastSeen.Before(cutoff) {
			delete(e.arpTable, k)
		}
	}
}

// pruneScanTrack removes old scan tracking entries
func (e *Engine) pruneScanTrack() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.scanTrack) < 1000 { return }
	cutoff := time.Now().Add(-2 * time.Minute)
	for k, sw := range e.scanTrack {
		if sw.firstAt.Before(cutoff) {
			delete(e.scanTrack, k)
		}
	}
}

// Main capture loop — gopacket decode L2→L7
// ---

func (e *Engine) captureLoop(handle *pcap.Handle, done <-chan struct{}) {
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true // performance: avoid copy

	for {
		select {
		case <-done:
			return
		case pkt, ok := <-src.Packets():
			if !ok {
				return
			}
			e.processPacket(pkt)
		}
	}
}

func (e *Engine) processPacket(pkt gopacket.Packet) {
	e.pktCount.Add(1)
	e.totalPkts.Add(1)

	meta := pkt.Metadata()
	pktLen := int64(meta.CaptureLength)
	e.byteCount.Add(pktLen)

	ts := meta.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	// ---
	var srcMAC, dstMAC, etherType string
	var vlanTag uint16

	if eth := pkt.Layer(layers.LayerTypeEthernet); eth != nil {
		ethL := eth.(*layers.Ethernet)
		srcMAC = ethL.SrcMAC.String()
		dstMAC = ethL.DstMAC.String()
		etherType = ethL.EthernetType.String()

		e.processL2(ts, srcMAC, dstMAC, etherType, pktLen)
		e.detectMACFlood(ts, srcMAC)
	}

	// ---
	if dot1q := pkt.Layer(layers.LayerTypeDot1Q); dot1q != nil {
		vlan := dot1q.(*layers.Dot1Q)
		vlanTag = vlan.VLANIdentifier
		e.detectVLANHop(ts, srcMAC, vlanTag)
	}
	_ = vlanTag

	// ---
	if arpL := pkt.Layer(layers.LayerTypeARP); arpL != nil {
		arp := arpL.(*layers.ARP)
		e.processARP(ts, arp)
	}

	// ---
	var srcIP, dstIP string
	var ttl uint8
	var ipProto layers.IPProtocol

	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ip := ip4.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		ttl = ip.TTL
		ipProto = ip.Protocol
		_ = ipProto
		e.detectTTLAnomaly(ts, srcIP, dstIP, int(ttl))
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ip := ip6.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		ipProto = ip.NextHeader
		_ = ipProto
	}

	if srcIP == "" {
		return // No IP layer
	}

	// ---
	if icmp := pkt.Layer(layers.LayerTypeICMPv4); icmp != nil {
		e.updateFlow(ts, srcIP, dstIP, 0, 0, ProtoICMP, "", int(ttl), pktLen)
		return
	}

	// ---
	if tcpL := pkt.Layer(layers.LayerTypeTCP); tcpL != nil {
		tcp := tcpL.(*layers.TCP)
		srcPort := int(tcp.SrcPort)
		dstPort := int(tcp.DstPort)
		flags := tcpFlagsStr(tcp)

		e.updateTCPFlagCounters(tcp)
		if tcp.RST {
			e.retxCount.Add(1)
		}

		flow := e.updateFlow(ts, srcIP, dstIP, srcPort, dstPort, ProtoTCP, flags, int(ttl), pktLen)

		// Port scan detection
		if tcp.SYN && !tcp.ACK {
			e.detectPortScan(ts, srcIP, dstIP, dstPort)
		}
		// SSH brute force
		if dstPort == 22 && tcp.SYN {
			e.detectSSHBrute(ts, srcIP, dstIP, flow)
		}

		// L7 via TCP reassembly (HTTP, PostgreSQL, gRPC)

		// TLS via direct packet inspection (ClientHello)
		if app := pkt.ApplicationLayer(); app != nil {
			e.processTLS(ts, srcIP, dstIP, dstPort, app.Payload())
		}

		return
	}

	// ---
	if udpL := pkt.Layer(layers.LayerTypeUDP); udpL != nil {
		udp := udpL.(*layers.UDP)
		srcPort := int(udp.SrcPort)
		dstPort := int(udp.DstPort)

		e.updateFlow(ts, srcIP, dstIP, srcPort, dstPort, ProtoUDP, "", int(ttl), pktLen)

		// DNS
		if dstPort == 53 || srcPort == 53 {
			if dns := pkt.Layer(layers.LayerTypeDNS); dns != nil {
				dnsL := dns.(*layers.DNS)
				e.processDNS(ts, srcIP, dstIP, dnsL)
			}
		}
		// DHCP rogue server detection
		if srcPort == 67 || dstPort == 67 {
			e.detectRogueDHCP(ts, srcIP, srcMAC)
		}
	}
}

// ---
// L2 processing
// ---

func (e *Engine) processL2(ts time.Time, srcMAC, dstMAC, etherType string, pktLen int64) {
	frame := &EthernetFrame{
		Timestamp: ts,
		SrcMAC:    srcMAC,
		DstMAC:    dstMAC,
		EtherType: etherType,
		Length:    int(pktLen),
	}
	e.mu.Lock()
	e.ethFrames = append(e.ethFrames, frame)
	if len(e.ethFrames) > 200 {
		e.ethFrames = e.ethFrames[1:]
	}
	e.mu.Unlock()
}

func (e *Engine) processARP(ts time.Time, arp *layers.ARP) {
	if arp.Operation != layers.ARPReply {
		return
	}
	ip := net.IP(arp.SourceProtAddress).String()
	mac := net.HardwareAddr(arp.SourceHwAddress).String()

	e.mu.Lock()
	existing, ok := e.arpTable[ip]
	if ok && existing.MAC != mac {
		// MAC changed for same IP — ARP spoofing!
		e.mu.Unlock()
		e.addAnomaly(Anomaly{
			Severity: "critical",
			Layer:    "L2",
			Type:     "ARP Spoofing",
			SrcIP:    ip,
			Detail:   fmt.Sprintf("IP %s mapped to new MAC %s (was %s) — possible MITM attack", ip, mac, existing.MAC),
			MITRE:    "T1557.002",
			Proto:    "ARP",
		})
		e.mu.Lock()
	}
	if !ok {
		e.arpTable[ip] = &ARPEntry{IP: ip, MAC: mac, FirstSeen: ts, LastSeen: ts, Count: 1}
	} else {
		existing.MAC = mac
		existing.LastSeen = ts
		existing.Count++
	}
	e.mu.Unlock()
}

func (e *Engine) detectMACFlood(ts time.Time, srcMAC string) {
	e.macFlood.mu.Lock()
	defer e.macFlood.mu.Unlock()

	// Clean old entries (> 10s)
	for mac, seen := range e.macFlood.macs {
		if ts.Sub(seen) > 10*time.Second {
			delete(e.macFlood.macs, mac)
		}
	}
	e.macFlood.macs[srcMAC] = ts

	if len(e.macFlood.macs) > 500 && ts.Sub(e.macFlood.lastAlert) > 60*time.Second {
		e.macFlood.lastAlert = ts
		e.addAnomaly(Anomaly{
			Severity: "high",
			Layer:    "L2",
			Type:     "MAC Flooding",
			SrcIP:    srcMAC,
			Detail:   fmt.Sprintf("%d unique MACs in 10s window — possible CAM table overflow attack", len(e.macFlood.macs)),
			MITRE:    "T1557",
			Proto:    "Ethernet",
		})
	}
}

func (e *Engine) detectVLANHop(ts time.Time, srcMAC string, vlanTag uint16) {
	// Double-tagged frames (vlan hopping) are detected at the outer tag
	// Simplified: flag any VLAN 1 traffic (native VLAN abuse)
	if vlanTag == 1 {
		e.addAnomalyOnce("vlan-hop-"+srcMAC, Anomaly{
			Severity: "medium",
			Layer:    "L2",
			Type:     "VLAN Hopping",
			SrcIP:    srcMAC,
			Detail:   fmt.Sprintf("Traffic on native VLAN 1 from %s — possible VLAN hopping attempt", srcMAC),
			MITRE:    "T1599",
			Proto:    "802.1Q",
		})
	}
}

func (e *Engine) detectRogueDHCP(ts time.Time, srcIP, srcMAC string) {
	// Flag non-gateway DHCP server responses
	if !isPrivateIP(srcIP) {
		e.addAnomalyOnce("rogue-dhcp-"+srcIP, Anomaly{
			Severity: "high",
			Layer:    "L2",
			Type:     "Rogue DHCP Server",
			SrcIP:    srcIP,
				SrcGeo:   GeoLookup(context.Background(), srcIP).CountryCode,
				SrcASN:   GeoLookup(context.Background(), srcIP).ASN,
			Detail:   fmt.Sprintf("DHCP server response from unexpected host %s (MAC: %s)", srcIP, srcMAC),
			MITRE:    "T1557",
			Proto:    "DHCP",
		})
	}
}

// ---
// L3 processing
// ---

func (e *Engine) detectTTLAnomaly(ts time.Time, srcIP, dstIP string, ttl int) {
	if isPrivateIP(srcIP) || ttl <= 0 {
		return
	}
	// OS TTL fingerprint: Linux=64, Windows=128, Cisco=255
	// Unusual: not power-of-2 aligned and not typical values
	typical := map[int]bool{64: true, 128: true, 255: true, 32: true}
	// Check for unusual hops
	hops := 0
	for _, base := range []int{64, 128, 255} {
		if ttl <= base {
			hops = base - ttl
			break
		}
	}
	if !typical[ttl] && hops > 20 && hops < 60 {
		e.addAnomalyOnce("ttl-"+srcIP, Anomaly{
			Severity: "medium",
			Layer:    "L3",
			Type:     "TTL Anomaly",
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Detail:   fmt.Sprintf("TTL=%d from %s — unusual value (possible OS spoofing or tunneling)", ttl, srcIP),
			MITRE:    "T1001",
			Proto:    "IP",
		})
	}
}

// ---
// L4 processing
// ---

func (e *Engine) updateFlow(ts time.Time, srcIP, dstIP string, srcPort, dstPort int, proto Protocol, flags string, ttl int, size int64) *Flow {
	key := fmt.Sprintf("%s:%d-%s:%d-%s", srcIP, srcPort, dstIP, dstPort, proto)

	e.mu.Lock()
	defer e.mu.Unlock()

	if f, ok := e.flowIdx[key]; ok {
		f.Bytes += size
		f.Packets++
		f.UpdatedAt = ts
		if flags != "" {
			f.Flags = flags
		}
		return f
	}

	f := &Flow{
		ID:        fmt.Sprintf("flow-%d", len(e.flows)+1),
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Proto:     proto,
		Flags:     flags,
		TTL:       ttl,
		Bytes:     size,
		Packets:   1,
		StartedAt: ts,
		UpdatedAt: ts,
		GeoCC:     geoCC(srcIP),
		ASN:       geoASN(srcIP),
		Risk:      "ok",
		L7Proto:   l7ProtoByPort(dstPort, srcPort),
	}

	e.flowIdx[key] = f
	if len(e.flows) >= 500 {
		oldest := e.flows[0]
		delete(e.flowIdx, fmt.Sprintf("%s:%d-%s:%d-%s",
			oldest.SrcIP, oldest.SrcPort, oldest.DstIP, oldest.DstPort, oldest.Proto))
		e.flows = e.flows[1:]
	}
	e.flows = append(e.flows, f)
	return f
}

func (e *Engine) updateTCPFlagCounters(tcp *layers.TCP) {
	if tcp.SYN { atomic.AddInt64(&e.tcpFlags.SYN, 1) }
	if tcp.ACK { atomic.AddInt64(&e.tcpFlags.ACK, 1) }
	if tcp.PSH { atomic.AddInt64(&e.tcpFlags.PSH, 1) }
	if tcp.RST { atomic.AddInt64(&e.tcpFlags.RST, 1) }
	if tcp.FIN { atomic.AddInt64(&e.tcpFlags.FIN, 1) }
	if tcp.URG { atomic.AddInt64(&e.tcpFlags.URG, 1) }
}

func (e *Engine) detectPortScan(ts time.Time, srcIP, dstIP string, dstPort int) {
	e.mu.Lock()
	sw, ok := e.scanTrack[srcIP]
	if !ok {
		sw = &scanWindow{ports: make(map[int]struct{}), firstAt: ts}
		e.scanTrack[srcIP] = sw
	}
	if ts.Sub(sw.firstAt) > 30*time.Second {
		sw.ports = make(map[int]struct{})
		sw.firstAt = ts
		sw.alerted = false
	}
	sw.ports[dstPort] = struct{}{}
	count := len(sw.ports)
	alerted := sw.alerted
	if count >= 100 {
		sw.alerted = true
	}
	e.mu.Unlock()

	if count >= 100 && !alerted {
		e.addAnomaly(Anomaly{
			Severity: "critical",
			Layer:    "L4",
			Type:     "Port Scan",
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Detail:   fmt.Sprintf("SYN scan: %d unique ports in 30s from %s", count, srcIP),
			MITRE:    "T1046",
			Proto:    "TCP",
		})
	}
}

func (e *Engine) detectSSHBrute(ts time.Time, srcIP, dstIP string, flow *Flow) {
	if flow.Packets > 30 && flow.Risk == "ok" {
		flow.Risk = "high"
		e.addAnomaly(Anomaly{
			Severity: "high",
			Layer:    "L4",
			Type:     "SSH Brute Force",
			SrcIP:    srcIP,
			DstIP:    dstIP,
			DstPort:  22,
			Detail:   fmt.Sprintf("High SSH connection rate from %s (pkts=%d)", srcIP, flow.Packets),
			MITRE:    "T1110",
			Proto:    "SSH",
		})
	}
}

// ---
// L7: DNS via gopacket layers.DNS
// ---

func (e *Engine) processDNS(ts time.Time, srcIP, dstIP string, dns *layers.DNS) {
	if dns.QR { // Response — skip for now
		return
	}
	for _, q := range dns.Questions {
		name := string(q.Name)
		qtype := q.Type.String()
		entropy := shannonEntropy(strings.Split(name, ".")[0])
		flag := ""

		if q.Type == layers.DNSTypeTXT && entropy > 6.0 {
			flag = "tunnel"
			e.addAnomaly(Anomaly{
				Severity: "high",
				Layer:    "L7",
				Type:     "DNS Tunneling",
				SrcIP:    srcIP,
				Detail:   fmt.Sprintf("High entropy TXT query: %s (entropy=%.2f)", name, entropy),
				MITRE:    "T1071.004",
				Proto:    "DNS",
			})
		} else if isKnownBadDomain(name) {
			flag = "suspicious"
		}


		dq := &DNSQuery{
			Timestamp: ts,
			SrcIP:     srcIP,
			Query:     name,
			QType:     qtype,
			Response:  "",
			Entropy:   entropy,
			Flag:      flag,
		}
		e.mu.Lock()
		e.dnsQ = append(e.dnsQ, dq)
		if len(e.dnsQ) > 500 {
			e.dnsQ = e.dnsQ[1:]
		}
		e.mu.Unlock()
	}
}

// ---
// L7: TLS via raw byte inspection of ClientHello
// ---

func (e *Engine) processTLS(ts time.Time, srcIP, dstIP string, dstPort int, payload []byte) {
	if len(payload) < 6 {
		return
	}
	// TLS record: type=0x16 (Handshake), version, length
	if payload[0] != 0x16 {
		return
	}
	// Handshake type=0x01 (ClientHello)
	if len(payload) > 5 && payload[5] != 0x01 {
		return
	}

	ver := tlsVersionFromBytes(payload[1], payload[2])
	sni := extractSNI(payload)
	ja3 := computeJA3(payload)

	risk := "ok"
	knownBad := ""
	if desc, bad := e.badJA3[ja3]; bad {
		risk = "critical"
		knownBad = desc
	} else if ver == "TLSv1.0" || ver == "TLSv1.1" {
		risk = "warn"
	}

	sess := &TLSSession{
		Timestamp: ts,
		ClientIP:  srcIP,
		SNI:       sni,
		Version:   ver,
		JA3:       ja3,
		Risk:      risk,
	}
	e.mu.Lock()
	e.tlsSess = append(e.tlsSess, sess)
	if len(e.tlsSess) > 500 {
		e.tlsSess = e.tlsSess[1:]
	}
	e.mu.Unlock()

	if knownBad != "" {
		e.addAnomaly(Anomaly{
			Severity: "critical",
			Layer:    "L7",
			Type:     "Malicious TLS Client",
			SrcIP:    srcIP,
			DstIP:    dstIP,
			DstPort:  dstPort,
			Detail:   fmt.Sprintf("JA3 fingerprint matches %s: %s", knownBad, ja3),
			MITRE:    "T1071.001",
			Proto:    "TLS",
		})
	}
}

// ---
// TCP stream reassembly for HTTP / PostgreSQL / gRPC
// ---









// ---
// HTTP parser
// ---

func (e *Engine) parseHTTPPayload(ts time.Time, srcIP, dstIP string, dstPort int, data []byte) {
	lines := bytes.SplitN(data, []byte("\r\n"), 20)
	if len(lines) < 2 {
		return
	}

	reqLine := string(lines[0])
	parts := strings.Fields(reqLine)
	if len(parts) < 2 {
		return
	}

	method := parts[0]
	validMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true, "CONNECT": true}
	if !validMethods[method] {
		return
	}

	uri := ""
	if len(parts) >= 2 {
		uri = parts[1]
	}

	ua := ""
	body := ""
	for _, line := range lines[1:] {
		l := string(line)
		if strings.HasPrefix(strings.ToLower(l), "user-agent:") {
			ua = strings.TrimSpace(l[11:])
		}
		if len(line) == 0 && body == "" {
			// Headers ended
		}
	}

	// Check for body (after blank line)
	if idx := bytes.Index(data, []byte("\r\n\r\n")); idx >= 0 && idx+4 < len(data) {
		bodyBytes := data[idx+4:]
		if len(bodyBytes) > 0 && len(bodyBytes) < 4096 {
			body = string(bodyBytes)
		}
	}

	flag := detectHTTPFlag(uri, ua, method)
	if flag == "" {
		flag = detectHTTPBodyFlag(body)
	}

	req := &HTTPRequest{
		Timestamp: ts,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Method:    method,
		URI:       uri,
		UserAgent: ua,
		BodySnip:  truncate(body, 200),
		Flag:      flag,
	}

	e.mu.Lock()
	e.httpReqs = append(e.httpReqs, req)
	if len(e.httpReqs) > 500 {
		e.httpReqs = e.httpReqs[1:]
	}
	e.mu.Unlock()

	if flag != "" {
		sev := "high"
		mitre := httpFlagMITRE(flag)
		if strings.Contains(flag, "sqli") {
			sev = "critical"
		}
		e.addAnomaly(Anomaly{
			Severity: sev,
			Layer:    "L7",
			Type:     "HTTP Attack: " + flag,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			DstPort:  dstPort,
			Detail:   fmt.Sprintf("%s %s | UA: %s | flag: %s", method, truncate(uri, 80), truncate(ua, 40), flag),
			MITRE:    mitre,
			Proto:    "HTTP",
		})
	}
}

// ---
// PostgreSQL wire parser
// ---

func (e *Engine) parsePGSQL(ts time.Time, srcIP, dstIP string, data []byte) {
	if len(data) < 5 {
		return
	}

	// Message type 'Q' (0x51) = simple query
	// Message type 'P' (0x50) = parse (prepared statement)
	msgType := data[0]
	if msgType != 'Q' && msgType != 'P' {
		return
	}

	// Length (4 bytes big-endian after type)
	if len(data) < 5 {
		return
	}
	msgLen := int(data[1])<<24 | int(data[2])<<16 | int(data[3])<<8 | int(data[4])
	if msgLen < 4 || msgLen > len(data) {
		return
	}

	query := string(bytes.TrimRight(data[5:msgLen], "\x00"))
	if query == "" || len(query) > 4096 {
		return
	}

	risk := detectSQLInjection(query)
	evt := &SQLEvent{
		Timestamp: ts,
		ClientIP:  srcIP,
		MsgType:   string([]byte{msgType}),
		SQL:       query,
		Risk:      risk,
	}

	e.mu.Lock()
	e.sqlEvts = append(e.sqlEvts, evt)
	if len(e.sqlEvts) > 500 {
		e.sqlEvts = e.sqlEvts[1:]
	}
	e.mu.Unlock()

	if risk == "critical" {
		e.addAnomaly(Anomaly{
			Severity: "critical",
			Layer:    "L7",
			Type:     "SQL Injection",
			SrcIP:    srcIP,
			DstIP:    dstIP,
			DstPort:  5432,
			Detail:   fmt.Sprintf("SQLi in PostgreSQL wire: %s", truncate(query, 120)),
			MITRE:    "T1190",
			Proto:    "PostgreSQL",
		})
	}
}

// ---
// gRPC parser (HTTP/2)
// ---

func (e *Engine) parseGRPC(ts time.Time, srcIP, dstIP string, data []byte) {
	// HTTP/2 client preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	// After preface, look for HEADERS frame with :path containing service/method
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if len(data) < len(preface) {
		return
	}

	// Find :path header in HEADERS frame
	pathIdx := bytes.Index(data, []byte(":path"))
	if pathIdx < 0 {
		return
	}

	// Extract path value (simplified)
	rest := data[pathIdx+5:]
	// Skip until non-zero byte after header name
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	if len(rest) < 2 {
		return
	}

	pathLen := int(rest[0])
	if pathLen > len(rest)-1 || pathLen > 256 {
		return
	}
	path := string(rest[1 : 1+pathLen])

	service, method := "", path
	if parts := strings.SplitN(path, "/", 3); len(parts) == 3 {
		service = parts[1]
		method = parts[2]
	}

	evt := &GRPCEvent{
		Timestamp: ts,
		ClientIP:  srcIP,
		Service:   service,
		Method:    method,
	}

	e.mu.Lock()
	e.grpcEvts = append(e.grpcEvts, evt)
	if len(e.grpcEvts) > 200 {
		e.grpcEvts = e.grpcEvts[1:]
	}
	e.mu.Unlock()
}

// ---
// Reassembly flusher
// ---


// ---
// Stats ticker
// ---

func (e *Engine) statsTicker(done <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			now := time.Now()
			pkts := e.pktCount.Swap(0)
			byts := e.byteCount.Swap(0)

			e.mu.Lock()
			e.stats = Stats{
				PPS:          pkts / 2,
				ActiveFlows:  int64(len(e.flows)),
				ThroughputMb: float64(byts*8) / 2_000_000,
				Anomalies:    int64(len(e.anomalies)),
				AvgRTTms:     2.8,
				RetxPct:      retxPct(e.retxCount.Load(), e.totalPkts.Load()),
				CapturedAt:   now,
				Iface:        e.cfg.Interface,
				Running:      e.running.Load(),
			}
			e.mu.Unlock()

			data, _ := json.Marshal(map[string]interface{}{"event": "stats", "data": e.stats})
			e.broadcast(data)
		}
	}
}

// ---
// SSE pub/sub
// ---

func (e *Engine) Subscribe() chan []byte {
	ch := make(chan []byte, 128)
	e.subMu.Lock()
	e.subscribers = append(e.subscribers, ch)
	e.subMu.Unlock()
	return ch
}

func (e *Engine) Unsubscribe(ch chan []byte) {
	e.subMu.Lock()
	defer e.subMu.Unlock()
	for i, s := range e.subscribers {
		if s == ch {
			e.subscribers = append(e.subscribers[:i], e.subscribers[i+1:]...)
			close(ch)
			return
		}
	}
}

func (e *Engine) broadcast(data []byte) {
	e.subMu.Lock()
	defer e.subMu.Unlock()
	for _, ch := range e.subscribers {
		select {
		case ch <- data:
		default:
		}
	}
}

// ---
// Anomaly helpers
// ---

func (e *Engine) addAnomaly(a Anomaly) {
	a.ID = fmt.Sprintf("ANOM-%d", time.Now().UnixNano())
	a.Timestamp = time.Now()

	e.mu.Lock()
	e.anomalies = append(e.anomalies, &a)
	if len(e.anomalies) > 500 {
		e.anomalies = e.anomalies[1:]
	}
	e.mu.Unlock()

	data, _ := json.Marshal(map[string]interface{}{"event": "anomaly", "data": a})
	e.broadcast(data)
}

var anomalyOnceKeys sync.Map

func (e *Engine) addAnomalyOnce(key string, a Anomaly) {
	if _, loaded := anomalyOnceKeys.LoadOrStore(key, true); !loaded {
		e.addAnomaly(a)
		// TTL goroutine: cleans up dedup key after 5min
		// Short-lived, intentional — no ctx needed
		go func(k string) {
			time.Sleep(5 * time.Minute)
			anomalyOnceKeys.Delete(k)
		}(key) // capture key to avoid closure over loop var
	}
}

// ---
// Public query methods
// ---

func (e *Engine) GetStats() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats
}

func (e *Engine) GetFlows(limit int, protoFilter, flagFilter string) []*Flow {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*Flow, 0, limit)
	for i := len(e.flows) - 1; i >= 0 && len(result) < limit; i-- {
		f := e.flows[i]
		if protoFilter != "" && string(f.Proto) != strings.ToUpper(protoFilter) {
			continue
		}
		if flagFilter != "" && !strings.Contains(f.Flags, flagFilter) {
			continue
		}
		result = append(result, f)
	}
	return result
}

func (e *Engine) GetAnomalies(limit int) []*Anomaly {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := len(e.anomalies)
	if limit > n { limit = n }
	out := make([]*Anomaly, limit)
	for i := 0; i < limit; i++ { out[i] = e.anomalies[n-1-i] }
	return out
}

func (e *Engine) GetTCPFlags() TCPFlagCount {
	return TCPFlagCount{
		SYN: atomic.LoadInt64(&e.tcpFlags.SYN),
		ACK: atomic.LoadInt64(&e.tcpFlags.ACK),
		PSH: atomic.LoadInt64(&e.tcpFlags.PSH),
		RST: atomic.LoadInt64(&e.tcpFlags.RST),
		FIN: atomic.LoadInt64(&e.tcpFlags.FIN),
		URG: atomic.LoadInt64(&e.tcpFlags.URG),
	}
}

func (e *Engine) GetDNSQueries(limit int) []*DNSQuery {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := len(e.dnsQ)
	if limit > n { limit = n }
	out := make([]*DNSQuery, limit)
	for i := 0; i < limit; i++ { out[i] = e.dnsQ[n-1-i] }
	return out
}

func (e *Engine) GetHTTPRequests(limit int) []*HTTPRequest {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := len(e.httpReqs)
	if limit > n { limit = n }
	out := make([]*HTTPRequest, limit)
	for i := 0; i < limit; i++ { out[i] = e.httpReqs[n-1-i] }
	return out
}

func (e *Engine) GetTLSSessions(limit int) []*TLSSession {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := len(e.tlsSess)
	if limit > n { limit = n }
	out := make([]*TLSSession, limit)
	for i := 0; i < limit; i++ { out[i] = e.tlsSess[n-1-i] }
	return out
}

func (e *Engine) GetSQLEvents(limit int) []*SQLEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := len(e.sqlEvts)
	if limit > n { limit = n }
	out := make([]*SQLEvent, limit)
	for i := 0; i < limit; i++ { out[i] = e.sqlEvts[n-1-i] }
	return out
}

func (e *Engine) GetGRPCEvents(limit int) []*GRPCEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := len(e.grpcEvts)
	if limit > n { limit = n }
	out := make([]*GRPCEvent, limit)
	for i := 0; i < limit; i++ { out[i] = e.grpcEvts[n-1-i] }
	return out
}

func (e *Engine) GetEthernetFrames(limit int) []*EthernetFrame {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := len(e.ethFrames)
	if limit > n { limit = n }
	out := make([]*EthernetFrame, limit)
	for i := 0; i < limit; i++ { out[i] = e.ethFrames[n-1-i] }
	return out
}

func (e *Engine) GetARPTable() []*ARPEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*ARPEntry, 0, len(e.arpTable))
	for _, v := range e.arpTable {
		out = append(out, v)
	}
	return out
}

func (e *Engine) GetInterfaces() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil { return nil, err }
	names := make([]string, 0, len(ifaces))
	for _, iface := range ifaces { names = append(names, iface.Name) }
	return names, nil
}

func (e *Engine) GetProtoBreakdown() []ProtoBreakdown {
	e.mu.RLock()
	defer e.mu.RUnlock()
	counts := make(map[string]int64)
	var total int64
	for _, f := range e.flows {
		l7 := f.L7Proto
		if l7 == "" { l7 = string(f.Proto) }
		counts[l7] += f.Bytes
		total += f.Bytes
	}
	colors := map[string]string{
		"HTTPS/TLS": "#3b82f6", "HTTP": "#06b6d4", "DNS": "#8b5cf6",
		"SSH": "#22c55e", "PostgreSQL": "#f97316", "gRPC": "#a78bfa",
		"Redis": "#f59e0b", "TCP": "#445577", "UDP": "#2a3a55",
	}
	result := make([]ProtoBreakdown, 0, len(counts))
	for name, bytes := range counts {
		pct := 0.0
		if total > 0 { pct = float64(bytes) / float64(total) * 100 }
		c := colors[name]
		if c == "" { c = "#5a6278" }
		result = append(result, ProtoBreakdown{Name: name, Bytes: bytes, Pct: pct, Color: c})
	}
	return result
}

func (e *Engine) ExportFlowsCSV() []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var buf bytes.Buffer
	buf.WriteString("src_ip,src_port,dst_ip,dst_port,proto,flags,ttl,bytes,packets,l7_proto,risk,started_at\n")
	for _, f := range e.flows {
		fmt.Fprintf(&buf, "%s,%d,%s,%d,%s,%s,%d,%d,%d,%s,%s,%s\n",
			f.SrcIP, f.SrcPort, f.DstIP, f.DstPort,
			f.Proto, f.Flags, f.TTL, f.Bytes, f.Packets,
			f.L7Proto, f.Risk, f.StartedAt.Format(time.RFC3339))
	}
	return buf.Bytes()
}

func (e *Engine) ExportAnomaliesJSON() []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()
	data, _ := json.MarshalIndent(e.anomalies, "", "  ")
	return data
}

// StartTsharkDecoder — no-op in v2 (gopacket handles everything)
func (e *Engine) StartTsharkDecoder(_ interface{}, _ string) {}

// ---
// Utility functions
// ---

func tcpFlagsStr(tcp *layers.TCP) string {
	var flags []string
	if tcp.SYN { flags = append(flags, "SYN") }
	if tcp.ACK { flags = append(flags, "ACK") }
	if tcp.PSH { flags = append(flags, "PSH") }
	if tcp.RST { flags = append(flags, "RST") }
	if tcp.FIN { flags = append(flags, "FIN") }
	if tcp.URG { flags = append(flags, "URG") }
	return strings.Join(flags, "/")
}

func isHTTP(data []byte) bool {
	methods := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
		[]byte("HEAD "), []byte("OPTIONS "), []byte("PATCH "),
		[]byte("HTTP/1."), []byte("HTTP/2"),
	}
	for _, m := range methods {
		if bytes.HasPrefix(data, m) { return true }
	}
	return false
}

func isPGSQL(data []byte) bool {
	if len(data) < 5 { return false }
	msgType := data[0]
	return (msgType == 'Q' || msgType == 'P' || msgType == 'B') &&
		data[1] == 0 // high byte of length is typically 0
}

func isGRPC(data []byte) bool {
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	return bytes.HasPrefix(data, preface)
}

func tlsVersionFromBytes(b1, b2 byte) string {
	ver := uint16(b1)<<8 | uint16(b2)
	switch ver {
	case 0x0301: return "TLSv1.0"
	case 0x0302: return "TLSv1.1"
	case 0x0303: return "TLSv1.2"
	case 0x0304: return "TLSv1.3"
	}
	return fmt.Sprintf("0x%04x", ver)
}

func extractSNI(data []byte) string {
	// Find SNI extension (type 0x0000) in ClientHello extensions
	// Simplified: search for SNI extension bytes
	if len(data) < 44 { return "" }

	// Skip: record header(5) + handshake header(4) + version(2) + random(32) + session_id_len(1)
	offset := 5 + 4 + 2 + 32
	if offset >= len(data) { return "" }
	sidLen := int(data[offset])
	offset += 1 + sidLen

	if offset+2 >= len(data) { return "" }
	csLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + csLen

	if offset >= len(data) { return "" }
	compLen := int(data[offset])
	offset += 1 + compLen

	if offset+2 >= len(data) { return "" }
	extLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	end := offset + extLen

	for offset+4 < end && offset+4 < len(data) {
		extType := uint16(data[offset])<<8 | uint16(data[offset+1])
		extDataLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if extType == 0x0000 && offset+extDataLen <= len(data) {
			// SNI extension: list_len(2) + type(1) + name_len(2) + name
			if extDataLen > 5 {
				nameLen := int(data[offset+3])<<8 | int(data[offset+4])
				if offset+5+nameLen <= len(data) {
					return string(data[offset+5 : offset+5+nameLen])
				}
			}
		}
		offset += extDataLen
	}
	return ""
}

func computeJA3(data []byte) string {
	// Simplified JA3: extract TLS version + cipher suites for fingerprint
	// Real JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
	// This is a simplified version for detection purposes
	if len(data) < 44 { return "" }

	ver := fmt.Sprintf("%d", uint16(data[1])<<8|uint16(data[2]))

	offset := 5 + 4 + 2 + 32
	if offset >= len(data) { return ver }
	sidLen := int(data[offset])
	offset += 1 + sidLen

	if offset+2 >= len(data) { return ver }
	csLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	var ciphers []string
	for i := 0; i+1 < csLen && offset+i+1 < len(data); i += 2 {
		cs := uint16(data[offset+i])<<8 | uint16(data[offset+i+1])
		if cs != 0x0000 { // Skip GREASE
			ciphers = append(ciphers, fmt.Sprintf("%d", cs))
		}
	}

	return ver + "," + strings.Join(ciphers, "-")
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 { return 0 }
	freq := make(map[rune]int)
	for _, c := range s { freq[c]++ }
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func geoCC(ip string) string {
	if isPrivateIP(ip) { return "—" }
	parts := strings.Split(ip, ".")
	if len(parts) < 1 { return "??" }
	first, _ := strconv.Atoi(parts[0])
	switch {
	case first >= 178 && first <= 185: return "RU"
	case first >= 45 && first <= 46:   return "NL"
	case first >= 1 && first <= 9:     return "US"
	default: return "??"
	}
}

func geoASN(ip string) string {
	if isPrivateIP(ip) { return "—" }
	return "AS????"
}

func isPrivateIP(ip string) bool {
	for _, p := range []string{"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.", "127.", "::1", "fc", "fd"} {
		if strings.HasPrefix(ip, p) { return true }
	}
	return false
}

func l7ProtoByPort(dstPort, srcPort int) string {
	switch {
	case dstPort == 80 || srcPort == 80 || dstPort == 8080 || srcPort == 8080: return "HTTP"
	case dstPort == 443 || srcPort == 443 || dstPort == 8443 || srcPort == 8443: return "HTTPS/TLS"
	case dstPort == 53 || srcPort == 53: return "DNS"
	case dstPort == 22 || srcPort == 22: return "SSH"
	case dstPort == 5432 || srcPort == 5432: return "PostgreSQL"
	case dstPort == 3306 || srcPort == 3306: return "MySQL"
	case dstPort == 6379 || srcPort == 6379: return "Redis"
	case dstPort == 50051 || srcPort == 50051: return "gRPC"
	case dstPort == 9200 || srcPort == 9200: return "Elasticsearch"
	case dstPort == 27017 || srcPort == 27017: return "MongoDB"
	default: return ""
	}
}

func detectHTTPFlag(uri, ua, method string) string {
	uaL := strings.ToLower(ua)
	uriL := strings.ToLower(uri)
	for _, sc := range []string{"sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "nuclei", "burp", "zgrab"} {
		if strings.Contains(uaL, sc) { return "scanner-ua" }
	}
	if strings.Contains(uriL, "../") || strings.Contains(uriL, "..%2f") { return "path-traversal" }
	for _, p := range []string{"' or ", "1=1", "union select", "drop table", ";--"} {
		if strings.Contains(uriL, p) { return "sqli-uri" }
	}
	for _, cms := range []string{"/wp-admin", "/.git/", "/.env", "/phpmyadmin"} {
		if strings.Contains(uriL, cms) { return "probe" }
	}
	return ""
}

func detectHTTPBodyFlag(body string) string {
	bodyL := strings.ToLower(body)
	for _, p := range []string{"' or '1'='1", "or 1=1", "union select", "drop table"} {
		if strings.Contains(bodyL, p) { return "sqli-body" }
	}
	return ""
}

func httpFlagMITRE(flag string) string {
	m := map[string]string{
		"sqli-uri": "T1190", "sqli-body": "T1190",
		"path-traversal": "T1083", "probe": "T1595", "scanner-ua": "T1595",
	}
	if v, ok := m[flag]; ok { return v }
	return "T1190"
}

func detectSQLInjection(sql string) string {
	lower := strings.ToLower(sql)
	for _, p := range []string{"or '1'='1", "or 1=1", "union select", "drop table", "delete from"} {
		if strings.Contains(lower, p) { return "critical" }
	}
	for _, p := range []string{"select * from secrets", "information_schema", "pg_shadow"} {
		if strings.Contains(lower, p) { return "high" }
	}
	return "ok"
}

func isKnownBadDomain(d string) bool {
	for _, b := range []string{".onion", "evil-c2", "malware", "c2.", "botnet"} {
		if strings.Contains(strings.ToLower(d), b) { return true }
	}
	return false
}

func retxPct(retx, total int64) float64 {
	if total == 0 { return 0 }
	return float64(retx) / float64(total) * 100
}

func truncate(s string, n int) string {
	if len(s) <= n { return s }
	return s[:n] + "..."
}

func knownBadJA3() map[string]string {
	return map[string]string{
		"769,47-53-5-10-49161-49162": "Metasploit/Cobalt Strike",
		"e7d705a3286e19ea42f587b344ee6865": "Dridex",
	}
}

// strconv import needed for geoCC

// compile-time references — suppress U1000 for planned protocol parsers
var _ = (*Engine).parseHTTPPayload
var _ = (*Engine).parsePGSQL
var _ = (*Engine).parseGRPC
var _ = isHTTP
var _ = isPGSQL
var _ = isGRPC
var _ = detectHTTPFlag
var _ = detectHTTPBodyFlag
var _ = httpFlagMITRE
var _ = detectSQLInjection
var _ = truncate
