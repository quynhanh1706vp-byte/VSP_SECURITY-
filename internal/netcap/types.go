package netcap

import "time"

type Protocol string

const (
	ProtoTCP   Protocol = "TCP"
	ProtoUDP   Protocol = "UDP"
	ProtoICMP  Protocol = "ICMP"
	ProtoOther Protocol = "OTHER"
)

type CaptureConfig struct {
	Interface   string `json:"interface"`
	BPFFilter   string `json:"bpf_filter"`
	SnapLen     int    `json:"snaplen"`
	Promiscuous bool   `json:"promiscuous"`
}

type Flow struct {
	ID        string    `json:"id"`
	SrcIP     string    `json:"src_ip"`
	SrcGeo    string    `json:"src_geo,omitempty"`
	SrcASN    string    `json:"src_asn,omitempty"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   int       `json:"src_port"`
	DstPort   int       `json:"dst_port"`
	Proto     Protocol  `json:"proto"`
	Flags     string    `json:"flags"`
	TTL       int       `json:"ttl"`
	Bytes     int64     `json:"bytes"`
	Packets   int64     `json:"packets"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
	GeoCC     string    `json:"geo_cc"`
	ASN       string    `json:"asn"`
	Risk      string    `json:"risk"`
	L7Proto   string    `json:"l7_proto"`
}

type Stats struct {
	PPS          int64     `json:"pps"`
	ActiveFlows  int64     `json:"active_flows"`
	ThroughputMb float64   `json:"throughput_mb"`
	Anomalies    int64     `json:"anomalies"`
	AvgRTTms     float64   `json:"avg_rtt_ms"`
	RetxPct      float64   `json:"retx_pct"`
	CapturedAt   time.Time `json:"captured_at"`
	Iface        string    `json:"iface"`
	Running      bool      `json:"running"`
}

type Anomaly struct {
	ID        string    `json:"id"`
	Severity  string    `json:"severity"`
	Layer     string    `json:"layer"`
	Type      string    `json:"type"`
	SrcIP     string    `json:"src_ip"`
	SrcGeo    string    `json:"src_geo,omitempty"`
	SrcASN    string    `json:"src_asn,omitempty"`
	DstIP     string    `json:"dst_ip"`
	DstPort   int       `json:"dst_port"`
	Detail    string    `json:"detail"`
	MITRE     string    `json:"mitre"`
	Proto     string    `json:"proto"`
	Timestamp time.Time `json:"timestamp"`
}

type TCPFlagCount struct {
	SYN int64 `json:"syn"`
	ACK int64 `json:"ack"`
	PSH int64 `json:"psh"`
	RST int64 `json:"rst"`
	FIN int64 `json:"fin"`
	URG int64 `json:"urg"`
}

type ProtoBreakdown struct {
	Name  string  `json:"name"`
	Bytes int64   `json:"bytes"`
	Pct   float64 `json:"pct"`
	Color string  `json:"color"`
}

type HTTPRequest struct {
	Timestamp  time.Time `json:"ts"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	Method     string    `json:"method"`
	URI        string    `json:"uri"`
	StatusCode int       `json:"status_code"`
	UserAgent  string    `json:"user_agent"`
	BodySnip   string    `json:"body_snip"`
	RTTms      float64   `json:"rtt_ms"`
	Flag       string    `json:"flag"`
	Size       int64     `json:"size"`
}

type DNSQuery struct {
	Timestamp time.Time `json:"ts"`
	SrcIP     string    `json:"src_ip"`
	SrcGeo    string    `json:"src_geo,omitempty"`
	SrcASN    string    `json:"src_asn,omitempty"`
	Query     string    `json:"query"`
	QType     string    `json:"qtype"`
	Response  string    `json:"response"`
	TTL       int       `json:"ttl"`
	Flag      string    `json:"flag"`
	Entropy   float64   `json:"entropy"`
}

type SQLEvent struct {
	Timestamp  time.Time `json:"ts"`
	ClientIP   string    `json:"client_ip"`
	MsgType    string    `json:"msg_type"`
	SQL        string    `json:"sql"`
	Rows       int       `json:"rows"`
	DurationMs float64   `json:"duration_ms"`
	Risk       string    `json:"risk"`
}

type TLSSession struct {
	Timestamp   time.Time `json:"ts"`
	ClientIP    string    `json:"client_ip"`
	SNI         string    `json:"sni"`
	Version     string    `json:"version"`
	CipherSuite string    `json:"cipher_suite"`
	JA3         string    `json:"ja3"`
	Risk        string    `json:"risk"`
	KnownBad    bool      `json:"known_bad"`
}

type GRPCEvent struct {
	Timestamp  time.Time `json:"ts"`
	ClientIP   string    `json:"client_ip"`
	Service    string    `json:"service"`
	Method     string    `json:"method"`
	Status     string    `json:"status"`
	DurationMs float64   `json:"duration_ms"`
}
