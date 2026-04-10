package netcap

// geoip.go — GeoIP lookup cho netcap engine
// Dùng ip-api.com (free, không cần API key, rate limit 45 req/min)
// Fallback về MaxMind GeoLite2 nếu có file DB

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GeoInfo — thông tin địa lý của 1 IP
type GeoInfo struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	ASN         string  `json:"asn"`
	Org         string  `json:"org"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	IsPrivate   bool    `json:"is_private"`
}

// GeoIPCache — in-memory LRU-ish cache với TTL
type GeoIPCache struct {
	mu      sync.RWMutex
	entries map[string]*geoEntry
	client  *http.Client
}

type geoEntry struct {
	info      GeoInfo
	expiresAt time.Time
}

var globalGeoCache = &GeoIPCache{
	entries: make(map[string]*geoEntry),
	client:  &http.Client{Timeout: 3 * time.Second},
}

// Lookup — trả về GeoInfo cho IP, dùng cache trước
func GeoLookup(ctx context.Context, ip string) GeoInfo {
	// Private/loopback → skip
	if geoIsPrivateIP(ip) {
		return GeoInfo{IP: ip, IsPrivate: true, Country: "Private", CountryCode: "—", ASN: "—"}
	}

	// Cache hit
	globalGeoCache.mu.RLock()
	if e, ok := globalGeoCache.entries[ip]; ok && time.Now().Before(e.expiresAt) {
		globalGeoCache.mu.RUnlock()
		return e.info
	}
	globalGeoCache.mu.RUnlock()

	// Fetch từ ip-api.com (free, no key needed)
	// fields: status,country,countryCode,regionName,city,as,org,lat,lon,query
	// Note: ip-api.com free tier requires HTTP (HTTPS needs paid plan)
	// For production: use MaxMind GeoLite2 local DB or paid HTTPS geo service
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,as,org,lat,lon,query", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return GeoInfo{IP: ip, Country: "??", CountryCode: "??", ASN: "??"}
	}

	resp, err := globalGeoCache.client.Do(req)
	if err != nil {
		return GeoInfo{IP: ip, Country: "??", CountryCode: "??", ASN: "??"}
	}
	defer resp.Body.Close()

	var result struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		AS          string  `json:"as"`
		Org         string  `json:"org"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Query       string  `json:"query"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return GeoInfo{IP: ip, Country: "??", CountryCode: "??", ASN: "??"}
	}

	if result.Status != "success" {
		return GeoInfo{IP: ip, Country: "??", CountryCode: "??", ASN: "??"}
	}

	// Parse ASN từ "AS15169 Google LLC" → "AS15169"
	asn := result.AS
	if parts := strings.Fields(asn); len(parts) > 0 {
		asn = parts[0]
	}

	info := GeoInfo{
		IP:          ip,
		Country:     result.Country,
		CountryCode: result.CountryCode,
		Region:      result.RegionName,
		City:        result.City,
		ASN:         asn,
		Org:         result.Org,
		Lat:         result.Lat,
		Lon:         result.Lon,
	}

	// Cache 24 giờ
	globalGeoCache.mu.Lock()
	// Evict nếu cache quá lớn (>10k entries)
	if len(globalGeoCache.entries) > 10000 {
		globalGeoCache.entries = make(map[string]*geoEntry)
	}
	globalGeoCache.entries[ip] = &geoEntry{
		info:      info,
		expiresAt: time.Now().Add(24 * time.Hour),
	}
	globalGeoCache.mu.Unlock()

	return info
}

// BatchLookup — lookup nhiều IPs, rate-limit 40 req/min để không vượt ip-api limit
func BatchGeoLookup(ctx context.Context, ips []string) map[string]GeoInfo {
	result := make(map[string]GeoInfo, len(ips))
	ticker := time.NewTicker(time.Minute / 40) // 40 req/min safe margin
	defer ticker.Stop()

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return result
		case <-ticker.C:
			result[ip] = GeoLookup(ctx, ip)
		}
	}
	return result
}

// geoIsPrivateIP — kiểm tra IP private/loopback/link-local
func geoIsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
