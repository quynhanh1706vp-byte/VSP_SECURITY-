// cmd/cosign-api/main.go
//
// VSP Cosign / Supply-Chain microservice
// ──────────────────────────────────────────────────────────────────────────
// Mirrors the design of cmd/trivy-api/main.go:
//   - stdlib only (no external deps)
//   - single global mutex serialises every cosign invocation
//     (cosign keyring / OCI registry token cache races otherwise)
//   - CORS enabled for :8080 → :8091 cross-origin calls
//   - password is read ONCE from /etc/vsp/cosign.pass at startup
//     (file must be 0640 or stricter (no other perms), owned by service user)
//   - all results persisted to /var/lib/vsp/sigs.json so signatures
//     survive restarts
//
// Endpoints
//
//	POST /sign                    → cosign sign --key cosign.key {image}
//	POST /verify                  → cosign verify --key cosign.pub {image}
//	GET  /signatures              → list every signature this service has produced
//	GET  /signatures/{id}         → single record
//	POST /attest                  → SLSA / in-toto provenance attestation
//	GET  /attestations/{image}    → cosign download attestation
//	POST /sbom/diff               → diff two CycloneDX/SPDX JSON SBOMs
//	GET  /healthz                 → liveness
//
// Build:  go build -o vsp-cosign-api ./cmd/cosign-api
// Run:    ./vsp-cosign-api -addr :8091 -keydir /etc/vsp -store /var/lib/vsp
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── flags ────────────────────────────────────────────────────────────────

var (
	addr      = flag.String("addr", ":8091", "listen address")
	keyDir    = flag.String("keydir", "/etc/vsp", "directory containing cosign.key, cosign.pub, cosign.pass")
	storeDir  = flag.String("store", "/var/lib/vsp", "directory for sigs.json + attestations cache")
	cosignBin = flag.String("cosign", "cosign", "cosign binary path")
	scanTO    = flag.Duration("timeout", 90*time.Second, "per-call cosign timeout")
)

// ─── globals ──────────────────────────────────────────────────────────────

var (
	signMutex sync.Mutex // serialises every cosign exec.Cmd
	storeMu   sync.RWMutex
	store     = map[string]Signature{} // id → record
	password  string                   // loaded from cosign.pass at boot
	keyPath   string
	pubPath   string
	storePath         string
	signingConfigPath string
)

// ─── types ────────────────────────────────────────────────────────────────

type Signature struct {
	ID     string `json:"id"`
	Image  string `json:"image"`
	Digest string `json:"digest,omitempty"`
	// Status taxonomy — these have distinct security implications and
	// must NOT be conflated. Pre-Sprint-7, every verify failure was
	// labelled "tampered" which was alarming + wrong.
	//
	//   signed       sign call succeeded — local artefact written
	//   verified     verify call succeeded — sig matches the configured key
	//   tampered     verify ran, signature exists, but DOES NOT match key
	//                (this is the actual security incident — escalate)
	//   unsigned     image has no signature attached at the registry
	//                (not necessarily a problem in dev / public images)
	//   not_found    image / registry unreachable (network problem)
	//   unavailable  cosign binary missing or unrunnable (ops problem)
	//   failed       sign-side failure (write / push to registry)
	Status    string    `json:"status"`
	Bundle    string    `json:"bundle,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Predicate string    `json:"predicate,omitempty"` // for attestations: slsaprovenance | spdx | cyclonedx
	Output    string    `json:"output,omitempty"`    // raw cosign stdout/stderr (truncated)
}

// classifyVerifyFailure inspects cosign's combined output and returns the
// most specific status that fits. Order matters — we prefer "unavailable"
// over "not_found" so an ops problem isn't mis-tagged as a registry one.
func classifyVerifyFailure(combined string, runErr error) (status, reason string) {
	out := strings.ToLower(combined)
	switch {
	case runErr == nil:
		return "verified", ""
	case strings.Contains(out, "executable file not found") ||
		strings.Contains(out, "no such file or directory") ||
		strings.Contains(out, "permission denied"):
		return "unavailable", "cosign binary not runnable"
	case strings.Contains(out, "no signatures found") ||
		strings.Contains(out, "no matching signatures"):
		return "unsigned", "registry has no signature for this image"
	case strings.Contains(out, "manifest unknown") ||
		strings.Contains(out, "manifest_unknown") ||
		strings.Contains(out, "name unknown") ||
		strings.Contains(out, "name_unknown") ||
		strings.Contains(out, "no such host") ||
		strings.Contains(out, "connection refused") ||
		strings.Contains(out, "dial tcp") ||
		strings.Contains(out, "404"):
		return "not_found", "image or registry unreachable"
	case strings.Contains(out, "signature verification failed") ||
		strings.Contains(out, "invalid signature") ||
		strings.Contains(out, "could not verify signature"):
		// THIS is the real security event — signature exists but does
		// not match the configured key.
		return "tampered", "signature does not match configured public key"
	}
	// Fallback: cosign returned non-zero but we can't classify. Tag as
	// "failed" rather than "tampered" — refusing to cry wolf.
	if runErr != nil {
		return "failed", runErr.Error()
	}
	return "failed", ""
}

type signReq struct {
	Image     string `json:"image"`
	Predicate string `json:"predicate,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
}

type errEnvelope struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

type sbomComp struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl,omitempty"`
}

type sbomDiffReq struct {
	A json.RawMessage `json:"a"`
	B json.RawMessage `json:"b"`
}

type sbomDiffResp struct {
	Added     []sbomComp `json:"added"`
	Removed   []sbomComp `json:"removed"`
	Persisted []sbomComp `json:"persisted"`
	Stats     struct {
		ASize    int `json:"a_size"`
		BSize    int `json:"b_size"`
		AddedN   int `json:"added"`
		RemovedN int `json:"removed"`
		PersistN int `json:"persisted"`
		ChurnPct int `json:"churn_pct"`
	} `json:"stats"`
}

// ─── helpers ──────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, code int, msg string, detail error) {
	d := ""
	if detail != nil {
		d = detail.Error()
	}
	writeJSON(w, code, errEnvelope{Error: msg, Detail: d})
}

func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func newID(prefix string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())))
	return prefix + "-" + hex.EncodeToString(h[:6])
}

// truncate cosign output so JSON payload doesn't blow up
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(truncated)"
}

// ─── store persistence ────────────────────────────────────────────────────

func loadStore() {
	b, err := os.ReadFile(storePath)
	if err != nil {
		return // first boot
	}
	var arr []Signature
	if err := json.Unmarshal(b, &arr); err != nil {
		log.Printf("[store] corrupt %s: %v — starting fresh", storePath, err)
		return
	}
	storeMu.Lock()
	for _, s := range arr {
		store[s.ID] = s
	}
	storeMu.Unlock()
	log.Printf("[store] loaded %d signatures from %s", len(arr), storePath)
}

func persistStore() {
	storeMu.RLock()
	arr := make([]Signature, 0, len(store))
	for _, s := range store {
		arr = append(arr, s)
	}
	storeMu.RUnlock()
	sort.Slice(arr, func(i, j int) bool { return arr[i].CreatedAt.After(arr[j].CreatedAt) })
	b, _ := json.MarshalIndent(arr, "", "  ")
	tmp := storePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("[store] write %s: %v", tmp, err)
		return
	}
	_ = os.Rename(tmp, storePath)
}

func saveSig(s Signature) {
	storeMu.Lock()
	store[s.ID] = s
	storeMu.Unlock()
	go persistStore()
}

// ─── cosign exec wrapper ──────────────────────────────────────────────────

func runCosign(ctx context.Context, args ...string) (string, string, error) {
	signMutex.Lock()
	defer signMutex.Unlock()

	cctx, cancel := context.WithTimeout(ctx, *scanTO)
	defer cancel()

	// #nosec G702 -- exec.CommandContext passes args via argv (no shell), so
	// special characters in user-provided image names are literal arguments
	// to cosign, not shell metacharacters.
	cmd := exec.CommandContext(cctx, *cosignBin, args...)
	cmd.Env = append(os.Environ(),
		"COSIGN_PASSWORD="+password,
		"COSIGN_YES=true", // auto-confirm transparency log upload
	)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("%s %s: %w (%s)",
			*cosignBin, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), stderr.String(), nil
}

// ─── handlers ─────────────────────────────────────────────────────────────

func handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", nil)
		return
	}
	var req signReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json", err)
		return
	}
	if req.Image = strings.TrimSpace(req.Image); req.Image == "" {
		writeErr(w, 400, "image required", nil)
		return
	}

	sig := Signature{
		ID:        newID("sig"),
		Image:     req.Image,
		CreatedAt: time.Now().UTC(),
	}

	args := []string{"sign", "--key", keyPath, "--signing-config", signingConfigPath}
	if req.Recursive {
		args = append(args, "--recursive")
	}
	args = append(args, req.Image)

	stdout, stderr, err := runCosign(r.Context(), args...)
	sig.Output = clip(stdout+"\n"+stderr, 4096)
	if err != nil {
		sig.Status = "failed"
		sig.Reason = err.Error()
		saveSig(sig)
		writeJSON(w, 500, sig)
		return
	}
	sig.Status = "signed"
	// best-effort digest pull
	if d := extractDigest(stderr); d != "" {
		sig.Digest = d
	}
	saveSig(sig)
	writeJSON(w, 200, sig)
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", nil)
		return
	}
	var req signReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json", err)
		return
	}
	if req.Image = strings.TrimSpace(req.Image); req.Image == "" {
		writeErr(w, 400, "image required", nil)
		return
	}
	sig := Signature{
		ID:        newID("ver"),
		Image:     req.Image,
		CreatedAt: time.Now().UTC(),
	}
	args := []string{"verify", "--key", pubPath,
		"--insecure-ignore-tlog=true", req.Image}

	stdout, stderr, err := runCosign(r.Context(), args...)
	sig.Output = clip(stdout+"\n"+stderr, 4096)
	sig.Status, sig.Reason = classifyVerifyFailure(stdout+"\n"+stderr, err)
	saveSig(sig)
	writeJSON(w, 200, sig) // 200 always — verification ran, status carries the result
}

func handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", nil)
		return
	}
	var req signReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json", err)
		return
	}
	if req.Image == "" {
		writeErr(w, 400, "image required", nil)
		return
	}
	predicate := req.Predicate
	if predicate == "" {
		predicate = "slsaprovenance"
	}

	// build minimal predicate file
	pred := buildPredicate(predicate, req.Image)
	predFile := filepath.Join(*storeDir, "pred-"+newID("p")+".json")
	if err := os.WriteFile(predFile, pred, 0o600); err != nil {
		writeErr(w, 500, "write predicate", err)
		return
	}
	defer os.Remove(predFile)

	sig := Signature{
		ID:        newID("att"),
		Image:     req.Image,
		Predicate: predicate,
		CreatedAt: time.Now().UTC(),
	}
	args := []string{"attest", "--key", keyPath, "--signing-config", signingConfigPath,
		"--predicate", predFile, "--type", predicate,
		"--yes", req.Image}

	stdout, stderr, err := runCosign(r.Context(), args...)
	sig.Output = clip(stdout+"\n"+stderr, 4096)
	if err != nil {
		sig.Status = "failed"
		sig.Reason = err.Error()
		saveSig(sig)
		writeJSON(w, 500, sig)
		return
	}
	sig.Status = "signed"
	saveSig(sig)
	writeJSON(w, 200, sig)
}

func handleSignaturesList(w http.ResponseWriter, r *http.Request) {
	storeMu.RLock()
	arr := make([]Signature, 0, len(store))
	for _, s := range store {
		arr = append(arr, s)
	}
	storeMu.RUnlock()
	sort.Slice(arr, func(i, j int) bool { return arr[i].CreatedAt.After(arr[j].CreatedAt) })
	writeJSON(w, 200, map[string]any{"total": len(arr), "signatures": arr})
}

func handleSignatureGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/signatures/")
	storeMu.RLock()
	s, ok := store[id]
	storeMu.RUnlock()
	if !ok {
		writeErr(w, 404, "not found", nil)
		return
	}
	writeJSON(w, 200, s)
}

func handleAttestationsGet(w http.ResponseWriter, r *http.Request) {
	image := strings.TrimPrefix(r.URL.Path, "/attestations/")
	if image == "" {
		writeErr(w, 400, "image path required", nil)
		return
	}
	stdout, stderr, err := runCosign(r.Context(),
		"download", "attestation", image)
	if err != nil {
		writeErr(w, 500, "cosign download attestation failed",
			errors.New(clip(stderr, 1024)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, stdout)
}

func handleSBOMDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", nil)
		return
	}
	var req sbomDiffReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json", err)
		return
	}
	a, errA := parseSBOM(req.A)
	b, errB := parseSBOM(req.B)
	if errA != nil || errB != nil {
		writeErr(w, 400, "unrecognised SBOM (need CycloneDX or SPDX JSON)",
			fmt.Errorf("a=%v b=%v", errA, errB))
		return
	}

	idx := func(comps []sbomComp) map[string]sbomComp {
		m := make(map[string]sbomComp, len(comps))
		for _, c := range comps {
			k := c.Name + "@" + c.Version
			m[k] = c
		}
		return m
	}
	ma, mb := idx(a), idx(b)

	resp := sbomDiffResp{Added: []sbomComp{}, Removed: []sbomComp{}, Persisted: []sbomComp{}}
	for k, c := range mb {
		if _, ok := ma[k]; ok {
			resp.Persisted = append(resp.Persisted, c)
		} else {
			resp.Added = append(resp.Added, c)
		}
	}
	for k, c := range ma {
		if _, ok := mb[k]; !ok {
			resp.Removed = append(resp.Removed, c)
		}
	}
	sortComps := func(s []sbomComp) {
		sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	}
	sortComps(resp.Added)
	sortComps(resp.Removed)
	sortComps(resp.Persisted)

	resp.Stats.ASize = len(a)
	resp.Stats.BSize = len(b)
	resp.Stats.AddedN = len(resp.Added)
	resp.Stats.RemovedN = len(resp.Removed)
	resp.Stats.PersistN = len(resp.Persisted)
	denom := len(a)
	if denom == 0 {
		denom = 1
	}
	resp.Stats.ChurnPct = (resp.Stats.AddedN + resp.Stats.RemovedN) * 100 / denom
	writeJSON(w, 200, resp)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	storeMu.RLock()
	n := len(store)
	storeMu.RUnlock()
	writeJSON(w, 200, map[string]any{
		"status":      "ok",
		"signatures":  n,
		"key":         keyPath,
		"pub":         pubPath,
		"cosign_bin":  *cosignBin,
		"server_time": time.Now().UTC(),
	})
}

// ─── parsing helpers ──────────────────────────────────────────────────────

// extractDigest scrapes the sha256:abcd… reference cosign prints to stderr.
func extractDigest(s string) string {
	i := strings.Index(s, "sha256:")
	if i < 0 {
		return ""
	}
	rest := s[i:]
	end := len(rest)
	for j, r := range rest {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == ':') {
			end = j
			break
		}
	}
	return rest[:end]
}

// parseSBOM handles CycloneDX 1.4+ and SPDX 2.3 JSON SBOMs
func parseSBOM(raw json.RawMessage) ([]sbomComp, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty sbom")
	}
	// CycloneDX
	var cdx struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Purl    string `json:"purl"`
		} `json:"components"`
		BomFormat string `json:"bomFormat"`
	}
	if err := json.Unmarshal(raw, &cdx); err == nil && (cdx.BomFormat == "CycloneDX" || len(cdx.Components) > 0) {
		out := make([]sbomComp, 0, len(cdx.Components))
		for _, c := range cdx.Components {
			if c.Name == "" {
				continue
			}
			out = append(out, sbomComp{Name: c.Name, Version: c.Version, Purl: c.Purl})
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	// SPDX
	var spdx struct {
		SPDXVersion string `json:"spdxVersion"`
		Packages    []struct {
			Name    string `json:"name"`
			Version string `json:"versionInfo"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &spdx); err == nil && (strings.HasPrefix(spdx.SPDXVersion, "SPDX-") || len(spdx.Packages) > 0) {
		out := make([]sbomComp, 0, len(spdx.Packages))
		for _, p := range spdx.Packages {
			if p.Name == "" {
				continue
			}
			out = append(out, sbomComp{Name: p.Name, Version: p.Version})
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	return nil, errors.New("unrecognised SBOM format")
}

func buildPredicate(kind, image string) []byte {
	switch kind {
	case "slsaprovenance", "slsaprovenance02":
		p := map[string]any{
			"buildType": "https://vsp.local/build/v1",
			"builder":   map[string]any{"id": "https://vsp.local/cosign-api"},
			"invocation": map[string]any{
				"configSource": map[string]any{"uri": image},
			},
			"metadata": map[string]any{
				"buildStartedOn":  time.Now().UTC().Format(time.RFC3339),
				"buildFinishedOn": time.Now().UTC().Format(time.RFC3339),
				"reproducible":    false,
			},
		}
		b, _ := json.MarshalIndent(p, "", "  ")
		return b
	default:
		// generic statement
		p := map[string]any{"image": image, "issuedAt": time.Now().UTC()}
		b, _ := json.MarshalIndent(p, "", "  ")
		return b
	}
}

// ─── boot ─────────────────────────────────────────────────────────────────

func mustLoadPassword() {
	passPath := filepath.Join(*keyDir, "cosign.pass")
	st, err := os.Stat(passPath)
	if err != nil {
		log.Fatalf("[boot] cannot stat %s: %v (create it with `echo -n <password> > %s && chmod 600 %s`)",
			passPath, err, passPath, passPath)
	}
	mode := st.Mode().Perm()
	if mode&0o007 != 0 {
		log.Fatalf("[boot] %s is mode %o — must be 0640 or stricter (no other perms) (chmod 600 %s)",
			passPath, mode, passPath)
	}
	b, err := os.ReadFile(passPath)
	if err != nil {
		log.Fatalf("[boot] read %s: %v", passPath, err)
	}
	password = strings.TrimRight(string(b), "\r\n")
	log.Printf("[boot] loaded cosign password from %s (len=%d, perm=%o)",
		passPath, len(password), mode)
}

func mustExist(p, hint string) {
	if _, err := os.Stat(p); err != nil {
		log.Fatalf("[boot] %s missing (%s): %v", p, hint, err)
	}
}

func main() {
	flag.Parse()

	keyPath = filepath.Join(*keyDir, "cosign.key")
	pubPath = filepath.Join(*keyDir, "cosign.pub")
	storePath = filepath.Join(*storeDir, "sigs.json")
	signingConfigPath = filepath.Join(*keyDir, "signing-config.json")

	mustExist(keyPath, "run `cosign generate-key-pair` and copy cosign.key here")
	mustExist(pubPath, "run `cosign generate-key-pair` and copy cosign.pub here")
	if err := os.MkdirAll(*storeDir, 0o700); err != nil {
		log.Fatalf("[boot] mkdir store: %v", err)
	}
	mustLoadPassword()
	loadStore()

	// verify cosign binary is callable
	if _, err := exec.LookPath(*cosignBin); err != nil {
		log.Fatalf("[boot] cosign not on PATH (-cosign=%s): %v", *cosignBin, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", cors(handleHealth))
	mux.HandleFunc("/sign", cors(handleSign))
	mux.HandleFunc("/verify", cors(handleVerify))
	mux.HandleFunc("/attest", cors(handleAttest))
	mux.HandleFunc("/signatures", cors(handleSignaturesList))
	mux.HandleFunc("/signatures/", cors(handleSignatureGet))
	mux.HandleFunc("/attestations/", cors(handleAttestationsGet))
	mux.HandleFunc("/sbom/diff", cors(handleSBOMDiff))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("[vsp-cosign-api] listening on %s — keydir=%s store=%s",
		*addr, *keyDir, *storeDir)
	log.Fatal(srv.ListenAndServe())
}
