// Command osai-probe actively sweeps a host's AI/ML service ports and fetches the
// enumerative endpoint for each known service (models, experiments, collections,
// flows, version/settings). It is the Linux analog of the aiSvcProbe BOF, but
// uses a real net/http client so it can parse a little JSON and print the
// interesting fields rather than just the first 300 bytes.
//
// Usage:
//   osai-probe                 # sweep 127.0.0.1
//   osai-probe 10.80.219.45    # sweep a remote host (reachable via ligolo route)
//   osai-probe 127.0.0.1 -t 1  # 1s per-probe timeout
//
// Zero child processes. Single static Go binary. No curl/nmap.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var banner = strings.Repeat("=", 40)

// probe describes one service: port, label, and an HTTP path (empty => raw TCP).
// path == ""      -> raw TCP connect (+ handshake for known binary protocols)
// path != ""      -> HTTP(S) GET; body is scanned for the JSON keys in jsonKeys
type probe struct {
	port     int
	svc      string
	path     string
	tls      bool // use https
	jsonKeys []string
}

var probes = []probe{
	{11434, "ollama", "/api/tags", false, []string{"name", "model"}},
	{11434, "ollama", "/api/version", false, []string{"version"}},
	{5000, "mlflow", "/api/2.0/mlflow/experiments/search", false, nil},
	{5001, "mlflow/registry", "/api/2.0/mlflow/registered-models/search", false, nil},
	{5005, "mlflow-registry-svc", "/api/2.0/mlflow/registered-models/search", false, nil},
	{7860, "gradio", "/", false, nil},
	{3000, "n8n|gitea|grafana|open-webui", "/", false, nil},
	{8000, "a2a-orch", "/.well-known/agent.json", false, []string{"name", "url", "capabilities"}},
	{8001, "a2a-agent", "/.well-known/agent.json", false, []string{"name", "url"}},
	{8002, "fastapi", "/openapi.json", false, []string{"title", "version"}},
	{8003, "fastapi", "/openapi.json", false, []string{"title", "version"}},
	{8080, "weaviate", "/v1/schema", false, nil},
	{6333, "qdrant", "/collections", false, nil},
	{16333, "qdrant-staging", "/collections", false, nil},
	{8000, "chroma", "/api/v1/collections", false, nil}, // chroma often on 8000
	{6379, "redis", "", false, nil},                     // raw TCP INFO
	{5432, "postgres", "", false, nil},                  // raw banner
	{1433, "mssql", "", false, nil},                     // raw banner
	{27017, "mongodb", "", false, nil},                  // raw banner
	{9200, "elasticsearch", "/", false, []string{"version", "cluster_name"}},
	{9000, "minio|milvus", "/", false, nil},
	{9090, "prometheus", "/api/v1/status/buildinfo", false, []string{"version"}},
	{8888, "jupyter", "/api/status", false, nil},
	{6006, "tensorboard", "/", false, nil},
	{5672, "rabbitmq-amqp", "", false, nil},
	{15672, "rabbitmq-mgmt", "/api/overview", false, []string{"rabbitmq_version", "cluster_name"}},
	{8501, "tf-serving", "/v1/models", false, nil},
	{8081, "langflow", "/api/v1/flows", false, nil},
	{8500, "langflow-alt", "/api/v1/flows", false, nil},
	{22, "ssh", "", false, nil}, // banner
	{80, "http", "/api/health", false, nil},
	{443, "https", "/api/health", true, nil},
}

type result struct {
	pr   probe
	open bool
	body string
	raw  string // first-line banner for raw-TCP services
}

func main() {
	to := flag.Duration("t", 2*time.Second, "per-probe timeout")
	flag.Parse()
	host := "127.0.0.1"
	args := flag.Args()
	if len(args) > 0 && args[0] != "" {
		host = args[0]
	}

	fmt.Printf("\n%s\n          OSAI AI/ML Service Probe (osai-probe)\n%s\n", banner, banner)
	fmt.Printf("[*] host=%s timeout=%s  (%d probes)\n\n", host, to, len(probes))

	client := &http.Client{
		Timeout: *to,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional for recon
			DisableKeepAlives: true,
		},
	}

	hits := 0
	for _, pr := range probes {
		r := probeOne(host, pr, *to, client)
		if r.open {
			hits++
			printResult(r)
		}
	}
	fmt.Printf("\n[*] done, %d/%d open on %s\n", hits, len(probes), host)
	if hits == 0 {
		os.Exit(1)
	}
}

func probeOne(host string, pr probe, to time.Duration, client *http.Client) result {
	r := result{pr: pr}
	addr := fmt.Sprintf("%s:%d", host, pr.port)
	conn, err := net.DialTimeout("tcp", addr, to)
	if err != nil {
		return r
	}
	r.open = true

	if pr.path == "" {
		// raw TCP — grab a banner / fire a protocol handshake
		_ = conn.SetReadDeadline(time.Now().Add(to))
		switch pr.svc {
		case "redis":
			_, _ = conn.Write([]byte("INFO\r\n"))
		case "ssh":
			// SSH banner is sent by the server immediately, no write needed.
		default:
			// postgres/mssql/mongodb/milvus/minio/rabbitmq-amqp — just read banner if any.
		}
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		_ = conn.Close()
		if n > 0 {
			r.raw = strings.TrimRight(string(buf[:n]), "\r\n\x00")
		}
		return r
	}

	_ = conn.Close() // HTTP path uses the client, not this conn

	scheme := "http"
	if pr.tls {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d%s", scheme, host, pr.port, pr.path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		r.body = "<bad request>"
		return r
	}
	req.Header.Set("User-Agent", "osai-probe/1.0")
	resp, err := client.Do(req)
	if err != nil {
		r.body = "<" + cleanErr(err) + ">"
		return r
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	r.body = fmt.Sprintf("HTTP %d  %s", resp.StatusCode, summarize(string(body), pr.jsonKeys))
	return r
}

func printResult(r result) {
	if r.pr.path == "" {
		banner := r.raw
		if banner == "" {
			banner = "(open, no banner)"
		}
		if len(banner) > 120 {
			banner = banner[:120] + "..."
		}
		fmt.Printf("  %-7d %-26s OPEN  %s\n", r.pr.port, r.pr.svc, banner)
		return
	}
	b := r.body
	if len(b) > 200 {
		b = b[:200] + "..."
	}
	fmt.Printf("  %-7d %-26s OPEN  %s\n", r.pr.port, r.pr.svc, b)
}

// summarize extracts the named JSON keys (first occurrence) from a body so the
// one-line output shows the interesting fields (model names, versions, counts)
// without dumping the whole response.
func summarize(body string, keys []string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return "(empty body)"
	}
	if len(keys) == 0 || !strings.HasPrefix(body, "{") && !strings.HasPrefix(body, "[") {
		// no keys requested, or not JSON — return first non-empty line
		if i := strings.IndexAny(body, "\r\n"); i > 0 {
			return body[:i]
		}
		if len(body) > 120 {
			return body[:120] + "..."
		}
		return body
	}
	// generic key extraction: find "key" : "value" or "key": value
	var out []string
	for _, k := range keys {
		needle := "\"" + k + "\""
		idx := strings.Index(body, needle)
		if idx < 0 {
			continue
		}
		rest := body[idx+len(needle):]
		rest = strings.TrimLeft(rest, " \t:")
		val := readJSONValue(rest)
		if val != "" {
			out = append(out, k+"="+val)
		}
	}
	if len(out) > 0 {
		return strings.Join(out, "  ")
	}
	// fallback: first line
	if i := strings.IndexAny(body, "\r\n"); i > 0 {
		return body[:i]
	}
	if len(body) > 120 {
		return body[:120] + "..."
	}
	return body
}

// readJSONValue reads a scalar value right after a key in minified JSON: a quoted
// string, a number, a bool, or null. For arrays/objects it returns "[...]".
func readJSONValue(s string) string {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return ""
	}
	switch s[0] {
	case '"':
		// quoted string — find closing quote (no escape handling needed for recon)
		end := strings.IndexByte(s[1:], '"')
		if end < 0 {
			return ""
		}
		return s[1 : 1+end]
	case '[':
		return "[...]"
	case '{':
		return "{...}"
	default:
		// number / bool / null — read until delimiter
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c == ',' || c == '}' || c == ']' || c == ' ' || c == '\n' || c == '\r' {
				return s[:i]
			}
		}
		return s
	}
}

func cleanErr(err error) string {
	s := err.Error()
	// strip the noisy "tcp dial: connect: " prefix stack
	for _, p := range []string{"dial tcp: connect: ", "dial tcp ", "connect: ", ": "} {
		if strings.Contains(s, p) {
			s = strings.TrimPrefix(s, p)
		}
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// keep json import even if future probes grow structured parsing
var _ = json.Marshal