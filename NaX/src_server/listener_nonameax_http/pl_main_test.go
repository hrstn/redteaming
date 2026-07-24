package main

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"strconv"
	"testing"
	"time"
)

// TestListenerCreateBindsPort verifies that Create returns successfully and
// that a subsequent Start binds the configured port. We allocate an ephemeral
// port by listening on :0, record the port, close it, then ask the listener
// under test to bind that same port (there is a small TOCTOU window, but it is
// acceptable for a unit test on loopback).
func TestListenerCreateBindsPort(t *testing.T) {
	// Allocate a free port.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not allocate test port: %v", err)
	}
	port := tmp.Addr().(*net.TCPAddr).Port
	_ = tmp.Close()

	cfg := map[string]any{
		"host_bind":    "127.0.0.1",
		"port_bind":    float64(port),
		"uri":          []any{"/api/v1/status"},
		"hb_header":    "X-Beacon-Id",
		"encrypt_key":  hex.EncodeToString(make([]byte, 16)),
		"user_agent":   []any{"Mozilla/5.0"},
		"http_method":  "POST",
		"ssl":          false,
		"page-error":   "<html><body>404</body></html>",
		"page-payload": "",
	}
	cfgJSON, _ := json.Marshal(cfg)

	pl := &PluginListener{}

	// Create signature (from SDK):
	//   Create(name, config string, customData []byte) (ExtenderListener, ListenerData, []byte, error)
	active, listenerData, _, err := pl.Create("test-listener", string(cfgJSON), nil)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	// ListenerData.Name is the listener's registered name.
	if listenerData.Name != "test-listener" {
		t.Errorf("listenerData.Name = %q; expected \"test-listener\"", listenerData.Name)
	}
	if active == nil {
		t.Fatal("Create returned nil ExtenderListener")
	}

	if err := active.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	// Give the goroutine a moment to bind.
	time.Sleep(50 * time.Millisecond)

	// Confirm something is listening on the expected port.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
	if err != nil {
		t.Fatalf("nothing listening on port %d after Start: %v", port, err)
	}
	conn.Close()

	if err := active.Stop(); err != nil {
		t.Errorf("Stop returned error: %v", err)
	}
}
