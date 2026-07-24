package main

import (
	"testing"

	adaptix "github.com/Adaptix-Framework/axc2"
)

func TestInitPluginReturnsNonNilAgent(t *testing.T) {
	got := InitPlugin(stubTeamserver{}, "/tmp/nonameax-test", "no4a4178")
	if got == nil {
		t.Fatal("InitPlugin returned nil")
	}
}

// stubTeamserver satisfies the host interface for tests. We only need it to be
// type-assertable; no methods are called by the stubs.
type stubTeamserver struct{}

// --- Phase 2a: CreateAgent tests ---

func TestCreateAgentPopulatesFromRegisterFrame(t *testing.T) {
	body := []byte{}
	body = append(body, 0x04, 0x00)
	body = append(body, []byte("HOST")...)
	body = append(body, 0x05, 0x00)
	body = append(body, []byte("alice")...)
	body = append(body, 0x01)
	body = append(body, 0x39, 0x05, 0x00, 0x00) // pid = 1337
	body = append(body, 0xe8, 0x03, 0x00, 0x00) // sleep_ms = 1000

	frame := EncodeFrame(WireTypeRegister, body)

	testKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	encrypted, err := EncryptCBCRandomIV(testKey, frame)
	if err != nil {
		t.Fatalf("EncryptCBC: %v", err)
	}

	const fakeBeaconID = "deadbeef12345678"
	beat := append([]byte(fakeBeaconID), testKey...)
	beat = append(beat, encrypted...)

	p := &PluginAgent{}
	ad, ext, err := p.CreateAgent(beat)
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if ext == nil {
		t.Error("ExtenderAgent must not be nil")
	}
	if ad.Id != fakeBeaconID {
		t.Errorf("Id: got %q, want %q", ad.Id, fakeBeaconID)
	}
	if ad.Computer != "HOST" {
		t.Errorf("Computer: got %q, want HOST", ad.Computer)
	}
	if ad.Username != "alice" {
		t.Errorf("Username: got %q, want alice", ad.Username)
	}
	if ad.Pid != "1337" {
		t.Errorf("Pid: got %q, want 1337", ad.Pid)
	}
	if ad.Arch != "x64" {
		t.Errorf("Arch: got %q, want x64", ad.Arch)
	}
	if ad.Sleep != 1 {
		// sleep_ms = 1000 → Sleep in seconds = 1
		t.Errorf("Sleep: got %d, want 1", ad.Sleep)
	}
}

func TestCreateAgentAcceptsHeartbeatAsReregister(t *testing.T) {
	frame := EncodeFrame(WireTypeHeartbeat, nil)

	testKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	encrypted, _ := EncryptCBCRandomIV(testKey, frame)

	beat := append([]byte("deadbeef12345678"), testKey...)
	beat = append(beat, encrypted...)
	p := &PluginAgent{}
	ad, ext, err := p.CreateAgent(beat)
	if err != nil {
		t.Errorf("HEARTBEAT re-register must not return error, got: %v", err)
	}
	if ad.Id != "deadbeef12345678" {
		t.Errorf("Id: got %q, want deadbeef12345678", ad.Id)
	}
	if ext == nil {
		t.Error("ExtenderAgent must not be nil")
	}
}

// --- Phase 2a: ProcessData + identity crypto tests ---

func TestProcessDataAcceptsHeartbeat(t *testing.T) {
	frame := EncodeFrame(WireTypeHeartbeat, nil)
	ext := &ExtenderAgent{}
	if err := ext.ProcessData(adaptix.AgentData{}, frame); err != nil {
		t.Errorf("HEARTBEAT should not error: %v", err)
	}
}

func TestProcessDataIgnoresDuplicateRegister(t *testing.T) {
	frame := EncodeFrame(WireTypeRegister, []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0})
	ext := &ExtenderAgent{}
	if err := ext.ProcessData(adaptix.AgentData{}, frame); err != nil {
		t.Errorf("duplicate REGISTER should be ignored, not errored: %v", err)
	}
}

func TestProcessDataAcceptsResultStub(t *testing.T) {
	frame := EncodeFrame(WireTypeResult, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	ext := &ExtenderAgent{}
	if err := ext.ProcessData(adaptix.AgentData{}, frame); err != nil {
		t.Errorf("RESULT is a no-op in Phase 2 (Phase 3 implements); got error: %v", err)
	}
}

func TestProcessDataRejectsUnknownType(t *testing.T) {
	// 0x55 is in the reserved range and not used by v0
	frame := EncodeFrame(0x55, nil)
	ext := &ExtenderAgent{}
	if err := ext.ProcessData(adaptix.AgentData{}, frame); err == nil {
		t.Error("expected error for unknown message type")
	}
}

func TestProcessDataRejectsCorruptFrame(t *testing.T) {
	ext := &ExtenderAgent{}
	if err := ext.ProcessData(adaptix.AgentData{}, []byte{0x02, 0x00}); err == nil {
		t.Error("expected error for under-4-byte frame")
	}
}

func TestExtenderEncryptIsIdentity(t *testing.T) {
	ext := &ExtenderAgent{}
	data := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	got, err := ext.Encrypt(data, []byte("ignored-key"))
	if err != nil {
		t.Fatalf("Encrypt should not error: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("Encrypt must be identity (listener owns AES): got %x, want %x", got, data)
	}
}

func TestExtenderDecryptIsIdentity(t *testing.T) {
	ext := &ExtenderAgent{}
	data := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	got, err := ext.Decrypt(data, []byte("ignored-key"))
	if err != nil {
		t.Fatalf("Decrypt should not error: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("Decrypt must be identity (listener owns AES): got %x, want %x", got, data)
	}
}
