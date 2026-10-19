package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

/*
Crypt conventions pinned by tests:

  1. TestChaChaPinnedVector   - ChaCha20 stream pinned to a pycryptodome /
     RFC 7539 IETF vector (generated 2026-10-17, 130-byte plaintext crossing
     3 keystream blocks) - proves counter starts at 0 and the layout matches.
  2. TestEncryptDecryptRoundtrip - EncryptShellcode output decrypts back.
  3. TestShellEncShape - OBF byte nonzero, key material randomized per call.
*/

func TestChaChaPinnedVector(t *testing.T) {
	var key [32]byte
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	var nonce [12]byte
	for i := 0; i < 12; i++ {
		nonce[i] = byte(0x10 + i)
	}
	pt := make([]byte, 130)
	for i := range pt {
		pt[i] = byte(i)
	}
	ct := append([]byte(nil), pt...)
	chachaXOR(&key, &nonce, ct)

	// pycryptodome ChaCha20.new(key=00..1f, nonce=10..1b).encrypt(range(130))
	want := "0xe0, 0x2c, 0x35, 0x81, 0xde, 0xa3, 0x46, 0x4c, 0xfa, 0x53, 0x86, 0x1d"
	var buf strings.Builder
	for i, b := range ct {
		if i >= 12 {
			break
		}
		fmt.Fprintf(&buf, "0x%02x, ", b)
	}
	if !strings.HasPrefix(want, strings.TrimSuffix(buf.String(), ", ")) {
		t.Fatalf("chacha stream mismatch: got %x", ct[:12])
	}
	if ct[12] != 0x38 || ct[13] != 0x95 || ct[64] != 0x1e || ct[129] != 0xc4 {
		t.Fatalf("chacha stream mismatch beyond first block: got %x", ct)
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	blob := bytes.Repeat([]byte("NAX-ROUNDTRIP-TEST-"), 40) // 760 bytes
	orig := append([]byte(nil), blob...)

	enc, err := EncryptShellcode(blob)
	if err != nil {
		t.Fatalf("EncryptShellcode: %v", err)
	}

	// decrypt with the deobfuscated key
	var key [32]byte
	for i := range key {
		key[i] = enc.KeyObf[i] ^ enc.OBFByte
	}
	if enc.OBFByte == 0 {
		t.Fatal("obf byte zero")
	}

	// MAC is over the CIPHERTEXT - keep a copy before decrypting in place
	ctCopy := append([]byte(nil), blob...)
	chachaXOR(&key, &enc.Nonce, enc.Data)
	if !bytes.Equal(enc.Data, orig) {
		t.Fatal("decrypt does not reproduce plaintext")
	}

	mac := hmac.New(sha256.New, key[:])
	mac.Write(ctCopy)
	if !hmac.Equal(mac.Sum(nil), enc.MAC[:]) {
		t.Fatal("MAC mismatch")
	}
}

func TestShellEncShape(t *testing.T) {
	enc1, _ := EncryptShellcode(bytes.Repeat([]byte{0x41}, 300))
	enc2, _ := EncryptShellcode(bytes.Repeat([]byte{0x41}, 300))
	if bytes.Equal(keyUnobf(enc1), keyUnobf(enc2)) {
		t.Fatal("two builds produced identical keys - randomness broken")
	}
	if bytes.Equal(enc1.Nonce[:], enc2.Nonce[:]) {
		t.Fatal("two builds produced identical nonces - randomness broken")
	}
}

func keyUnobf(e *ShellEnc) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(e.KeyObf[i] ^ e.OBFByte)
	}
	return out
}