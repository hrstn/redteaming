package main

import (
	"bytes"
	"os"
	"testing"
)

/*
Integration test: the wrapped exe embeds the beacon ENCRYPTED (W0.3).

Requires mingw (x86_64-w64-mingw32-g++) on PATH; skipped with -short.
*/

func TestWrapperEncryptBuild(t *testing.T) {
	setModuleDirForTest(t)
	if testing.Short() {
		t.Skip("short")
	}
	if _, err := os.Stat("../../build/nax.x64.debug.bin"); err != nil {
		t.Skip("no built beacon; run make -C NaX debug")
	}
	pic, err := os.ReadFile("../../build/nax.x64.debug.bin")
	if err != nil {
		t.Fatal(err)
	}

	pe, name, err := compileWrapper(append([]byte(nil), pic...), "exe", "", "", false, nil)
	if err != nil {
		t.Fatalf("compileWrapper: %v", err)
	}
	if name != "nax.x64.exe" || len(pe) < len(pic) {
		t.Fatalf("unexpected wrapper output: %s (%d bytes, beacon %d)", name, len(pe), len(pic))
	}

	// no plaintext beacon in the wrapper: sample 16-byte chunks across the
	// beacon body and confirm none survive in the built PE
	chunks := 16
	for c := 0; c < chunks; c++ {
		off := (len(pic) / chunks) * c
		probe := pic[off : off+16]
		if bytes.Contains(pe, probe) {
			t.Fatalf("plaintext beacon leaked into wrapper at beacon offset %d", off)
		}
	}

	// generated Shellcode.h must carry KEY_OBF/NONCE/MAC + ciphertext-only Data
	scH, err := generateShellcodeH(append([]byte(nil), pic...))
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"KEY_OBF", "NONCE", "MAC", "OBF_BYTE ="} {
		if !bytes.Contains(scH, []byte(want)) {
			t.Fatalf("Shellcode.h missing %s", want)
		}
	}
}

func TestWrapperAllFormatsCompile(t *testing.T) {
	setModuleDirForTest(t)
	if testing.Short() {
		t.Skip("short")
	}
	if _, err := os.Stat("../../build/nax.x64.debug.bin"); err != nil {
		t.Skip("no built beacon; run make -C NaX debug")
	}
	pic, err := os.ReadFile("../../build/nax.x64.debug.bin")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []struct{ fmt, svc, exp string }{
		{"exe", "", "nax.x64.exe"},
		{"dll", "", "nax.x64.dll"},
		{"svc", "TestSvc", "nax.x64.svc.exe"},
	} {
		_, name, err := compileWrapper(append([]byte(nil), pic...), w.fmt, w.svc, "", false, nil)
		if err != nil {
			t.Fatalf("%s wrapper: %v", w.fmt, err)
		}
		if name != w.exp {
			t.Fatalf("%s: got %s want %s", w.fmt, name, w.exp)
		}
	}
}

func setModuleDirForTest(t *testing.T) {
	t.Helper()
	prev := ModuleDir
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	ModuleDir = wd
	t.Cleanup(func() { ModuleDir = prev })
}
