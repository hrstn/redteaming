package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

/*
Shellcode-at-rest crypto for the PE wrappers (Exe/Dll/Svc templates).

Convention (must match pe_templates/Decrypt.h and hostpayload_v2/pack.py):
  - ChaCha20 RFC 7539 IETF keystream, first block counter 0
  - HMAC-SHA256 over the CIPHERTEXT only
  - key = KEY_OBF[i] ^ OBF_BYTE (XOR-obfuscated before embedding)

ChaCha20 is vendored here (~60 lines) rather than adding golang.org/x/crypto;
it is pinned to pycryptodome by TestChaChaPinnedVector in pl_shellcrypt_test.go.
*/

func chachaQuarterRound(a, b, c, d *uint32) {
	*a += *b
	*d ^= *a
	*d = (*d << 16) | (*d >> 16)
	*c += *d
	*b ^= *c
	*b = (*b << 12) | (*b >> 20)
	*a += *b
	*d ^= *a
	*d = (*d << 8) | (*d >> 24)
	*c += *d
	*b ^= *c
	*b = (*b << 7) | (*b >> 25)
}

func chachaBlock(key *[32]byte, nonce *[12]byte, counter uint32) [64]byte {
	var x [16]uint32
	var sigma = [16]byte{'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'}
	for i := 0; i < 4; i++ {
		x[i] = binary.LittleEndian.Uint32(sigma[i*4:])
	}
	for i := 0; i < 8; i++ {
		x[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	x[12] = counter
	x[13] = binary.LittleEndian.Uint32(nonce[0:])
	x[14] = binary.LittleEndian.Uint32(nonce[4:])
	x[15] = binary.LittleEndian.Uint32(nonce[8:])
	var w [16]uint32
	copy(w[:], x[:])
	for i := 0; i < 10; i++ {
		chachaQuarterRound(&w[0], &w[4], &w[8], &w[12])
		chachaQuarterRound(&w[1], &w[5], &w[9], &w[13])
		chachaQuarterRound(&w[2], &w[6], &w[10], &w[14])
		chachaQuarterRound(&w[3], &w[7], &w[11], &w[15])
		chachaQuarterRound(&w[0], &w[5], &w[10], &w[15])
		chachaQuarterRound(&w[1], &w[6], &w[11], &w[12])
		chachaQuarterRound(&w[2], &w[7], &w[8], &w[13])
		chachaQuarterRound(&w[3], &w[4], &w[9], &w[14])
	}
	var out [64]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], w[i]+x[i])
	}
	return out
}

func chachaXOR(key *[32]byte, nonce *[12]byte, data []byte) {
	var block [64]byte
	var counter uint32 = 0
	for i := 0; i < len(data); {
		block = chachaBlock(key, nonce, counter)
		counter++
		n := 64
		if len(data)-i < 64 {
			n = len(data) - i
		}
		for j := 0; j < n; j++ {
			data[i+j] ^= block[j]
		}
		i += n
	}
}

// ShellEnc is the encrypted-at-rest form embedded into the PE wrapper.
type ShellEnc struct {
	OBFByte byte
	KeyObf  [32]byte // key XORed with OBFByte
	Nonce   [12]byte
	MAC     [32]byte // HMAC-SHA256 over ciphertext
	Data    []byte   // ciphertext (modifies the input slice)
}

// EncryptShellcode encrypts blob in place with a fresh random key and returns
// the embed form. Always generates per-build randomness; never reuse across builds.
func EncryptShellcode(blob []byte) (*ShellEnc, error) {
	var key [32]byte
	var nonce [12]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	keyObf := key
	buf := make([]byte, 1)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	obf := buf[0]
	if obf == 0 {
		obf = 1
	}
	for i := range keyObf {
		keyObf[i] ^= obf
	}

	chachaXOR(&key, &nonce, blob)
	mac := hmac.New(sha256.New, key[:])
	mac.Write(blob)

	e := &ShellEnc{
		OBFByte: obf,
		Nonce:   nonce,
		Data:    blob,
	}
	copy(e.KeyObf[:], keyObf[:])
	copy(e.MAC[:], mac.Sum(nil))
	return e, nil
}