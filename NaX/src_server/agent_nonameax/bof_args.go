package main

import "encoding/binary"

// BofPacker builds a packed argument buffer for BOF execution.
// Format is Cobalt Strike compatible:
//   str:   4-byte LE length + raw bytes (no null terminator)
//   wstr:  4-byte LE length + UTF-16LE bytes (no null)
//   int:   4 bytes LE
//   short: 2 bytes LE
//   bin:   4-byte LE length + raw bytes
//
// The final buffer is passed directly to go(args, size) - no leading
// total-length prefix is added (unlike Kharon). The beacon receives the
// raw packed args and size via the wire.

type BofPacker struct {
	buf []byte
}

func NewBofPacker() *BofPacker {
	return &BofPacker{}
}

func (p *BofPacker) AddStr(s string) {
	b := []byte(s)
	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, uint32(len(b)))
	p.buf = append(p.buf, ln...)
	p.buf = append(p.buf, b...)
}

func (p *BofPacker) AddWStr(s string) {
	runes := []rune(s)
	wide := make([]byte, len(runes)*2)
	for i, r := range runes {
		wide[i*2] = byte(r & 0xFF)
		wide[i*2+1] = byte((r >> 8) & 0xFF)
	}
	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, uint32(len(wide)))
	p.buf = append(p.buf, ln...)
	p.buf = append(p.buf, wide...)
}

func (p *BofPacker) AddInt(v int32) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	p.buf = append(p.buf, b...)
}

func (p *BofPacker) AddShort(v int16) {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(v))
	p.buf = append(p.buf, b...)
}

func (p *BofPacker) AddBin(data []byte) {
	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, uint32(len(data)))
	p.buf = append(p.buf, ln...)
	p.buf = append(p.buf, data...)
}

func (p *BofPacker) Bytes() []byte {
	return p.buf
}
