/*
 * mininflate.c — minimal RFC1951 DEFLATE inflater (no deps).
 * Public-domain-style, compact. Used by gitMine.c to read zlib-compressed git
 * loose objects (.git/objects/??/<38hex>). Caller skips the 2-byte zlib header.
 *
 * API: int mininflate(const unsigned char* in, int inlen,
 *                     unsigned char* out, int outmax);
 *      returns output length on success, negative on error.
 */
#include "aibof.h"
#define MAXBITS 15
#define MAXLCODES 286
#define MAXDCODES 30
#define MAXCODES (MAXLCODES + MAXDCODES)
#define FIXLCODES 288

typedef struct { const unsigned char* p; int len; int pos; } br_t;
typedef struct { short count[MAXBITS+1]; short symbol[MAXCODES]; } huff_t;

static int br_bit(br_t* b) {
  if ((b->pos >> 3) >= b->len) return -1;
  int v = (b->p[b->pos >> 3] >> (b->pos & 7)) & 1;
  b->pos++; return v;
}
static int br_bits(br_t* b, int n) {
  int v = 0;
  for (int i = 0; i < n; i++) { int x = br_bit(b); if (x < 0) return -1; v |= x << i; }
  return v;
}

/* build huffman from code lengths (0 = unused). returns 0 ok, <0 err */
static int construct(huff_t* h, const short* length, int n) {
  for (int i = 0; i <= MAXBITS; i++) h->count[i] = 0;
  for (int s = 0; s < n; s++) h->count[length[s]]++;
  int left = 1;
  for (int len = 1; len <= MAXBITS; len++) { left <<= 1; left -= h->count[len]; if (left < 0) return left; }
  short offs[MAXBITS+2];
  offs[1] = 0;
  for (int len = 1; len < MAXBITS; len++) offs[len+1] = (short)(offs[len] + h->count[len]);
  for (int s = 0; s < n; s++)
    if (length[s]) h->symbol[offs[length[s]]++] = (short)s;
  return left;
}

static int decode(br_t* b, huff_t* h) {
  int code = 0, first = 0, index = 0;
  for (int len = 1; len <= MAXBITS; len++) {
    int bit = br_bit(b); if (bit < 0) return -1;
    code |= bit;
    int count = h->count[len];
    if (code - count < first) return h->symbol[index + (code - first)];
    index += count; first += count; first <<= 1; code <<= 1;
  }
  return -1;
}

/* dynamic huffman block */
static int dynamic_block(br_t* b, unsigned char* out, int opos, int outmax) {
  int nlen = br_bits(b, 5); if (nlen < 0) return -1; nlen += 257;
  int ndist = br_bits(b, 5); if (ndist < 0) return -1; ndist += 1;
  int ncode = br_bits(b, 4); if (ncode < 0) return -1; ncode += 4;
  if (nlen > MAXLCODES || ndist > MAXDCODES) return -1;

  static const short order[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
  short clen[MAXCODES]; for (int z=0;z<MAXCODES;z++) clen[z]=0;
  for (int i = 0; i < ncode; i++) { int v = br_bits(b, 3); if (v < 0) return -1; clen[order[i]] = (short)v; }
  huff_t ch; if (construct(&ch, clen, 19) < 0) return -1;

  short lencodes[MAXCODES]; for (int z=0;z<MAXCODES;z++) lencodes[z]=0;
  int idx = 0;
  while (idx < nlen + ndist) {
    int sym = decode(b, &ch); if (sym < 0) return -1;
    if (sym < 16) { lencodes[idx++] = (short)sym; }
    else if (sym == 16) { int rep = br_bits(b, 2); if (rep < 0) return -1; rep += 3;
      if (idx == 0) return -1; short prev = lencodes[idx-1];
      while (rep--) { if (idx >= MAXCODES) return -1; lencodes[idx++] = prev; } }
    else if (sym == 17) { int rep = br_bits(b, 3); if (rep < 0) return -1; rep += 3;
      while (rep--) { if (idx >= MAXCODES) return -1; lencodes[idx++] = 0; } }
    else { int rep = br_bits(b, 7); if (rep < 0) return -1; rep += 11;
      while (rep--) { if (idx >= MAXCODES) return -1; lencodes[idx++] = 0; } }
  }
  huff_t lh; if (construct(&lh, lencodes, nlen) < 0) return -1;
  huff_t dh; if (construct(&dh, lencodes + nlen, ndist) < 0) return -1;

  static const short lenbase[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
  static const short lenextra[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
  static const short distbase[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
  static const short distextra[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};

  for (;;) {
    int sym = decode(b, &lh); if (sym < 0) return -1;
    if (sym == 256) return opos; /* end of block */
    if (sym < 256) { if (opos >= outmax) return -1; out[opos++] = (unsigned char)sym; continue; }
    sym -= 257; if (sym >= 29) return -1;
    int x = br_bits(b, lenextra[sym]); if (x < 0) return -1;
    int len = lenbase[sym] + x;
    int dsym = decode(b, &dh); if (dsym < 0 || dsym >= 30) return -1;
    int dx = br_bits(b, distextra[dsym]); if (dx < 0) return -1;
    int dist = distbase[dsym] + dx;
    if (dist > opos) return -1;
    if (opos + len > outmax) return -1;
    int from = opos - dist;
    for (int k = 0; k < len; k++) out[opos++] = out[from++];
  }
}

static int stored_block(br_t* b, unsigned char* out, int opos, int outmax) {
  b->pos = (b->pos + 7) & ~7; /* align */
  int blen = br_bits(b, 16); if (blen < 0) return -1;
  int nlen = br_bits(b, 16); if (nlen < 0) return -1;
  if ((blen ^ 0xffff) != nlen) return -1;
  if (opos + blen > outmax) return -1;
  /* byte-aligned read of blen bytes (stream is byte-aligned after LEN/NLEN) */
  int bytepos = b->pos >> 3;
  if (bytepos + blen > b->len) return -1;
  for (int i = 0; i < blen; i++) out[opos++] = b->p[bytepos + i];
  b->pos = (bytepos + blen) << 3;
  return opos;
}

static int fixed_block(br_t* b, unsigned char* out, int opos, int outmax) {
  short lens[288];
  for (int i = 0; i < 144; i++) lens[i] = 8;
  for (int i = 144; i < 256; i++) lens[i] = 9;
  for (int i = 256; i < 280; i++) lens[i] = 7;
  for (int i = 280; i < 288; i++) lens[i] = 8;
  short dlens[30]; for (int i = 0; i < 30; i++) dlens[i] = 5;
  huff_t lh; construct(&lh, lens, 288);
  huff_t dh; construct(&dh, dlens, 30);
  static const short lenbase[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
  static const short lenextra[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
  static const short distbase[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
  static const short distextra[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
  for (;;) {
    int sym = decode(b, &lh); if (sym < 0) return -1;
    if (sym == 256) return opos;
    if (sym < 256) { if (opos >= outmax) return -1; out[opos++] = (unsigned char)sym; continue; }
    sym -= 257; if (sym >= 29) return -1;
    int x = br_bits(b, lenextra[sym]); if (x < 0) return -1;
    int len = lenbase[sym] + x;
    int dsym = decode(b, &dh); if (dsym < 0 || dsym >= 30) return -1;
    int dx = br_bits(b, distextra[dsym]); if (dx < 0) return -1;
    int dist = distbase[dsym] + dx;
    if (dist > opos) return -1;
    if (opos + len > outmax) return -1;
    int from = opos - dist;
    for (int k = 0; k < len; k++) out[opos++] = out[from++];
  }
}

int mininflate(const unsigned char* in, int inlen, unsigned char* out, int outmax) {
  br_t b; b.p = in; b.len = inlen; b.pos = 0;
  int opos = 0;
  int final;
  do {
    final = br_bit(&b); if (final < 0) return -1;
    int type = br_bits(&b, 2); if (type < 0) return -1;
    if (type == 0) { opos = stored_block(&b, out, opos, outmax); if (opos < 0) return -1; }
    else if (type == 1) { opos = fixed_block(&b, out, opos, outmax); if (opos < 0) return -1; }
    else if (type == 2) { opos = dynamic_block(&b, out, opos, outmax); if (opos < 0) return -1; }
    else return -1;
  } while (!final);
  return opos;
}