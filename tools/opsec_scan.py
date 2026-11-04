#!/usr/bin/env python3
"""
opsec scan — repo-wide merge gate (run via `make audit` at the repo root).

Checks (default mode = tracked files only):
  1. tracked-binary guard     — no compiled artifacts (.o/.exe/.dll/.bin/.pdb/...) in the index
  2. generated-key guard      — beacon configs / key headers stay untracked
  3. secret patterns          — PAT/slack/AWS/JWT/PEM key shapes in tracked content (+ --history)
  4. wire-IOC strings         — tool-branded strings in *our* authored code (vendored upstream
                                trees are excluded by default; see AUTHORED dirs below)
  5. artifact-name strings    — fixed temp-file prefixes / named-dump paths in our code
  6. RWX patterns             — PAGE_EXECUTE_READWRITE in our C/C++ sources
  7. COFF probes              — any *_bin/*.o present on disk is swept for (5) strings

Exit 0 only when everything passes. Exceptions live in tools/opsec_scan_exceptions.txt
as `# path-regex | needle` lines; every hit is printed with the file:line.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

AUTHORED_DIRS = [
    r"^NaX/",
    r"^Cenotaph/",
    r"^profiler/",
    r"^hostpayload_v2/",
    r"^remote_bof_loader/",
    r"^RemoteLoader/",
    r"^Extension-Kit/AI-BOF/",
    r"^Extension-Kit/Persistence-BOF/",
    r"^Extension-Kit/Capture-BOF/",
    r"^Extension-Kit/LateralMovement-BOF/pth/",
    r"^OSAI-ENUM/",
    r"^OSEP-ENUM/",
    r"^OSAI-LINUX/",
    r"^PrivescCheckExe/",
    r"^tools/",
]

BINARY_EXTENSIONS = {".o", ".exe", ".dll", ".bin", ".obj", ".pdb", ".sys",
                     ".efi", ".so", ".pyd", ".axs.bin", ".lib", ".dmp"}

GENERATED_MUST_NOT_TRACK = [
    r"^NaX/src_beacon/include/Config\.h$",
    r"^NaX/src_beacon/include/Config_sleepmask\.h$",
    r"^NaX/src_beacon/include/Config_profile\.h$",
    r"^Cenotaph/include/CenKey\.h$",
]

SECRET_PATTERNS = [
    (r"gh[pousr]_[A-Za-z0-9]{28,}", "GitHub token"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "GitHub fine-grained PAT"),
    (r"AKIA[0-9A-Z]{16}\b", "AWS access key id"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"sk-[A-Za-z0-9]{30,}", "API key (sk-)"),
    (r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}", "JWT-shaped secret"),
    (r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY", "PEM private key"),
    (r"[Aa]uthorization.*Bearer\s+[A-Za-z0-9_.-]{30,}", "hardcoded bearer token"),
]

WIRE_IOC_PATTERNS = [
    (r"X-NaX-Public", "beacon fallback header"),
    (r"NoNameAx-Public-Build", "build string"),
    (r"X-NaX-Public-Agent", "agent version string"),
    (r"/nax/", "tool-branded URI"),
    (r"nax_oss_release", "build string"),
    (r"X-Beacon-Id", "generic beacon header name"),
    (r"WindowsUpdateService", "stale fixed service name"),
    (r"\btmpBla\.tmp", "upstream coerce-path artifact"),
    (r"report\.docx", "named dump path"),
    (r"submit\.php", "public default C2 URI"),
    (r"/api/v1/status", "public default C2 URI"),
]

ARTIFACT_PATTERNS = [
    (r"C:\\Windows\\Temp\\report\.docx", "nanodump default dump path"),
    (r"NanoDumpPPLmedicPipe|NanoDumpSSPPipe", "static pipe name"),
    (r"axabe_%lu", "static pipe name (klepto)"),
    (r"bhi_%llu|pwk_", "fixed temp prefix"),
]

RWX_PATTERN = re.compile(
    r"(?i)(virtualalloc|ntallocatevirtualmemory|"
    r"virtualprotect|ntprotectvirtualmemory).*\bPAGE_EXECUTE_READWRITE\b")

# vendored upstream trees that legitimately carry their own strings/authors
VENDORED_DIRS = [
    r"^Extension-Kit/(AD-BOF|Creds-BOF|Elevation-BOF|Execution-BOF|Injection-BOF|"
    r"LateralMovement-BOF|Postex-BOF|Process-BOF|SAL-BOF|SAR-BOF)",
    r"^C2-Tool-Collection/",
    r"^CS-Remote-OPs-BOF/",
    r"^Extension-Kit/AD-BOF/(ADCS-BOF|Kerbeus-BOF|LDAP-BOF|DCSync-BOF|SQL-BOF|RelayInformer)",
    r"^redteaming/ai-pentesting/",
    r"^ai-pentesting/",
]


def is_vendored(path: str) -> bool:
    return any(re.match(p, path) for p in VENDORED_DIRS)


def is_authored(path: str) -> bool:
    return any(re.match(p, path) for p in AUTHORED_DIRS)


def load_exceptions(path: Path):
    rules = []
    if not path.exists():
        return rules
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if "|" in line:
            pr, needle = line.rsplit("|", 1)   # regex column may contain '|'
            needle = needle.strip()
            if not needle:
                continue
            rules.append((pr.strip(), needle))
    return rules


def excepted(path: str, needle: str, rules) -> bool:
    for pr, nd in rules:
        if re.search(pr, path) and (nd == "*" or nd == needle):
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--history", action="store_true",
                    help="also sweep full git history for secret patterns (slow)")
    ap.add_argument("--exceptions", type=Path,
                    default=Path(__file__).parent / "opsec_scan_exceptions.txt")
    args = ap.parse_args()

    rules = load_exceptions(args.exceptions)
    findings = []

    git = subprocess.run(
        ["git", "-C", str(REPO), "ls-files"],
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()

    # ---- 1. tracked binaries ----
    for f in git:
        if Path(f).suffix.lower() in BINARY_EXTENSIONS:
            if not excepted(f, "tracked-binary", rules):
                findings.append((f, 0, "tracked-binary", str(Path(f).suffix)))

    # ---- 2. generated configs ----
    for f in git:
        for pat in GENERATED_MUST_NOT_TRACK:
            if re.match(pat, f):
                findings.append((f, 0, "generated-key-config", pat))

    # ---- 3-6. content sweeps (tracked text files) ----
    tracked_text = [f for f in git
                    if Path(f).suffix.lower() in
                    (".c", ".h", ".cpp", ".cs", ".go", ".py", ".js", ".axs",
                     ".md", ".json", ".yaml", ".yml", ".xml", ".sh", ".cna",
                     ".csproj", ".sln", ".ld", ".asm", ".cmd", ".ps1", ".txt")]
    for f in tracked_text:
        p = REPO / f
        try:
            content = p.read_text(errors="replace")
        except OSError:
            continue
        lines = content.splitlines()
        vendored = is_vendored(f)
        authored = is_authored(f)

        for i, line in enumerate(lines, 1):
            for pat, label in SECRET_PATTERNS:
                if re.search(pat, line):
                    if not excepted(f, label, rules):
                        findings.append((f, i, label, line.strip()[:80]))
            if authored:
                for pat, label in WIRE_IOC_PATTERNS:
                    if re.search(re.escape(pat), line):
                        if not excepted(f, label, rules):
                            findings.append((f, i, f"wire-IOC:{label}", line.strip()[:80]))
                if vendored:
                    continue
                for pat, label in ARTIFACT_PATTERNS:
                    if re.search(pat, line):
                        if not excepted(f, label, rules):
                            findings.append((f, i, f"artifact:{label}", line.strip()[:80]))
                if Path(f).suffix.lower() in (".c", ".h", ".cpp"):
                    if RWX_PATTERN.search(line):
                        if not excepted(f, "RWX-flag", rules):
                            findings.append((f, i, "RWX-flag", line.strip()[:80]))

    # ---- 7. COFF probes on disk ----
    for bin_dir in REPO.rglob("_bin"):
        for coff in bin_dir.glob("*.o"):
            blob = coff.read_bytes()
            text = blob.decode("latin-1", errors="replace")
            for pat, label in WIRE_IOC_PATTERNS:
                if pat in text:
                    if not excepted(str(coff), label, rules):
                        findings.append((str(coff), 0, f"coff:{label}", pat))
            for m in re.finditer(r"[A-Za-z0-9_./\\]{4,}", text):
                tok = m.group(0)
                for pat, label in ARTIFACT_PATTERNS:
                    if re.search(pat, tok) and tok == m.group(0):

                        if not excepted(str(coff), label, rules):
                            findings.append((str(coff), 0, f"coff:{label}", tok[:80]))

    # ---- optional: history secret sweep ----
    if args.history:
        hist = subprocess.run(
            ["git", "-C", str(REPO), "log", "--all", "-p"],
            capture_output=True, check=True,
        ).stdout.decode("utf-8", errors="replace")
        for pat, label in SECRET_PATTERNS:
            for m in re.finditer(pat, hist):
                findings.append(("(git history)", 0, f"history:{label}", m.group(0)[:80]))

    if findings:
        print(f"[-] opsec scan: {len(findings)} finding(s)")
        for f, i, kind, detail in findings:
            print(f"  {f}:{i}  {kind}: {detail}")
        return 1

    print("[+] opsec scan: clean "
          f"({len(tracked_text)} text files, {len(git)} tracked, "
          f"authored={len([f for f in git if is_authored(f)])})")
    return 0


if __name__ == "__main__":
    sys.exit(main())