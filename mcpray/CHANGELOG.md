# Changelog

All notable changes to mcpray will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

## [1.0.0] - 2025-06-09

### Added
- Initial public release
- MCP server discovery and enumeration (active scanner)
- UNION-based SQL injection detection and enumeration (`sqli` module)
  - MySQL, SQLite, PostgreSQL, MSSQL, Oracle dialect support
  - Automatic dialect detection and caching
- Command injection testing and exploitation (`cmdinj` module, requires `--unsafe-mode`)
- SSRF detection with cloud metadata endpoint probing (`ssrf` module)
- MITM proxy for MCP traffic interception (`mitm` module)
- Context poisoning detection (`poison` module)
- Indirect prompt injection detection (`pi` module)
- MCP fuzzer for tool and resource inputs (`fuzz` module)
- Interactive REPL with prompt_toolkit autocomplete
- AI-assisted analysis (OpenAI/Ollama integration)
- Output: JSON, HTML, SARIF, Nuclei templates, standalone PoC scripts
- RFC 6570 URI template parameter support (`{param*}` explode modifier)
- sqlmap HTTP proxy bridge generator

### Fixed
- RFC 6570 `{param*}` (explode modifier) not recognized in template parameter extraction
- MySQL `--` comment requires trailing space (`-- `); fixed in all UNION payloads
- Boolean-based SQLi detection fails when false-case response is `None`
- REPL `--template "value"` passing literal quote characters (fixed with `shlex.split`)
- `dump_table` MySQL incompatibility (`||` is logical OR in MySQL, not concatenation)
