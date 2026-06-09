> **LEGAL DISCLAIMER**  
> mcpray is provided for **authorized security testing only**. Use against systems 
> without explicit written permission is illegal. The authors accept no responsibility 
> for unauthorized use. See [SECURITY.md](SECURITY.md) for full policy.

# mcpray

**MCP Server Security Scanner** — an offensive security scanner for auditing
[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers.

mcpray audits the JSON-RPC API exposed by MCP servers — the tools, resources, and prompts
they serve to AI clients — and probes for vulnerabilities such as SQL injection, command
injection, SSRF, and prompt injection.

## Installation

```bash
git clone https://github.com/hstn/mcpray
cd mcpray
pip install -e ".[repl,reports]"
```

Then mcpray is available as a CLI command:

```bash
mcpray --help
```

## Documentation

Full usage documentation, CLI reference, the interactive REPL cheatsheet, and the HTB
AI Red Teamer attack workflow are maintained in [`mcpray/README.md`](mcpray/README.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the
pull request process.

## Security

See [SECURITY.md](SECURITY.md) for the authorized-use-only policy and capabilities
disclosure.

## License

[MIT](LICENSE) © 2025 hstn
