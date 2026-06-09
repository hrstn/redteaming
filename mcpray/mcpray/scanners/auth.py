from __future__ import annotations

from ..findings import AbuseCategory, Finding, Severity, ServerInventory
from ..scoring import score_tool_abuse
from .base import BaseScanner


class AuthScanner(BaseScanner):
    name = "AUTH"

    async def scan(self, inventory: ServerInventory) -> list[Finding]:
        self._findings = []

        self._check_anonymous_access(inventory)
        self._check_transport_security(inventory)
        self._check_anonymous_tool_access(inventory)
        self._check_long_lived_credentials(inventory)

        return self._findings

    def _check_anonymous_access(self, inventory: ServerInventory) -> None:
        if not inventory.auth_required:
            f = Finding(
                id=self._next_id(),
                title="Anonymous Access to MCP Server",
                severity=Severity.HIGH,
                affected_component=f"MCP Server ({inventory.target})",
                evidence=(
                    f"Connected to {inventory.target} without providing any authentication credentials. "
                    f"Server exposed {len(inventory.tools)} tools, {len(inventory.resources)} resources, "
                    f"and {len(inventory.prompts)} prompts without authentication."
                ),
                reproduction_steps=[
                    f"from fastmcp import Client",
                    f"async with Client('{inventory.target}') as c:",
                    f"    tools = await c.list_tools()  # returns {len(inventory.tools)} tools without auth",
                ],
                impact=(
                    "Any unauthenticated actor on the network can enumerate all server capabilities, "
                    "execute tools, read resources, and manipulate the MCP agent without credentials."
                ),
                remediation=(
                    "Implement API key or OAuth 2.0 authentication. Require the Authorization header "
                    "for all MCP requests. Consider mTLS for service-to-service communication."
                ),
                abuse_categories=[AbuseCategory.AUTH_BYPASS],
                risk_score=8.0,
                tags=["authentication", "anonymous-access"],
            )
            self._findings.append(f)

    def _check_transport_security(self, inventory: ServerInventory) -> None:
        if "INSECURE" in inventory.transport or inventory.transport == "HTTP (INSECURE)":
            f = Finding(
                id=self._next_id(),
                title="Unencrypted Transport (HTTP)",
                severity=Severity.MEDIUM,
                affected_component=f"Transport Layer ({inventory.target})",
                evidence=f"MCP server is accessible over plain HTTP: {inventory.target}",
                reproduction_steps=[
                    f"# Capture traffic with: tcpdump -i any -A host <server-ip>",
                    f"# MCP messages transmitted in plaintext over HTTP",
                ],
                impact=(
                    "All MCP communication including tool inputs/outputs, resource contents, and any "
                    "authentication tokens are transmitted in plaintext, enabling MITM attacks."
                ),
                remediation=(
                    "Enable HTTPS with a valid TLS certificate. "
                    "Enforce HSTS. Redirect all HTTP traffic to HTTPS."
                ),
                abuse_categories=[AbuseCategory.INFORMATION_DISCLOSURE, AbuseCategory.AUTH_BYPASS],
                risk_score=6.5,
                tags=["transport", "encryption", "mitm"],
            )
            self._findings.append(f)

    def _check_anonymous_tool_access(self, inventory: ServerInventory) -> None:
        if inventory.auth_required:
            return
        # Flag if dangerous tools are accessible anonymously
        dangerous_names = {"exec", "shell", "bash", "admin", "root", "sudo", "eval", "run"}
        for tool in inventory.tools:
            name_lower = tool["name"].lower()
            if any(d in name_lower for d in dangerous_names):
                f = Finding(
                    id=self._next_id(),
                    title=f"High-Risk Tool '{tool['name']}' Accessible Without Authentication",
                    severity=Severity.CRITICAL,
                    affected_component=f"Tool: {tool['name']}",
                    evidence=(
                        f"Tool '{tool['name']}' is accessible without any authentication. "
                        f"Description: {tool.get('description', 'N/A')[:200]}"
                    ),
                    reproduction_steps=[
                        f"async with Client('{inventory.target}') as c:",
                        f"    # No auth required",
                        f"    result = await c.call_tool('{tool['name']}', {{...}})",
                    ],
                    impact=(
                        f"Unauthenticated execution of high-risk tool '{tool['name']}' can lead to "
                        "complete server compromise."
                    ),
                    remediation=(
                        "Implement authentication immediately. Even if the tool is required to be "
                        "accessible, it must require valid credentials."
                    ),
                    abuse_categories=[AbuseCategory.AUTH_BYPASS, AbuseCategory.REMOTE_EXECUTION],
                    risk_score=9.5,
                    tags=["authentication", "high-risk-tool", "anonymous"],
                )
                self._findings.append(f)

    def _check_long_lived_credentials(self, inventory: ServerInventory) -> None:
        # Flag if the server appears to use static/long-lived API keys based on transport metadata
        # This is a heuristic — if auth is required and transport is HTTP, likely static key
        if inventory.auth_required and "HTTP" in inventory.transport:
            f = Finding(
                id=self._next_id(),
                title="Potential Long-Lived Static API Key over Unencrypted Transport",
                severity=Severity.MEDIUM,
                affected_component=f"Authentication ({inventory.target})",
                evidence=(
                    "Server requires authentication over plain HTTP. Static API keys transmitted over "
                    "HTTP are trivially captured by network observers."
                ),
                reproduction_steps=[
                    "# Intercept HTTP traffic to capture Authorization header",
                    "# Static keys do not expire and can be reused indefinitely",
                ],
                impact=(
                    "Captured static API keys provide indefinite access to the MCP server. "
                    "No session invalidation or expiry limits the exposure window."
                ),
                remediation=(
                    "Use short-lived tokens (OAuth 2.0 access tokens). "
                    "Implement token rotation and revocation. Enforce HTTPS to protect credentials in transit."
                ),
                abuse_categories=[AbuseCategory.AUTH_BYPASS, AbuseCategory.CREDENTIAL_ACCESS],
                risk_score=6.0,
                tags=["authentication", "credentials", "token-management"],
            )
            self._findings.append(f)
