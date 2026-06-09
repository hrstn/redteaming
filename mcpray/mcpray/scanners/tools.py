from __future__ import annotations

import re
from ..findings import AbuseCategory, Finding, Severity, ServerInventory, ToolAbuseFactor
from ..rules.loader import match_tool_rule
from ..scoring import score_tool_abuse, severity_from_score
from .base import BaseScanner


_BROAD_ACCESS_SIGNALS = re.compile(
    r"\b(any|arbitrary|all|unrestricted|no\s+restriction|without\s+limit)\b", re.I
)


class ToolScanner(BaseScanner):
    name = "TOOL"

    def __init__(self, client, rules):
        super().__init__(client, rules)
        self._abuse_factors: list[ToolAbuseFactor] = []

    async def scan(self, inventory: ServerInventory) -> list[Finding]:
        self._findings = []
        self._abuse_factors = []

        for tool in inventory.tools:
            self._analyze_tool(tool, inventory)

        self._check_excessive_permissions(inventory)
        self._check_missing_role_separation(inventory)

        return self._findings

    def abuse_factors(self) -> list[ToolAbuseFactor]:
        return list(self._abuse_factors)

    def _analyze_tool(self, tool: dict, inventory: ServerInventory) -> None:
        name = tool["name"]
        desc = tool.get("description", "") or ""
        schema = tool.get("inputSchema", {}) or {}
        properties = schema.get("properties", {}) or {}
        required = schema.get("required", []) or []
        param_names = list(properties.keys())

        matched_rules = []
        categories: list[AbuseCategory] = []
        dangerous_params: list[str] = []

        for rule in self.rules.get("tool_rules", []):
            if match_tool_rule(rule, name, desc, param_names):
                matched_rules.append(rule)
                for cat in rule.get("abuse_categories", []):
                    try:
                        c = AbuseCategory(cat)
                        if c not in categories:
                            categories.append(c)
                    except ValueError:
                        pass
                for param in rule.get("param_patterns", []):
                    for p in param_names:
                        if param.lower() in p.lower() and p not in dangerous_params:
                            dangerous_params.append(p)

        if matched_rules:
            top_rule = max(matched_rules, key=lambda r: r.get("base_score", 5.0))
            risk = score_tool_abuse(categories, dangerous_params)
            severity = severity_from_score(risk)

            # Build param summary
            param_details = []
            for pname, pdef in properties.items():
                ptype = pdef.get("type", "any")
                pdesc = pdef.get("description", "")
                req = " [required]" if pname in required else ""
                param_details.append(f"  - {pname} ({ptype}){req}: {pdesc[:80]}")

            finding = Finding(
                id=self._next_id(),
                title=f"{top_rule['title']}: '{name}'",
                severity=severity,
                affected_component=f"Tool: {name}",
                evidence=(
                    f"Tool '{name}' matched security rules: {', '.join(r['id'] for r in matched_rules)}.\n"
                    f"Description: {desc[:300]}\n"
                    f"Parameters ({len(param_names)}):\n" + ("\n".join(param_details) if param_details else "  (none)")
                ),
                reproduction_steps=[
                    f"# Enumerate tool via MCP",
                    f"tools = await client.list_tools()",
                    f"# Tool '{name}' is exposed with {len(param_names)} parameter(s)",
                    f"# Abuse example:",
                    *self._generate_abuse_examples(name, param_names, categories),
                ],
                impact=top_rule.get("impact", "Potential misuse of tool capabilities"),
                remediation=top_rule.get("remediation", "Review tool permissions and access controls"),
                abuse_categories=categories,
                risk_score=risk,
                tags=["tool-security", *[r["id"].lower() for r in matched_rules]],
            )
            self._findings.append(finding)

        # Always compute abuse factor for every tool
        if not categories:
            categories = self._infer_categories(name, desc)
        abuse_score = score_tool_abuse(categories, dangerous_params) if categories else 1.0
        vectors = self._compute_attack_vectors(name, desc, param_names, categories)

        self._abuse_factors.append(
            ToolAbuseFactor(
                tool_name=name,
                risk_score=abuse_score,
                abuse_categories=categories,
                attack_vectors=vectors,
                dangerous_params=dangerous_params,
            )
        )

    def _infer_categories(self, name: str, desc: str) -> list[AbuseCategory]:
        """Heuristic category assignment for tools that don't match any rule."""
        combined = (name + " " + desc).lower()
        cats = []
        if any(k in combined for k in ("file", "read", "write", "path", "directory")):
            cats.append(AbuseCategory.DATA_EXFILTRATION)
        if any(k in combined for k in ("http", "url", "fetch", "request", "network")):
            cats.append(AbuseCategory.SSRF)
        if any(k in combined for k in ("database", "db", "query", "sql")):
            cats.append(AbuseCategory.INJECTION)
        return cats

    def _generate_abuse_examples(
        self, name: str, params: list[str], categories: list[AbuseCategory]
    ) -> list[str]:
        examples = []
        params_lower = [p.lower() for p in params]

        if AbuseCategory.REMOTE_EXECUTION in categories:
            cmd_params = [p for p in params if any(k in p.lower() for k in ("cmd", "command", "exec", "shell"))]
            p = cmd_params[0] if cmd_params else (params[0] if params else "command")
            examples.append(f"result = await client.call_tool('{name}', {{'{p}': 'cat /etc/passwd'}})")

        if AbuseCategory.DATA_EXFILTRATION in categories or AbuseCategory.CREDENTIAL_ACCESS in categories:
            path_params = [p for p in params if any(k in p.lower() for k in ("path", "file", "dir"))]
            p = path_params[0] if path_params else (params[0] if params else "path")
            examples.append(f"result = await client.call_tool('{name}', {{'{p}': '../../../../etc/passwd'}})")
            examples.append(f"result = await client.call_tool('{name}', {{'{p}': '/root/.ssh/id_rsa'}})")

        if AbuseCategory.SSRF in categories:
            url_params = [p for p in params if any(k in p.lower() for k in ("url", "uri", "host", "endpoint"))]
            p = url_params[0] if url_params else (params[0] if params else "url")
            examples.append(f"result = await client.call_tool('{name}', {{'{p}': 'http://169.254.169.254/latest/meta-data/'}})")

        if AbuseCategory.INJECTION in categories:
            q_params = [p for p in params if any(k in p.lower() for k in ("query", "sql", "filter"))]
            p = q_params[0] if q_params else (params[0] if params else "query")
            examples.append(f"result = await client.call_tool('{name}', {{'{p}': \"' OR '1'='1; DROP TABLE users;--\"}})")

        return examples or [f"result = await client.call_tool('{name}', {{...}})"]

    def _compute_attack_vectors(
        self, name: str, desc: str, params: list[str], categories: list[AbuseCategory]
    ) -> list[str]:
        vectors = []
        combined = (name + " " + desc).lower()

        if AbuseCategory.REMOTE_EXECUTION in categories:
            vectors.append("Remote code / command execution")
        if AbuseCategory.DATA_EXFILTRATION in categories:
            vectors.append("Arbitrary file read / data exfiltration")
        if AbuseCategory.SSRF in categories:
            vectors.append("Server-Side Request Forgery (SSRF)")
            if any(k in combined for k in ("metadata", "cloud", "aws", "azure", "gcp")):
                vectors.append("Cloud metadata endpoint access via SSRF")
        if AbuseCategory.INJECTION in categories:
            vectors.append("SQL / NoSQL injection")
        if AbuseCategory.PRIVILEGE_ESCALATION in categories:
            vectors.append("Privilege escalation via tool misuse")
        if AbuseCategory.CREDENTIAL_ACCESS in categories:
            vectors.append("Credential / secret harvesting")
        if AbuseCategory.LATERAL_MOVEMENT in categories:
            vectors.append("Internal network lateral movement")
        if AbuseCategory.DOS in categories:
            vectors.append("Denial of service via resource exhaustion")

        # Parameter-specific vectors
        params_lower = " ".join(params).lower()
        if any(k in params_lower for k in ("path", "file", "directory")):
            vectors.append("Path traversal (../../)")
        if any(k in params_lower for k in ("url", "uri", "host", "endpoint")):
            vectors.append("SSRF via arbitrary URL parameter")

        return vectors or ["General tool misuse"]

    def _check_excessive_permissions(self, inventory: ServerInventory) -> None:
        """Flag when tool descriptions indicate broad/unrestricted access."""
        for tool in inventory.tools:
            desc = tool.get("description", "") or ""
            if _BROAD_ACCESS_SIGNALS.search(desc):
                f = Finding(
                    id=self._next_id(),
                    title=f"Excessive Permissions Indicated: '{tool['name']}'",
                    severity=Severity.MEDIUM,
                    affected_component=f"Tool: {tool['name']}",
                    evidence=(
                        f"Tool description contains broad access language: "
                        f"'{_BROAD_ACCESS_SIGNALS.search(desc).group(0)}'\n"
                        f"Full description: {desc[:300]}"
                    ),
                    reproduction_steps=[
                        f"# Tool '{tool['name']}' explicitly advertises unrestricted access",
                        f"# No scope or permission boundaries are documented",
                    ],
                    impact=(
                        "Tools with explicitly unrestricted access violate least-privilege principles "
                        "and expand the blast radius of any account compromise."
                    ),
                    remediation=(
                        "Implement scope restrictions. Document and enforce permission boundaries. "
                        "Require explicit justification for any broad-access tool."
                    ),
                    abuse_categories=[AbuseCategory.PRIVILEGE_ESCALATION],
                    risk_score=5.5,
                    tags=["excessive-permissions", "least-privilege"],
                )
                self._findings.append(f)

    def _check_missing_role_separation(self, inventory: ServerInventory) -> None:
        """Flag if both read and write/admin tools coexist without apparent separation."""
        tool_names = [t["name"].lower() for t in inventory.tools]
        has_admin = any(k in n for n in tool_names for k in ("admin", "root", "sudo", "manage"))
        has_exec = any(k in n for n in tool_names for k in ("exec", "run", "shell", "bash"))
        has_read = any(k in n for n in tool_names for k in ("read", "get", "list", "fetch"))

        if (has_admin or has_exec) and has_read and len(inventory.tools) > 3:
            f = Finding(
                id=self._next_id(),
                title="Missing Role Separation — Read and Privileged Tools Coexist",
                severity=Severity.MEDIUM,
                affected_component="Tool Inventory",
                evidence=(
                    f"Server exposes {len(inventory.tools)} tools mixing read-only and privileged operations "
                    "without documented role separation. Any client with tool access can use all tools."
                ),
                reproduction_steps=[
                    "# Single connection accesses both read and privileged tools",
                    "# No per-tool authentication or authorization differentiation observed",
                ],
                impact=(
                    "A compromised read-access token or session also provides access to privileged operations. "
                    "Violates principle of least privilege."
                ),
                remediation=(
                    "Implement role-based access control (RBAC) at the MCP server level. "
                    "Separate read-only and privileged tool access into distinct endpoints or credentials."
                ),
                abuse_categories=[AbuseCategory.PRIVILEGE_ESCALATION, AbuseCategory.AUTH_BYPASS],
                risk_score=5.0,
                tags=["rbac", "role-separation", "least-privilege"],
            )
            self._findings.append(f)
