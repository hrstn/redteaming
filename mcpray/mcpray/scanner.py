from __future__ import annotations

import logging
from datetime import datetime, timezone

from .client import MCPClient
from .findings import AttackPath, AbuseCategory, Finding, ScanResult, Severity, ToolAbuseFactor
from .rules import load_rules
from .scanners import AuthScanner, ToolScanner, ResourceScanner, PromptScanner, ActiveScanner
from .scoring import overall_risk_score

logger = logging.getLogger("mcpray.scanner")

__version__ = "1.0.0"


async def run_scan(
    target: str,
    active: bool = False,
    headers: dict | None = None,
    timeout: int = 30,
    custom_rules: str | None = None,
) -> ScanResult:
    rules = load_rules(custom_rules)
    timestamp = datetime.now(timezone.utc).isoformat()

    async with MCPClient(target, headers=headers, timeout=timeout) as client:
        # Auth probe before enumeration
        anon_access = await client.probe_auth()

        logger.info("Enumerating server inventory: %s", target)
        inventory = await client.get_inventory()
        inventory.auth_required = not anon_access

        logger.info(
            "Inventory: %d tools, %d resources, %d templates, %d prompts",
            len(inventory.tools),
            len(inventory.resources),
            len(inventory.resource_templates),
            len(inventory.prompts),
        )

        all_findings: list[Finding] = []
        tool_abuse_factors: list[ToolAbuseFactor] = []

        # Run passive scanners
        auth_scanner = AuthScanner(client, rules)
        tool_scanner = ToolScanner(client, rules)
        resource_scanner = ResourceScanner(client, rules)
        prompt_scanner = PromptScanner(client, rules)

        for scanner in (auth_scanner, tool_scanner, resource_scanner, prompt_scanner):
            findings = await scanner.scan(inventory)
            all_findings.extend(findings)
            logger.info("%s scanner: %d findings", scanner.name, len(findings))

        tool_abuse_factors = tool_scanner.abuse_factors()

        # Run active scanner if requested
        if active:
            active_scanner = ActiveScanner(client, rules)
            active_findings = await active_scanner.scan(inventory)
            all_findings.extend(active_findings)
            logger.info("ACT scanner: %d findings", len(active_findings))

    # Deduplicate findings by title + component
    all_findings = _deduplicate(all_findings)

    # Score and rank
    risk_scores = [f.risk_score for f in all_findings if f.risk_score > 0]
    total_score, risk_level = overall_risk_score(risk_scores)

    # Generate attack paths
    attack_paths = _generate_attack_paths(all_findings, tool_abuse_factors, inventory)

    # Sort findings by severity desc
    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                 Severity.LOW: 3, Severity.INFORMATIONAL: 4}
    all_findings.sort(key=lambda f: sev_order.get(f.severity, 9))
    tool_abuse_factors.sort(key=lambda t: t.risk_score, reverse=True)

    return ScanResult(
        target=target,
        scan_timestamp=timestamp,
        scanner_version=__version__,
        findings=all_findings,
        tool_abuse_factors=tool_abuse_factors,
        server_inventory=inventory,
        attack_paths=attack_paths,
        overall_risk_score=total_score,
        risk_level=risk_level,
        active_testing_enabled=active,
    )


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique = []
    for f in findings:
        key = f"{f.title}|{f.affected_component}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _generate_attack_paths(
    findings: list[Finding],
    abuse_factors: list[ToolAbuseFactor],
    inventory,
) -> list[AttackPath]:
    paths: list[AttackPath] = []

    finding_ids = [f.id for f in findings]
    categories_present = {cat for f in findings for cat in f.abuse_categories}
    tool_names = [t["name"] for t in inventory.tools]

    has_anon_access = any(AbuseCategory.AUTH_BYPASS in f.abuse_categories for f in findings)
    has_rce = AbuseCategory.REMOTE_EXECUTION in categories_present
    has_file_read = AbuseCategory.DATA_EXFILTRATION in categories_present
    has_credential = AbuseCategory.CREDENTIAL_ACCESS in categories_present
    has_ssrf = AbuseCategory.SSRF in categories_present
    has_prompt_injection = AbuseCategory.PROMPT_INJECTION in categories_present
    has_privesc = AbuseCategory.PRIVILEGE_ESCALATION in categories_present
    has_sqli = AbuseCategory.INJECTION in categories_present

    # Path 1: Unauthenticated Complete Compromise
    if has_anon_access and has_rce:
        rce_ids = [f.id for f in findings if AbuseCategory.REMOTE_EXECUTION in f.abuse_categories]
        paths.append(AttackPath(
            name="Unauthenticated Remote Code Execution",
            steps=[
                "Attacker connects to MCP server without credentials",
                "Enumerates tools — discovers command execution tool(s)",
                f"Identifies command execution tool: {next((t for t in tool_names if any(k in t.lower() for k in ('exec','shell','bash','run'))), 'exec_tool')}",
                "Calls tool with malicious command payload",
                "Achieves arbitrary code execution on server host",
                "Escalates to persistence (backdoor, cron job, SSH key injection)",
            ],
            prerequisites=["Network access to MCP server"],
            impact="Full server compromise — arbitrary code execution without authentication",
            likelihood="CRITICAL",
            related_findings=rce_ids[:3],
        ))

    # Path 2: Credential Harvesting Chain
    if has_anon_access and has_file_read and has_credential:
        cred_ids = [f.id for f in findings if AbuseCategory.CREDENTIAL_ACCESS in f.abuse_categories]
        paths.append(AttackPath(
            name="Unauthenticated Credential Harvesting",
            steps=[
                "Attacker connects anonymously to MCP server",
                "Enumerates tools and resources — no auth required",
                "Discovers file-read tool or sensitive resource",
                "Reads /etc/passwd, /root/.ssh/id_rsa, .env, or config files",
                "Extracts API keys, database credentials, SSH private keys",
                "Uses harvested credentials to access downstream systems",
                "Achieves lateral movement across the infrastructure",
            ],
            prerequisites=["Network access to MCP server"],
            impact="Complete credential compromise enabling lateral movement to all connected systems",
            likelihood="HIGH",
            related_findings=cred_ids[:3],
        ))

    # Path 3: SSRF to Internal Services
    if has_ssrf:
        ssrf_ids = [f.id for f in findings if AbuseCategory.SSRF in f.abuse_categories]
        paths.append(AttackPath(
            name="SSRF to Internal Network / Cloud Metadata Exfiltration",
            steps=[
                "Attacker identifies HTTP/URL-accepting tool via tool enumeration",
                "Probes internal IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16",
                "Discovers active internal services (databases, admin panels, APIs)",
                "Requests cloud metadata endpoint: http://169.254.169.254/latest/meta-data/",
                "Extracts IAM role credentials from metadata API",
                "Uses IAM credentials to access cloud APIs (S3, RDS, Secrets Manager)",
                "Achieves full cloud account compromise",
            ],
            prerequisites=["Access to MCP server", "Tool with URL/host parameter"],
            impact="Internal network reconnaissance and cloud credential theft leading to cloud account takeover",
            likelihood="HIGH",
            related_findings=ssrf_ids[:3],
        ))

    # Path 4: Prompt Injection Agent Hijacking
    if has_prompt_injection:
        pi_ids = [f.id for f in findings if AbuseCategory.PROMPT_INJECTION in f.abuse_categories]
        paths.append(AttackPath(
            name="Prompt Injection → Agent Hijacking → Data Exfiltration",
            steps=[
                "Attacker crafts malicious input targeting MCP prompt templates",
                "Injects instruction override payload via user-controlled argument",
                "Agent instructions are hijacked — new goal: exfiltrate internal data",
                "Hijacked agent uses its authorized tool access to read sensitive resources",
                "Exfiltrates data by encoding it into subsequent agent responses or API calls",
                "Attacker retrieves exfiltrated data from response channel",
            ],
            prerequisites=["Access to MCP prompt endpoint", "Prompts with user-controlled arguments"],
            impact="Agent behavior hijacking leading to unauthorized data access and exfiltration through trusted agent identity",
            likelihood="MEDIUM",
            related_findings=pi_ids[:3],
        ))

    # Path 5: SQL Injection Data Dump
    if has_sqli:
        sqli_ids = [f.id for f in findings if AbuseCategory.INJECTION in f.abuse_categories]
        paths.append(AttackPath(
            name="SQL Injection → Full Database Exfiltration",
            steps=[
                "Attacker discovers database query tool via tool enumeration",
                "Tests query parameter with injection payloads: ' OR '1'='1",
                "Confirms SQL injection via error messages or altered results",
                "Enumerates database schema: tables, columns, stored procedures",
                "Extracts all user data, credentials, and sensitive records",
                "Attempts privilege escalation via database functions (xp_cmdshell, UDF)",
            ],
            prerequisites=["Access to database query tool"],
            impact="Complete database compromise — all data exfiltrated, potential OS-level code execution",
            likelihood="HIGH",
            related_findings=sqli_ids[:3],
        ))

    # Path 6: File Write to RCE
    write_tools = [t for t in abuse_factors if AbuseCategory.REMOTE_EXECUTION in t.abuse_categories
                   and any(k in t.tool_name.lower() for k in ("write", "save", "create", "put"))]
    if write_tools:
        paths.append(AttackPath(
            name="Arbitrary File Write → Remote Code Execution",
            steps=[
                f"Attacker identifies file write tool: '{write_tools[0].tool_name}'",
                "Writes malicious content to server-executed paths:",
                "  - Web shell to web root (/var/www/html/shell.php)",
                "  - Cron job to /etc/cron.d/backdoor",
                "  - SSH authorized_keys to /root/.ssh/",
                "  - Python/Node startup scripts",
                "Triggers code execution via written payload",
                "Achieves persistent backdoor access",
            ],
            prerequisites=["Access to file write tool", "Write permissions on execution paths"],
            impact="Persistent remote code execution via strategically placed files",
            likelihood="HIGH",
            related_findings=[write_tools[0].tool_name],
        ))

    return paths
