from __future__ import annotations

import logging
import re

from ..findings import AbuseCategory, Finding, Severity, ServerInventory
from ..rules.loader import get_content_secret_patterns, match_resource_rule
from ..scoring import severity_from_score
from .base import BaseScanner

logger = logging.getLogger("mcpray.scanners.resources")

_PRIVATE_IP = re.compile(
    r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|127\.\d+\.\d+\.\d+|169\.254\.\d+\.\d+)\b"
)
_METADATA_URLS = re.compile(
    r"169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2", re.I
)


class ResourceScanner(BaseScanner):
    name = "RES"

    async def scan(self, inventory: ServerInventory) -> list[Finding]:
        self._findings = []

        all_resources = inventory.resources + [
            {"name": t.get("name", ""), "uri": t.get("uriTemplate", ""),
             "description": t.get("description", ""), "mimeType": ""}
            for t in inventory.resource_templates
        ]

        for resource in all_resources:
            self._analyze_resource(resource, inventory)

        # Attempt to read suspicious resources for content-level secret scanning
        for resource in inventory.resources:
            uri = resource.get("uri", "")
            name = resource.get("name", "").lower()
            desc = resource.get("description", "").lower()
            # Only probe resources that look sensitive
            if any(k in name + desc + uri.lower() for k in (
                "secret", "config", "env", "credential", "token", "key", "password",
                "passwd", "private", "auth"
            )):
                content = await self.client.read_resource(uri)
                if content:
                    self._scan_content_for_secrets(content, resource)

        self._check_cross_user_exposure(inventory)

        return self._findings

    def _analyze_resource(self, resource: dict, inventory: ServerInventory) -> None:
        uri = resource.get("uri", "") or resource.get("uriTemplate", "") or ""
        name = resource.get("name", "") or ""
        desc = resource.get("description", "") or ""

        for rule in self.rules.get("resource_rules", []):
            if match_resource_rule(rule, uri, name, desc):
                categories = []
                for cat in rule.get("abuse_categories", []):
                    try:
                        categories.append(AbuseCategory(cat))
                    except ValueError:
                        pass

                severity = Severity(rule.get("severity", "MEDIUM"))
                risk = rule.get("base_score", 5.0)

                f = Finding(
                    id=self._next_id(),
                    title=f"{rule['title']}: '{name or uri}'",
                    severity=severity,
                    affected_component=f"Resource: {name or uri}",
                    evidence=(
                        f"Resource matched rule {rule['id']}.\n"
                        f"Name: {name}\n"
                        f"URI: {uri}\n"
                        f"Description: {desc[:300]}"
                    ),
                    reproduction_steps=[
                        f"resources = await client.list_resources()",
                        f"# Resource '{name}' is exposed at: {uri}",
                        f"content = await client.read_resource('{uri}')",
                        f"# Content may contain: {rule.get('impact', 'sensitive data')}",
                    ],
                    impact=rule.get("impact", "Sensitive resource exposed"),
                    remediation=rule.get("remediation", "Restrict access to this resource"),
                    abuse_categories=categories,
                    risk_score=risk,
                    tags=["resource-security", rule["id"].lower()],
                )
                self._findings.append(f)
                return  # One finding per resource (highest-priority rule wins)

        # Check for private IP / metadata in URI even if no rule matched
        if _METADATA_URLS.search(uri):
            f = Finding(
                id=self._next_id(),
                title=f"Cloud Metadata Endpoint in Resource URI: '{name}'",
                severity=Severity.CRITICAL,
                affected_component=f"Resource: {name}",
                evidence=f"Resource URI contains cloud metadata endpoint address: {uri}",
                reproduction_steps=[
                    f"content = await client.read_resource('{uri}')",
                    "# Returns cloud instance metadata including IAM credentials",
                ],
                impact="Leaks cloud IAM credentials enabling cloud account takeover",
                remediation="Remove metadata endpoint resources immediately",
                abuse_categories=[AbuseCategory.CREDENTIAL_ACCESS, AbuseCategory.LATERAL_MOVEMENT],
                risk_score=9.8,
                tags=["cloud-metadata", "imds", "credential-access"],
            )
            self._findings.append(f)
        elif _PRIVATE_IP.search(uri):
            f = Finding(
                id=self._next_id(),
                title=f"Internal Network Address in Resource URI: '{name}'",
                severity=Severity.HIGH,
                affected_component=f"Resource: {name}",
                evidence=f"Resource URI references internal IP address: {uri}",
                reproduction_steps=[
                    f"content = await client.read_resource('{uri}')",
                    "# Accesses internal network service",
                ],
                impact="Exposes internal network services to external MCP clients",
                remediation="Replace internal IPs with externally routable service endpoints",
                abuse_categories=[AbuseCategory.LATERAL_MOVEMENT, AbuseCategory.INFORMATION_DISCLOSURE],
                risk_score=7.5,
                tags=["internal-network", "ssrf"],
            )
            self._findings.append(f)

    def _scan_content_for_secrets(self, content: str, resource: dict) -> None:
        patterns = get_content_secret_patterns(self.rules)
        found_secrets = []
        for pattern in patterns:
            for match in pattern.finditer(content):
                snippet = match.group(0)[:80]
                if snippet not in found_secrets:
                    found_secrets.append(snippet)

        if found_secrets:
            uri = resource.get("uri", "")
            name = resource.get("name", "")
            f = Finding(
                id=self._next_id(),
                title=f"Secret / Credential Leaked in Resource Content: '{name}'",
                severity=Severity.CRITICAL,
                affected_component=f"Resource Content: {name}",
                evidence=(
                    f"Resource '{name}' ({uri}) contains pattern-matched secrets:\n"
                    + "\n".join(f"  - {s}" for s in found_secrets[:5])
                    + ("\n  ... (more)" if len(found_secrets) > 5 else "")
                ),
                reproduction_steps=[
                    f"content = await client.read_resource('{uri}')",
                    "# Content contains live credential material",
                ],
                impact=(
                    "Live credentials in resource content can be read by any MCP client with resource access. "
                    "Immediate rotation of all exposed credentials required."
                ),
                remediation=(
                    "Rotate all exposed credentials immediately. "
                    "Remove secrets from resource content. Use secrets managers. "
                    "Audit all MCP client access logs for unauthorized reads."
                ),
                abuse_categories=[AbuseCategory.CREDENTIAL_ACCESS, AbuseCategory.DATA_EXFILTRATION],
                risk_score=9.8,
                tags=["secret-leakage", "credential-exposure", "live-credential"],
            )
            self._findings.append(f)

    def _check_cross_user_exposure(self, inventory: ServerInventory) -> None:
        """Flag template resources with user/account IDs that may allow cross-user access."""
        user_signals = re.compile(r"\{(user|account|id|owner|tenant|org)\}", re.I)
        for tmpl in inventory.resource_templates:
            uri_tmpl = tmpl.get("uriTemplate", "")
            if not user_signals.search(uri_tmpl):
                continue
            # Check if the template lacks any authorization context in description
            desc = (tmpl.get("description", "") or "").lower()
            if not any(k in desc for k in ("own", "authorized", "permission", "current user", "authenticated")):
                f = Finding(
                    id=self._next_id(),
                    title=f"Potential Cross-User Data Exposure via Template: '{uri_tmpl}'",
                    severity=Severity.HIGH,
                    affected_component=f"Resource Template: {uri_tmpl}",
                    evidence=(
                        f"Template '{uri_tmpl}' accepts user/account identifiers as parameters. "
                        f"No authorization boundary mentioned in description: '{tmpl.get('description', 'N/A')[:200]}'"
                    ),
                    reproduction_steps=[
                        f"# Template: {uri_tmpl}",
                        "# Try accessing another user's data by substituting their ID",
                        "# If no IDOR protection exists, cross-user data is accessible",
                    ],
                    impact=(
                        "Missing authorization checks on user-parameterized templates allows Insecure Direct "
                        "Object Reference (IDOR) attacks and cross-user data exposure."
                    ),
                    remediation=(
                        "Enforce server-side authorization on all template parameters. "
                        "Verify the requester owns or has permission to access the requested resource identifier."
                    ),
                    abuse_categories=[AbuseCategory.DATA_EXFILTRATION, AbuseCategory.AUTH_BYPASS],
                    risk_score=7.8,
                    tags=["idor", "authorization", "cross-user"],
                )
                self._findings.append(f)
