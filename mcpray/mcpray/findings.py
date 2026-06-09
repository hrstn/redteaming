from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @property
    def numeric(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1}[self.value]

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "#ff2d55",
            "HIGH": "#ff6b35",
            "MEDIUM": "#ffd60a",
            "LOW": "#30d158",
            "INFORMATIONAL": "#636366",
        }[self.value]


class AbuseCategory(str, Enum):
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    REMOTE_EXECUTION = "remote_execution"
    LATERAL_MOVEMENT = "lateral_movement"
    DOS = "dos"
    SOCIAL_ENGINEERING = "social_engineering"
    SSRF = "ssrf"
    INJECTION = "injection"
    INFORMATION_DISCLOSURE = "information_disclosure"
    AUTH_BYPASS = "auth_bypass"
    CREDENTIAL_ACCESS = "credential_access"
    PROMPT_INJECTION = "prompt_injection"


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    affected_component: str
    evidence: str
    reproduction_steps: list[str]
    impact: str
    remediation: str
    abuse_categories: list[AbuseCategory] = field(default_factory=list)
    risk_score: float = 0.0
    tags: list[str] = field(default_factory=list)
    # AI-enhanced fields — populated by the AI layer, never by core scanners
    ai_analysis: dict | None = None
    payload_suggestions: list[dict] | None = None
    verified: bool | None = None

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "affected_component": self.affected_component,
            "evidence": self.evidence,
            "reproduction_steps": self.reproduction_steps,
            "impact": self.impact,
            "remediation": self.remediation,
            "abuse_categories": [c.value for c in self.abuse_categories],
            "risk_score": round(self.risk_score, 2),
            "tags": self.tags,
        }
        if self.ai_analysis is not None:
            d["ai_analysis"] = self.ai_analysis
        if self.payload_suggestions is not None:
            d["payload_suggestions"] = self.payload_suggestions
        if self.verified is not None:
            d["verified"] = self.verified
        return d


@dataclass
class ToolAbuseFactor:
    tool_name: str
    risk_score: float
    abuse_categories: list[AbuseCategory]
    attack_vectors: list[str]
    dangerous_params: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "risk_score": round(self.risk_score, 2),
            "abuse_categories": [c.value for c in self.abuse_categories],
            "attack_vectors": self.attack_vectors,
            "dangerous_params": self.dangerous_params,
        }


@dataclass
class AttackPath:
    name: str
    steps: list[str]
    prerequisites: list[str]
    impact: str
    likelihood: str
    related_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "steps": self.steps,
            "prerequisites": self.prerequisites,
            "impact": self.impact,
            "likelihood": self.likelihood,
            "related_findings": self.related_findings,
        }


@dataclass
class ServerInventory:
    target: str
    transport: str
    auth_required: bool
    tools: list[dict]
    resources: list[dict]
    resource_templates: list[dict]
    prompts: list[dict]
    capabilities: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "transport": self.transport,
            "auth_required": self.auth_required,
            "tool_count": len(self.tools),
            "resource_count": len(self.resources),
            "resource_template_count": len(self.resource_templates),
            "prompt_count": len(self.prompts),
            "tools": self.tools,
            "resources": self.resources,
            "resource_templates": self.resource_templates,
            "prompts": self.prompts,
            "capabilities": self.capabilities,
        }


@dataclass
class ScanResult:
    target: str
    scan_timestamp: str
    scanner_version: str
    findings: list[Finding]
    tool_abuse_factors: list[ToolAbuseFactor]
    server_inventory: ServerInventory
    attack_paths: list[AttackPath]
    overall_risk_score: float
    risk_level: Severity
    active_testing_enabled: bool = False

    def to_dict(self) -> dict:
        severity_counts = Counter(f.severity.value for f in self.findings)
        return {
            "meta": {
                "target": self.target,
                "scan_timestamp": self.scan_timestamp,
                "scanner_version": self.scanner_version,
                "overall_risk_score": round(self.overall_risk_score, 2),
                "risk_level": self.risk_level.value,
                "total_findings": len(self.findings),
                "active_testing_enabled": self.active_testing_enabled,
                "severity_summary": {
                    "CRITICAL": severity_counts.get("CRITICAL", 0),
                    "HIGH": severity_counts.get("HIGH", 0),
                    "MEDIUM": severity_counts.get("MEDIUM", 0),
                    "LOW": severity_counts.get("LOW", 0),
                    "INFORMATIONAL": severity_counts.get("INFORMATIONAL", 0),
                },
            },
            "server_inventory": self.server_inventory.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "tool_abuse_factors": [t.to_dict() for t in self.tool_abuse_factors],
            "attack_paths": [p.to_dict() for p in self.attack_paths],
        }
