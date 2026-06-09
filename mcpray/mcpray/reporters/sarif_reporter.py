from __future__ import annotations

import json
from pathlib import Path

from ..findings import ScanResult, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "none",
}

_SARIF_RANK = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFORMATIONAL: 0.0,
}


def write(result: ScanResult, output_path: str) -> None:
    rules = []
    seen_rule_ids: set[str] = set()
    results = []

    for finding in result.findings:
        rule_id = finding.id

        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": finding.title.replace(" ", ""),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.impact},
                "helpUri": "https://github.com/your-org/mcpray",
                "properties": {
                    "tags": finding.tags,
                    "security-severity": str(_SARIF_RANK[finding.severity]),
                },
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL[finding.severity]
                },
            })

        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[finding.severity],
            "rank": _SARIF_RANK[finding.severity],
            "message": {
                "text": (
                    f"{finding.title}\n\n"
                    f"Affected: {finding.affected_component}\n"
                    f"Evidence: {finding.evidence[:500]}\n\n"
                    f"Impact: {finding.impact}\n\n"
                    f"Remediation: {finding.remediation}"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": result.target,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [
                        {
                            "name": finding.affected_component,
                            "kind": "module",
                        }
                    ],
                }
            ],
            "properties": {
                "risk_score": finding.risk_score,
                "abuse_categories": [c.value for c in finding.abuse_categories],
                "reproduction_steps": finding.reproduction_steps,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpray",
                        "version": result.scanner_version,
                        "informationUri": "https://github.com/your-org/mcpray",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "commandLine": f"mcpray scan {result.target}",
                        "executionSuccessful": True,
                        "startTimeUtc": result.scan_timestamp,
                    }
                ],
                "properties": {
                    "overall_risk_score": result.overall_risk_score,
                    "risk_level": result.risk_level.value,
                    "target": result.target,
                },
            }
        ],
    }

    Path(output_path).write_text(json.dumps(sarif, indent=2, default=str))
