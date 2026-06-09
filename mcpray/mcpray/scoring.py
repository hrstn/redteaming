from __future__ import annotations

from .findings import AbuseCategory, Severity

# Base scores per abuse category (CVSS-inspired)
CATEGORY_BASE_SCORES: dict[AbuseCategory, float] = {
    AbuseCategory.REMOTE_EXECUTION: 9.8,
    AbuseCategory.PRIVILEGE_ESCALATION: 8.8,
    AbuseCategory.CREDENTIAL_ACCESS: 8.5,
    AbuseCategory.DATA_EXFILTRATION: 8.2,
    AbuseCategory.AUTH_BYPASS: 8.0,
    AbuseCategory.SSRF: 7.8,
    AbuseCategory.INJECTION: 7.5,
    AbuseCategory.LATERAL_MOVEMENT: 7.2,
    AbuseCategory.PROMPT_INJECTION: 7.0,
    AbuseCategory.DOS: 6.0,
    AbuseCategory.SOCIAL_ENGINEERING: 6.5,
    AbuseCategory.INFORMATION_DISCLOSURE: 5.5,
}

# Dangerous parameter names → multiplier
DANGEROUS_PARAM_MULTIPLIERS: dict[str, float] = {
    "command": 1.5,
    "cmd": 1.5,
    "exec": 1.5,
    "shell": 1.5,
    "bash": 1.5,
    "args": 1.2,
    "argv": 1.2,
    "path": 1.2,
    "file": 1.1,
    "url": 1.2,
    "uri": 1.2,
    "host": 1.1,
    "query": 1.3,
    "sql": 1.4,
    "script": 1.4,
    "code": 1.4,
    "expression": 1.3,
    "eval": 1.5,
}


def score_tool_abuse(
    categories: list[AbuseCategory],
    dangerous_params: list[str],
    description_risk_weight: float = 1.0,
) -> float:
    if not categories:
        return 0.0
    scores = sorted([CATEGORY_BASE_SCORES.get(c, 5.0) for c in categories], reverse=True)
    # Weighted average: top score counts most
    if len(scores) == 1:
        base = scores[0]
    elif len(scores) == 2:
        base = scores[0] * 0.7 + scores[1] * 0.3
    else:
        base = scores[0] * 0.6 + scores[1] * 0.25 + scores[2] * 0.15

    # Param multiplier
    if dangerous_params:
        param_mult = max(DANGEROUS_PARAM_MULTIPLIERS.get(p.lower(), 1.0) for p in dangerous_params)
        base = min(10.0, base * (0.9 + (param_mult - 1.0) * 0.2))

    return round(min(10.0, base * description_risk_weight), 2)


def severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 0.1:
        return Severity.LOW
    return Severity.INFORMATIONAL


def overall_risk_score(finding_scores: list[float]) -> tuple[float, Severity]:
    if not finding_scores:
        return 0.0, Severity.INFORMATIONAL
    sorted_scores = sorted(finding_scores, reverse=True)
    # Top finding dominates; others contribute logarithmically
    top = sorted_scores[0]
    rest = sorted_scores[1:]
    bonus = sum(s * 0.05 for s in rest[:5])
    score = round(min(10.0, top + bonus), 2)
    return score, severity_from_score(score)
