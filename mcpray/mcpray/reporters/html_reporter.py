from __future__ import annotations

import html
from collections import Counter
from pathlib import Path

from ..findings import ScanResult, Severity

_SEV_BADGE = {
    "CRITICAL": '<span class="badge badge-critical">CRITICAL</span>',
    "HIGH": '<span class="badge badge-high">HIGH</span>',
    "MEDIUM": '<span class="badge badge-medium">MEDIUM</span>',
    "LOW": '<span class="badge badge-low">LOW</span>',
    "INFORMATIONAL": '<span class="badge badge-info">INFO</span>',
}

_RISK_COLORS = {
    "CRITICAL": "#ff2d55",
    "HIGH": "#ff6b35",
    "MEDIUM": "#ffd60a",
    "LOW": "#30d158",
    "INFORMATIONAL": "#636366",
}


def _e(s: str) -> str:
    return html.escape(str(s))


def write(result: ScanResult, output_path: str) -> None:
    Path(output_path).write_text(_render(result), encoding="utf-8")


def _render(r: ScanResult) -> str:
    sev_counts = Counter(f.severity.value for f in r.findings)
    risk_color = _RISK_COLORS.get(r.risk_level.value, "#636366")
    non_info = [f for f in r.findings if f.severity != Severity.INFORMATIONAL]
    top_findings = non_info[:3]

    findings_html = "\n".join(_render_finding(f) for f in r.findings)
    abuse_rows = "\n".join(_render_abuse_row(t) for t in r.tool_abuse_factors[:20])
    path_html = "\n".join(_render_attack_path(p, i) for i, p in enumerate(r.attack_paths))
    inventory_html = _render_inventory(r.server_inventory)
    top_findings_html = "\n".join(
        '<div class="top-finding"><span class="tf-severity" style="color:{color}">[{sev}]</span> {title}</div>'.format(
            color=_RISK_COLORS.get(f.severity.value, "#fff"),
            sev=f.severity.value,
            title=_e(f.title),
        )
        for f in top_findings
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCP Security Report — {_e(r.target)}</title>
<style>
  :root {{
    --bg: #0a0a0f;
    --bg2: #13131a;
    --bg3: #1c1c28;
    --border: #2a2a3d;
    --text: #e0e0f0;
    --text-muted: #7070a0;
    --accent: #7b5ea7;
    --critical: #ff2d55;
    --high: #ff6b35;
    --medium: #ffd60a;
    --low: #30d158;
    --info: #636366;
    --font: 'Segoe UI', 'SF Pro Display', system-ui, sans-serif;
    --mono: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--accent); text-decoration: none; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 0 24px; }}

  /* Header */
  header {{ background: linear-gradient(135deg, #0d0d1a 0%, #1a1a2e 100%); border-bottom: 1px solid var(--border); padding: 32px 0; }}
  .header-inner {{ display: flex; justify-content: space-between; align-items: flex-start; }}
  .header-title {{ font-size: 24px; font-weight: 700; letter-spacing: -0.5px; color: #fff; }}
  .header-subtitle {{ color: var(--text-muted); font-size: 13px; margin-top: 4px; }}
  .risk-badge {{ background: {risk_color}22; border: 1px solid {risk_color}; color: {risk_color};
                 padding: 8px 20px; border-radius: 8px; font-weight: 700; font-size: 16px; text-align: center; }}
  .risk-score {{ font-size: 32px; font-weight: 800; color: {risk_color}; display: block; }}

  /* Nav */
  nav {{ background: var(--bg2); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 100; }}
  nav ul {{ display: flex; list-style: none; padding: 0; }}
  nav a {{ display: block; padding: 12px 20px; color: var(--text-muted); font-size: 13px; font-weight: 500;
           transition: color 0.2s; }}
  nav a:hover {{ color: var(--text); }}

  /* Sections */
  section {{ padding: 40px 0; border-bottom: 1px solid var(--border); }}
  h2 {{ font-size: 20px; font-weight: 700; margin-bottom: 24px; color: #fff; display: flex; align-items: center; gap: 8px; }}
  h2::before {{ content: ''; display: block; width: 4px; height: 20px; background: var(--accent); border-radius: 2px; }}

  /* Summary grid */
  .summary-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  .severity-counts {{ display: flex; gap: 12px; flex-wrap: wrap; }}
  .sev-count {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 8px;
               padding: 16px 20px; text-align: center; flex: 1; min-width: 80px; }}
  .sev-count .num {{ font-size: 28px; font-weight: 800; display: block; }}
  .sev-count .label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}
  .sev-count.critical .num {{ color: var(--critical); }}
  .sev-count.high .num {{ color: var(--high); }}
  .sev-count.medium .num {{ color: var(--medium); }}
  .sev-count.low .num {{ color: var(--low); }}

  /* Findings */
  .finding {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
             margin-bottom: 16px; overflow: hidden; }}
  .finding-header {{ padding: 16px 20px; cursor: pointer; display: flex; align-items: center; gap: 12px;
                    user-select: none; }}
  .finding-header:hover {{ background: var(--bg3); }}
  .finding-title {{ flex: 1; font-weight: 600; font-size: 14px; }}
  .finding-body {{ padding: 0 20px 20px; display: none; }}
  .finding.open .finding-body {{ display: block; }}
  .finding-meta {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px; }}
  .meta-block {{ background: var(--bg3); border-radius: 6px; padding: 12px; }}
  .meta-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 4px; }}
  .meta-value {{ font-size: 13px; }}
  pre.evidence {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px;
                font-family: var(--mono); font-size: 12px; overflow-x: auto; white-space: pre-wrap;
                word-break: break-all; margin-top: 8px; color: #aab; }}
  .steps ol {{ padding-left: 20px; }}
  .steps li {{ font-family: var(--mono); font-size: 12px; color: #99c; margin: 4px 0; }}
  .abuse-tags {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }}
  .abuse-tag {{ background: var(--accent)22; color: var(--accent); border: 1px solid var(--accent)44;
               padding: 2px 8px; border-radius: 4px; font-size: 11px; }}

  /* Badges */
  .badge {{ padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; }}
  .badge-critical {{ background: var(--critical)22; color: var(--critical); border: 1px solid var(--critical)66; }}
  .badge-high {{ background: var(--high)22; color: var(--high); border: 1px solid var(--high)66; }}
  .badge-medium {{ background: var(--medium)22; color: var(--medium); border: 1px solid var(--medium)66; }}
  .badge-low {{ background: var(--low)22; color: var(--low); border: 1px solid var(--low)66; }}
  .badge-info {{ background: var(--info)22; color: var(--info); border: 1px solid var(--info)66; }}

  /* Table */
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: var(--bg3); color: var(--text-muted); font-weight: 600; padding: 10px 14px;
       text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
       border-bottom: 1px solid var(--border); }}
  td {{ padding: 10px 14px; border-bottom: 1px solid var(--border)88; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--bg3); }}
  .risk-bar {{ background: var(--bg); border-radius: 4px; height: 8px; overflow: hidden; min-width: 80px; }}
  .risk-fill {{ height: 100%; border-radius: 4px; }}

  /* Attack paths */
  .attack-path {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
                 margin-bottom: 16px; overflow: hidden; }}
  .path-header {{ padding: 16px 20px; display: flex; align-items: center; justify-content: space-between; }}
  .path-title {{ font-weight: 700; font-size: 15px; color: #fff; }}
  .path-body {{ padding: 0 20px 20px; }}
  .path-steps {{ counter-reset: step; }}
  .path-step {{ display: flex; align-items: flex-start; gap: 12px; padding: 8px 0;
               border-bottom: 1px solid var(--border)44; }}
  .path-step:last-child {{ border-bottom: none; }}
  .step-num {{ background: var(--accent); color: white; width: 22px; height: 22px;
              border-radius: 50%; display: flex; align-items: center; justify-content: center;
              font-size: 11px; font-weight: 700; flex-shrink: 0; margin-top: 1px; }}
  .path-step .step-text {{ color: var(--text); font-size: 13px; }}
  .arrow {{ color: var(--accent); font-size: 20px; padding: 4px 0; }}

  /* Inventory */
  .inv-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
  .inv-stat {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
  .inv-stat .num {{ font-size: 32px; font-weight: 800; color: var(--accent); }}
  .inv-stat .label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}

  /* Top findings */
  .top-finding {{ padding: 8px 12px; border-left: 3px solid var(--accent);
                margin-bottom: 8px; background: var(--bg3); border-radius: 0 6px 6px 0; font-size: 13px; }}
  .tf-severity {{ font-weight: 700; margin-right: 8px; }}

  /* Footer */
  footer {{ padding: 24px 0; text-align: center; color: var(--text-muted); font-size: 12px; }}
</style>
</head>
<body>

<header>
<div class="container">
  <div class="header-inner">
    <div>
      <div class="header-title">MCP Security Assessment Report</div>
      <div class="header-subtitle">
        Target: <strong>{_e(r.target)}</strong> &nbsp;|&nbsp;
        Scanned: {_e(r.scan_timestamp[:19].replace('T', ' '))} UTC &nbsp;|&nbsp;
        Transport: {_e(r.server_inventory.transport)} &nbsp;|&nbsp;
        Auth Required: {"Yes" if r.server_inventory.auth_required else "<span style='color:var(--critical)'>No</span>"} &nbsp;|&nbsp;
        mcpray v{_e(r.scanner_version)}
      </div>
    </div>
    <div class="risk-badge">
      <span class="risk-score">{r.overall_risk_score:.1f}</span>
      {_e(r.risk_level.value)}
    </div>
  </div>
</div>
</header>

<nav>
<div class="container">
  <ul>
    <li><a href="#summary">Executive Summary</a></li>
    <li><a href="#findings">Findings ({len(r.findings)})</a></li>
    <li><a href="#tools">Tool Abuse Analysis</a></li>
    <li><a href="#paths">Attack Paths</a></li>
    <li><a href="#inventory">Server Inventory</a></li>
  </ul>
</div>
</nav>

<div class="container">

<section id="summary">
  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div>
      <div class="severity-counts">
        <div class="sev-count critical">
          <span class="num">{sev_counts.get('CRITICAL', 0)}</span>
          <span class="label">Critical</span>
        </div>
        <div class="sev-count high">
          <span class="num">{sev_counts.get('HIGH', 0)}</span>
          <span class="label">High</span>
        </div>
        <div class="sev-count medium">
          <span class="num">{sev_counts.get('MEDIUM', 0)}</span>
          <span class="label">Medium</span>
        </div>
        <div class="sev-count low">
          <span class="num">{sev_counts.get('LOW', 0)}</span>
          <span class="label">Low</span>
        </div>
      </div>
    </div>
    <div>
      <div style="font-size:13px; color:var(--text-muted); margin-bottom:12px;">Top Findings</div>
      {top_findings_html if top_findings_html else '<div style="color:var(--text-muted)">No high-severity findings.</div>'}
    </div>
  </div>
</section>

<section id="findings">
  <h2>Findings ({len(r.findings)})</h2>
  {findings_html}
</section>

<section id="tools">
  <h2>Tool Abuse Analysis</h2>
  <table>
    <thead>
      <tr>
        <th>Tool Name</th>
        <th>Risk Score</th>
        <th>Abuse Categories</th>
        <th>Attack Vectors</th>
        <th>Dangerous Params</th>
      </tr>
    </thead>
    <tbody>
      {abuse_rows}
    </tbody>
  </table>
</section>

<section id="paths">
  <h2>Attack Paths ({len(r.attack_paths)})</h2>
  {path_html if path_html else '<p style="color:var(--text-muted)">No attack paths identified.</p>'}
</section>

<section id="inventory">
  <h2>Server Inventory</h2>
  {inventory_html}
</section>

</div>

<footer>
  <div class="container">
    Generated by <strong>mcpray v{_e(r.scanner_version)}</strong> — MCP Security Scanner
    &nbsp;|&nbsp; {_e(r.scan_timestamp[:19].replace('T', ' '))} UTC
  </div>
</footer>

<script>
  document.querySelectorAll('.finding-header').forEach(h => {{
    h.addEventListener('click', () => {{
      h.closest('.finding').classList.toggle('open');
    }});
  }});
</script>
</body>
</html>"""


def _render_finding(f) -> str:
    badge = _SEV_BADGE.get(f.severity.value, "")
    abuse_tags = " ".join(
        f'<span class="abuse-tag">{_e(c.value)}</span>'
        for c in f.abuse_categories
    )
    steps = "\n".join(f"<li>{_e(s)}</li>" for s in f.reproduction_steps)

    return f"""
<div class="finding">
  <div class="finding-header">
    {badge}
    <div class="finding-title">{_e(f.title)}</div>
    <div style="color:var(--text-muted);font-size:12px">{_e(f.id)} &nbsp; Score: {f.risk_score:.1f}</div>
  </div>
  <div class="finding-body">
    <div class="finding-meta">
      <div class="meta-block">
        <div class="meta-label">Affected Component</div>
        <div class="meta-value">{_e(f.affected_component)}</div>
      </div>
      <div class="meta-block">
        <div class="meta-label">Risk Score</div>
        <div class="meta-value" style="font-size:20px;font-weight:700;color:{_RISK_COLORS.get(f.severity.value,'#fff')}">{f.risk_score:.1f} / 10</div>
      </div>
    </div>

    <div style="margin-top:16px">
      <div class="meta-label">Evidence</div>
      <pre class="evidence">{_e(f.evidence)}</pre>
    </div>

    <div class="finding-meta" style="margin-top:16px">
      <div class="meta-block">
        <div class="meta-label">Impact</div>
        <div class="meta-value">{_e(f.impact)}</div>
      </div>
      <div class="meta-block">
        <div class="meta-label">Remediation</div>
        <div class="meta-value">{_e(f.remediation)}</div>
      </div>
    </div>

    <div style="margin-top:16px" class="steps">
      <div class="meta-label">Reproduction Steps</div>
      <pre class="evidence"><ol>{steps}</ol></pre>
    </div>

    <div style="margin-top:12px">
      <div class="meta-label">Abuse Categories</div>
      <div class="abuse-tags">{abuse_tags}</div>
    </div>
  </div>
</div>"""


def _risk_fill_color(score: float) -> str:
    if score >= 9:
        return "var(--critical)"
    if score >= 7:
        return "var(--high)"
    if score >= 4:
        return "var(--medium)"
    return "var(--low)"


def _render_abuse_row(t) -> str:
    fill_color = _risk_fill_color(t.risk_score)
    cats = ", ".join(c.value for c in t.abuse_categories[:4])
    vectors = "<br>".join(_e(v) for v in t.attack_vectors[:3])
    params = ", ".join(_e(p) for p in t.dangerous_params[:5]) or "—"
    width = int(t.risk_score * 10)

    return f"""
<tr>
  <td style="font-family:var(--mono);font-weight:600">{_e(t.tool_name)}</td>
  <td>
    <div style="display:flex;align-items:center;gap:8px">
      <span style="font-weight:700;color:{fill_color};min-width:28px">{t.risk_score:.1f}</span>
      <div class="risk-bar" style="flex:1">
        <div class="risk-fill" style="width:{width}%;background:{fill_color}"></div>
      </div>
    </div>
  </td>
  <td style="font-size:12px;color:var(--text-muted)">{_e(cats)}</td>
  <td style="font-size:12px">{vectors}</td>
  <td style="font-family:var(--mono);font-size:12px;color:var(--accent)">{params}</td>
</tr>"""


def _render_attack_path(p, idx: int) -> str:
    steps_html = "".join(
        f'<div class="path-step"><div class="step-num">{i+1}</div>'
        f'<div class="step-text">{_e(s)}</div></div>'
        for i, s in enumerate(p.steps)
    )
    likelihood_color = {
        "CRITICAL": "var(--critical)", "HIGH": "var(--high)",
        "MEDIUM": "var(--medium)", "LOW": "var(--low)",
    }.get(p.likelihood.upper(), "var(--text-muted)")

    return f"""
<div class="attack-path">
  <div class="path-header">
    <div class="path-title">{_e(p.name)}</div>
    <div style="color:{likelihood_color};font-weight:700;font-size:12px">Likelihood: {_e(p.likelihood)}</div>
  </div>
  <div class="path-body">
    <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">
      <strong>Impact:</strong> {_e(p.impact)} &nbsp;|&nbsp;
      <strong>Prerequisites:</strong> {_e(', '.join(p.prerequisites))}
    </div>
    <div class="path-steps">{steps_html}</div>
  </div>
</div>"""


def _render_inventory(inv) -> str:
    tool_rows = "\n".join(
        f"<tr><td style='font-family:var(--mono);font-weight:600'>{_e(t['name'])}</td>"
        f"<td style='font-size:12px;color:var(--text-muted)'>{_e(t.get('description','')[:120])}</td>"
        f"<td style='font-family:var(--mono);font-size:11px;color:var(--accent)'>"
        f"{_e(', '.join(t.get('inputSchema',{}).get('properties',{}).keys()))}</td></tr>"
        for t in inv.tools
    )
    resource_rows = "\n".join(
        f"<tr><td style='font-family:var(--mono)'>{_e(r.get('name',''))}</td>"
        f"<td style='font-family:var(--mono);font-size:12px;color:var(--accent)'>{_e(r.get('uri',''))}</td>"
        f"<td style='font-size:12px;color:var(--text-muted)'>{_e(r.get('description','')[:120])}</td></tr>"
        for r in inv.resources
    )

    return f"""
<div class="inv-grid">
  <div class="inv-stat"><div class="num">{len(inv.tools)}</div><div class="label">Tools</div></div>
  <div class="inv-stat"><div class="num">{len(inv.resources)}</div><div class="label">Resources</div></div>
  <div class="inv-stat"><div class="num">{len(inv.resource_templates)}</div><div class="label">Templates</div></div>
  <div class="inv-stat"><div class="num">{len(inv.prompts)}</div><div class="label">Prompts</div></div>
</div>

{"<h3 style='font-size:14px;margin-bottom:12px;color:var(--text-muted)'>Tools</h3><table><thead><tr><th>Name</th><th>Description</th><th>Parameters</th></tr></thead><tbody>" + tool_rows + "</tbody></table>" if inv.tools else ""}

{"<h3 style='font-size:14px;margin:24px 0 12px;color:var(--text-muted)'>Resources</h3><table><thead><tr><th>Name</th><th>URI</th><th>Description</th></tr></thead><tbody>" + resource_rows + "</tbody></table>" if inv.resources else ""}
"""
