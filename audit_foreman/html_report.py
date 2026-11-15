"""Renders an AuditReport as a self-contained HTML dashboard."""

from __future__ import annotations

from html import escape

from audit_foreman.models import AuditReport, Finding

_SEVERITY_COLOR = {"info": "#34d399", "warning": "#fbbf24", "critical": "#f87171"}


def _finding_row(f: Finding) -> str:
    # record_id (and, in principle, any specialist-authored message) can carry
    # attacker-controlled input from the audited records — escape everything
    # before interpolating into HTML to avoid stored XSS.
    color = _SEVERITY_COLOR.get(f.severity.value, "#a79fe0")
    return f"""
    <tr>
      <td><span class="sev" style="background:{color}22;color:{color}">{escape(f.severity.value.upper())}</span></td>
      <td>
        <div class="mono rule">{escape(f.rule_id)}</div>
        <div class="mono who">{escape(f.specialist)} · {escape(f.record_id)}</div>
      </td>
      <td>{escape(f.message)}</td>
    </tr>"""


def _summary_bar(report: AuditReport) -> str:
    total = report.total_findings or 1
    passed_pct = report.passed / total * 100
    resolved_pct = len(report.auto_resolved) / total * 100
    judgment_pct = report.human_review_count / total * 100
    return f"""
  <div class="bar">
    <div style="width:{passed_pct:.2f}%;background:#34d399" title="Passed clean"></div>
    <div style="width:{resolved_pct:.2f}%;background:#fbbf24" title="Auto-resolved"></div>
    <div style="width:{judgment_pct:.2f}%;background:#f87171" title="Needs judgment"></div>
  </div>"""


def render_html(report: AuditReport) -> str:
    rows = "\n".join(_finding_row(f) for f in report.needs_judgment)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AuditForeman Report</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{
    margin: 0; padding: 48px; background: #0e0c28; min-height: 100vh; box-sizing: border-box;
    background-image: radial-gradient(90% 50% at 50% 0%, rgba(251,191,36,.18), transparent 60%);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #f1effa;
    display: flex; flex-direction: column; justify-content: center;
  }}
  .mono {{ font-family: ui-monospace, "SF Mono", Menlo, monospace; }}
  h1 {{ font-size: 32px; margin: 0 0 8px; }}
  .tag {{ color: #fbbf24; font-family: ui-monospace, monospace; letter-spacing: 2px; font-size: 14px; }}
  .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 16px; margin: 28px 0 18px; }}
  .kpi {{ background: #151236; border: 1px solid #2a2558; border-radius: 14px; padding: 20px 22px; }}
  .kpi .v {{ font-size: 36px; font-weight: 700; }}
  .kpi .l {{ font-size: 12px; color: #a79fe0; text-transform: uppercase; letter-spacing: 1px; margin-top: 6px; }}
  .bar {{ display: flex; height: 14px; border-radius: 999px; overflow: hidden; margin: 0 0 32px; background: #151236; }}
  table {{ width: 100%; border-collapse: collapse; background: #151236; border-radius: 14px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 18px 20px; border-bottom: 1px solid #2a2558; font-size: 15px; vertical-align: top; }}
  th {{ color: #a79fe0; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
  .sev {{ padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 700; white-space: nowrap; }}
  .rule {{ font-size: 15px; margin-bottom: 4px; }}
  .who {{ font-size: 12px; color: #8f8ac2; }}
  .section {{ color: #fbbf24; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; margin: 0 0 14px; }}
</style>
</head>
<body>
  <span class="tag">AUDITFOREMAN</span>
  <h1>Compliance Audit Report</h1>
  <div class="kpis">
    <div class="kpi"><div class="v">{report.total_records}</div><div class="l">Records audited</div></div>
    <div class="kpi"><div class="v" style="color:#34d399">{report.passed}</div><div class="l">Passed clean</div></div>
    <div class="kpi"><div class="v" style="color:#fbbf24">{len(report.auto_resolved)}</div><div class="l">Auto-resolved</div></div>
    <div class="kpi"><div class="v" style="color:#f87171">{report.human_review_count}</div><div class="l">Needs judgment</div></div>
  </div>
  {_summary_bar(report)}
  <div class="section">Judgment calls for a human</div>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Message</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
