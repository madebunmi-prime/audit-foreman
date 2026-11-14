"""Renders an AuditReport as a self-contained HTML dashboard."""

from __future__ import annotations

from audit_foreman.models import AuditReport, Finding

_SEVERITY_COLOR = {"info": "#34d399", "warning": "#fbbf24", "critical": "#f87171"}


def _finding_row(f: Finding) -> str:
    color = _SEVERITY_COLOR.get(f.severity.value, "#a79fe0")
    return f"""
    <tr>
      <td><span class="sev" style="background:{color}22;color:{color}">{f.severity.value.upper()}</span></td>
      <td class="mono">{f.specialist}</td>
      <td class="mono">{f.rule_id}</td>
      <td class="mono">{f.record_id}</td>
      <td>{f.message}</td>
    </tr>"""


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
    margin: 0; padding: 48px; background: #0e0c28;
    background-image: radial-gradient(90% 60% at 70% 0%, rgba(251,191,36,.18), transparent 60%);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #f1effa;
  }}
  .mono {{ font-family: ui-monospace, "SF Mono", Menlo, monospace; }}
  h1 {{ font-size: 32px; margin: 0 0 6px; }}
  .tag {{ color: #fbbf24; font-family: ui-monospace, monospace; letter-spacing: 2px; font-size: 14px; }}
  .kpis {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 32px 0; }}
  .kpi {{ background: #151236; border: 1px solid #2a2558; border-radius: 14px; padding: 18px 20px; }}
  .kpi .v {{ font-size: 32px; font-weight: 700; }}
  .kpi .l {{ font-size: 12px; color: #a79fe0; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; background: #151236; border-radius: 14px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 12px 16px; border-bottom: 1px solid #2a2558; font-size: 14px; }}
  th {{ color: #a79fe0; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
  .sev {{ padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; }}
  .section {{ color: #fbbf24; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; margin: 32px 0 12px; }}
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
  <div class="section">Judgment calls for a human</div>
  <table>
    <thead><tr><th>Severity</th><th>Specialist</th><th>Rule</th><th>Record</th><th>Message</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
