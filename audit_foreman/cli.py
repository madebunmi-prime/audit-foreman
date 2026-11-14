"""CLI: `audit-foreman run --input records.json`"""

from __future__ import annotations

import argparse
import json
import sys

from audit_foreman.models import Record
from audit_foreman.orchestrator import run_audit


def main() -> None:
    parser = argparse.ArgumentParser(prog="audit-foreman")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="Run an audit over a JSON file of records.")
    run_parser.add_argument(
        "--input", required=True, help="Path to a JSON array of records."
    )
    run_parser.add_argument(
        "--format", choices=["json", "markdown"], default="markdown"
    )

    args = parser.parse_args()

    if args.command == "run":
        with open(args.input) as f:
            raw = json.load(f)
        records = [Record(**r) for r in raw]
        report = run_audit(records)

        if args.format == "json":
            print(report.model_dump_json(indent=2))
        else:
            print(_as_markdown(report))


def _as_markdown(report) -> str:
    lines = [
        "# Audit Report",
        "",
        f"- Records audited: **{report.total_records}**",
        f"- Total findings: **{report.total_findings}**",
        f"- Passed clean: **{report.passed}**",
        f"- Auto-resolved: **{len(report.auto_resolved)}**",
        f"- **Needs human judgment: {report.human_review_count}**",
        "",
    ]
    if report.needs_judgment:
        lines.append("## Judgment calls for a human")
        lines.append("")
        for f in report.needs_judgment:
            lines.append(
                f"- [{f.severity.value.upper()}] `{f.rule_id}` ({f.specialist}) on `{f.record_id}`: {f.message}"
            )
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
