"""The foreman: a LangGraph StateGraph that routes records to domain specialists
and aggregates their findings into an AuditReport.

Pattern: one orchestrator, many independent specialists, no peer-to-peer calls
between specialists ("foreman pattern"). The graph loops one record at a time
through `audit_record`, then `aggregate` classifies every finding as something
already resolved automatically or something that needs a human's judgment call.
"""

from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, StateGraph

from audit_foreman.models import AuditReport, Finding, Record, Verdict
from audit_foreman.specialists import DEFAULT_SPECIALISTS, Specialist


class ForemanState(TypedDict):
    queue: list[Record]
    findings: list[Finding]
    report: AuditReport | None


def _audit_record(
    state: ForemanState, specialists: dict[str, Specialist]
) -> ForemanState:
    queue = list(state["queue"])
    record = queue.pop(0)
    specialist = specialists.get(record.domain)
    new_findings = (
        specialist.audit(record)
        if specialist
        else [
            Finding(
                record_id=record.id,
                specialist="foreman",
                rule_id="foreman.unknown_domain",
                severity="warning",
                verdict=Verdict.NEEDS_JUDGMENT,
                message=f"No specialist registered for domain '{record.domain}' — needs a human to route this.",
                confidence=0.0,
            )
        ]
    )
    return {
        "queue": queue,
        "findings": state["findings"] + new_findings,
        "report": None,
    }


def _has_more_records(state: ForemanState) -> str:
    return "audit_record" if state["queue"] else "aggregate"


def _aggregate(state: ForemanState) -> ForemanState:
    findings = state["findings"]
    auto_resolved = [f for f in findings if f.verdict == Verdict.AUTO_RESOLVED]
    needs_judgment = [f for f in findings if f.verdict == Verdict.NEEDS_JUDGMENT]
    passed = sum(1 for f in findings if f.verdict == Verdict.PASS)

    record_ids = {f.record_id for f in findings}
    report = AuditReport(
        total_records=len(record_ids),
        total_findings=len(findings),
        auto_resolved=auto_resolved,
        needs_judgment=needs_judgment,
        passed=passed,
    )
    return {"queue": [], "findings": findings, "report": report}


def build_foreman_graph(specialists: dict[str, Specialist] | None = None):
    specialists = specialists or DEFAULT_SPECIALISTS
    graph = StateGraph(ForemanState)

    graph.add_node("audit_record", lambda s: _audit_record(s, specialists))
    graph.add_node("aggregate", _aggregate)

    graph.set_entry_point("audit_record")
    graph.add_conditional_edges(
        "audit_record",
        _has_more_records,
        {
            "audit_record": "audit_record",
            "aggregate": "aggregate",
        },
    )
    graph.add_edge("aggregate", END)

    return graph.compile()


def run_audit(
    records: list[Record], specialists: dict[str, Specialist] | None = None
) -> AuditReport:
    if not records:
        return AuditReport(
            total_records=0,
            total_findings=0,
            auto_resolved=[],
            needs_judgment=[],
            passed=0,
        )

    foreman = build_foreman_graph(specialists)
    result: ForemanState = foreman.invoke(
        {"queue": records, "findings": [], "report": None}
    )
    report = result["report"]
    assert report is not None
    return report
