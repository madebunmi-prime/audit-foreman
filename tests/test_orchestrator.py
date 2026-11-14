from audit_foreman.models import Record, Verdict
from audit_foreman.orchestrator import run_audit


def test_empty_input_returns_empty_report():
    report = run_audit([])
    assert report.total_records == 0
    assert report.total_findings == 0


def test_mixed_domains_routes_to_correct_specialists():
    records = [
        Record(
            id="d1",
            domain="network",
            data={"encrypted_in_transit": True, "management_plane_public": False},
        ),
        Record(
            id="i1",
            domain="billing",
            data={"metered_usage": 1000, "invoiced_usage": 1000},
        ),
        Record(
            id="g1",
            domain="access",
            data={
                "role": "editor",
                "mfa_enabled": True,
                "last_used_date": "2026-11-10",
            },
        ),
    ]
    report = run_audit(records)
    assert report.total_records == 3
    specialists_seen = {
        f.specialist for f in report.auto_resolved + report.needs_judgment
    }
    assert specialists_seen.issubset({"network", "billing", "access"})


def test_unknown_domain_is_routed_to_human_judgment():
    records = [Record(id="x1", domain="quantum", data={})]
    report = run_audit(records)
    assert report.human_review_count == 1
    assert report.needs_judgment[0].rule_id == "foreman.unknown_domain"


def test_only_judgment_findings_surfaced_for_review_not_clean_passes():
    records = [
        Record(
            id="d1",
            domain="network",
            data={"encrypted_in_transit": True, "management_plane_public": False},
        ),
        Record(id="d2", domain="network", data={"encrypted_in_transit": False}),
    ]
    report = run_audit(records)
    assert report.passed >= 1
    assert all(f.verdict == Verdict.NEEDS_JUDGMENT for f in report.needs_judgment)
    assert "d1" not in {f.record_id for f in report.needs_judgment}
