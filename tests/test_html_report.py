from audit_foreman.html_report import render_html
from audit_foreman.models import Record
from audit_foreman.orchestrator import run_audit


def test_html_report_includes_kpis_and_judgment_calls():
    records = [
        Record(id="d1", domain="network", data={"encrypted_in_transit": False}),
        Record(
            id="i1",
            domain="billing",
            data={"metered_usage": 1000, "invoiced_usage": 1001},
        ),
    ]
    report = run_audit(records)
    html = render_html(report)

    assert "<html" in html
    assert str(report.total_records) in html
    assert "d1" in html
    assert "net.encryption" in html


def test_html_report_is_self_contained():
    report = run_audit([])
    html = render_html(report)
    assert "<style>" in html
    assert "http://" not in html and "https://" not in html


def test_html_report_escapes_attacker_controlled_record_id():
    records = [
        Record(
            id="<script>alert(1)</script>",
            domain="network",
            data={"encrypted_in_transit": False},
        ),
    ]
    report = run_audit(records)
    html = render_html(report)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
