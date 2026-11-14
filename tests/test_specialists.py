from audit_foreman.models import Record, Verdict
from audit_foreman.specialists.access import AccessSpecialist
from audit_foreman.specialists.billing import BillingSpecialist
from audit_foreman.specialists.network import NetworkSpecialist


def _verdicts(findings):
    return {f.rule_id: f.verdict for f in findings}


class TestNetworkSpecialist:
    def test_clean_device_passes(self):
        record = Record(
            id="d1",
            domain="network",
            data={
                "encrypted_in_transit": True,
                "firmware_eol_date": "2099-01-01",
                "management_plane_public": False,
            },
        )
        verdicts = _verdicts(NetworkSpecialist().audit(record))
        assert verdicts["net.encryption"] == Verdict.PASS
        assert verdicts["net.firmware_eol"] == Verdict.PASS
        assert verdicts["net.mgmt_exposure"] == Verdict.PASS

    def test_unencrypted_device_needs_judgment(self):
        record = Record(id="d2", domain="network", data={"encrypted_in_transit": False})
        verdicts = _verdicts(NetworkSpecialist().audit(record))
        assert verdicts["net.encryption"] == Verdict.NEEDS_JUDGMENT

    def test_public_management_plane_needs_judgment(self):
        record = Record(
            id="d3",
            domain="network",
            data={
                "encrypted_in_transit": True,
                "management_plane_public": True,
            },
        )
        verdicts = _verdicts(NetworkSpecialist().audit(record))
        assert verdicts["net.mgmt_exposure"] == Verdict.NEEDS_JUDGMENT

    def test_firmware_within_grace_window_auto_resolves(self):
        from datetime import date, timedelta

        eol = (date.today() - timedelta(days=30)).isoformat()
        record = Record(
            id="d4",
            domain="network",
            data={"encrypted_in_transit": True, "firmware_eol_date": eol},
        )
        verdicts = _verdicts(NetworkSpecialist().audit(record))
        assert verdicts["net.firmware_eol"] == Verdict.AUTO_RESOLVED

    def test_firmware_past_grace_window_needs_judgment(self):
        from datetime import date, timedelta

        eol = (date.today() - timedelta(days=400)).isoformat()
        record = Record(
            id="d5",
            domain="network",
            data={"encrypted_in_transit": True, "firmware_eol_date": eol},
        )
        verdicts = _verdicts(NetworkSpecialist().audit(record))
        assert verdicts["net.firmware_eol"] == Verdict.NEEDS_JUDGMENT


class TestBillingSpecialist:
    def test_within_tolerance_passes(self):
        record = Record(
            id="i1",
            domain="billing",
            data={"metered_usage": 1000, "invoiced_usage": 1005},
        )
        verdicts = _verdicts(BillingSpecialist().audit(record))
        assert verdicts["billing.reconciliation"] == Verdict.PASS

    def test_ambiguous_band_auto_resolves(self):
        record = Record(
            id="i2",
            domain="billing",
            data={"metered_usage": 1000, "invoiced_usage": 1030},
        )
        verdicts = _verdicts(BillingSpecialist().audit(record))
        assert verdicts["billing.reconciliation"] == Verdict.AUTO_RESOLVED

    def test_large_drift_needs_judgment(self):
        record = Record(
            id="i3",
            domain="billing",
            data={"metered_usage": 1000, "invoiced_usage": 1200},
        )
        verdicts = _verdicts(BillingSpecialist().audit(record))
        assert verdicts["billing.reconciliation"] == Verdict.NEEDS_JUDGMENT

    def test_negative_usage_needs_judgment(self):
        record = Record(
            id="i4", domain="billing", data={"metered_usage": -5, "invoiced_usage": 0}
        )
        verdicts = _verdicts(BillingSpecialist().audit(record))
        assert verdicts["billing.negative_usage"] == Verdict.NEEDS_JUDGMENT

    def test_missing_meter_needs_judgment(self):
        record = Record(id="i5", domain="billing", data={})
        verdicts = _verdicts(BillingSpecialist().audit(record))
        assert verdicts["billing.missing_meter"] == Verdict.NEEDS_JUDGMENT


class TestAccessSpecialist:
    def test_privileged_without_mfa_always_needs_judgment(self):
        record = Record(
            id="g1",
            domain="access",
            data={
                "role": "admin",
                "mfa_enabled": False,
                "last_used_date": "2026-11-10",
            },
        )
        verdicts = _verdicts(AccessSpecialist().audit(record))
        assert verdicts["access.privileged_mfa"] == Verdict.NEEDS_JUDGMENT

    def test_non_privileged_stale_grant_auto_resolves(self):
        record = Record(
            id="g2",
            domain="access",
            data={
                "role": "editor",
                "mfa_enabled": True,
                "last_used_date": "2025-01-01",
            },
        )
        verdicts = _verdicts(AccessSpecialist().audit(record))
        assert verdicts["access.stale_grant"] == Verdict.AUTO_RESOLVED

    def test_privileged_stale_grant_needs_judgment(self):
        record = Record(
            id="g3",
            domain="access",
            data={"role": "admin", "mfa_enabled": True, "last_used_date": "2025-01-01"},
        )
        verdicts = _verdicts(AccessSpecialist().audit(record))
        assert verdicts["access.stale_grant"] == Verdict.NEEDS_JUDGMENT

    def test_fresh_privileged_grant_with_mfa_passes(self):
        record = Record(
            id="g4",
            domain="access",
            data={"role": "admin", "mfa_enabled": True, "last_used_date": "2026-11-10"},
        )
        verdicts = _verdicts(AccessSpecialist().audit(record))
        assert verdicts["access.stale_grant"] == Verdict.PASS
        assert verdicts["access.privileged_mfa"] == Verdict.PASS
