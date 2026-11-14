"""Network/infrastructure compliance specialist.

Rules modeled on real network-operations audit patterns (device encryption,
firmware end-of-life, management-plane exposure) — generalized, not tied to
any one employer's infrastructure.
"""

from __future__ import annotations

from datetime import date

from audit_foreman.models import Finding, Record, Severity, Verdict
from audit_foreman.specialists.base import Specialist


class NetworkSpecialist(Specialist):
    domain = "network"

    def audit(self, record: Record) -> list[Finding]:
        findings: list[Finding] = []
        d = record.data

        findings.append(self._check_encryption(record, d))
        findings.append(self._check_eol_firmware(record, d))
        findings.append(self._check_management_exposure(record, d))

        return [f for f in findings if f is not None]

    def _check_encryption(self, record: Record, d: dict) -> Finding | None:
        if d.get("encrypted_in_transit") is True:
            return Finding(
                record_id=record.id,
                specialist=self.domain,
                rule_id="net.encryption",
                severity=Severity.INFO,
                verdict=Verdict.PASS,
                message="Device traffic is encrypted in transit.",
                confidence=1.0,
            )
        if d.get("encrypted_in_transit") is False:
            return Finding(
                record_id=record.id,
                specialist=self.domain,
                rule_id="net.encryption",
                severity=Severity.CRITICAL,
                verdict=Verdict.NEEDS_JUDGMENT,
                message="Device traffic is unencrypted — needs a human call on whether the segment is isolated enough to accept the risk.",
                confidence=0.6,
                evidence={"encrypted_in_transit": False},
            )
        return Finding(
            record_id=record.id,
            specialist=self.domain,
            rule_id="net.encryption",
            severity=Severity.WARNING,
            verdict=Verdict.NEEDS_JUDGMENT,
            message="Encryption status unknown for this device — needs manual verification.",
            confidence=0.3,
        )

    def _check_eol_firmware(self, record: Record, d: dict) -> Finding | None:
        eol = d.get("firmware_eol_date")
        if not eol:
            return None
        eol_date = date.fromisoformat(eol)
        days_past = (date.today() - eol_date).days
        if days_past <= 0:
            return Finding(
                record_id=record.id,
                specialist=self.domain,
                rule_id="net.firmware_eol",
                severity=Severity.INFO,
                verdict=Verdict.PASS,
                message="Firmware is within its support window.",
                confidence=1.0,
            )
        if days_past <= 90:
            return Finding(
                record_id=record.id,
                specialist=self.domain,
                rule_id="net.firmware_eol",
                severity=Severity.WARNING,
                verdict=Verdict.AUTO_RESOLVED,
                message=f"Firmware EOL {days_past}d ago — within the 90-day grace window, auto-flagged for the next maintenance cycle.",
                confidence=0.9,
                evidence={"days_past_eol": days_past},
            )
        return Finding(
            record_id=record.id,
            specialist=self.domain,
            rule_id="net.firmware_eol",
            severity=Severity.CRITICAL,
            verdict=Verdict.NEEDS_JUDGMENT,
            message=f"Firmware EOL {days_past}d ago, past the grace window — needs a human decision on upgrade priority vs. replacement.",
            confidence=0.7,
            evidence={"days_past_eol": days_past},
        )

    def _check_management_exposure(self, record: Record, d: dict) -> Finding | None:
        if not d.get("management_plane_public"):
            return Finding(
                record_id=record.id,
                specialist=self.domain,
                rule_id="net.mgmt_exposure",
                severity=Severity.INFO,
                verdict=Verdict.PASS,
                message="Management plane is not publicly reachable.",
                confidence=1.0,
            )
        return Finding(
            record_id=record.id,
            specialist=self.domain,
            rule_id="net.mgmt_exposure",
            severity=Severity.CRITICAL,
            verdict=Verdict.NEEDS_JUDGMENT,
            message="Management plane is publicly reachable — needs immediate human review of whether this is intentional.",
            confidence=0.5,
            evidence={"management_plane_public": True},
        )
