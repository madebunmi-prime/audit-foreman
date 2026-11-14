"""Access/security compliance specialist.

Rules modeled on standard access-governance checks (stale grants, scope
creep, missing MFA on privileged roles).
"""

from __future__ import annotations

from datetime import date

from audit_foreman.models import Finding, Record, Severity, Verdict
from audit_foreman.specialists.base import Specialist

STALE_GRANT_DAYS = 90
PRIVILEGED_ROLES = {"admin", "owner", "root"}


class AccessSpecialist(Specialist):
    domain = "access"

    def audit(self, record: Record) -> list[Finding]:
        findings: list[Finding] = []
        d = record.data

        findings.append(self._check_stale_grant(record, d))
        findings.append(self._check_privileged_mfa(record, d))

        return [f for f in findings if f is not None]

    def _check_stale_grant(self, record: Record, d: dict) -> Finding | None:
        last_used = d.get("last_used_date")
        if not last_used:
            return Finding(
                record_id=record.id,
                specialist=self.domain,
                rule_id="access.stale_grant",
                severity=Severity.WARNING,
                verdict=Verdict.NEEDS_JUDGMENT,
                message="No last-used date on this access grant — needs a human call on whether it's genuinely unused or just unlogged.",
                confidence=0.3,
            )
        idle_days = (date.today() - date.fromisoformat(last_used)).days
        if idle_days < STALE_GRANT_DAYS:
            return Finding(
                record_id=record.id,
                specialist=self.domain,
                rule_id="access.stale_grant",
                severity=Severity.INFO,
                verdict=Verdict.PASS,
                message=f"Grant used {idle_days}d ago, within policy.",
                confidence=1.0,
            )
        if d.get("role") not in PRIVILEGED_ROLES:
            return Finding(
                record_id=record.id,
                specialist=self.domain,
                rule_id="access.stale_grant",
                severity=Severity.WARNING,
                verdict=Verdict.AUTO_RESOLVED,
                message=f"Non-privileged grant idle {idle_days}d — auto-flagged for routine revocation.",
                confidence=0.9,
                evidence={"idle_days": idle_days},
            )
        return Finding(
            record_id=record.id,
            specialist=self.domain,
            rule_id="access.stale_grant",
            severity=Severity.CRITICAL,
            verdict=Verdict.NEEDS_JUDGMENT,
            message=f"Privileged grant idle {idle_days}d — needs a human call before revoking an admin/owner/root role.",
            confidence=0.6,
            evidence={"idle_days": idle_days, "role": d.get("role")},
        )

    def _check_privileged_mfa(self, record: Record, d: dict) -> Finding | None:
        if d.get("role") not in PRIVILEGED_ROLES:
            return None
        if d.get("mfa_enabled") is True:
            return Finding(
                record_id=record.id,
                specialist=self.domain,
                rule_id="access.privileged_mfa",
                severity=Severity.INFO,
                verdict=Verdict.PASS,
                message="Privileged role has MFA enabled.",
                confidence=1.0,
            )
        return Finding(
            record_id=record.id,
            specialist=self.domain,
            rule_id="access.privileged_mfa",
            severity=Severity.CRITICAL,
            verdict=Verdict.NEEDS_JUDGMENT,
            message="Privileged role without MFA — needs immediate human review; this is never auto-resolved.",
            confidence=0.9,
            evidence={"role": d.get("role")},
        )
