"""Billing / usage-reconciliation compliance specialist.

Rules modeled on real metered-billing reconciliation patterns (usage vs.
invoiced amount, negative/anomalous usage, missing metering data) —
generalized, not tied to any one employer's billing system.
"""

from __future__ import annotations

from audit_foreman.models import Finding, Record, Severity, Verdict
from audit_foreman.specialists.base import Specialist

RECONCILIATION_TOLERANCE_PCT = 1.0
AMBIGUOUS_BAND_PCT = 5.0


class BillingSpecialist(Specialist):
    domain = "billing"

    def audit(self, record: Record) -> list[Finding]:
        findings: list[Finding] = []
        d = record.data

        findings.append(self._check_reconciliation(record, d))
        findings.append(self._check_negative_usage(record, d))
        findings.append(self._check_missing_metering(record, d))

        return [f for f in findings if f is not None]

    def _check_reconciliation(self, record: Record, d: dict) -> Finding | None:
        usage = d.get("metered_usage")
        invoiced = d.get("invoiced_usage")
        if usage is None or invoiced is None:
            return None
        if usage == 0:
            return None
        drift_pct = abs(invoiced - usage) / usage * 100

        if drift_pct <= RECONCILIATION_TOLERANCE_PCT:
            return Finding(
                record_id=record.id,
                specialist=self.domain,
                rule_id="billing.reconciliation",
                severity=Severity.INFO,
                verdict=Verdict.PASS,
                message=f"Invoiced usage within tolerance ({drift_pct:.2f}% drift).",
                confidence=1.0,
            )
        if drift_pct <= AMBIGUOUS_BAND_PCT:
            return Finding(
                record_id=record.id,
                specialist=self.domain,
                rule_id="billing.reconciliation",
                severity=Severity.WARNING,
                verdict=Verdict.AUTO_RESOLVED,
                message=f"Drift {drift_pct:.2f}% is a known rounding/meter-lag band — auto-corrected to metered usage.",
                confidence=0.85,
                evidence={"drift_pct": round(drift_pct, 2)},
            )
        return Finding(
            record_id=record.id,
            specialist=self.domain,
            rule_id="billing.reconciliation",
            severity=Severity.CRITICAL,
            verdict=Verdict.NEEDS_JUDGMENT,
            message=f"Drift {drift_pct:.2f}% exceeds the ambiguous band — needs a human call on whether this is a billing error or a legitimate adjustment (credits, disputes).",
            confidence=0.6,
            evidence={"drift_pct": round(drift_pct, 2)},
        )

    def _check_negative_usage(self, record: Record, d: dict) -> Finding | None:
        usage = d.get("metered_usage")
        if usage is None:
            return None
        if usage < 0:
            return Finding(
                record_id=record.id,
                specialist=self.domain,
                rule_id="billing.negative_usage",
                severity=Severity.CRITICAL,
                verdict=Verdict.NEEDS_JUDGMENT,
                message="Negative metered usage — needs a human call on whether this is a legitimate credit/refund or a metering fault.",
                confidence=0.5,
                evidence={"metered_usage": usage},
            )
        return None

    def _check_missing_metering(self, record: Record, d: dict) -> Finding | None:
        if d.get("metered_usage") is not None:
            return None
        return Finding(
            record_id=record.id,
            specialist=self.domain,
            rule_id="billing.missing_meter",
            severity=Severity.WARNING,
            verdict=Verdict.NEEDS_JUDGMENT,
            message="No metered usage on record — needs a human call on whether to estimate, re-read, or escalate to the account.",
            confidence=0.4,
        )
