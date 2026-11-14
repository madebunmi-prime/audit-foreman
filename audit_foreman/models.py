"""Core data models for AuditForeman."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Verdict(str, Enum):
    PASS = "pass"
    AUTO_RESOLVED = "auto_resolved"
    NEEDS_JUDGMENT = "needs_judgment"


class Record(BaseModel):
    """One unit of evidence being audited (an invoice, a device, an access grant, ...)."""

    id: str
    domain: str = Field(
        description="Which specialist domain this record belongs to, e.g. 'billing', 'network', 'access'."
    )
    data: dict[str, Any]


class Finding(BaseModel):
    """A specialist's judgment on a single record against one rule."""

    record_id: str
    specialist: str
    rule_id: str
    severity: Severity
    verdict: Verdict
    message: str
    confidence: float = Field(
        ge=0.0, le=1.0, description="How confident the specialist is in this verdict."
    )
    evidence: dict[str, Any] = Field(default_factory=dict)


class AuditReport(BaseModel):
    """The foreman's aggregated output: every finding, with only the judgment calls surfaced."""

    total_records: int
    total_findings: int
    auto_resolved: list[Finding]
    needs_judgment: list[Finding]
    passed: int

    @property
    def human_review_count(self) -> int:
        return len(self.needs_judgment)
