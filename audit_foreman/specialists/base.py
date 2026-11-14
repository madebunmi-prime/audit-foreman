"""Specialist agent contract: every domain specialist implements this."""

from __future__ import annotations

from abc import ABC, abstractmethod

from audit_foreman.models import Finding, Record


class Specialist(ABC):
    """A specialist owns one compliance domain and knows nothing about the others.

    The foreman routes records to specialists by `domain`; a specialist never
    talks to another specialist directly (the "foreman pattern" — one
    orchestrator, many independent experts, no peer-to-peer calls).
    """

    domain: str

    @abstractmethod
    def audit(self, record: Record) -> list[Finding]:
        """Return zero or more findings for this record. Empty list = fully clean."""
        raise NotImplementedError
