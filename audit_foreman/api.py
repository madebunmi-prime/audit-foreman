"""Minimal FastAPI service exposing the foreman as an HTTP endpoint."""

from __future__ import annotations

from fastapi import FastAPI

from audit_foreman.models import AuditReport, Record
from audit_foreman.orchestrator import run_audit

app = FastAPI(title="AuditForeman", version="0.1.0")


@app.post("/audit", response_model=AuditReport)
def audit(records: list[Record]) -> AuditReport:
    return run_audit(records)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
