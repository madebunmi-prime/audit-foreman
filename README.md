# audit-foreman

A multi-agent compliance auditing system: domain specialists each own one
rule-set, a LangGraph foreman routes every record to the right specialist,
and the output surfaces **only the findings that need a human's judgment
call** — everything clean or auto-resolvable never reaches a human.

## Why

Compliance auditing is the kind of work multi-agent systems are best suited
for right now: it's tedious, it requires specialized judgment per framework,
and most of it is mechanical. A single generalist agent either misses
domain-specific rules or drowns a human reviewer in noise. The **foreman
pattern** — one orchestrator, several independent specialists, no
peer-to-peer calls between them — keeps each domain's logic isolated and
testable, while the foreman's only job is routing and aggregation.

## Architecture

```
records (network / billing / access / ...)
        │
        ▼
   Foreman (LangGraph StateGraph)
        │  routes each record by `domain`
        ▼
 ┌─────────────┬─────────────┬─────────────┐
 │  Network     │  Billing    │  Access     │   ...pluggable
 │  Specialist  │  Specialist │  Specialist │
 └─────────────┴─────────────┴─────────────┘
        │
        ▼
   Aggregated AuditReport
        │
        ├─ passed / auto_resolved   (never reaches a human)
        └─ needs_judgment           (the only thing a human sees)
```

Each specialist returns a `Finding` per rule with a `Verdict`:
- **`pass`** — clean, no action.
- **`auto_resolved`** — a known, safe pattern (e.g. firmware past EOL but
  within a grace window) that the system can flag for routine handling
  without a human decision.
- **`needs_judgment`** — ambiguous, conflicting, or high-stakes enough that
  only a human should decide (e.g. a privileged account without MFA, a
  billing drift outside the tolerance band).

## Install

```sh
pip install -e ".[dev]"
```

## Run it

```sh
# CLI, against the bundled example dataset
audit-foreman run --input examples/sample_records.json

# as JSON
audit-foreman run --input examples/sample_records.json --format json

# as an HTTP service
uvicorn audit_foreman.api:app --reload
# POST /audit with a JSON array of records
```

## Specialists included

| Domain | Rules |
|---|---|
| `network` | encryption-in-transit, firmware end-of-life (with grace window), public management-plane exposure |
| `billing` | usage/invoice reconciliation (tolerance + ambiguous band), negative usage, missing metering |
| `access` | stale access grants (role-aware), privileged roles without MFA |

Adding a new domain means writing a new `Specialist` subclass and registering
it in `DEFAULT_SPECIALISTS` — the foreman and every existing specialist stay
untouched.

## Tests

```sh
pytest
```
