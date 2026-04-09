# Architecture

## Pipeline Overview

The k1n Phishing Surface Monitor processes a brand domain through parallel
analysis flows depending on the operator's objective:

```
Brand Domain
     │
     ▼
┌─────────────────────┐
│  Variant Generation  │  analyzers/typosquatting/detector.py
│  (typosquats)        │
└─────────────────────┘
     │  list[DomainVariant]  (filtered by similarity threshold)
     ├───────────────────────────────┐
     │                               │
     ▼
┌─────────────────────┐
│   DNS Resolution     │  analyzers/dns_checker.py
│   Check              │
└─────────────────────┘
     │  DnsResult per variant
     ▼
┌─────────────────────┐
│   Risk Scoring       │  schemas/case.py  →  compute_risk()
│                      │  Produces BrandFinding objects
└─────────────────────┘
     │  list[BrandFinding]
     ▼
┌─────────────────────┐
│   Report / Display   │  reports/generator.py  +  cli/main.py
│                      │  Markdown, JSON, rich table
└─────────────────────┘
     
     Variant list / explicit domains
                  │
                  ▼
        ┌─────────────────────┐
        │ Email Posture        │  analyzers/email_security/mx_spf_checker.py
        │ MX / SPF / DKIM /    │  Heuristic DNS lookups only
        │ DMARC gap analysis   │
        └─────────────────────┘
                  │  EmailPosture per domain
                  ▼
        ┌─────────────────────┐
        │ Rich / JSON output   │  cli/main.py
        │ prioritized by risk  │
        └─────────────────────┘
```

---

## Stage 1: Variant Generation

**Module:** `analyzers/typosquatting/detector.py`

`generate_typosquats(brand_domain)` accepts a single brand domain (e.g., `example.com`) and applies seven generation techniques to produce a deduplicated list of `DomainVariant` dataclass instances. Each variant carries:

- `domain`: the candidate string
- `technique`: the generation method applied
- `similarity_score`: SequenceMatcher ratio vs. the brand domain

The list is returned sorted by `similarity_score` descending so the most dangerous candidates surface first. No network calls are made at this stage.

---

## Stage 2: DNS Resolution Check

**Module:** `analyzers/dns_checker.py`

`check_dns(domain, timeout)` calls `socket.getaddrinfo` with a configurable timeout (default 3 seconds). It returns a `DnsResult` dataclass with:

- `domain`: the queried domain
- `resolves`: boolean
- `a_records`: list of unique IPv4 addresses (empty if no resolution)

This module uses only the system's standard resolver. It does not perform port scanning, HTTP probing, or any form of active fingerprinting.

---

## Stage 3: Risk Scoring

**Module:** `schemas/case.py`

`compute_risk(similarity, resolves)` applies a decision table to map the two signals onto a `RiskLevel` enum:

| Condition | Risk Level |
|---|---|
| resolves=True, similarity >= 0.85 | CRITICAL |
| resolves=True, similarity >= 0.70 | HIGH |
| resolves=False, similarity >= 0.80 | MEDIUM |
| similarity >= 0.60 (any) | LOW |
| otherwise | INFO |

Each finding is wrapped in a `BrandFinding` Pydantic model that includes workflow metadata (`status`, `notes`, `detected_at`) for integration with case management systems.

---

## Stage 4: Reporting and Display

**Modules:** `reports/generator.py`, `cli/main.py`

Two report formats are supported:

- **Markdown** (`generate_markdown_report`): Human-readable, grouped by risk level, suitable for sharing with legal or management teams.
- **JSON** (`generate_json_report`): Machine-readable, serialised from Pydantic models, suitable for SIEM ingestion or API delivery.

The CLI (`cli/main.py`) also renders an interactive [Rich](https://github.com/Textualize/rich) table in the terminal with colour-coded risk levels for rapid triage.

---

## Email Abuse Posture Analysis

**Module:** `analyzers/email_security/mx_spf_checker.py`

`check_email_posture(domain, timeout, dkim_selectors)` performs DNS lookups for:

- `MX` records to determine whether a lookalike domain can receive replies
- Apex `TXT` records beginning with `v=spf1`
- `_dmarc.<domain>` `TXT` records beginning with `v=DMARC1`
- Common or operator-supplied DKIM selectors under `<selector>._domainkey.<domain>`

The module aggregates findings into an `EmailPosture` dataclass that exposes:

- `spf_posture`: `missing`, `permissive`, `neutral`, `softfail`, `strict`, or `present`
- `dmarc_posture`: `missing`, `none`, `quarantine`, `reject`, or `invalid`
- `risk_level`: derived from the most severe gap
- `gaps`: normalized `EmailGap` records with a control, severity, summary, and recommendation

This path remains passive-only. It never sends email, opens SMTP sessions, or
verifies mailbox existence.

---

## Module Dependency Graph

```
cli/main.py
  ├── analyzers/typosquatting/detector.py   (pure, no I/O)
  ├── analyzers/dns_checker.py              (network: DNS only)
  ├── analyzers/email_security/mx_spf_checker.py  (network: DNS TXT/MX only)
  ├── schemas/case.py                       (pure, Pydantic models)
  └── reports/generator.py
        └── schemas/case.py
```

There are no circular imports. The `analyzers` layer has no dependency on `schemas` or `reports`.

---

## Data Flow Contracts

| Boundary | Type | Notes |
|---|---|---|
| `generate_typosquats` output | `list[DomainVariant]` | Pure dataclasses, no Pydantic overhead |
| `check_dns` output | `DnsResult` | Pure dataclass |
| `compute_risk` output | `RiskLevel` | Enum |
| `BrandFinding` | Pydantic `BaseModel` | Validated, serialisable |
| Report outputs | `str` | Markdown or JSON string |

---

## Extension Points

- **New generation techniques**: Add a function to `detector.py` and call `_add()` within `generate_typosquats`.
- **Certificate transparency monitoring** (v0.2 delivered): `analyzers/ct_monitor.py` + `analyzers/ct_alerts.py` provide crt.sh querying, new-registration detection, wildcard alerting, and stateful comparison across executions.
- **MX/SPF/DKIM/DMARC analysis** (v0.3 delivered): `analyzers/email_security/mx_spf_checker.py` provides passive email-abuse posture scoring for explicit or generated lookalike domains.
- **Automated takedown templates** (planned v0.4): A new `reports/takedown.py` module producing registrar-specific abuse report templates.
