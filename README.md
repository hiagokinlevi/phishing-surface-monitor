# phishing-surface-monitor

Defensive brand protection toolkit for monitoring domains, detecting typosquatting, and organizing evidence for authorized takedown processes.

## Purpose

This tool helps security teams detect potential brand impersonation using public signals (domain similarity, DNS posture, CT logs, and email authentication records), then generate evidence-ready outputs for analyst triage and response.

## Installation Requirements

- Python 3.10+
- `pip`
- Network access for DNS/CT lookups

Install locally:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
```

(Optional) configure environment defaults:

```bash
cp .env.example .env
```

## Usage Examples

### 1) Typosquat scanning

```bash
phishing-monitor scan example.com --threshold 0.75
```

Limit output to top risk-ranked candidates:

```bash
phishing-monitor scan example.com --threshold 0.75 --top 10
```

Suppress weak lexical matches before risk ranking/output:

```bash
phishing-monitor scan example.com --min-similarity 0.85
```

Cap analyzed generated variants for quick triage runs:

```bash
phishing-monitor scan example.com --max-variants 200
```

Hide low/benign findings in terminal output during triage:

```bash
phishing-monitor scan example.com --hide-benign
```

Exclude trusted/owned domains from generated variants using a newline-delimited allowlist file:

```bash
phishing-monitor scan example.com --known-domains-file known_domains.txt
```

Filter out variants that do not use common registrable public suffixes:

```bash
phishing-monitor scan example.com --registrable-only
```

Run one invocation against multiple root domains from a newline-delimited file (blank lines and `#` comments ignored, duplicates deduplicated):

```bash
phishing-monitor scan --batch-file brands.txt --threshold 0.75
```

With report outputs:

```bash
phishing-monitor scan example.com --threshold 0.75 --top 10 --report --json-report
```

Write report artifacts into a specific directory (created automatically if missing):

```bash
phishing-monitor scan example.com --report --json-report --output-dir artifacts/reports
```

Apply report flags per domain during batch scans as well:

```bash
phishing-monitor scan --batch-file brands.txt --report --json-report --output-dir artifacts/reports
```

CI-friendly aggregate-only terminal summary (still writes artifacts when requested):

```bash
phishing-monitor scan example.com --summary-only --report --json-report
```

### 2) CT monitoring

Cap processed/displayed CT entries after filtering/dedup for faster triage:

```bash
phishing-monitor ct-monitor example.com --ct-limit 50
```
