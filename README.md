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

With report outputs:

```bash
phishing-monitor scan example.com --threshold 0.75 --top 10 --report --json-report
```

CI-friendly aggregate-only terminal summary (still writes artifacts when requested):

```bash
phishing-monitor scan example.com --summary-only --report --json-report
```

With CSV artifact output:

```bash
phishing-monitor scan example.com --threshold 0.75 --csv-report
```

Use a custom DNS resolver for DNS-dependent checks:

```bash
phishing-monitor scan example.com --resolver 1.1.1.1
```

### 2) CT log checks

```bash
phishing-monitor ct-monitor example.com --risk-threshold 0.70
```

### 3) DMARC lookup

```bash
phishing-monitor dmarc-check suspicious-example.net
```

### 4) Report generation

Generate Markdown + JSON artifacts from scan results:

```bash
phishing-monitor scan example.com --report --json-report
```

### Non-interactive environments

Use global `--no-color` to emit plain-text output for CI logs/SIEM ingestion:

```bash
phishing-monitor --no-color scan example.com --summary-only
```

## Ethical Use

Authorized, defensive use only. Do not run monitoring against organizations you do not own or explicitly protect. Follow applicable laws, contracts, and internal policy.
