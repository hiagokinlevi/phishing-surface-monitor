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

With report outputs:

```bash
phishing-monitor scan example.com --threshold 0.75 --report --json-report
```

### 2) CT log checks

```bash
phishing-monitor ct-monitor example.com
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

## Ethical Use

Authorized, defensive use only. Do not run monitoring against organizations you do not own or explicitly protect. Follow applicable laws, contracts, and internal policy.
