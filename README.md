# phishing-surface-monitor

Defensive brand protection toolkit for monitoring domains, detecting typosquatting, and organizing evidence for authorized takedown processes.

## Objective

Help security teams identify domains that may be impersonating their brand through typosquatting, lookalike names, or suspicious registration patterns — using only public metadata and authorized monitoring.

## Problem Solved

Security teams need systematic ways to monitor for brand impersonation without expensive commercial tools. This toolkit provides algorithms for similarity scoring, domain watchlists, case management, and evidence templates for institutional response.

## Use Cases

- Monitoring a brand's domain watchlist for new suspicious registrations
- Scoring similarity between observed domains and legitimate brand assets
- Monitoring CT logs for new lookalike certificate registrations
- Detecting wildcard certificates that may indicate broad phishing infrastructure
- Analyzing lookalike domains for email abuse posture across MX, SPF, DKIM, and DMARC
- Organizing evidence for authorized takedown requests
- Training analysts to recognize typosquatting patterns
- Generating reports on brand surface exposure

## Ethical Disclaimer

This toolkit is for authorized, defensive brand protection only. Do not use it to monitor organizations you have no relationship with. Do not interact invasively with suspected fraudulent infrastructure. All collection must comply with applicable laws and organizational policies.

## Structure

```
analyzers/      — Typosquatting detection, similarity scoring, CT alerting
monitors/       — DNS, certificate abuse, and takeover monitoring modules
schemas/        — Case and finding schemas
reports/        — Report generators
cli/            — Command-line interface
training/       — Tutorials and labs
docs/           — Methodology and governance guides
```

## How to Run

```bash
python3 -m venv .venv --system-site-packages
. .venv/bin/activate
python -m pip install --no-build-isolation --no-deps -e .

# Run a typosquatting + DNS surface scan
phishing-monitor scan example.com --threshold 0.75 --report --json-report

# Monitor CT logs for new registrations and wildcard alerts
phishing-monitor ct-monitor example.com --output-json reports-output/example_ct_alerts.json

# Analyze likely lookalike domains for email-receiving and spoofing gaps
phishing-monitor email-posture example.com --output-json reports-output/example_email_posture.json
```

`email-posture` can also inspect explicit candidates and custom DKIM selectors:

```bash
phishing-monitor email-posture example.com login-example.net secure-example.org --selector default --selector selector1
```

The offline-safe install above assumes a workstation that already has the shared
Python tooling used across the Cyber Port repos. If you have internet access and
prefer isolated dependency resolution, `python -m pip install -e ".[dev]"`
remains supported.

## License

MIT — see [LICENSE](LICENSE).
