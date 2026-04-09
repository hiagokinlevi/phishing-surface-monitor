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
pip install -e ".[dev]"

# Run a typosquatting + DNS surface scan
python -m cli.main scan example.com --threshold 0.75 --report --json-report

# Monitor CT logs for new registrations and wildcard alerts
python -m cli.main ct-monitor example.com --output-json reports-output/example_ct_alerts.json
```

## License

MIT — see [LICENSE](LICENSE).
