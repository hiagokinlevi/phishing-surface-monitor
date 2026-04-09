# phishing-surface-monitor

Defensive brand protection toolkit for monitoring domains, detecting typosquatting, and organizing evidence for authorized takedown processes.

## Objective

Help security teams identify domains that may be impersonating their brand through typosquatting, lookalike names, or suspicious registration patterns — using only public metadata and authorized monitoring.

## Problem Solved

Security teams need systematic ways to monitor for brand impersonation without expensive commercial tools. This toolkit provides algorithms for similarity scoring, domain watchlists, case management, and evidence templates for institutional response.

## Use Cases

- Monitoring a brand's domain watchlist for new suspicious registrations
- Scoring similarity between observed domains and legitimate brand assets
- Organizing evidence for authorized takedown requests
- Training analysts to recognize typosquatting patterns
- Generating reports on brand surface exposure

## Ethical Disclaimer

This toolkit is for authorized, defensive brand protection only. Do not use it to monitor organizations you have no relationship with. Do not interact invasively with suspected fraudulent infrastructure. All collection must comply with applicable laws and organizational policies.

## Structure

```
analyzers/      — Typosquatting detection, similarity scoring
collectors/     — Domain signal collectors
schemas/        — Case and finding schemas
reports/        — Report generators
cli/            — Command-line interface
training/       — Tutorials and labs
docs/           — Methodology and governance guides
```

## How to Run

```bash
pip install -e ".[dev]"

# Analyze a domain for typosquatting variants
k1n-phish-watch analyze-similarity --brand example.com --domain examp1e.com

# Generate similarity report for a watchlist
k1n-phish-watch generate-report --watchlist watchlist.yaml --output report.md
```

## License

MIT — see [LICENSE](LICENSE).
