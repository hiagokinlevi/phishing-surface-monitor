# Domain Monitoring Basics

## What is Typosquatting?

Typosquatting (also called URL hijacking) is a form of cybersquatting where threat actors register domain names that closely resemble a legitimate brand's domain. The goal is to intercept users who mistype a URL, click on a convincing phishing link, or trust a lookalike site enough to submit credentials or payment information.

Common techniques include:

| Technique | Example (brand: `example.com`) | Description |
|---|---|---|
| Character omission | `examle.com` | One character removed |
| Character doubling | `exammple.com` | One character repeated |
| Adjacent-key swap | `ezample.com` | One key replaced by neighbour on QWERTY |
| Hyphen insertion | `ex-ample.com` | Hyphen inserted between characters |
| Prefix addition | `myexample.com` | Common prefix prepended |
| Suffix addition | `example-login.com` | Common suffix appended |
| TLD variation | `example.net` | Top-level domain changed |
| Homoglyph substitution | `exаmple.com` (Cyrillic а) | Visually identical Unicode character |

---

## Why Monitoring Matters

Registered lookalike domains are frequently used to:

- Host phishing pages that harvest credentials
- Send phishing emails that appear to come from your brand
- Redirect users to malware downloads
- Conduct business email compromise (BEC) attacks

Early detection allows a brand protection team to:
1. Assess whether the domain is actively serving content
2. Initiate takedown procedures through registrars or ICANN
3. Alert users and internal security teams

---

## Using the CLI: Scanning a Brand Domain

### Installation

```bash
# Clone the repository
git clone https://github.com/hiagokinlevi/phishing-surface-monitor.git
cd phishing-surface-monitor

# Install with development dependencies
pip install -e ".[dev]"
```

### Running Your First Scan

```bash
# Basic scan with default 0.70 similarity threshold
python -m cli.main scan example.com

# Raise the threshold to reduce noise
python -m cli.main scan example.com --threshold 0.80

# Run in offline mode (no DNS checks) for quick variant enumeration
python -m cli.main scan example.com --no-dns

# Generate a Markdown report in the default output directory
python -m cli.main scan example.com --report

# Generate both Markdown and JSON reports in a custom directory
python -m cli.main scan example.com --report ./my-reports --json-report
```

### Understanding the Output Table

The CLI prints a table with the following columns:

| Column | Meaning |
|---|---|
| Domain | The candidate lookalike domain |
| Technique | Which generation method produced this variant |
| Similarity | SequenceMatcher ratio (0.0–1.0) vs. brand domain |
| Resolves | Whether the domain currently has active DNS records |
| IPs | Resolved A record IP addresses (if any) |
| Risk | Computed risk level: CRITICAL / HIGH / MEDIUM / LOW / INFO |

---

## Interpreting the Report

### What to act on immediately

- **CRITICAL** findings (resolves + similarity >= 0.85): These are the highest priority. The domain is live and nearly identical to your brand. Begin takedown procedures and notify your security team.
- **HIGH** findings (resolves + similarity >= 0.70): The domain is live. Investigate the hosted content before escalating.

### What to monitor

- **MEDIUM** findings (does not resolve + similarity >= 0.80): The domain is registered but not yet serving content. Monitor for activation.
- **LOW** findings: Lower similarity — less likely to deceive users. Log and review periodically.

### What can be deprioritised

- **INFO** findings: Very low similarity. Unlikely to pose a direct brand risk.

---

## Next Steps

- Read [02 - Risk Model Explained](02-risk-model-explained.md) for a deeper look at the scoring logic.
- Read [docs/architecture.md](../docs/architecture.md) to understand how the pipeline is assembled.
- See [docs/learning-paths/brand-protection.md](../docs/learning-paths/brand-protection.md) for a full learning path.
