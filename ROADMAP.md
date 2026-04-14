# Roadmap

## v0.1 — Core Detection (current)
- [x] Typosquatting variant generator (7 techniques)
- [x] DNS resolution checker
- [x] Similarity scoring (SequenceMatcher)
- [x] Risk level model (similarity + DNS)
- [x] Markdown and JSON report generator
- [x] CLI scan command

## v0.2 — Certificate Transparency
- [x] CT log stream monitoring (crt.sh API)
- [x] Wildcard certificate alerts
- [x] New certificate registration notifications

## v0.3 — MX & Email Infrastructure
- [x] MX record analysis for spoofing risk
- [x] SPF/DKIM/DMARC gap detection on lookalike domains

## v0.4 — Takedown Automation
- [x] ICANN/Registrar takedown request templates
- [x] Evidence packaging for abuse reports
- [x] Case status tracking

## v0.5 — Link Triage
- [x] Offline URL obfuscation and redirect triage CLI
- [x] JSON output for suspicious-link evidence handoff
- [x] CI-friendly `--fail-on-suspicious` gate for analyst queues

## Automated Completions
- [x] Initialize CLI entrypoint (cycle 1)
