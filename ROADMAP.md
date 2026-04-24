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
- [x] Implement DMARC record lookup (cycle 17)
- [x] Add simple risk scoring function (cycle 18)
- [x] Generate JSON monitoring report (cycle 19)
- [x] Add environment-based configuration loader (cycle 20)
- [x] Add basic logging utility (cycle 21)
- [x] Add takedown evidence bundle generator (cycle 22)
- [x] Create minimal README with usage examples (cycle 23)
- [x] Add IDN/Punycode normalization before similarity scoring (cycle 24)
- [x] Add --min-risk CLI filter for scan output (cycle 25)
- [x] Registrar abuse contact extraction utility (cycle 26)
- [x] CT monitor dedup cache by certificate fingerprint/domain pair (cycle 27)
- [x] Add JSON schema validation step before report write (cycle 28)
- [x] Expose suspicious URL reason codes in link triage summary table (cycle 29)
- [x] Add timeout and r
- [x] Add `--registrar-only` filter to takedown evidence generator (cycle 31)
