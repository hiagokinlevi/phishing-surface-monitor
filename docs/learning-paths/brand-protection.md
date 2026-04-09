# Learning Path: Brand Protection Practitioner

This learning path is designed for security analysts, brand protection specialists, and legal teams who need to identify and respond to domain-based impersonation threats.

---

## Level 1: Foundations

### Concepts to Master

- [ ] **Domain anatomy**: Understand TLDs, second-level domains, subdomains, and internationalised domain names (IDNs).
- [ ] **DNS basics**: How A records, MX records, CNAME, and NS records work. Why a registered domain may not resolve.
- [ ] **Phishing taxonomy**: Typosquatting vs. homoglyph attacks vs. combosquatting vs. subdomain abuse.
- [ ] **WHOIS and registration data**: How to look up registrant information and interpret redacted RDAP records.

### Recommended Reading

- ICANN Domain Abuse Activity Reporting (DAAR)
- ENISA Threat Landscape for Phishing
- RFC 5321 (SMTP) — understand how email headers can be spoofed

### Exercises

1. Run `python -m cli.main scan yourbrand.com --no-dns` and identify the five most similar variants.
2. Read [training/01-domain-monitoring-basics.md](../../training/01-domain-monitoring-basics.md).
3. Manually search for three of the generated variants in a WHOIS service to check registration status.

---

## Level 2: Tooling and Workflow

### Concepts to Master

- [ ] **Similarity scoring**: Understand the SequenceMatcher ratio and when it is and is not reliable (see [training/02-risk-model-explained.md](../../training/02-risk-model-explained.md)).
- [ ] **DNS as a risk signal**: Resolving domains are immediately actionable; non-resolving ones require monitoring.
- [ ] **Certificate transparency**: Learn how to query crt.sh to find TLS certificates issued for lookalike domains.
- [ ] **Report triage**: Prioritise CRITICAL and HIGH findings; establish a monitoring cadence for MEDIUM.

### Exercises

1. Run a full scan with DNS enabled: `python -m cli.main scan yourbrand.com --report --json-report`
2. Open the generated Markdown report and classify each CRITICAL/HIGH finding as:
   - Parked (no content)
   - Active phishing page
   - Legitimate third-party site (false positive)
3. Query `https://crt.sh/?q=%.yourbrand.com` and compare results to the scan output.

---

## Level 3: Incident Response and Takedown

### Concepts to Master

- [ ] **Registrar abuse reporting**: Identify the registrar from WHOIS, locate the abuse contact, and submit a takedown request.
- [ ] **UDRP and URS procedures**: When and how to file a Uniform Domain-Name Dispute-Resolution Policy complaint.
- [ ] **Hosting provider abuse**: If the domain resolves, the hosting provider may also be a takedown vector.
- [ ] **Evidence preservation**: Screenshot active phishing pages, capture HTTP headers, and preserve WHOIS data before takedown.

### Exercises

1. Draft an abuse report for a hypothetical CRITICAL finding using the standard template format (registrar abuse email, domain, evidence, brand owner details).
2. Research the UDRP process on WIPO's website and identify the three elements a complainant must prove.
3. Set up a recurring scan (e.g., via cron or GitHub Actions) to monitor a domain weekly.

---

## Level 4: Programme Management

### Concepts to Master

- [ ] **Risk appetite and thresholds**: Tune the `--threshold` value and `compute_risk` thresholds to match your brand's risk tolerance.
- [ ] **Coverage gaps**: Understand that this toolkit covers typosquatting; other vectors (look-alike social media accounts, mobile app impersonation) require separate monitoring.
- [ ] **Metrics and KPIs**: Mean time to detect (MTTD) new lookalikes; takedown success rate; recurrence rate.
- [ ] **Integration with SOAR**: How to pipe the JSON report into a ticketing system or SOAR platform.

### Programme Checklist

- [ ] Automated daily or weekly domain scans for all brand domains
- [ ] Alert routing: CRITICAL findings trigger same-day response
- [ ] MEDIUM findings enter a monitoring queue reviewed weekly
- [ ] Takedown templates prepared for top 5 registrars
- [ ] Legal team briefed on UDRP/URS procedures
- [ ] Internal stakeholder report distributed monthly

---

## Reference Resources

| Resource | URL |
|---|---|
| ICANN RDAP | https://lookup.icann.org |
| Certificate Transparency | https://crt.sh |
| WIPO UDRP | https://www.wipo.int/amc/en/domains |
| UDRP Policy | https://www.icann.org/resources/pages/udrp-2012-02-25-en |
| Anti-Phishing Working Group | https://apwg.org |
| PhishTank | https://phishtank.org |
| VirusTotal (domain check) | https://www.virustotal.com |

---

## Progression Map

```
Foundations (Level 1)
        │
        ▼
Tooling & Workflow (Level 2)
        │
        ▼
Incident Response & Takedown (Level 3)
        │
        ▼
Programme Management (Level 4)
```

Complete all exercises at each level before progressing. By Level 4 you should be capable of owning an end-to-end brand protection programme for a mid-sized organisation.
