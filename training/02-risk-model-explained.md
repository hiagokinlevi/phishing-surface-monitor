# Risk Model Explained

## Overview

Every lookalike domain detected by this toolkit is assigned a **risk level** based on two independent signals:

1. **Similarity score** — how closely the lookalike domain resembles the brand domain (character-level ratio, 0.0–1.0).
2. **DNS resolution** — whether the domain currently resolves to one or more IP addresses.

These two signals are combined in the `compute_risk` function (`schemas/case.py`) to produce one of five levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`.

---

## The Similarity Score

Similarity is calculated using Python's `difflib.SequenceMatcher`, which computes the ratio of matching characters between the brand domain and the candidate domain:

```
ratio = 2.0 * M / T
```

Where `M` is the number of matching characters and `T` is the total number of characters in both sequences.

**Key properties:**
- A score of `1.0` means the two strings are identical.
- A score of `0.0` means no characters match at all.
- Typical typosquats score between `0.70` and `0.98`.
- The CLI default threshold of `0.70` filters out clearly unrelated domains.

**Example scores for `example.com`:**

| Candidate | Score | Why |
|---|---|---|
| `exmaple.com` | ~0.95 | Two characters transposed |
| `example.net` | ~0.92 | Only TLD differs |
| `myexample.com` | ~0.87 | Short prefix added |
| `example-login.com` | ~0.80 | Suffix added |
| `exampl3.com` | ~0.91 | One character substituted |
| `totally-other.io` | ~0.30 | Entirely different |

---

## The DNS Resolution Signal

DNS resolution is checked using the standard system resolver (`socket.getaddrinfo`). A domain that **resolves** has been registered and is configured to serve traffic — which is a strong signal that it may be actively used.

A domain that **does not resolve** may still be:
- Registered but parked (not yet weaponised)
- Recently taken down
- Not yet propagated

In either case, the domain name itself may still cause confusion if used in email headers or printed phishing material.

---

## Risk Level Decision Table

```
similarity >= 0.85  AND  resolves = True   =>  CRITICAL
similarity >= 0.70  AND  resolves = True   =>  HIGH
similarity >= 0.80  AND  resolves = False  =>  MEDIUM
similarity >= 0.60  (any resolution)       =>  LOW
otherwise                                  =>  INFO
```

Source: `schemas/case.py` — `compute_risk(similarity, resolves)`

---

## Why Resolving Domains Are Elevated

A non-resolving domain with similarity `0.85` is rated **MEDIUM**, not CRITICAL, because without an active DNS record it cannot be accessed by end users in real time. It remains a concern (the registration itself is suspicious), but the immediate user-facing threat is lower.

A resolving domain with similarity `0.75` is rated **HIGH** because a real user could navigate to it by mistyping a URL or clicking a phishing link — and whatever content is served there is potentially harmful.

---

## Tuning the Model

The thresholds in `compute_risk` are intentionally conservative for a first release. Teams monitoring very short brand names (3–4 characters) may want to lower the `similarity >= 0.85` CRITICAL threshold, as short names naturally produce lower ratios even for near-identical variants.

Future versions may introduce:
- Configurable thresholds via `.env` or CLI flags
- Certificate transparency feed integration to catch newly issued TLS certificates for lookalikes
- MX record analysis to detect domains set up for phishing email infrastructure

---

## Relationship to Case Management

Each finding maps to a `BrandFinding` Pydantic model (`schemas/case.py`) with:
- `risk_level`: the computed risk enum
- `status`: workflow status (`open`, `under_review`, `takedown_requested`, `resolved`, `monitoring`)
- `notes`: free-text field for analyst annotations

This enables downstream integration with ticketing systems and SOAR platforms.
