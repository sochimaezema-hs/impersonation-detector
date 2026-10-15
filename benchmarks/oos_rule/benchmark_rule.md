# impersonation-detector benchmark v0.3.0

Generated 2026-10-15T09:09:35+00:00 on Darwin arm64 / Python 3.12.10. Intent backend: `rule`. Seed corpus: 75 messages (benign 30, credential_phish 10, payment_redirect 8, recruiter_scam 13, support_impersonation 14).

Flagged means: flagged = any L1 match | max L2 score >= 0.5 | L3 label malicious or unknown | pipeline action != allow.

## Recall / FPR by layer configuration and variant

| Config | clean | homoglyph | zero_width | leet | spaced | synonym | injection | link_homoglyph | link_subdomain | sender_homoglyph |
|---|---|---|---|---|---|---|---|---|---|---|
| L1 | R 0.04 / FPR 0.00 | – | – | – | – | – | – | – | – | – |
| L2 | R 0.60 / FPR 0.00 | – | – | – | – | – | – | – | – | – |
| L3 | R 0.91 / FPR 0.00 | – | – | – | – | – | – | – | – | – |
| L1+L2 | R 0.60 / FPR 0.00 | – | – | – | – | – | – | – | – | – |
| L1+L2+L3 | R 1.00 / FPR 0.00 | – | – | – | – | – | – | – | – | – |

## Per-class recall (clean) and injection hijack

| Config | credential_phish | payment_redirect | recruiter_scam | support_impersonation | hijacked (injection) | unknown (injection) | p50 ms |
|---|---|---|---|---|---|---|---|
| L1 | 0.20 | 0.00 | 0.00 | 0.00 | 0 | 0 | 0.3 |
| L2 | 0.90 | 0.38 | 0.08 | 1.00 | 0 | 0 | 0.15 |
| L3 | 1.00 | 1.00 | 1.00 | 0.71 | 0 | 0 | 0.58 |
| L1+L2 | 0.90 | 0.38 | 0.08 | 1.00 | 0 | 0 | 0.42 |
| L1+L2+L3 | 1.00 | 1.00 | 1.00 | 1.00 | 0 | 0 | 1.24 |

## Variants

- **clean**: unmodified seed message
- **homoglyph**: one confusable glyph in cue words and brand (body text; URLs untouched)
- **zero_width**: zero-width space inside cue words and brand
- **leet**: digit substitutions in cue words
- **spaced**: cue words letter-spaced
- **synonym**: cue words paraphrased from a fixed dictionary
- **injection**: prompt-injection text appended to the body (malicious only; recall)
- **link_homoglyph**: one confusable glyph in each link host (malicious only; recall)
- **link_subdomain**: brand domain embedded as a subdomain of attacker host (malicious only; recall)
- **sender_homoglyph**: sender domain is a confusable of the brand's domain (malicious only; recall)
