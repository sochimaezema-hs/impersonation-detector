# impersonation-detector benchmark v0.1.0

Generated 2026-10-09T06:06:15+00:00 on Darwin arm64 / Python 3.12.10. Intent backend: `rule`. Seed corpus: 76 messages (benign 30, credential_phish 10, payment_redirect 8, recruiter_scam 14, support_impersonation 14).

Flagged means: flagged = any L1 match | max L2 score >= 0.5 | L3 label malicious or unknown | pipeline action != allow.

## Recall / FPR by layer configuration and variant

| Config | clean | homoglyph | zero_width | leet | spaced | synonym | injection | link_homoglyph | link_subdomain | sender_homoglyph |
|---|---|---|---|---|---|---|---|---|---|---|
| L1 | R 0.04 / FPR 0.00 | R 0.04 / FPR 0.03 | R 0.04 / FPR 0.03 | R 0.04 / FPR 0.00 | R 0.07 / FPR 0.00 | R 0.04 / FPR 0.00 | R 0.04 | R 0.04 | R 0.04 | R 1.00 |
| L2 | R 0.28 / FPR 0.00 | R 0.33 / FPR 0.03 | R 0.28 / FPR 0.03 | R 0.28 / FPR 0.00 | R 0.28 / FPR 0.00 | R 0.28 / FPR 0.00 | R 0.28 | R 0.50 | R 0.52 | R 1.00 |
| L3 | R 0.98 / FPR 0.00 | R 0.96 / FPR 0.00 | R 0.98 / FPR 0.00 | R 0.83 / FPR 0.00 | R 0.98 / FPR 0.00 | R 0.89 / FPR 0.00 | R 0.98 | R 0.98 | R 0.98 | R 0.98 |
| L1+L2 | R 0.28 / FPR 0.00 | R 0.33 / FPR 0.03 | R 0.28 / FPR 0.03 | R 0.28 / FPR 0.00 | R 0.28 / FPR 0.00 | R 0.28 / FPR 0.00 | R 0.28 | R 0.50 | R 0.52 | R 1.00 |
| L1+L2+L3 | R 1.00 / FPR 0.00 | R 0.98 / FPR 0.03 | R 1.00 / FPR 0.03 | R 0.94 / FPR 0.00 | R 1.00 / FPR 0.00 | R 0.94 / FPR 0.00 | R 1.00 | R 1.00 | R 1.00 | R 1.00 |

## Per-class recall (clean) and injection hijack

| Config | credential_phish | payment_redirect | recruiter_scam | support_impersonation | hijacked (injection) | unknown (injection) | p50 ms |
|---|---|---|---|---|---|---|---|
| L1 | 0.20 | 0.00 | 0.00 | 0.00 | 0 | 0 | 0.27 |
| L2 | 0.20 | 0.12 | 0.00 | 0.71 | 0 | 0 | 0.12 |
| L3 | 1.00 | 1.00 | 1.00 | 0.93 | 0 | 0 | 0.32 |
| L1+L2 | 0.20 | 0.12 | 0.00 | 0.71 | 0 | 0 | 0.38 |
| L1+L2+L3 | 1.00 | 1.00 | 1.00 | 1.00 | 0 | 0 | 0.73 |

## Variants

- **clean**: unmodified seed message
- **homoglyph**: one confusable glyph in cue words, brand, link hosts
- **zero_width**: zero-width space inside cue words and brand
- **leet**: digit substitutions in cue words
- **spaced**: cue words letter-spaced
- **synonym**: cue words paraphrased from a fixed dictionary
- **injection**: prompt-injection text appended to the body (malicious only; recall)
- **link_homoglyph**: one confusable glyph in each link host (malicious only; recall)
- **link_subdomain**: brand domain embedded as a subdomain of attacker host (malicious only; recall)
- **sender_homoglyph**: sender domain is a confusable of the brand's domain (malicious only; recall)
