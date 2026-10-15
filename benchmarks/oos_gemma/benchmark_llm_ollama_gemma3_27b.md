# impersonation-detector benchmark v0.2.0

Generated 2026-10-15T02:48:23+00:00 on Darwin arm64 / Python 3.12.10. Intent backend: `llm:ollama/gemma3:27b`. Seed corpus: 76 messages (benign 30, credential_phish 10, payment_redirect 8, recruiter_scam 14, support_impersonation 14).

Flagged means: flagged = any L1 match | max L2 score >= 0.5 | L3 label malicious or unknown | pipeline action != allow.

## Recall / FPR by layer configuration and variant

| Config | clean | homoglyph | zero_width | leet | spaced | synonym | injection | link_homoglyph | link_subdomain | sender_homoglyph |
|---|---|---|---|---|---|---|---|---|---|---|
| L3 | R 1.00 / FPR 0.17 | – | – | – | – | – | – | – | – | – |
| L1+L2+L3 | R 1.00 / FPR 0.17 | – | – | – | – | – | – | – | – | – |

## Per-class recall (clean) and injection hijack

| Config | credential_phish | payment_redirect | recruiter_scam | support_impersonation | hijacked (injection) | unknown (injection) | p50 ms |
|---|---|---|---|---|---|---|---|
| L3 | 1.00 | 1.00 | 1.00 | 1.00 | 0 | 0 | 0.03 |
| L1+L2+L3 | 1.00 | 1.00 | 1.00 | 1.00 | 0 | 0 | 0.4 |

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
