# Changelog

## 0.2.0 — 2026-10-13

The other two legs of the endeavor, same approach as the message detector.

- **Lookalike-domain watch** (`domainwatch.py`): 13-technique permutation generator,
  pluggable resolver (system DNS, `dig` MX, public RDAP registration date), Layer 2
  scoring plus live / recently-registered / mail-capable evidence, JSON export, and a
  `blocklist=` parameter on `Detector` that blocks senders and links on judged domains.
  CLI `watch`, `analyze --blocklist`.
- **Account-takeover detector** (`ato.py`): per-account baseline, 15 named features,
  verdicts with reasons at every login and sensitive change; `CampaignDetector` for
  shared-IP credential stuffing across accounts, feeding `attacker_ips` back into the
  per-account scorer. Synthetic benchmark with 9 benign day types and 8 attack scripts
  (`ato_bench.py`, CLI `ato-bench`); CLI `ato` for JSONL event logs.
- Publishing: `publish.yml` releases to PyPI on a `v*` tag via Trusted Publishing.
- 61 tests.

## 0.1.0 — 2026-10-09

First complete release of all four layers.

- **Layer 1** (from 0.0.1): UTS #39 confusable skeletons, mixed-script detection,
  Damerau–Levenshtein typo distance, punycode decoding. New: `fold_skeleton` so
  confusables with upper-case prototypes (`0` → `O`) match case-insensitively.
- **Layer 2**: explainable logistic-regression sender scorer over 21 named features
  (lookalike domain, brand-in-subdomain, affix/prefix, TLD swap, leet, free-mail with
  brand display name, invisible characters, role words). Pure Python; weights shipped;
  retrain with `python -m impersonation_detector.train`. Holdout F1 0.99 on synthetic
  senders across 8 brands.
- **Layer 3**: message-intent classification (support impersonation, recruiter scam,
  credential phish, payment redirect). Rule baseline with request-verb and negation-aware
  cues, confusable folding, leet and letter-spacing de-obfuscation. LLM classifier with
  Ollama / OpenAI-compatible / Anthropic backends, nonce-delimited untrusted input,
  independent injection pre-filter, schema validation, fail-closed `unknown`.
- **Pipeline**: noisy-OR risk with Layer 1 and injection floors; allow / warn / hold /
  block; `Middleware.wrap` for send pipelines; JSON output.
- **Layer 4**: 76-message brand-parametric seed corpus, 10 label-preserving adversarial
  variants, per-layer recall / FPR / per-class recall / injection hijack rate / latency.
  `impersonation-detector bench` writes JSON and Markdown reports.
- CLI: `check`, `score`, `analyze`, `bench`, `export-seed`, `skeleton`.

## 0.0.1 — 2026-10-01

- Layer 1 only.
