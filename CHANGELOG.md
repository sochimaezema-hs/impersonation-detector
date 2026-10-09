# Changelog

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
