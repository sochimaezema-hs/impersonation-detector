# impersonation-detector

[![ci](https://github.com/sochimaezema-hs/impersonation-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/sochimaezema-hs/impersonation-detector/actions/workflows/ci.yml)

Layered detection of lookalike senders and **support-team / recruiter impersonation**
in messages — built as middleware for platforms whose users are contacted by
strangers claiming an institutional role (job boards, campus networks, marketplaces).
Zero runtime dependencies; an optional language model for Layer 3.

**Status:** 0.1.0 — all four layers implemented, benchmarked, and tested.

## Why this exists

Enterprise email security protects employees behind a corporate mailbox. The people
most targeted by employment and support-impersonation scams — students and early-career
job seekers — are contacted *inside* consumer platforms, where no mail gateway sees the
message. Existing open-source tools ([dnstwist](https://github.com/elceef/dnstwist),
[confusable_homoglyphs](https://github.com/vhf/confusable_homoglyphs)) work at the
domain level. This project works at the **message and sender** level and ships a
**public benchmark** with adversarial variants so detectors can be compared honestly.

## Install

```bash
pip install impersonation-detector
```

## Sixty-second tour

```python
from impersonation_detector import Detector, Message

det = Detector(["handshake.com", "Handshake", "Handshake Support"])
v = det.analyze(Message(
    body="This is the Handshake Security Team. Unusual login detected. Verify your identity "
         "within 24 hours at https://handshake-verify.app/login or your account will be suspended.",
    sender_name="Handshake Support", sender_address="handshake.support@gmail.com"))
print(v.action, round(v.risk, 2))     # block 1.0
for r in v.reasons: print(" -", r)
#  - L2 sender local_brand_token, display_claims_brand_off_domain, display_brand_token (p=1.00)
#  - L2 link 'handshake-verify.app' domain_brand_affix (p=0.89)
#  - L3 intent credential_phish (conf=0.95; authority_claim, credential_request, link_or_attachment, threat_or_consequence, urgency)
```

```bash
impersonation-detector check "hаndshake.com" -p handshake.com            # Layer 1
impersonation-detector score "Handshake Support <hs.support@gmail.com>" -p handshake.com -p Handshake
impersonation-detector analyze messages.jsonl -p handshake.com -p Handshake --backend ollama
impersonation-detector bench -p handshake.com -p Handshake --out benchmarks/
```

Drop it in front of a send pipeline:

```python
from impersonation_detector import Detector, Middleware
send = Middleware(Detector(protected)).wrap(raw_send)   # blocks, holds for review, or delivers with a verdict
```

## The four layers

| Layer | What it does | Basis | Explains itself by |
| --- | --- | --- | --- |
| **1 Lookalike** | Confusable-skeleton match, mixed-script, typo distance, punycode, against protected names | [Unicode UTS #39](https://www.unicode.org/reports/tr39/) §4–5 | reason tags per match |
| **2 Sender score** | Logistic regression over 21 named features: brand-in-subdomain, affix/prefix domains, TLD swap, leet, free-mail + brand display name, invisible characters, role words | trained on a synthetic generator across 8 brands; holdout F1 0.99 | per-feature contributions |
| **3 Intent** | Labels a message `support_impersonation`, `recruiter_scam`, `credential_phish`, `payment_redirect`, or `benign` with the signals seen | rule baseline (request-verb + negation-aware cues, confusable folding, leet/spacing de-obfuscation) **or** an LLM via Ollama / OpenAI-compatible / Anthropic | signals + rationale |
| **4 Benchmark** | 76-message brand-parametric corpus × 10 label-preserving adversarial variants; per-layer recall, FPR, per-class recall, injection hijack rate, latency | `impersonation-detector bench` | JSON + Markdown reports |

Risk is a noisy-OR of the sender score, the worst link score, and the intent risk, with
floors for a Layer 1 confusable hit (0.85) and a prompt-injection attempt (0.60).
Thresholds: warn 0.30, hold 0.60, block 0.85 — all configurable.

### Layer 3 hardening (OWASP LLM01)

The message is untrusted data. The LLM classifier wraps it in nonce-tagged delimiters and
strips fake closing tags; an **independent regex pre-filter** flags injection attempts
regardless of what the model says; output is schema-validated and a model that answers
"benign" to a message carrying an injection is overruled to `unknown`; unparseable output
fails closed. The rule baseline cannot be hijacked at all, which is why both ship.

## Benchmark results (rule backend, v0.1.0)

Full table: [`benchmarks/benchmark_rule.md`](benchmarks/benchmark_rule.md). Recall on
46 malicious messages / false-positive rate on 30 benign, by variant:

| Config | clean | homoglyph | zero_width | leet | spaced | synonym | injection¹ | link_homoglyph¹ | link_subdomain¹ | sender_homoglyph¹ |
|---|---|---|---|---|---|---|---|---|---|---|
| L1 | 0.04 / 0.00 | 0.04 / 0.03 | 0.04 / 0.03 | 0.04 / 0.00 | 0.07 / 0.00 | 0.04 / 0.00 | 0.04 | 0.04 | 0.04 | **1.00** |
| L2 | 0.28 / 0.00 | 0.33 / 0.03 | 0.28 / 0.03 | 0.28 / 0.00 | 0.28 / 0.00 | 0.28 / 0.00 | 0.28 | 0.50 | 0.52 | 1.00 |
| L3 | 0.98 / 0.00 | 0.96 / 0.00 | 0.98 / 0.00 | 0.83 / 0.00 | 0.98 / 0.00 | 0.89 / 0.00 | 0.98 | 0.98 | 0.98 | 0.98 |
| L1+L2+L3 | **1.00 / 0.00** | 0.98 / 0.03 | 1.00 / 0.03 | 0.94 / 0.00 | 1.00 / 0.00 | 0.94 / 0.00 | 1.00 | 1.00 | 1.00 | 1.00 |

¹ malicious-only variants (recall). Injection hijack rate for the rule backend: 0 of 46.

**Read these numbers honestly.** The seed corpus is also the development set for the
rule baseline, so its clean-corpus numbers are in-sample. The out-of-sample test is
`impersonation-detector paraphrase`, which has a model you choose rewrite every message,
and the `--extra` flag, which benchmarks against those rewrites. Layers 1 and 2 only
know the protected brand, so their low recall on scams that never mention it is expected;
their job is the sender, Layer 3's is the request.

What the benchmark already shows:

- **UTS #39 has gaps.** Cyrillic `т` and Greek `κ` have no Latin confusable mapping, so a
  skeleton-only detector misses `hаndsһaκe`; the mixed-script feature in Layer 2 closes it.
- **Regex cues die on cheap obfuscation.** Before confusable folding and de-spacing the rule
  baseline lost 37 points of recall to one swapped glyph; after, 2.
- **Negation matters.** "Never send bank details by email" from a real employer must not be
  a payment request.

## Reproduce

```bash
git clone https://github.com/sochimaezema-hs/impersonation-detector && cd impersonation-detector
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
pytest -q                                                   # 48 tests
python -m impersonation_detector.train                      # retrain Layer 2 (3 s, pure Python)
impersonation-detector bench -p handshake.com -p Handshake -p "Handshake Support" --out benchmarks/
impersonation-detector bench ... --backend ollama --model llama3.1:8b     # LLM Layer 3
impersonation-detector paraphrase ... --backend anthropic --out benchmarks/para.jsonl
impersonation-detector bench ... --extra benchmarks/para.jsonl
```

Swap in your own brand: every command takes `-p` names; the seed corpus is templated on
the first protected domain and brand.

## Limitations

- Protected names are a list, not a graph: an organization with many brands supplies them all.
- The public-suffix handling is a short built-in list, adequate for features, not for policy.
- The synthetic generator for Layer 2 encodes the techniques we know; novel ones need new
  features, which is why every feature is named and the trainer is 150 lines.
- The seed corpus is small and English-only by design (each example is hand-written and
  defensible). Contributions of labelled real-world messages, with consent, are welcome.
- A homonymous business ("Firm Handshake Consulting") will score as a lookalike. That is a
  product decision (warn, don't block) rather than a bug the detector can resolve alone.

## Prior work

UTS #39 (Unicode Consortium); Holgers, Watson & Gribble, *Cutting through the Confusion:
A Measurement Study of Homograph Attacks* (USENIX ATC 2006); Hu, Jan, Wang & Wang,
*Assessing Browser-level Defense against IDN-based Phishing* (USENIX Security 2021);
OWASP *Top 10 for LLM Applications* (LLM01 Prompt Injection); Fraud-R1 (arXiv 2502.12904)
and E-PhishGen (AISec '25) for LLM-generated phishing benchmarks, which are email-centric
where this corpus is platform-message-centric. Unicode data files are redistributed under
the [Unicode License](https://www.unicode.org/license.txt).

## Citation

See [`CITATION.cff`](CITATION.cff).

## License

MIT
