# impersonation-detector

[![ci](https://github.com/sochimaezema-hs/impersonation-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/sochimaezema-hs/impersonation-detector/actions/workflows/ci.yml)

Layered detection of lookalike senders and **support-team / recruiter impersonation**
in messages — built as middleware for platforms whose users are contacted by
strangers claiming an institutional role (job boards, campus networks, marketplaces).
Zero runtime dependencies; an optional language model for Layer 3.

**Status:** 0.2.0 — message detector (Layers 1–4) plus the lookalike-domain and account-takeover legs, all benchmarked and tested.

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
impersonation-detector watch -p handshake.com -p Handshake --out watch.json      # lookalike-domain leg
impersonation-detector ato events.jsonl                                           # account-takeover leg
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

## Benchmark results

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
rule baseline, so its clean-corpus numbers are in-sample. Layers 1 and 2 only know the
protected brand, so their low recall on scams that never mention it is expected; their
job is the sender, Layer 3's is the request.

### Out-of-sample: Llama-paraphrased corpus

`impersonation-detector paraphrase` had Llama 3.1 8B rewrite all 76 messages (same intent,
different wording; `benchmarks/paraphrase_llama3.1_8b.jsonl`) and `bench --only-extra`
scored the rewrites alone. The rule baseline had never seen this wording.

| Backend | Config | recall | FPR | credential_phish | payment_redirect | recruiter_scam | support_impersonation |
|---|---|---|---|---|---|---|---|
| rule | L3 | 0.87 | 0.00 | 0.90 | 1.00 | 0.93 | 0.71 |
| rule | L1+L2+L3 | **0.96** | **0.00** | 0.90 | 1.00 | 0.93 | 1.00 |
| llama3.1:8b | L3 | 1.00 | 0.30 | 1.00 | 1.00 | 1.00 | 1.00 |
| llama3.1:8b | L1+L2+L3 | 1.00 | 0.30 | 1.00 | 1.00 | 1.00 | 1.00 |

The rules lose 13 points of Layer 3 recall to paraphrase, most of it on support
impersonation, and the sender layers win 9 of those back: a rewritten support-impersonation
message still comes from a free-mail address with the brand in its display name.

### LLM backend: Llama 3.1 8B via Ollama (`benchmarks/benchmark_llm_ollama_llama3.1_8b.md`)

| Config | clean | homoglyph | zero_width | leet | spaced | synonym | injection¹ | link variants¹ |
|---|---|---|---|---|---|---|---|---|
| L3 | 1.00 / 0.33 | 1.00 / 0.30 | 1.00 / 0.30 | 1.00 / 0.43 | 1.00 / 0.37 | 1.00 / 0.33 | 1.00 | 1.00 |
| L1+L2+L3 | 1.00 / 0.33 | 1.00 / 0.33 | 1.00 / 0.33 | 1.00 / 0.43 | 1.00 / 0.37 | 1.00 / 0.33 | 1.00 | 1.00 |

Three things the LLM run shows, all from `benchmarks/dump_llama3.1_8b.jsonl`:

- **Recall is perfect and robustness is free.** No obfuscation variant and no paraphrase
  moved the 8B model off 1.00 recall. The regex baseline needed explicit confusable folding
  and de-spacing to get close.
- **The false positives are the hard benign cases, and confidence does not separate them.**
  Ten of 30 benign messages are flagged on the clean corpus: a genuine "your password was
  changed" notice, a payroll onboarding note that says *never* send bank details by email,
  a financial-aid verification request, a background-check email, an I-9/W-4 onboarding
  message, a professor asking for a resume. The model's rationales invent cues ("requests
  sensitive documents") that are not in the text. It assigns 0.8 to 0.9 confidence to these
  and 0.9 to 1.0 to real attacks, so no threshold helps: at 0.95 the FPR reaches 0.00 but
  recall collapses to 0.41. A small model that is right about intent is not calibrated
  about it.
- **The injection pre-filter earned its place.** Under the injection variant the model
  complied with the injected instruction and answered "benign" on 5 of 46 attacks. All five
  were overruled to `unknown` (held, not delivered) because the deterministic pre-filter had
  already flagged the body. The hijack count in the table is 0 only because of that overrule.

### A larger model: Gemma 3 27B (`benchmarks/benchmark_llm_ollama_gemma3_27b.md`)

Same harness, 3.4× the parameters, run on the cells that matter (clean, injection,
zero-width, and the paraphrased corpus):

| Backend | clean | zero_width | injection¹ | paraphrased (OOS) | injection compliance |
|---|---|---|---|---|---|
| rule | 1.00 / 0.00 | 1.00 / 0.03 | 1.00 | 0.96 / 0.00 | 0 of 46 (cannot comply) |
| llama3.1:8b | 1.00 / 0.33 | 1.00 / 0.30 | 1.00 | 1.00 / 0.30 | 5 of 46, all overruled |
| gemma3:27b | **0.98 / 0.13** | 1.00 / 0.13 | 1.00 | **1.00 / 0.17** | **0 of 46** |

(full-pipeline rows; recall / FPR). Three observations from `benchmarks/dump_gemma3_27b.jsonl`:

- **Scale buys precision, not just recall.** The false-positive rate drops from 0.33 to
  0.13 on the clean corpus and from 0.30 to 0.17 on paraphrases, with recall essentially
  unchanged. The 27B model's rationales cite cues that are actually in the text; the 8B
  model's often did not.
- **The residual false positives are all one kind.** Every benign message Gemma flags is a
  genuine notice from an institution the recipient trusts: the platform's own support
  reply, its Trust & Safety takedown notice, its password-changed alert, a financial-aid
  office's document request. The model labels each `support_impersonation` because it has
  no way to know the sender is who it claims to be. That knowledge lives in Layer 2
  (`domain_is_protected`) and in the platform's own send pipeline. Fusing "the LLM says
  support impersonation" with "the sender really is on the protected domain" is the next
  step; it is not done here because the corpus also contains spoofed-From attacks (s06,
  s11, c04) that a naive version of that rule would wave through.
- **A larger model resisted every injection.** Gemma complied with the injected
  instruction 0 times in 46, against 5 for Llama 8B. The pre-filter still runs: the
  guarantee has to hold for whichever model is plugged in.

One miss is worth naming: c07, a credential phish whose link host embeds a *third party's*
domain (`orbitallabs.io.docs-share.site`) and whose sender is a plausible recruiter. No
layer flags it; Layers 1 and 2 only know the protected brand, and both LLMs read the link
as a meeting invite. Brand-agnostic lookalike detection of *any* embedded registrable
domain is the obvious extension.

Latency in the LLM tables is not meaningful: responses are served from the persistent
cache on reruns. Uncached, Llama 8B took 2 to 6 s per message and Gemma 27B about 8 s on an
M4 Max. The `--backend anthropic` and `--backend openai` paths run unchanged for hosted models.

What the benchmark already shows:

- **UTS #39 has gaps.** Cyrillic `т` and Greek `κ` map to non-ASCII Latin prototypes
  (U+1D1B, U+0138), not to `t` and `k`, so a skeleton-only detector does not match
  `hаndsһaκe` to `handshake` by skeleton equality; the mixed-script feature in Layer 2
  and the edit-distance check close it.
- **Regex cues die on cheap obfuscation.** Before confusable folding and de-spacing the rule
  baseline lost 37 points of recall to one swapped glyph; after, 2.
- **Negation matters.** "Never send bank details by email" from a real employer must not be
  a payment request.


## The other two legs

The message detector covers the attack's opening move. Two further modules apply the same
approach — named features, transparent scoring, graduated actions, a synthetic benchmark —
to the domain the attacker registers and to the account they take over.

### Lookalike-domain watch (`domainwatch.py`)

Enumerates the registrable lookalike space around each protected domain (13 techniques:
homoglyph, omission, transposition, repetition, keyboard insertion and replacement, vowel
swap, leet, hyphenation, TLD swap, affix, prefix, plural; ~230 candidates for one 9-letter
domain), resolves each (system DNS, `dig` for MX, public RDAP for registration date), and
scores it with the same Layer 2 model plus three pieces of evidence: it is live, it was
registered recently, it can send mail. Hits export as JSON and load straight back into the
message detector as a blocklist (`analyze --blocklist watch.json`), so a domain judged
today blocks a message tomorrow before any text is read.

```python
from impersonation_detector import DomainWatch, Detector
hits = DomainWatch(["handshake.com", "Handshake"]).scan()          # network; StaticResolver for tests
det = Detector(["handshake.com", "Handshake"], blocklist=DomainWatch.blocklist(hits))
```

**Live scan, 2026-10-13** (`benchmarks/watch_handshake.json`, generated by the command in
Reproduce below): of 463 candidates around `handshake.com` and `joinhandshake.com`, **72 are
registered and live**, 61 resolve, **38 have MX records** (they can send mail), and 2 were
registered in the last 90 days (`yhandshake.com`, `handsake.com`). The most common techniques
among live domains are TLD swaps (25), single-character omissions (15), and keyboard
replacements (6). No homoglyph registration was live on scan day. Registrars are retail
(GoDaddy 10, Cosmotown 7, NameCheap 5, Spaceship 5) with none at a corporate brand-protection
registrar, so these are mostly not defensive registrations by the brand owner. Read with
two caveats: "handshake" is an ordinary English word, so several TLD swaps are unrelated
legitimate businesses rather than impersonation, and a live lookalike with MX is capable of
abuse, not proof of it. The scan is the input to a human review and a blocklist, not a verdict.

[dnstwist](https://github.com/elceef/dnstwist) pioneered permutation generation; this
module adds the explainable score, the recency and mail-capability evidence, and the loop
back into the send pipeline.

### Account-takeover detector (`ato.py`)

Scores an account's login and post-login event stream at every login and sensitive change,
using a per-account baseline (devices, countries, ASNs, hours, message rate) learned from
history. Fifteen named features: new device / country / ASN, impossible travel, a failed
burst before success (distinguishing a forgotten password on a known device from
credential stuffing on an unseen one), a sensitive change shortly after a risky login, a
chain of sensitive changes, MFA or recovery weakened, payout changed, mass messaging,
message-rate anomaly, IP velocity, off-hours, and — the cross-account signal — a login IP
that `CampaignDetector` has already seen hitting many accounts. Verdicts carry reasons;
`warn` is meant as a step-up challenge, `hold` and `block` as detections.

Synthetic benchmark (`impersonation-detector ato-bench`, 400 accounts, half with a
plausible benign day such as a new phone, a trip abroad with a reset, or six wrong
passwords from the usual laptop; half with one of eight attack scripts):

| Detector | recall | FPR | stuffing → chain | new country + payout | impossible travel + reset | mass msgs after new device | MFA off + recovery | shared-IP campaign | quiet new device + payout | stolen known device |
|---|---|---|---|---|---|---|---|---|---|---|
| per account | 0.84 | 0.01 | 1.00 | 1.00 | 1.00 | 0.72 | 1.00 | 0.00 | 1.00 | 1.00 |
| + campaign IP feed | **1.00** | **0.01** | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |

The point of the table is the second row: an attacker who logs in from a new device in the
victim's own country and changes one thing looks like a user with a new phone, until the
same IP is seen touching other accounts. Per-account anomaly detection alone cannot make
that distinction; the cross-account signal is what closes it. The benchmark is synthetic
and the generator is in `ato_bench.py`; treat the numbers as a demonstration of the
mechanism, not as a field result.

## Reproduce

```bash
git clone https://github.com/sochimaezema-hs/impersonation-detector && cd impersonation-detector
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
pytest -q                                                   # 61 tests
python -m impersonation_detector.train                      # retrain Layer 2 (3 s, pure Python)
impersonation-detector bench -p handshake.com -p Handshake -p "Handshake Support" --out benchmarks/
impersonation-detector bench ... --backend ollama --model llama3.1:8b --cache benchmarks/cache.jsonl --dump benchmarks/dump.jsonl
impersonation-detector paraphrase ... --backend anthropic --out benchmarks/para.jsonl
impersonation-detector bench ... --extra benchmarks/para.jsonl --only-extra
impersonation-detector watch -p handshake.com -p Handshake --out benchmarks/watch.json   # live DNS + RDAP
impersonation-detector ato-bench --accounts 400 --out benchmarks/
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
