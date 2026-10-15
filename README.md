# impersonation-detector

[![ci](https://github.com/sochimaezema-hs/impersonation-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/sochimaezema-hs/impersonation-detector/actions/workflows/ci.yml)

Layered detection of lookalike senders and **support-team / recruiter impersonation**
in messages — built as middleware for platforms whose users are contacted by
strangers claiming an institutional role (job boards, campus networks, marketplaces).
Zero runtime dependencies; an optional language model for Layer 3.

**Status:** 0.3.0 — message detector (Layers 1–4 with Layer 2→3 fusion) plus the lookalike-domain and account-takeover legs, all benchmarked and tested.

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

## Benchmark results (v0.3.0)

Full pipeline (Layers 1+2+3 with fusion), recall on the 46 malicious messages / false-positive
rate on the 30 benign, by Layer 3 backend. Source files are named in each row.

**Development sets** (used while iterating on cues, fusion, and the benchmark itself):

| Layer 3 backend | seed corpus, 10 variants | Llama-paraphrased (75) | Gemma-paraphrased #1 (76) | injection compliance | files |
|---|---|---|---|---|---|
| rule (no model) | **1.00 / 0.00** on every variant | **1.00 / 0.00** | **1.00 / 0.00** | cannot comply | `benchmark_rule.*`, `oos_rule/`, `heldout_rule/` |
| Llama 3.1 8B | 1.00 / 0.03 (clean, zero-width, injection) | 1.00 / 0.03 | 1.00 / 0.07 | 6 of 46, all overruled | `benchmark_llm_ollama_llama3.1_8b.*`, `oos_llama3_1_8b/`, `heldout_llama3_1_8b/` |
| Gemma 3 27B | **1.00 / 0.00** (clean, zero-width, injection) | **1.00 / 0.00** | **1.00 / 0.00** | 0 of 46 | `benchmark_llm_ollama_gemma3_27b.*`, `oos_gemma3_27b/`, `heldout_gemma3_27b/` |

**Held-out set, evaluated once after every change was frozen** (`heldout2_gemma3_27b.jsonl`:
Gemma rewrote all 76 messages in a different register, casual chat where the original was
formal and vice versa, sentence order changed, every URL, address, amount and name kept):

| Layer 3 backend | recall | FPR | misses | false positives | files |
|---|---|---|---|---|---|
| rule (no model) | **1.00** | 0.03 | none | b08 | `heldout2_rule/` |
| Llama 3.1 8B | **1.00** | 0.10 | none | b08, b17, b23 | `heldout2_llama3_1_8b/` |
| Gemma 3 27B | **1.00** | **0.03** | none | b08 | `heldout2_gemma3_27b/` |

No backend misses an attack on the frozen set. The one false positive all three share is a
casual recruiter writing "You'll earn $30/hour working about 40 hours a week, and we provide
the laptop": the too-good-to-be-true cue ("earn $") fires, which vetoes the fusion discount,
and both models also read it as a scam. Llama additionally holds the password-changed notice
(b17) and a financial-aid office's document request (b23) because it reports a credential ask
on both; see "What the fusion does" for why a verified sender with a model-claimed ask is held
rather than waved through. Unfused Layer 3 alone on this set: rule 0.83 / 0.03, Llama 1.00 /
0.47, Gemma 1.00 / 0.07, which is the clearest statement of what the fusion is worth.

**How to read this.** The development-set zeros are the product of iterating: every miss and
false positive the benchmark surfaced was traced to a cause and fixed in the detector, the
fusion rules, or (twice) the benchmark itself. The first Gemma-paraphrased corpus was meant to
be held out and instead exposed a design flaw in the fusion gate (below), so it became a
development set too and a second corpus was generated in a different register. The frozen
table is the number to quote. The LLM backends themselves were never tuned. The seed corpus
is small (76 messages) and English-only by design; a platform deploying this should expect
to re-run the benchmark on its own labelled traffic.

### What each layer alone sees

The unfused rows (`benchmark_rule.md`) show why the layers exist. Layer 1 alone catches 4% of
attacks (it only knows confusables of the brand) but 100% of sender-domain homographs; Layer 2
alone 30% (it only knows the brand) but 100% of embedded and lookalike link hosts; the rule
Layer 3 alone 100% on the clean corpus and 98% on the hardest variants, falling to 91% on
paraphrases; the fused pipeline closes each of those gaps with the other layers' evidence.
The LLM Layer 3 alone is the opposite shape: recall 1.00 everywhere with a false-positive
rate of 0.40 (Llama 8B) or 0.03 (Gemma 27B), which fusion brings to 0.00.

### What the fusion does

Layers 1 and 2 hand Layer 3 structured sender facts: whether the sender's domain is the
platform's own, a university's, free webmail, a lookalike, or an unrelated organisation;
whether the display name claims the brand; whether link hosts stay on the platform, go to the
sender's own domain, imitate the platform, or hide another organisation's domain inside their
own. The LLM reads them with an explicit platform policy (the platform's real support never
asks for codes, passwords, or payment). The rule classifier reads them directly.

Then a deterministic discount applies to an impersonation verdict when four things hold. The
sender is a verified institution, an organisation on its own domain that Layer 2 finds
unremarkable (score below 0.3, which excludes lure-worded throwaway domains such as
`hr-portal.co` or `auth-check.top`), or a webmail peer. Nothing sensitive is asked for, as
judged by three vetoes: the cue detector over de-obfuscated text, the model's label when it is
an ask type (credential phish, payment redirect), and, for verified senders only, the model's
own signal list. Links go nowhere the sender does not control. And the body does not claim the
platform's authority from a non-platform address. Risk components below 0.20 (above the 99th
percentile of Layer 2's score on 3,200 synthetic benign senders) do not combine, so an
ordinary organisation domain plus a role word plus a discounted intent cannot sum to a warning.

Two design choices came out of the held-out run rather than the development sets. The first
version of the gate let the deterministic cues alone decide whether a sensitive ask was present,
and a cue list cannot keep up with a paraphrasing model: six messages that both LLMs had
labelled correctly ("respond with the six-digit code", "purchase the initial kit") were
discounted because the regexes did not recognise the wording. The model's own ask-type label
now vetoes the discount. The second is the lure-domain feature: an attacker's "own domain" is
usually `secure-portal.app`, not `acmerobotics.com`, and Layer 2 can tell them apart.

What the fusion costs: Llama 8B still insists that a genuine "your password was changed"
notice from the platform is a credential phish, and because a verified sender whose message the
model reads as asking for credentials is held for review rather than waved through, that notice
is held. That is the designed outcome for a weak model and the only false positive it keeps.
Gemma 27B, given the same facts, labels every genuine platform notice benign on its own. The
spoofed-From attacks in the corpus (the real platform domain in the From, a lookalike link or a
request for a one-time code in the body) stay caught because each has a sensitive ask or a
foreign link.

### Findings the benchmark produced

- **UTS #39 has gaps.** Cyrillic `т` and Greek `κ` map to non-ASCII Latin prototypes
  (U+1D1B, U+0138), not to `t` and `k`, so a skeleton-only detector does not match
  `hаndsһaκe` to `handshake` by skeleton equality; the mixed-script feature in Layer 2
  and the edit-distance check close it. ASCII confusables run the other way: `rn` for `m`
  (`Venrno`) is folded by UTS #39 *toward* `rn`, so the detector needs an explicit view.
- **Regex cues die on cheap obfuscation** until the text is normalized: confusable folding,
  two leet readings (`1` as `l` and as `i`), de-spacing. Before those views the rule
  baseline lost 37 points of recall to one swapped glyph.
- **Negation has a conditional exception.** "Never send bank details by email" is advice;
  "your privileges will be revoked if you don't verify your account" is a threat. The first
  version of the negation guard treated both as negated requests and discounted a support
  impersonation that all three backends had correctly labelled.
- **Small models invent evidence.** Llama 8B's rationales cite cues absent from the text and
  its confidence does not separate its errors (0.8–0.9 on false positives, 0.9–1.0 on real
  attacks). Gemma 27B's cues are real and its confidence is usable. Neither should be the
  sole judge of whether a sender is who it claims to be: that is Layer 2's knowledge.
- **The pre-filter earns its place.** Under the injection variant the 8B model complied with
  the injected instruction on 6 of 46 attacks; every one was overruled because the
  deterministic pre-filter had already flagged the body. The 27B model complied 0 times.
  The guarantee has to hold for whichever model is plugged in.
- **Brand-agnostic deception exists.** A credential phish whose link host embeds a *third
  party's* domain (`orbitallabs.io.docs-share.site`) from a plausible recruiter was missed by
  every layer in v0.2.0; a public TLD as an interior host label is now a Layer 2 feature and
  a Layer 1 floor.
- **Benchmarks have bugs too.** Two false positives in earlier tables were the benchmark
  mutating the platform's own link inside a benign message; a paraphrase set shrank to 25
  rows because the refusal filter mistook "Here is the rewritten message:" for a refusal.
  Both are fixed and documented in the changelog.

Latency in the LLM tables is not meaningful: responses are served from the persistent cache
on reruns. Uncached, Llama 8B took 2 to 6 s per message and Gemma 27B about 8 s on an M4
Max. The `--backend anthropic` and `--backend openai` paths run unchanged for hosted models.

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
pytest -q                                                   # 78 tests
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
