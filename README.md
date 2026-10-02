# impersonation-detector

Detect lookalike domains, spoofed senders, and brand/support-team impersonation
in messages — built as middleware for messaging platforms that serve people
scammers target.

**Status:** pre-alpha (Layer 1). See the roadmap below.

## Why

Impersonation is the opening move of most scams: a sender that looks like your
support team, a domain one glyph off from the real one, a "recruiter" using a
brand's name. Existing open-source tools ([dnstwist](https://github.com/elceef/dnstwist),
[confusable_homoglyphs](https://github.com/vhf/confusable_homoglyphs)) work at
the *domain* level. This project works at the *message and sender* level —
display names, email local parts, in-app message content — and is designed to
sit in front of a platform's own send pipeline.

## Install

```bash
pip install impersonation-detector
```

## Use

```python
from impersonation_detector import LookalikeDetector

det = LookalikeDetector(["handshake.com", "Handshake Support"])
for m in det.check("hаndshake.com"):   # Cyrillic а
    print(m.protected, m.reasons)
# handshake.com ('confusable-skeleton', 'mixed-script:Cyrillic+Latin')
```

```bash
impersonation-detector check "hаndshake.com" "handshkae.com" -p handshake.com
impersonation-detector skeleton "pаypal"
```

## What Layer 1 does

| Check | Basis |
| --- | --- |
| Confusable skeleton match | [Unicode UTS #39 §4](https://www.unicode.org/reports/tr39/) `confusables.txt` |
| Mixed-script detection | UTS #39 §5 Highly Restrictive profile, `Scripts.txt` |
| Typo distance | Damerau–Levenshtein (OSA), threshold scaled by name length |
| Punycode decoding | `xn--` labels judged by what they display |

Every match carries its reasons so a downstream system can explain or weight it.

## Roadmap

- **Layer 2** — learned impersonation scorer (glyph visual similarity,
  display-name/domain mismatch, brand-term proximity).
- **Layer 3** — message-intent classification with a local LLM for
  support-team and fake-recruiter impersonation, hardened against prompt
  injection ([OWASP LLM01](https://genai.owasp.org/)).
- **Layer 4** — public benchmark of AI-generated lookalike and phishing
  variants, with per-layer recall.
- Measurement study of lookalike registrations against career, university,
  and student-finance domains.

## Prior work

This builds on UTS #39 and on the measurement literature on IDN homograph
attacks — Holgers, Watson & Gribble (USENIX ATC 2006); Hu, Jan, Wang & Wang,
*Assessing Browser-level Defense against IDN-based Phishing* (USENIX Security
2021). Unicode data files are redistributed under the
[Unicode License](https://www.unicode.org/license.txt).

## License

MIT
