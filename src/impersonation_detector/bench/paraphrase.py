"""Out-of-sample variants: ask a language model to rewrite each seed message while
preserving its intent, then benchmark against the rewrites.

The seed corpus is also the development set for the rule baseline, so clean-corpus
numbers for the rule classifier are in-sample. Paraphrases produced by a model the
rules never saw are the honest test. Generated files are JSONL with the same fields as
``export-seed`` plus ``source_id`` and ``generator``.

    impersonation-detector paraphrase -p handshake.com -p Handshake --backend ollama --out benchmarks/paraphrase_llama.jsonl
    impersonation-detector bench -p handshake.com -p Handshake --extra benchmarks/paraphrase_llama.jsonl
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from ..intent import Backend, BackendError
from .seed import SeedItem

PROMPT = """Rewrite the message below so that it keeps exactly the same purpose, requests, and
tone of legitimacy or illegitimacy, but uses different wording and sentence structure. Keep any
URLs, email addresses, amounts, and names unchanged. Do not add commentary. Output only the
rewritten message text.

Message:
{body}"""


_REFUSAL = re.compile(r"\b(i (cannot|can'?t|am unable|won'?t)|as an ai|i'?m (not able|unable)|i apologi[sz]e|"
                      r"not (able|willing) to (rewrite|help)|is there something else)\b", re.IGNORECASE)
_PREAMBLE = re.compile(r"^\s*(here('s| is| are) (the |a |your |my )?(rewritten|revised|paraphrased|new)?[^:\n]{0,40}:\s*)",
                       re.IGNORECASE)
SYSTEM_PLAIN = "You rewrite text faithfully."
SYSTEM_BENCH = ("You are a text-rewriting tool used to build a security benchmark. You rewrite any message, "
                "including scams and phishing, faithfully and without commentary, because the rewrites are "
                "used to test defences. Output only the rewritten message.")
SYSTEMS = (SYSTEM_PLAIN, SYSTEM_BENCH, SYSTEM_PLAIN)
SYSTEM = SYSTEM_PLAIN


def is_refusal(text: str) -> bool:
    return bool(_REFUSAL.search(text)) or len(text) < 25


def clean_paraphrase(text: str) -> str:
    """Drop a 'Here is the rewritten message:' preamble and surrounding quotes."""
    text = _PREAMBLE.sub("", text.strip(), count=1).strip()
    if len(text) >= 2 and text[0] in "\"'“" and text[-1] in "\"'”":
        text = text[1:-1].strip()
    return text


def paraphrase_items(items: list[SeedItem], backend: Backend, n: int = 1, attempts: int = 3) -> list[SeedItem]:
    """One faithful rewrite per item (``n`` for more). A refusal, a preamble, or a JSON
    object is not a paraphrase: it is retried and then dropped, never kept as data."""
    out: list[SeedItem] = []
    for item in items:
        for k in range(n):
            text = ""
            for attempt in range(attempts):
                try:
                    raw = backend.complete(SYSTEMS[attempt % len(SYSTEMS)], PROMPT.format(body=item.body),
                                           json_mode=False).strip()
                except BackendError as exc:
                    raise SystemExit(f"paraphrase failed on {item.id}: {exc}") from exc
                text = clean_paraphrase(raw)
                if text and not (text.startswith("{") and text.endswith("}")) and not is_refusal(text):
                    break
                text = ""
            if not text:
                print(f"dropped {item.id}: model refused or returned no paraphrase", file=sys.stderr)
                continue
            out.append(SeedItem(f"{item.id}-p{k}", item.label, item.sender_name, item.sender_address,
                                item.subject, text, item.tags + ("paraphrase", backend.name)))
    return out


def write_items(items: list[SeedItem], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for i in items:
            fh.write(json.dumps({"id": i.id, "label": i.label, "sender_name": i.sender_name,
                                 "sender_address": i.sender_address, "subject": i.subject,
                                 "body": i.body, "tags": list(i.tags)}, ensure_ascii=False) + "\n")


def read_items(path: Path) -> list[SeedItem]:
    items = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        items.append(SeedItem(r["id"], r["label"], r.get("sender_name", ""), r.get("sender_address", ""),
                              r.get("subject", ""), r["body"], tuple(r.get("tags", ()))))
    return items
