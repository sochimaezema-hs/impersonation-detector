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
from pathlib import Path

from ..intent import Backend, BackendError
from .seed import SeedItem

PROMPT = """Rewrite the message below so that it keeps exactly the same purpose, requests, and
tone of legitimacy or illegitimacy, but uses different wording and sentence structure. Keep any
URLs, email addresses, amounts, and names unchanged. Do not add commentary. Output only the
rewritten message text.

Message:
{body}"""


def paraphrase_items(items: list[SeedItem], backend: Backend, n: int = 1) -> list[SeedItem]:
    out: list[SeedItem] = []
    for item in items:
        for k in range(n):
            try:
                text = backend.complete("You rewrite text faithfully.", PROMPT.format(body=item.body)).strip()
            except BackendError as exc:
                raise SystemExit(f"paraphrase failed on {item.id}: {exc}") from exc
            if not text:
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
