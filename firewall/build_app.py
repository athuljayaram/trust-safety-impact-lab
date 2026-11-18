"""Build report.html: a self-contained, offline app that runs the firewall live.

    python3 firewall/build_app.py      # also called by evaluate.py

Inlines firewall.js, the rules exported from firewall.py, and the real data
(held-out test split, Phase 2, synthetic benign, deepset). Runs parity.py first
so the page states whether the browser engine matches Python.
"""
import datetime
import json
from pathlib import Path

from firewall import export_spec
import parity

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA = ROOT / "data"

DEMO_CAUGHT = "59408651-ce3e-4243-991c-270f9aadd6b2"
DEMO_MISSED = "35ddb7e1-3123-4fc7-a904-21e98de2ec45"


def load(name):
    with open(DATA / name) as f:
        return [json.loads(line) for line in f]


def attack(r):
    o = r.get("objectives") or {}
    return {
        "kind": "attack", "id": r["RowKey"], "split": r["split"], "scenario": r.get("scenario") or "?",
        "subject": r.get("subject") or "", "body": r.get("body") or "",
        "sent": bool(o.get("exfil.sent")), "undetected": bool(o.get("defense.undetected")),
    }


def safe_json(obj):
    # Embedded in <script type="application/json">: keep "</script>" and "<!--" inert.
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")


def build(out=ROOT / "report.html"):
    p = parity.check(verbose=True)
    parity_note = f"{p[0]}/{p[1]} emails" if p else "not checked (node missing)"
    if p and p[2]:
        print(f"WARNING: {p[2]} emails get a different action in the browser engine")

    data = {
        "test": [attack(r) for r in load("attacks_test.jsonl")],
        "phase2": [attack(r) for r in load("attacks_phase2.jsonl")],
        "benign": [{"kind": "benign", "id": r["id"], "category": r["category"], "subject": r["subject"], "body": r["body"]}
                   for r in load("benign_synthetic.jsonl")],
        "deepset": [{"kind": "deepset", "label": r["label"], "subject": "", "body": r["text"]} for r in load("deepset_prompts.jsonl")],
        "demo": {"caught": DEMO_CAUGHT, "missed": DEMO_MISSED},
        "meta": {
            "dev_n": len(load("attacks_dev.jsonl")),
            "parity": parity_note,
            "sampled": "at seeded random offsets",
            "built": datetime.date.today().isoformat(),
        },
    }
    ids = {m["id"] for m in data["test"]}
    assert DEMO_CAUGHT in ids and DEMO_MISSED in ids, "demo emails missing from test split; re-run fetch.py"

    page = (HERE / "app.html").read_text()
    page = page.replace("__SPEC__", safe_json(export_spec()), 1)
    page = page.replace("__DATA__", safe_json(data), 1)
    page = page.replace("__ENGINE__", (HERE / "firewall.js").read_text(), 1)
    out.write_text(page)
    print(f"wrote {out.name} ({out.stat().st_size // 1024} KB), parity {parity_note}")


if __name__ == "__main__":
    build()
