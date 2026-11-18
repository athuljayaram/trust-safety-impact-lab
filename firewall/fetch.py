"""Pull a small, spread-out sample of LLMail-Inject attack emails.

Uses the Hugging Face dataset viewer API (no key, no install). Rows in the
dataset are grouped by team, so we read 100-row pages at random offsets
instead of the first N rows. Dev and test pages never overlap.

    python3 firewall/fetch.py            # dev + test samples into data/
"""
import json
import random
import time
import urllib.request
from pathlib import Path

API = "https://datasets-server.huggingface.co/rows"
DATASET = "microsoft/llmail-inject-challenge"
TOTALS = {"Phase1": 370724, "Phase2": 91000}  # Phase2 total is approximate; offsets stay well inside it
OUT = Path(__file__).resolve().parent.parent / "data"
KEEP = ["RowKey", "subject", "body", "scenario", "objectives", "team_id"]


def page(split, offset, length=100, dataset=DATASET):
    url = f"{API}?dataset={dataset}&config=default&split={split}&offset={offset}&length={length}"
    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return [row["row"] for row in json.load(r)["rows"]]
        except Exception as e:  # rate limits or transient errors
            time.sleep(2 + attempt * 3)
            last = e
    raise last


def sample(split, pages, rng, used):
    rows = []
    while len(rows) < pages * 100:
        off = rng.randrange(0, TOTALS[split] - 2000) // 100 * 100
        if (split, off) in used:
            continue
        used.add((split, off))
        for r in page(split, off):
            rec = {k: r.get(k) for k in KEEP}
            rec["split"] = split
            rec["objectives"] = json.loads(r["objectives"]) if r.get("objectives") else {}
            rows.append(rec)
        print(f"  {split} offset {off}: {len(rows)} rows so far")
    return rows


def dedupe(rows):
    seen, out = set(), []
    for r in rows:
        key = (r["subject"] or "") + "\n" + (r["body"] or "")
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def save(name, rows):
    OUT.mkdir(exist_ok=True)
    with open(OUT / name, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(rows)} unique rows to data/{name}")


def deepset():
    """Real (not synthetic) benign prompts for a second false-positive check."""
    rows = []
    for split, n in (("train", 546), ("test", 116)):
        for off in range(0, n, 100):
            rows += [dict(r, split=split) for r in page(split, off, dataset="deepset/prompt-injections")]
    save("deepset_prompts.jsonl", rows)


if __name__ == "__main__":
    import sys
    if "--deepset" in sys.argv:
        deepset()
        sys.exit()
    deepset()
    rng = random.Random(17)
    used = set()
    dev = dedupe(sample("Phase1", 5, rng, used))
    test = dedupe(sample("Phase1", 10, rng, used))
    test_keys = {(r["subject"], r["body"]) for r in dev}
    test = [r for r in test if (r["subject"], r["body"]) not in test_keys]
    phase2 = dedupe(sample("Phase2", 5, rng, used))
    save("attacks_dev.jsonl", dev)
    save("attacks_test.jsonl", test)
    save("attacks_phase2.jsonl", phase2)
