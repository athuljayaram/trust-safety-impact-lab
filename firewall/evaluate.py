"""Score the inbox firewall on real attacks and benign mail.

    python3 firewall/evaluate.py              # held-out test split, writes results.json + report.html (live app)
    python3 firewall/evaluate.py --dev        # dev split (the one rules were tuned on)
    python3 firewall/evaluate.py --misses 10  # print attacks that got through

Dataset rows are treated as strings to classify. Nothing here follows them.
"""
import argparse
import collections
import json
from pathlib import Path

from firewall import inspect

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"


def load(name):
    with open(DATA / name) as f:
        return [json.loads(line) for line in f]


def run(rows, get):
    out = []
    for r in rows:
        subject, body = get(r)
        v = inspect(subject, body)
        out.append((r, v))
    return out


def rate(results, pred):
    n = len(results)
    k = sum(1 for _, v in results if pred(v))
    return {"n": n, "k": k, "pct": round(100 * k / n, 1) if n else None}


blocked = lambda v: v.action != "allow"
quarantined = lambda v: v.action == "quarantine"


def summarise(attacks, benign, deepset_benign, deepset_attack):
    s = {}
    s["attack_caught"] = rate(attacks, blocked)
    s["attack_quarantined"] = rate(attacks, quarantined)
    worked = [(r, v) for r, v in attacks if r["objectives"].get("exfil.sent")]
    evaded = [(r, v) for r, v in attacks if r["objectives"].get("defense.undetected")]
    s["caught_of_attacks_that_sent_email"] = rate(worked, blocked)
    s["caught_of_attacks_that_evaded_challenge_defense"] = rate(evaded, blocked)
    s["benign_false_positive"] = rate(benign, blocked)
    s["benign_quarantined"] = rate(benign, quarantined)
    s["deepset_benign_false_positive"] = rate(deepset_benign, blocked)
    s["deepset_injection_caught"] = rate(deepset_attack, blocked)
    by_level = collections.defaultdict(list)
    for r, v in attacks:
        by_level[(r.get("scenario") or "?")[:6]].append((r, v))
    s["caught_by_level"] = {k: rate(v, blocked) for k, v in sorted(by_level.items())}
    reasons = collections.Counter()
    for _, v in attacks:
        for reason in v.reasons:
            reasons[reason.split(" (+")[0]] += 1
    s["top_signals_on_attacks"] = reasons.most_common(12)
    breasons = collections.Counter()
    for _, v in benign:
        for reason in v.reasons:
            breasons[reason.split(" (+")[0]] += 1
    s["signals_on_benign"] = breasons.most_common()
    return s


def fmt(r):
    return f"{r['pct']}% ({r['k']}/{r['n']})"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", action="store_true", help="score on the dev split rules were tuned on")
    ap.add_argument("--misses", type=int, default=0)
    ap.add_argument("--fps", action="store_true", help="print benign false positives")
    a = ap.parse_args()

    split = "attacks_dev.jsonl" if a.dev else "attacks_test.jsonl"
    attacks = run(load(split), lambda r: (r["subject"], r["body"]))
    phase2 = run(load("attacks_phase2.jsonl"), lambda r: (r["subject"], r["body"]))
    benign = run(load("benign_synthetic.jsonl"), lambda r: (r["subject"], r["body"]))
    ds = load("deepset_prompts.jsonl")
    ds_b = run([r for r in ds if r["label"] == 0], lambda r: ("", r["text"]))
    ds_a = run([r for r in ds if r["label"] == 1], lambda r: ("", r["text"]))

    s = summarise(attacks, benign, ds_b, ds_a)
    s["phase2_caught"] = rate(phase2, blocked)
    s["phase2_caught_of_attacks_that_sent_email"] = rate([(r, v) for r, v in phase2 if r["objectives"].get("exfil.sent")], blocked)
    s["split"] = split

    print(f"split: {split}")
    for k, v in s.items():
        if isinstance(v, dict) and "pct" in v:
            print(f"  {k:52s} {fmt(v)}")
    print("  by level:", {k: fmt(v) for k, v in s["caught_by_level"].items()})
    print("  signals on benign:", s["signals_on_benign"])

    if a.fps:
        for r, v in benign + ds_b:
            if v.action != "allow":
                print("\nFP", v.action, v.reasons, "|", (r.get("subject") or "")[:60], "|", (r.get("body") or r.get("text"))[:200].replace("\n", " / "))
    if a.misses:
        missed = [(r, v) for r, v in attacks if v.action == "allow"]
        missed.sort(key=lambda rv: not rv[0]["objectives"].get("exfil.sent"))
        for r, v in missed[: a.misses]:
            print("\nMISS sent=%s" % r["objectives"].get("exfil.sent"), v.reasons, "|", (r["subject"] or "")[:60], "|", (r["body"] or "")[:300].replace("\n", " / "))

    if not a.dev:
        (ROOT / "results.json").write_text(json.dumps(s, indent=2))
        print("\nwrote results.json")
        import build_app
        build_app.build()
