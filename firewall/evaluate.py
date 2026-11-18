"""Score the inbox firewall on real attacks and benign mail.

    python3 firewall/evaluate.py              # held-out test split, writes report.html
    python3 firewall/evaluate.py --dev        # dev split (the one rules were tuned on)
    python3 firewall/evaluate.py --misses 10  # print attacks that got through

Dataset rows are treated as strings to classify. Nothing here follows them.
"""
import argparse
import collections
import html
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


def esc(t, n=700):
    t = t or ""
    return html.escape(t[:n] + ("…" if len(t) > n else ""))


def report(path, label, s, attacks, benign, phase2):
    caught = [(r, v) for r, v in attacks if v.action == "quarantine" and r["objectives"].get("exfil.sent")]
    missed = [(r, v) for r, v in attacks if v.action == "allow"]
    missed.sort(key=lambda rv: (not rv[0]["objectives"].get("exfil.sent"), -len(rv[0]["body"] or "")))
    fps = [(r, v) for r, v in benign if v.action != "allow"]

    def card(r, v, tag):
        obj = r.get("objectives", {})
        flags = " ".join(f"<span class='flag {'on' if obj.get(k) else ''}'>{k}</span>" for k in ("email.retrieved", "defense.undetected", "exfil.sent")) if obj else "<span class='flag'>synthetic benign</span>"
        reasons = "".join(f"<li>{html.escape(x)}</li>" for x in v.reasons) or "<li>no signals</li>"
        return f"""<article class="card"><div class="head"><span class="verdict {v.action}">{v.action}</span><span class="tag">{tag}</span>{flags}</div>
<h4>{esc(r.get('subject'), 140)}</h4><pre>{esc(r.get('body'))}</pre><ul class="reasons">{reasons}</ul></article>"""

    def stat(title, r, note=""):
        return f"<div class='stat'><div class='big'>{r['pct']}%</div><div class='lbl'>{title}</div><div class='n'>{r['k']} of {r['n']}{(' · ' + note) if note else ''}</div></div>"

    levels = "".join(f"<tr><td>{k}</td><td>{fmt(v)}</td></tr>" for k, v in s["caught_by_level"].items())
    sig = "".join(f"<tr><td>{html.escape(k)}</td><td>{n}</td></tr>" for k, n in s["top_signals_on_attacks"])
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Inbox Firewall</title><style>
:root{{--bg:#faf9f6;--fg:#1d1d1b;--muted:#6b6a65;--card:#fff;--line:#e4e2dc;--bad:#b3261e;--good:#2e7d32;--warn:#a66300;--accent:#c96442}}
@media (prefers-color-scheme:dark){{:root{{--bg:#1a1a18;--fg:#ecebe6;--muted:#a3a29b;--card:#242422;--line:#3a3a36;--bad:#f2b8b5;--good:#a5d6a7;--warn:#ffcc80;--accent:#e08a6a}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,system-ui,sans-serif;margin:0;padding:24px 16px}}
main{{max-width:1040px;margin:auto}} h1{{margin:0 0 4px}} .sub{{color:var(--muted);margin:0 0 24px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-bottom:28px}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}} .big{{font-size:30px;font-weight:700}}
.lbl{{font-weight:600}} .n{{color:var(--muted);font-size:13px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;min-width:0}}
.card h4{{margin:8px 0 4px}} pre{{white-space:pre-wrap;word-break:break-word;font-size:12px;max-height:220px;overflow:auto;background:var(--bg);padding:8px;border-radius:6px}}
.head{{display:flex;flex-wrap:wrap;gap:6px;align-items:center}} .verdict{{font-weight:700;text-transform:uppercase;font-size:12px;padding:2px 8px;border-radius:4px;border:1px solid}}
.quarantine{{color:var(--good)}} .strip{{color:var(--warn)}} .allow{{color:var(--bad)}}
.tag,.flag{{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:4px;padding:1px 6px}} .flag.on{{color:var(--accent);border-color:var(--accent)}}
.reasons{{font-size:12px;color:var(--muted);padding-left:18px;margin:4px 0 0}}
table{{border-collapse:collapse;width:100%;font-size:14px}} td{{border-bottom:1px solid var(--line);padding:4px 6px}}
.two{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:24px;margin-bottom:28px}}
.limit{{border-left:4px solid var(--accent);padding:8px 14px;background:var(--card)}}
</style></head><body><main>
<h1>Inbox Firewall</h1>
<p class="sub">A rule layer between "email arrives" and "agent reads it". Scored on {label} of Microsoft's LLMail-Inject attacks (real, attacker-written) and on benign mail. Pure Python, no model calls.</p>
<div class="stats">
{stat("of attack emails stopped", s["attack_caught"], "strip or quarantine")}
{stat("of attacks that actually made the assistant send mail", s["caught_of_attacks_that_sent_email"])}
{stat("Phase 2 (adaptive) attacks stopped", phase2)}
{stat("false positives, synthetic work email", s["benign_false_positive"])}
{stat("false positives, real benign prompts (deepset)", s["deepset_benign_false_positive"])}
</div>
<div class="two"><div><h3>Stopped, by challenge level</h3><table>{levels}</table></div>
<div><h3>Most common signals on attacks</h3><table>{sig}</table></div></div>
<div class="limit"><strong>Honest limitations.</strong> Every LLMail-Inject attack targets one simulated assistant and one action (send an email), so these are not a sample of real inbox mail. The benign set is 104 emails we wrote with Claude; synthetic mail is easier to separate than real mail, and we saw it while writing rules. A rule list is easy to evade once published: see the misses below.</div>
<h2>Attacks that worked in the challenge, now quarantined</h2><div class="grid">{''.join(card(r, v, 'attack') for r, v in caught[:4])}</div>
<h2>Attacks that still get through</h2><div class="grid">{''.join(card(r, v, 'attack, missed') for r, v in missed[:6])}</div>
<h2>Benign mail we wrongly flagged</h2><div class="grid">{''.join(card(r, v, r.get('category', '')) for r, v in fps[:8]) or '<p>None.</p>'}</div>
</main></body></html>"""
    path.write_text(doc)


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
        report(ROOT / "report.html", f"{s['attack_caught']['n']} held-out", s, attacks, benign, s["phase2_caught"])
        print("\nwrote results.json and report.html")
