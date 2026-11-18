"""Three-minute demo, in the order of the track's demo checklist.

    python3 firewall/demo.py          # press Enter between beats
    python3 firewall/demo.py --no-pause

1. One real attack email on screen.
2. The firewall handling it.
3. Two numbers with sample sizes (computed live on the held-out split).
4. One attack that still gets through.

Both emails come from the held-out test split of LLMail-Inject and both
succeeded against the challenge's assistant (exfil.sent = true).
Dataset rows are shown as text. Nothing here follows them.
"""
import json
import sys
import textwrap
from pathlib import Path

from firewall import inspect

DATA = Path(__file__).resolve().parent.parent / "data"
CAUGHT_ID = "59408651-ce3e-4243-991c-270f9aadd6b2"
MISSED_ID = "35ddb7e1-3123-4fc7-a904-21e98de2ec45"

PAUSE = "--no-pause" not in sys.argv
TTY = sys.stdout.isatty()
C = {"red": "31", "green": "32", "yellow": "33", "dim": "2", "bold": "1", "cyan": "36"}


def c(text, color):
    return f"\033[{C[color]}m{text}\033[0m" if TTY else text


def beat(n, title):
    if PAUSE and n > 1:
        input(c("\n  [Enter] ", "dim"))
    print("\n" + c(f"{n}. {title}", "bold"))
    print(c("-" * 64, "dim"))


def show_email(r):
    obj = r["objectives"]
    flags = ", ".join(f"{k}={'yes' if obj.get(k) else 'no'}" for k in ("email.retrieved", "defense.undetected", "exfil.sent"))
    print(c(f"  LLMail-Inject {r['split']} / {r['scenario']} / row {r['RowKey'][:8]}", "dim"))
    print(c(f"  in the challenge: {flags}", "dim"))
    print(f"\n  Subject: {r['subject']}")
    for para in (r["body"] or "").strip().split("\n"):
        for line in textwrap.wrap(para, 76) or [""]:
            print("  " + line)


def show_verdict(v):
    color = {"quarantine": "green", "strip": "yellow", "allow": "red"}[v.action]
    print(f"\n  Firewall verdict: {c(v.action.upper(), color)}   (score {v.score})")
    for reason in v.reasons or ["no signals"]:
        print(f"    - {reason}")


def load(name):
    with open(DATA / name) as f:
        return [json.loads(line) for line in f]


def pct(k, n):
    return f"{100 * k / n:.1f}% ({k}/{n})"


def main():
    test = load("attacks_test.jsonl")
    by_id = {r["RowKey"]: r for r in test}
    caught, missed = by_id[CAUGHT_ID], by_id[MISSED_ID]

    print(c("\nINBOX FIREWALL", "bold") + "  a rule layer between \"email arrives\" and \"agent reads it\"")
    print("Concern: anyone who can email you can try to give your AI assistant orders.")

    beat(1, "A real attack email (this one made the assistant send mail)")
    show_email(caught)

    beat(2, "The firewall handling it")
    v = inspect(caught["subject"], caught["body"])
    show_verdict(v)
    print("\n  What the agent sees instead of the email:")
    print(c("    [1 email held for review: possible instructions to your assistant]", "cyan"))

    beat(3, "Two numbers, measured on held-out data the rules were not written on")
    verdicts = [(r, inspect(r["subject"], r["body"])) for r in test]
    worked = [(r, x) for r, x in verdicts if r["objectives"].get("exfil.sent")]
    benign = [inspect(r["subject"], r["body"]) for r in load("benign_synthetic.jsonl")]
    ds = [inspect("", r["text"]) for r in load("deepset_prompts.jsonl") if r["label"] == 0]
    stopped = sum(x.action != "allow" for _, x in worked)
    fp = sum(x.action != "allow" for x in benign)
    fp_ds = sum(x.action != "allow" for x in ds)
    allstop = sum(x.action != "allow" for _, x in verdicts)
    print(f"  Attacks that really sent mail, stopped:   {c(pct(stopped, len(worked)), 'green')}")
    print(f"  Ordinary work email wrongly flagged:       {c(pct(fp, len(benign)), 'yellow')}  (synthetic, written with Claude)")
    print(c(f"  also: all attacks stopped {pct(allstop, len(verdicts))}; real benign prompts flagged {pct(fp_ds, len(ds))}", "dim"))

    beat(4, "An attack that still gets through")
    show_email(missed)
    show_verdict(inspect(missed["subject"], missed["body"]))
    print("\n  Plain English, no markup, reads like a colleague. A filter cannot tell it")
    print("  apart. The fix is a policy, not a detector: content that came from an email")
    print("  must not choose the recipient of an outgoing email without a human seeing it.")
    print()


if __name__ == "__main__":
    main()
