"""Check that the browser engine (firewall.js) agrees with firewall.py on every email.

    python3 firewall/parity.py     # needs node
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from firewall import export_spec, inspect

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"


def all_rows():
    rows = []
    for name in ("attacks_dev", "attacks_test", "attacks_phase2", "benign_synthetic"):
        for line in open(DATA / f"{name}.jsonl"):
            r = json.loads(line)
            rows.append({"subject": r.get("subject") or "", "body": r.get("body") or ""})
    for line in open(DATA / "deepset_prompts.jsonl"):
        rows.append({"subject": "", "body": json.loads(line)["text"]})
    return rows


def check(verbose=True):
    """Returns (identical, total, rows_with_different_action) or None if node is missing."""
    if not shutil.which("node"):
        return None
    rows = all_rows()
    py = [inspect(r["subject"], r["body"]) for r in rows]
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "in.json").write_text(json.dumps({"spec": export_spec(), "rows": rows}))
        js = f"""
const fw = require({json.dumps(str(HERE / 'firewall.js'))}).build;
const {{spec, rows}} = JSON.parse(require('fs').readFileSync({json.dumps(d + '/in.json')}, 'utf8'));
const eng = fw(spec);
process.stdout.write(JSON.stringify(rows.map(r => {{ const v = eng.inspect(r.subject, r.body); return [v.action, v.score]; }})));
"""
        out = subprocess.run(["node", "-e", js], capture_output=True, text=True, check=True).stdout
    js_out = json.loads(out)
    diff = [(i, (p.action, p.score), tuple(j)) for i, (p, j) in enumerate(zip(py, js_out)) if (p.action, p.score) != tuple(j)]
    action_diff = [x for x in diff if x[1][0] != x[2][0]]
    if verbose:
        print(f"parity: {len(rows)} emails, {len(rows) - len(diff)} identical (action and score), {len(action_diff)} with a different action")
        for i, p, j in diff[:10]:
            print(f"  row {i}: python {p} vs js {j} | {rows[i]['body'][:100]!r}")
    return len(rows) - len(diff), len(rows), len(action_diff)


if __name__ == "__main__":
    res = check()
    if res is None:
        sys.exit("node not found")
    sys.exit(1 if res[2] else 0)
