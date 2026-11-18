#!/usr/bin/env bash
# Inbox Firewall: fetch real attack samples, build the benign set, score, write report.html
set -euo pipefail
cd "$(dirname "$0")"
[ -f data/attacks_test.jsonl ] || python3 firewall/fetch.py
python3 firewall/benign_emails.py
python3 firewall/evaluate.py "$@"
echo "open report.html"
