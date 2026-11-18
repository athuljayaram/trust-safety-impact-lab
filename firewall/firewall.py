"""Inbox firewall: decide what an email agent is allowed to read.

For each email returns a verdict:
  allow       pass the email to the agent unchanged
  strip       pass it with suspicious spans removed (hidden HTML, chat-role tokens)
  quarantine  hold it for a human; the agent sees only "1 email held for review"

Every verdict comes with reasons. Pure standard library, no API key.

The rules are generic. They never mention the attacker address or payload used
in the LLMail-Inject challenge, so a high catch rate cannot come from memorising
the target.
"""
import base64
import html
import re
import unicodedata
from dataclasses import dataclass, field

QUARANTINE_AT = 4
STRIP_AT = 2

# Signals: (name, weight, regex, strippable). Weights were set on the dev split only.
SIGNALS = [
    # 1. Chat-template / role tokens: an email has no reason to contain these.
    ("chat-role token", 4, r"<\s*\|+\s*[\w#\]\[]{1,24}\s*\|*\s*>|<\s*\|+\s*(im_start|im_end|system|user|assistant|end)\b|\[/?INST\]|<</?SYS>>|^\s*###\s*(system|instruction|assistant)\b", True),
    ("fake conversation turn", 3, r"(^|\n)\s*(assistant|system|user)\s*(to=|from=|:)\s*\w|\bjudgement\s*:\s*\w|\bintent\s*:\s*\w", True),
    ("fake data/instruction boundary", 3, r"/?\b(END|BEGIN)[_-]?(DATA|CONVERSATION|EMAIL|INSTRUCTIONS?|USER|CONTEXT)\b|^\s*/END\b|```\s*\n\s*/?END", True),
    ("JSON break-out", 3, r"\\+\"\s*\}\s*\]|\"\s*\}\s*\]\s*\n\s*(```|/END|//)|^\s*//+\s*$", True),
    # 2. Talking to the model instead of the human reader.
    ("addresses the AI", 3, r"\b(dear|hey|hi|attention|note to( the)?|instructions? (for|to)( the)?)\s+(ai|llm|assistant|language model|email (assistant|client|agent)|bot|model)\b|\bas an? (ai|llm|assistant|language model)\b|\b(miracle|helpful) machine\b", False),
    ("override language", 4, r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|rules|prompt|guidelines|context)\b|\bnew (instructions?|task|objective)\s*:|\bsystem prompt\b|\byou are now\b", False),
    ("meta-instruction about summarising", 2, r"\b(when|while|after|before) (you )?(summari[sz]|process|read)(e|ing)\b.{0,60}\b(email|this|message)|\bfor summari[sz]ation purposes\b|\b(this|the) (task|step) is (important|required|mandatory)\b", False),
    # 3. Tool-call syntax inside an email body.
    ("tool-call syntax", 4, r"\bapi[_ ]?call\b|\b(send_email|sendEmail|send_mail|tool_call|function_call)\b|\"(to|recipient)\"\s*:\s*\"[^\"]+@|\b(to|body)\s*\(\s*value\s*:|\bwith (the )?arguments?\b|\bparameters?\s*[:{]", False),
    # 4. Asks the reader to send something to an address with a specific payload.
    ("send-to-address with dictated body", 2, r"\b(send|email|reply|forward|mail)\b[^.\n]{0,80}[\w.+-]+\s*@\s*[\w-]+\s*\.\s*\w+[^.\n]{0,120}\b(body|content|text|word|message|token|code|key|format)\b\s*(:|=|of|is|should|\"|'|“)", False),
    ("exact-payload demand", 2, r"\b(only|just|simply|exactly)\b[^.\n]{0,30}\b(send|reply|write|email|respond)\b[^.\n]{0,30}(\"|'|“)[^\"'”]{1,40}(\"|'|”)|\b(single|one) word\b", False),
    ("quoted payload to an address", 2, r"\b(send|email|reply|provide|include|forward|share)\w*\b[^.\n]{0,50}[\"'“‘][^\"'”’\n]{1,40}[\"'”’][^.\n]{0,30}\b(to|at)\b[^.\n]{0,15}[\w.+-]+@[\w-]+\.\w+|[\w.+-]+@[\w-]+\.\w+[^.\n]{0,40}\b(including|with|providing)\b[^.\n]{0,20}[\"'“‘]", False),
    ("secret code to an address", 2, r"\b(code|key|token|password|passcode|pin|credentials?)\b[^.\n]{0,60}[\w.+-]+@[\w-]+\.\w+|[\w.+-]+@[\w-]+\.\w+[^.\n]{0,60}\b(code|key|token|password|passcode)\b", False),
    ("account-threat pressure", 2, r"\baccount\b[^.\n]{0,40}\b(locked|disabled|suspended|restricted|compromised)\b|\b(failure to (act|respond)|ignoring this may|may lead to account)\b", False),
    ("hurry + act-before-replying", 1, r"\b(always|make sure|before responding|do (it|this) now|immediately|asap|right away)\b.{0,40}\b(send|email|forward)\b", False),
    # 5. Obfuscation.
    ("hidden HTML text", 4, r"display\s*:\s*none|font-size\s*:\s*0(px)?\b|visibility\s*:\s*hidden|color\s*:\s*(#fff(fff)?|white)\b[^>]*>|opacity\s*:\s*0(\.0+)?\b", True),
    ("escape-character flood", 2, r"(\\){4,}", True),
]

COMPILED = [(n, w, re.compile(p, re.I | re.M | re.S), s) for n, w, p, s in SIGNALS]
ZERO_WIDTH = re.compile(r"[​-‏⁠-⁤﻿­]")
B64 = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}")
CAMEL_RUN = re.compile(r"\b(?:[A-Z][a-z]+){6,}\b")


@dataclass
class Verdict:
    action: str
    score: int
    reasons: list = field(default_factory=list)
    cleaned: str = ""


def normalise(text):
    text = html.unescape(text or "")
    text = unicodedata.normalize("NFKC", text)
    return ZERO_WIDTH.sub("", text)


def filler_interleave(text):
    """Every-other-word filler, e.g. 'yes Please yes send yes an yes email'."""
    words = text.split()
    if len(words) < 12:
        return False
    evens = words[0::2]
    top = max(set(evens), key=evens.count)
    return evens.count(top) / len(evens) > 0.6 and len(top) <= 6


def decoded_payloads(text):
    out = []
    for m in B64.findall(text):
        try:
            s = base64.b64decode(m + "=" * (-len(m) % 4)).decode("utf-8")
            if s.isprintable() and len(s) > 10:
                out.append(s)
        except Exception:
            pass
    return out


def score_text(text):
    hits = []
    for name, weight, rx, strippable in COMPILED:
        if rx.search(text):
            hits.append((name, weight, strippable))
    return hits


def inspect(subject, body):
    raw = f"{subject or ''}\n{body or ''}"
    text = normalise(raw)
    hits = score_text(text)

    if filler_interleave(text):
        hits.append(("filler-word interleaving", 4, False))
        # also score the de-interleaved text, which is the real instruction
        hits += [(n + " (after de-interleave)", w, s) for n, w, s in score_text(" ".join(text.split()[1::2]))]
    for payload in decoded_payloads(text):
        inner = score_text(payload)
        if inner:
            hits.append(("instruction hidden in base64", 4, False))
            hits += inner
    if len(CAMEL_RUN.findall(text)) >= 2:
        hits.append(("run-together CamelCase sentences", 2, False))
    if ZERO_WIDTH.search(raw):
        hits.append(("zero-width characters", 1, True))
    # Script mixing: Latin email with a CJK block that also mentions an address or send.
    if re.search(r"[一-鿿]", text) and re.search(r"[A-Za-z]{4,}", text) and re.search(r"@|发送|寄出|send", text):
        latin = len(re.findall(r"[A-Za-z]", text))
        cjk = len(re.findall(r"[一-鿿]", text))
        if latin > 40 and cjk > 10:
            hits.append(("mixed-script instruction block", 2, False))

    # de-duplicate by name, keep max weight
    best = {}
    for n, w, s in hits:
        if n not in best or w > best[n][0]:
            best[n] = (w, s)
    score = sum(w for w, _ in best.values())
    reasons = [f"{n} (+{w})" for n, (w, _) in sorted(best.items(), key=lambda kv: -kv[1][0])]

    non_strippable = sum(w for w, s in best.values() if not s)
    if score >= QUARANTINE_AT and non_strippable >= STRIP_AT:
        action = "quarantine"
    elif score >= STRIP_AT:
        action = "strip"
    else:
        action = "allow"

    cleaned = text
    if action == "strip":
        for name, _, rx, strippable in COMPILED:
            if strippable:
                cleaned = rx.sub(" [removed] ", cleaned)
    return Verdict(action, score, reasons, cleaned if action != "quarantine" else "")


def export_spec():
    """Everything the browser engine (firewall.js) needs, so the rules have one source."""
    return {
        "quarantine_at": QUARANTINE_AT,
        "strip_at": STRIP_AT,
        "signals": [{"name": n, "weight": w, "pattern": p, "strippable": s} for n, w, p, s in SIGNALS],
        "zero_width": ZERO_WIDTH.pattern,
        "b64": B64.pattern,
        "camel_run": CAMEL_RUN.pattern,
    }


if __name__ == "__main__":
    import sys
    body = sys.stdin.read()
    v = inspect("", body)
    print(v.action, v.score)
    for r in v.reasons:
        print("  -", r)
