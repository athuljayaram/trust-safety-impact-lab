// Browser/Node port of firewall.py. The rules come from export_spec() in
// firewall.py, so there is one source of truth; this file only mirrors inspect().
// parity.py checks that both give the same verdict on every email.
(function (root) {
  "use strict";

  const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

  // Same decoder in Node and the browser, so parity.py covers what the page runs.
  function unescapeHtml(text) {
    return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
      if (e[0] === "#") {
        const cp = e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        try { return String.fromCodePoint(cp); } catch (_) { return m; }
      }
      return ENTITIES[e.toLowerCase()] ?? m;
    });
  }

  function decodeB64(s) {
    try {
      s = s + "=".repeat((4 - (s.length % 4)) % 4);
      let bin;
      if (typeof atob === "function") bin = atob(s);
      else bin = Buffer.from(s, "base64").toString("binary");
      const bytes = Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (_) {
      return null;
    }
  }

  const PRINTABLE = /^(?:[^\p{C}\p{Z}]| )*$/u;

  // Python's \w and \b are Unicode-aware; JavaScript's are ASCII-only even with
  // the u flag. Rewrite them so CJK or Cyrillic text matches the same way.
  const W = "\\p{L}\\p{N}_";
  const B = `(?:(?<![${W}])(?=[${W}])|(?<=[${W}])(?![${W}]))`;

  function pyToJs(src) {
    let out = "", inClass = false;
    for (let i = 0; i < src.length; i++) {
      const ch = src[i];
      if (ch === "\\" && i + 1 < src.length) {
        const nx = src[++i];
        if (nx === "w") out += inClass ? W : `[${W}]`;
        else if (nx === "b" && !inClass) out += B;
        else if (nx === '"' || nx === "'") out += nx; // identity escapes are errors under /u
        else out += "\\" + nx;
        continue;
      }
      if (ch === "[" && !inClass) inClass = true;
      else if (ch === "]" && inClass) inClass = false;
      out += ch;
    }
    return out;
  }

  const re = (src, flags) => new RegExp(pyToJs(src), flags + "u");

  function build(spec) {
    const signals = spec.signals.map((s) => ({
      name: s.name,
      weight: s.weight,
      strippable: s.strippable,
      test: re(s.pattern, "ims"),
      all: re(s.pattern, "gims"),
    }));
    const zw = re(spec.zero_width, "");
    const zwAll = re(spec.zero_width, "g");
    const b64 = re(spec.b64, "g");
    const camel = re(spec.camel_run, "g");

    function normalise(text) {
      return unescapeHtml(text || "").normalize("NFKC").replace(zwAll, "");
    }

    function scoreText(text) {
      const hits = [];
      for (const s of signals) if (s.test.test(text)) hits.push([s.name, s.weight, s.strippable]);
      return hits;
    }

    function words(text) {
      const t = text.trim();
      return t ? t.split(/\s+/) : [];
    }

    function fillerInterleave(text) {
      const w = words(text);
      if (w.length < 12) return false;
      const evens = w.filter((_, i) => i % 2 === 0);
      const counts = new Map();
      for (const x of evens) counts.set(x, (counts.get(x) || 0) + 1);
      let top = null, n = 0;
      for (const [k, v] of counts) if (v > n) { top = k; n = v; }
      return n / evens.length > 0.6 && top.length <= 6;
    }

    function decodedPayloads(text) {
      const out = [];
      for (const m of text.match(b64) || []) {
        const s = decodeB64(m);
        if (s && PRINTABLE.test(s) && s.length > 10) out.push(s);
      }
      return out;
    }

    // Character ranges that each signal matched, for highlighting.
    function spans(text) {
      const out = [];
      for (const s of signals) {
        s.all.lastIndex = 0;
        let m;
        while ((m = s.all.exec(text)) !== null) {
          if (m[0].length === 0) { s.all.lastIndex++; continue; }
          out.push({ start: m.index, end: m.index + m[0].length, name: s.name });
        }
      }
      return out.sort((a, b) => a.start - b.start);
    }

    function inspect(subject, body) {
      const raw = (subject || "") + "\n" + (body || "");
      const text = normalise(raw);
      let hits = scoreText(text);

      if (fillerInterleave(text)) {
        hits.push(["filler-word interleaving", 4, false]);
        const odd = words(text).filter((_, i) => i % 2 === 1).join(" ");
        hits = hits.concat(scoreText(odd).map(([n, w, s]) => [n + " (after de-interleave)", w, s]));
      }
      for (const payload of decodedPayloads(text)) {
        const inner = scoreText(payload);
        if (inner.length) {
          hits.push(["instruction hidden in base64", 4, false]);
          hits = hits.concat(inner);
        }
      }
      if ((text.match(camel) || []).length >= 2) hits.push(["run-together CamelCase sentences", 2, false]);
      if (zw.test(raw)) hits.push(["zero-width characters", 1, true]);
      if (/[一-鿿]/.test(text) && /[A-Za-z]{4,}/i.test(text) && /@|发送|寄出|send/.test(text)) {
        const latin = (text.match(/[A-Za-z]/g) || []).length;
        const cjk = (text.match(/[一-鿿]/g) || []).length;
        if (latin > 40 && cjk > 10) hits.push(["mixed-script instruction block", 2, false]);
      }

      const best = new Map();
      for (const [n, w, s] of hits) if (!best.has(n) || w > best.get(n)[0]) best.set(n, [w, s]);
      let score = 0, nonStrip = 0;
      for (const [w, s] of best.values()) { score += w; if (!s) nonStrip += w; }
      const reasons = [...best.entries()]
        .sort((a, b) => b[1][0] - a[1][0])
        .map(([n, [w, s]]) => ({ name: n, weight: w, strippable: s }));

      let action = "allow";
      if (score >= spec.quarantine_at && nonStrip >= spec.strip_at) action = "quarantine";
      else if (score >= spec.strip_at) action = "strip";

      let cleaned = text;
      if (action === "strip") {
        for (const s of signals) if (s.strippable) cleaned = cleaned.replace(s.all, " [removed] ");
      }
      return { action, score, reasons, text, cleaned: action === "quarantine" ? "" : cleaned, spans: spans(text) };
    }

    return { inspect, normalise };
  }

  const api = { build };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.Firewall = api;
})(typeof window !== "undefined" ? window : globalThis);
