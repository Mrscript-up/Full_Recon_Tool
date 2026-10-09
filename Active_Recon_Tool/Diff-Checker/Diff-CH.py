# -*- coding: utf-8 -*-
#
# Diff-checker.py - pure CLI version of ReqDiff2Obsidian.py
# ------------------------------------------------------------------
# Fully NON-INTERACTIVE: give the XML file(s), get the diff note. Done.
#
# * Compares 2 OR MORE requests by URL + Body (headers/cookies ignored)
#   and appends an Obsidian-friendly diff note to a .md file.
# * Multi-file input: each file = one side of the comparison.
#   Sides are auto-labelled: User A, User B, User C, User D, ... (AA, AB, ...).
# * --pairs A,B,C,... accepts any number of items (N-way diff).
# * --nway: compare ALL loaded items in a single N-way diff.
#
# Usage:
#   python Diff-checker.py a.xml b.xml                 # a vs b (User A/B)
#   python Diff-checker.py a.xml b.xml c.xml d.xml     # 4-way diff (User A..D)
#   python Diff-checker.py export.xml                  # consecutive pairs (1-2, 2-3, ...)
#   python Diff-checker.py export.xml --nway           # ALL items in one N-way diff
#   python Diff-checker.py export.xml --pairs 1,3
#   python Diff-checker.py export.xml --pairs 1,2,3    # 3-way diff
#   python Diff-checker.py export.xml --pairs 1,2 4,5  # repeatable
#   python Diff-checker.py export.xml --list
# ------------------------------------------------------------------

import argparse
import base64
import codecs
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET

try:                                   # Python 2
    from urllib import unquote_plus
except ImportError:                    # Python 3
    from urllib.parse import unquote_plus

try:                                   # Python 2
    unicode
except NameError:                      # Python 3
    unicode = str

# ----------------------------- CONFIG ---------------------------------
OUTPUT_FILE     = ""   # e.g. r"D:\Vaults\Sec\burp-diffs.md" | "" = ~/Desktop/burp-diffs.md
LABEL_A         = "User A"
LABEL_B         = "User B"
MAX_DIFF_LINES  = 10   # responses: keep max N diff lines
RESP_SKIP_LINES = 15   # non-JSON response longer than this -> skip
BODY_SKIP_LINES = 15   # raw (non-JSON) body longer than this -> skip
# -----------------------------------------------------------------------


def _col_name(i):
    """0->A, 1->B, ..., 25->Z, 26->AA, 27->AB, ..."""
    name = ""
    i += 1
    while i > 0:
        i, r = divmod(i - 1, 26)
        name = chr(65 + r) + name
    return name


class _URL(object):
    """Minimal stand-in for java.net.URL (only what _extract needs)."""
    def __init__(self, host, path, query):
        self._host, self._path, self._query = host, path, query
    def getHost(self):  return self._host
    def getPath(self):  return self._path
    def getQuery(self): return self._query


class ReqDiffCLI(object):

    _ABSENT = object()  # sentinel: key missing on one side

    # ---------------------------------------------------- lifecycle
    def __init__(self, output=None, labels=None):
        self._output = output or OUTPUT_FILE or os.path.join(
            os.path.expanduser("~"), "Desktop\\burp-diffs.md")
        self._labels = labels or []   # optional per-side label overrides

    def _side_label(self, i):
        """User A, User B, User C, ... (with optional overrides)."""
        if i < len(self._labels) and self._labels[i]:
            return self._labels[i]
        if i == 0:
            return LABEL_A
        if i == 1:
            return LABEL_B
        return u"User " + _col_name(i)

    # ---------------------------------------------------- XML input
    def _load_xml(self, path):
        """Parse a Burp Suite 'Save selected items' XML file."""
        items = []
        try:
            root = ET.parse(path).getroot()
        except Exception as ex:
            print("[ReqDiff] ERROR: cannot read XML file %s: %s" % (path, ex))
            return items
        n = 0
        for el in root.iter("item"):
            n += 1
            req = self._element_text(el.find("request"))
            if req is None or not req.strip():
                continue
            resp = self._element_text(el.find("response"))
            if resp is not None and not resp.strip():
                resp = None
            items.append({
                "file":     os.path.basename(path),
                "src":      path,
                "host":     (el.findtext("host") or "").strip(),
                "method":   (el.findtext("method") or "").strip(),
                "url":      (el.findtext("url") or "").strip(),
                "request":  req,
                "response": resp,
            })
        print("[ReqDiff] %s: %d item(s)" % (path, n))
        return items

    def _element_text(self, el):
        """Decode a <request>/<response> element (honours base64="true")."""
        if el is None:
            return None
        data = el.text or ""
        if (el.get("base64") or "").strip().lower() == "true":
            try:
                b = base64.b64decode(data)
                try:
                    data = b.decode("utf-8")
                except UnicodeDecodeError:
                    data = b.decode("latin-1", "replace")
            except Exception:
                pass
        return self._u(data)

    # ---------------------------------------------------- listing
    def _list_items(self, items):
        print("")
        print("[ReqDiff] %d item(s) loaded:" % len(items))
        for i, it in enumerate(items, 1):
            tgt = it["url"] or (it["host"] + "/")
            print("  %3d. [%s] %-6s %s" % (i, it["file"], it["method"], tgt))

    def _parse_pairs_arg(self, specs, n):
        """Each spec: 2+ comma-separated numbers -> one (N-way) comparison."""
        groups, ok = [], True
        for spec in specs:
            parts = [p.strip() for p in spec.split(",") if p.strip()]
            if len(parts) < 2:
                print("[ReqDiff] ERROR: bad spec '%s' (need at least 2 numbers, "
                      "e.g. 1,2 or 1,2,3)" % spec)
                ok = False
                continue
            try:
                idxs = [int(x) for x in parts]
            except ValueError:
                print("[ReqDiff] ERROR: bad spec '%s' (numbers only)" % spec)
                ok = False
                continue
            if len(set(idxs)) != len(idxs):
                print("[ReqDiff] ERROR: spec '%s' has duplicate numbers" % spec)
                ok = False
                continue
            if any(not (1 <= x <= n) for x in idxs):
                print("[ReqDiff] ERROR: spec '%s' out of range (1..%d)" % (spec, n))
                ok = False
                continue
            groups.append([x - 1 for x in idxs])
        return groups if ok else None

    # ---------------------------------------------------- main flow
    def _compare_multi(self, msgs):
        """Compare 2..N requests in one note."""
        try:
            sides = [self._extract(m) for m in msgs]
            labels = [self._side_label(i) for i in range(len(sides))]
            note, has_diff = self._build_note(sides, labels)
            if not has_diff:
                print("[ReqDiff] %s: URL & Body are identical. Nothing saved."
                      % " vs ".join("#" + m.get("num", "?") for m in msgs))
                return
            self._append(note)
            print("[ReqDiff] saved -> %s" % self._output)
        except Exception as ex:
            print("[ReqDiff] ERROR: %s" % ex)

    def _extract(self, http_msg):
        req = http_msg["request"]
        ri = self._analyze_request(req)

        host = http_msg["host"]
        if not host:
            for h in ri["headers"]:
                if h.lower().startswith("host:"):
                    host = h.split(":", 1)[1].strip()
                    break
        url = _URL(host, ri["path"], ri["query"])

        body = ri["body"].strip()

        # only used to *decide how to parse* the body - never written to notes
        ctype = ""
        for h in ri["headers"]:
            hl = h.lower()
            if hl.startswith("content-type:"):
                ctype = hl.split(":", 1)[1].strip()
                break

        resp_body = None
        resp = http_msg["response"]
        if resp is not None:
            resp_body = self._split_http(resp)[1]

        return {
            "method": ri["method"],
            "host":   url.getHost(),
            "path":   url.getPath() or "/",
            "query":  url.getQuery() or "",
            "ctype":  ctype,
            "body":   body,
            "resp":   resp_body,
        }

    # ---------------------------------------------------- raw HTTP parsing
    def _split_http(self, raw):
        i = raw.find("\r\n\r\n")
        j = raw.find("\n\n")
        if i != -1 and (j == -1 or i < j):
            return raw[:i], raw[i + 4:]
        if j != -1:
            return raw[:j], raw[j + 2:]
        return raw, ""

    def _analyze_request(self, raw):
        head, body = self._split_http(raw)
        lines = [l.rstrip("\r") for l in head.split("\n")]
        reqline = lines[0] if lines else ""
        parts = reqline.split(" ")
        method = parts[0] if parts else ""
        target = parts[1] if len(parts) > 1 else "/"
        m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/]+(/.*)?$", target)
        if m:  # absolute-form target (proxy style) -> keep path?query only
            target = m.group(1) or "/"
        if "?" in target:
            path, query = target.split("?", 1)
        else:
            path, query = target, ""
        return {"method": method, "path": path, "query": query,
                "headers": lines, "body": body}

    # ---------------------------------------------------- note builder (N-way)
    def _build_note(self, sides, labels):
        n = len(sides)
        L = []
        has_diff = False

        L.append("")
        L.append("---")
        L.append(u"#### ReqDiff | %s" % time.strftime("%Y-%m-%d %H:%M"))

        # ---------- REQ-ENDPOINT ----------
        eps = set((s["method"], s["path"]) for s in sides)
        if len(eps) == 1:
            qs = set(s["query"] for s in sides)
            q = ("?" + sides[0]["query"]) if (sides[0]["query"] and len(qs) == 1) else ""
            L.append("**REQ-ENDPOINT**: `%s` %s%s" % (sides[0]["method"], sides[0]["path"], q))
        else:
            L.append("**REQ-ENDPOINT**:")
            for s, lab in zip(sides, labels):
                L.append("- %s: `%s %s%s`" % (lab, s["method"], s["path"],
                                              ("?" + s["query"]) if s["query"] else ""))
            has_diff = True

        hosts = set(s["host"] for s in sides)
        if len(hosts) > 1:
            if n == 2:  # keep the original 2-way line format
                L.append("- host %s: `%s` | host %s: `%s`"
                         % (labels[0], sides[0]["host"], labels[1], sides[1]["host"]))
            else:
                groups = {}
                for s, lab in zip(sides, labels):
                    groups.setdefault(s["host"], []).append(lab)
                L.append("- hosts: " + " | ".join(
                    "`%s` (%s)" % (h, ", ".join(labs)) for h, labs in groups.items()))
            has_diff = True

        # ---------- DATAS (query params + body) ----------
        parsed = [self._parse_body(s["body"], s["ctype"]) for s in sides]
        datas = None
        if all(p is not None for p in parsed):
            body_diffs = self._diff_maps_n(parsed)
            url_diffs = self._diff_maps_n([self._parse_query(s["query"]) for s in sides])
            body_keys = set(k for k, _v in body_diffs)
            merged = []
            for k, vals in url_diffs:
                merged.append(("url." + k if k in body_keys else k, vals))
            merged += body_diffs
            if merged:
                datas = self._kv_block_n(merged, labels, "**DATAS-ENDPOINT**:")
        else:
            # unparseable body (XML / multipart / plain text) -> raw line diff
            bodies = [s["body"] for s in sides]
            if any(b != bodies[0] for b in bodies[1:]):
                if any(len(b.splitlines()) > BODY_SKIP_LINES for b in bodies):
                    datas = ["**DATAS-ENDPOINT**: skipped (body > %d lines, not JSON/urlencoded)"
                             % BODY_SKIP_LINES]
                else:
                    entries = self._line_diff_n(bodies, MAX_DIFF_LINES)
                    if entries:
                        grouped = [[] for _ in sides]
                        for i, t in entries:
                            grouped[i].append(t)
                        datas = self._raw_block_n(grouped, labels, "**DATAS-ENDPOINT**")

        if datas is not None:
            L += datas
            has_diff = True
        else:
            L.append("**DATAS-ENDPOINT**: (identical)")

        # ---------- RESPONSE ----------
        rl, r_diff = self._resp_section(sides, labels)
        L += rl
        if r_diff:
            has_diff = True

        L.append("")
        return "\n".join(L) + "\n", has_diff

    def _resp_section(self, sides, labels):
        resps = [s["resp"] for s in sides]
        n = len(sides)
        if all(r is None for r in resps):
            return [], False
        if any(r is None for r in resps):
            if n == 2:  # keep the original wording for 2-way
                return ["**RESPONSE**: (response not recorded on one side - skipped)"], False
            return ["**RESPONSE**: (response not recorded on one or more sides - skipped)"], False

        flats = [self._try_json_flat(r) for r in resps]
        if all(f is not None for f in flats):
            diffs = self._diff_maps_n(flats)[:MAX_DIFF_LINES]
            if not diffs:
                return ["**RESPONSE**: (identical)"], False
            return self._kv_block_n(diffs, labels,
                                    "**RESPONSE-DIFF** (max %d lines)" % MAX_DIFF_LINES), True

        # non-JSON: apply the 10/15-lines rule to avoid dumping HTML
        if any(len(r.splitlines()) > RESP_SKIP_LINES for r in resps):
            return ["**RESPONSE**: skipped (> %d lines - probably HTML)" % RESP_SKIP_LINES], False
        entries = self._line_diff_n(resps, MAX_DIFF_LINES)
        if not entries:
            return ["**RESPONSE**: (identical)"], False
        grouped = [[] for _ in sides]
        for i, t in entries:
            grouped[i].append(t)
        return self._raw_block_n(grouped, labels,
                                 "**RESPONSE-DIFF** (first %d lines)" % MAX_DIFF_LINES), True

    # ---------------------------------------------------- output blocks (N-way)
    def _kv_block_n(self, diffs, labels, header):
        lines = [header, "```json"]
        for i, lab in enumerate(labels):
            lines.append("// %s:" % lab)
            for k, vals in diffs:
                lines.append(u"\t%s: %s" % (json.dumps(self._u(k), ensure_ascii=False),
                                            self._fmt_val(vals[i])))
        lines.append("```")
        return lines

    def _raw_block_n(self, grouped, labels, header):
        lines = [header, "```json"]
        for i, lab in enumerate(labels):
            lines.append("// %s:" % lab)
            lines += [u"\t" + t for t in grouped[i]]
        lines.append("```")
        return lines

    # ---------------------------------------------------- parsing helpers
    _RE_URLENC = re.compile(r"^[^=&\s]+=[^&]*(?:&[^=&\s]+=[^&]*)*$")

    def _u(self, x):
        if isinstance(x, unicode):
            return x
        try:
            return unicode(x)
        except Exception:
            return unicode(str(x), "utf-8", "replace")

    def _uq(self, s):
        try:
            return unquote_plus(s)
        except Exception:
            return s

    def _parse_query(self, q):
        d = {}
        if not q:
            return d
        for pair in q.split("&"):
            if not pair:
                continue
            if "=" in pair:
                k, v = pair.split("=", 1)
            else:
                k, v = pair, ""
            d[self._u(self._uq(k))] = self._u(self._uq(v))
        return d

    def _parse_body(self, body, ctype):
        if not body:
            return {}
        flat = self._try_json_flat(body)
        if flat is not None:
            return flat
        if ("x-www-form-urlencoded" in ctype) or self._RE_URLENC.match(body):
            d = {}
            for pair in body.split("&"):
                if not pair:
                    continue
                if "=" in pair:
                    k, v = pair.split("=", 1)
                else:
                    k, v = pair, ""
                d[self._u(self._uq(k))] = self._u(self._uq(v))
            return d
        return None  # not parseable -> caller falls back to raw line diff

    def _try_json_flat(self, s):
        if not s:
            return None
        try:
            obj = json.loads(s)
        except Exception:
            return None
        if isinstance(obj, (dict, list)):
            return self._flatten(obj)
        return None

    def _flatten(self, obj, prefix=u""):
        flat = {}
        if isinstance(obj, dict):
            if not obj:
                flat[prefix or u"<root>"] = u"{}"
            for k in obj.keys():
                kk = self._u(k)
                key = (prefix + u"." + kk) if prefix else kk
                flat.update(self._flatten(obj[k], key))
        elif isinstance(obj, list):
            if not obj:
                flat[prefix or u"<root>"] = u"[]"
            for i in range(len(obj)):
                key = (prefix + u"[%d]" % i) if prefix else (u"[%d]" % i)
                flat.update(self._flatten(obj[i], key))
        else:
            flat[prefix] = obj
        return flat

    # ---------------------------------------------------- diff helpers
    def _diff_maps_n(self, dicts):
        """Keys where the values are NOT identical across ALL sides."""
        keys = set()
        for d in dicts:
            keys.update(d.keys())
        out = []
        for k in sorted(keys, key=self._u):
            vals = [d.get(k, self._ABSENT) for d in dicts]
            first = vals[0]
            if any(v != first for v in vals[1:]):
                out.append((k, vals))
        return out

    def _fmt_val(self, v):
        if v is self._ABSENT:
            return u"<absent>"
        if isinstance(v, bool):
            return u"true" if v else u"false"
        if v is None:
            return u"null"
        if isinstance(v, (int, float)):
            return unicode(v)
        return json.dumps(self._u(v), ensure_ascii=False)

    def _line_diff_n(self, texts, cap):
        """Per side: lines that do not appear in ANY other side."""
        split = []
        for t in texts:
            split.append([l for l in t.replace("\r\n", "\n").split("\n") if l.strip()])
        out = []
        for i in range(len(split)):
            others = set()
            for j, ls in enumerate(split):
                if j != i:
                    others.update(ls)
            for l in split[i]:
                if l not in others:
                    out.append((i, l))
        return out[:cap]

    # ---------------------------------------------------- file writer
    def _append(self, text):
        d = os.path.dirname(self._output)
        if d and not os.path.isdir(d):
            os.makedirs(d)
        f = codecs.open(self._output, "a", "utf-8")
        try:
            f.write(text)
        finally:
            f.close()


# ------------------------------------------------------------------ CLI
def main(argv=None):
    global LABEL_A, LABEL_B   # must be the FIRST statement in the function

    p = argparse.ArgumentParser(
        prog="Diff-checker",
        description="Non-interactive CLI: compares 2 OR MORE requests (URL + body) "
                    "taken from Burp Suite XML exports and appends an Obsidian-friendly "
                    "diff note to a .md file. Never prompts.")
    p.add_argument("xml", nargs="+",
                   help="one or more Burp Suite XML export files ('Save selected items'); "
                        "multiple files = one N-way comparison (User A, User B, User C, ...)")
    p.add_argument("-o", "--output", default=None,
                   help="output .md file (default: ~/Desktop/burp-diffs.md)")
    p.add_argument("--pairs", nargs="+", metavar="A,B[,C...]", default=None,
                   help="compare the given items together (1-based, global numbering); "
                        "any count >= 2 allowed for N-way: --pairs 1,2,3; repeatable")
    p.add_argument("--all", action="store_true",
                   help="compare consecutive 2-way pairs (1-2, 2-3, ...) instead of "
                        "the multi-file N-way default")
    p.add_argument("--nway", action="store_true",
                   help="compare ALL loaded items in a single N-way diff")
    p.add_argument("--list", action="store_true",
                   help="just list loaded items (with their numbers) and exit")
    p.add_argument("--label-a", default=None,
                   help="override LABEL_A (default: %s)" % LABEL_A)
    p.add_argument("--label-b", default=None,
                   help="override LABEL_B (default: %s)" % LABEL_B)
    p.add_argument("--labels", default=None,
                   help="comma-separated side labels for N-way, e.g. 'Admin,Guest,Service'")
    args = p.parse_args(argv)

    if args.label_a:
        LABEL_A = args.label_a
    if args.label_b:
        LABEL_B = args.label_b

    labels_override = None
    if args.labels:
        labels_override = [x.strip() for x in args.labels.split(",") if x.strip()]

    tool = ReqDiffCLI(output=args.output, labels=labels_override)
    print("[ReqDiff] output file: %s" % tool._output)

    items = []
    for f in args.xml:
        items.extend(tool._load_xml(f))
    if not items:
        print("[ReqDiff] no items found - nothing to do.")
        return 1

    for i, it in enumerate(items):
        it["idx"] = i
        it["num"] = str(i + 1)

    if args.list:
        tool._list_items(items)
        return 0

    n = len(items)
    comparisons = None

    if args.pairs:
        comparisons = tool._parse_pairs_arg(args.pairs, n)
        if comparisons is None:
            return 1
    elif args.nway:
        if n < 2:
            print("[ReqDiff] --nway needs at least 2 loaded items.")
            return 1
        comparisons = [list(range(n))]
    elif len(args.xml) >= 2:
        # DEFAULT for multiple files: one N-way comparison, each file = one side
        # (item #1 of every file). Labels: User A, User B, User C, ...
        order, groups = [], {}
        for it in items:
            if it["src"] not in groups:
                order.append(it["src"])
                groups[it["src"]] = []
            groups[it["src"]].append(it)
        if len(order) >= 2:
            sides = []
            for pth in order:
                g = groups[pth]
                if len(g) > 1:
                    print("[ReqDiff] note: %s has %d items - using item #%s"
                          % (pth, len(g), g[0]["num"]))
                sides.append(g[0])
            comparisons = [[s["idx"] for s in sides]]
            print("[ReqDiff] file comparison: " + " | ".join(
                "%s = %s (#%s)" % (tool._side_label(i), items[s["idx"]]["src"], s["num"])
                for i, s in enumerate(sides)))
        # else: effectively one usable file -> fall through to consecutive pairs

    if comparisons is None:
        # single file (or --all): consecutive 2-way pairs
        if n < 2:
            print("[ReqDiff] only %d item(s) loaded - need at least 2 to compare." % n)
            return 1
        comparisons = [(i, i + 1) for i in range(n - 1)]

    compared = 0
    for group in comparisons:
        print("")
        print("[ReqDiff] comparing %s ..." % " vs ".join("#" + items[i]["num"] for i in group))
        tool._compare_multi([items[i] for i in group])
        compared += 1
    print("")
    print("[ReqDiff] done - %d comparison(s), notes appended to: %s"
          % (compared, tool._output))
    return 0


if __name__ == "__main__":
    print("""
██████╗ ██╗███████╗███████╗     ██████╗██╗  ██╗
██╔══██╗██║██╔════╝██╔════╝    ██╔════╝██║  ██║
██║  ██║██║█████╗  █████╗      ██║     ███████║
██║  ██║██║██╔══╝  ██╔══╝      ██║     ██╔══██║
██████╔╝██║██║     ██║         ╚██████╗██║  ██║
╚═════╝ ╚═╝╚═╝     ╚═╝          ╚═════╝╚═╝  ╚═╝
            diff checker tool
""")
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[ReqDiff] aborted.")
