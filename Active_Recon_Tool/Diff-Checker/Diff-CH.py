# -*- coding: utf-8 -*-
#
# Diff-checker.py - pure CLI version of ReqDiff2Obsidian.py
# ------------------------------------------------------------------
# Fully NON-INTERACTIVE: give the XML file(s), get the diff note. Done.
#
# * Diff logic, note format, config values and output-file behaviour
#   are UNCHANGED from the original Burp extension.
# * Input : one or more Burp Suite XML exports ("Save selected items").
# * Default: every consecutive pair of items is compared (1-2, 2-3, ...).
#   Items are numbered globally across all given files, so two files
#   with one request each are simply compared as file1 vs file2.
# * Use --pairs A,B to compare specific items instead. Never prompts.
#
# Usage:
#   python Diff-checker.py a.xml b.xml               # a vs b
#   python Diff-checker.py export.xml                # all consecutive pairs
#   python Diff-checker.py export.xml --pairs 1,3
#   python Diff-checker.py export.xml --pairs 1,2 4,5
#   python Diff-checker.py export.xml --list         # show items and exit
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
    def __init__(self, output=None):
        self._output = output or OUTPUT_FILE or os.path.join(
            os.path.expanduser("~"), "Desktop\\burp-diffs.md")

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
        pairs, ok = [], True
        for spec in specs:
            parts = [p.strip() for p in spec.split(",") if p.strip()]
            if len(parts) != 2:
                print("[ReqDiff] ERROR: bad pair spec '%s' (use A,B e.g. 1,2)" % spec)
                ok = False
                continue
            try:
                a, b = int(parts[0]), int(parts[1])
            except ValueError:
                print("[ReqDiff] ERROR: bad pair spec '%s' (numbers only)" % spec)
                ok = False
                continue
            if a == b or not (1 <= a <= n) or not (1 <= b <= n):
                print("[ReqDiff] ERROR: pair '%s' out of range (1..%d) or equal" % (spec, n))
                ok = False
                continue
            pairs.append((a - 1, b - 1))
        return pairs if ok else None

    # ---------------------------------------------------- main flow
    def _compare(self, msgA, msgB):
        try:
            A = self._extract(msgA)
            B = self._extract(msgB)
            note, has_diff = self._build_note(A, B)
            if not has_diff:
                print("[ReqDiff] #%s vs #%s: URL & Body are identical. Nothing saved."
                      % (msgA.get("num", "?"), msgB.get("num", "?")))
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
    # (replaces self._helpers.analyzeRequest / analyzeResponse)
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

    # ---------------------------------------------------- note builder
    def _build_note(self, A, B):
        L = []
        has_diff = False

        L.append("")
        L.append("---")
        L.append(u"#### ReqDiff | %s" % time.strftime("%Y-%m-%d %H:%M"))

        # ---------- REQ-ENDPOINT ----------
        same_ep = (A["method"] == B["method"] and A["path"] == B["path"])
        if same_ep:
            q = ("?" + A["query"]) if (A["query"] and A["query"] == B["query"]) else ""
            L.append("**REQ-ENDPOINT**: `%s` %s%s" % (A["method"], A["path"], q))
        else:
            L.append("**REQ-ENDPOINT**:")
            L.append("- %s: `%s %s%s`" % (LABEL_A, A["method"], A["path"],
                                          ("?" + A["query"]) if A["query"] else ""))
            L.append("- %s: `%s %s%s`" % (LABEL_B, B["method"], B["path"],
                                          ("?" + B["query"]) if B["query"] else ""))
            has_diff = True

        if A["host"] != B["host"]:
            L.append("- host %s: `%s` | host %s: `%s`" % (LABEL_A, A["host"], LABEL_B, B["host"]))
            has_diff = True

        # ---------- DATAS (query params + body) ----------
        url_diffs = self._diff_maps(self._parse_query(A["query"]),
                                    self._parse_query(B["query"]))
        pa = self._parse_body(A["body"], A["ctype"])
        pb = self._parse_body(B["body"], B["ctype"])

        datas = None
        if pa is not None and pb is not None:
            body_diffs = self._diff_maps(pa, pb)
            body_keys = set(k for k, _, _ in body_diffs)
            merged = []
            for k, va, vb in url_diffs:
                merged.append(("url." + k if k in body_keys else k, va, vb))
            merged += body_diffs
            if merged:
                datas = self._kv_block(merged, "**DATAS-ENDPOINT**:")
        else:
            # unparseable body (XML / multipart / plain text) -> raw line diff
            if A["body"] != B["body"]:
                la = len(A["body"].splitlines())
                lb = len(B["body"].splitlines())
                if la > BODY_SKIP_LINES or lb > BODY_SKIP_LINES:
                    datas = ["**DATAS-ENDPOINT**: skipped (body > %d lines, not JSON/urlencoded)"
                             % BODY_SKIP_LINES]
                else:
                    entries = self._line_diff(A["body"], B["body"], MAX_DIFF_LINES)
                    if entries:
                        datas = self._raw_block(entries, "**DATAS-ENDPOINT**")

        if datas is not None:
            L += datas
            has_diff = True
        else:
            L.append("**DATAS-ENDPOINT**: (identical)")

        # ---------- RESPONSE ----------
        rl, r_diff = self._resp_section(A, B)
        L += rl
        if r_diff:
            has_diff = True

        L.append("")
        return "\n".join(L) + "\n", has_diff

    def _resp_section(self, A, B):
        ra, rb = A["resp"], B["resp"]
        if ra is None and rb is None:
            return [], False
        if ra is None or rb is None:
            return ["**RESPONSE**: (response not recorded on one side - skipped)"], False

        fa = self._try_json_flat(ra)
        fb = self._try_json_flat(rb)
        if fa is not None and fb is not None:
            diffs = self._diff_maps(fa, fb)[:MAX_DIFF_LINES]
            if not diffs:
                return ["**RESPONSE**: (identical)"], False
            return self._kv_block(diffs, "**RESPONSE-DIFF** (max %d lines)" % MAX_DIFF_LINES), True

        # non-JSON: apply the 10/15-lines rule to avoid dumping HTML
        if len(ra.splitlines()) > RESP_SKIP_LINES or len(rb.splitlines()) > RESP_SKIP_LINES:
            return ["**RESPONSE**: skipped (> %d lines - probably HTML)" % RESP_SKIP_LINES], False
        entries = self._line_diff(ra, rb, MAX_DIFF_LINES)
        if not entries:
            return ["**RESPONSE**: (identical)"], False
        return self._raw_block(entries, "**RESPONSE-DIFF** (first %d lines)" % MAX_DIFF_LINES), True

    # ---------------------------------------------------- output blocks
    def _kv_block(self, diffs, header):
        lines = [header, "```json", "// %s:" % LABEL_A]
        for k, va, _vb in diffs:
            lines.append(u"\t%s: %s" % (json.dumps(self._u(k), ensure_ascii=False),
                                        self._fmt_val(va)))
        lines.append("// %s:" % LABEL_B)
        for k, _va, vb in diffs:
            lines.append(u"\t%s: %s" % (json.dumps(self._u(k), ensure_ascii=False),
                                        self._fmt_val(vb)))
        lines.append("```")
        return lines

    def _raw_block(self, entries, header):
        lines = [header, "```json", "// %s:" % LABEL_A]
        lines += [u"\t" + t for s, t in entries if s == "A"]
        lines.append("// %s:" % LABEL_B)
        lines += [u"\t" + t for s, t in entries if s == "B"]
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
    def _diff_maps(self, da, db):
        out = []
        for k in sorted(set(da.keys()) | set(db.keys()), key=self._u):
            va = da.get(k, self._ABSENT)
            vb = db.get(k, self._ABSENT)
            if va != vb:
                out.append((k, va, vb))
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

    def _line_diff(self, sa, sb, cap):
        a = [l for l in sa.replace("\r\n", "\n").split("\n") if l.strip()]
        b = [l for l in sb.replace("\r\n", "\n").split("\n") if l.strip()]
        out = [("A", l) for l in a if l not in b]
        out += [("B", l) for l in b if l not in a]
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
        description="Non-interactive CLI: compares requests (URL + body) taken "
                    "from Burp Suite XML exports and appends an Obsidian-friendly "
                    "diff note to a .md file. Never prompts.")
    p.add_argument("xml", nargs="+",
                   help="one or more Burp Suite XML export files ('Save selected items')")
    p.add_argument("-o", "--output", default=None,
                   help="output .md file (default: ~/Desktop/burp-diffs.md)")
    p.add_argument("--pairs", nargs="+", metavar="A,B", default=None,
                   help="compare item A with item B (1-based, global numbering "
                        "across all files); repeatable: --pairs 1,2 3,4")
    p.add_argument("--all", action="store_true",
                   help="compare every consecutive pair (1-2, 2-3, ...) - this "
                        "is already the default, kept for explicitness")
    p.add_argument("--list", action="store_true",
                   help="just list loaded items (with their numbers) and exit")
    p.add_argument("--label-a", default=None,
                   help="override LABEL_A (default: %s)" % LABEL_A)
    p.add_argument("--label-b", default=None,
                   help="override LABEL_B (default: %s)" % LABEL_B)
    args = p.parse_args(argv)

    if args.label_a:
        LABEL_A = args.label_a
    if args.label_b:
        LABEL_B = args.label_b

    tool = ReqDiffCLI(output=args.output)
    print("[ReqDiff] output file: %s" % tool._output)

    items = []
    for f in args.xml:
        items.extend(tool._load_xml(f))
    if not items:
        print("[ReqDiff] no items found - nothing to do.")
        return 1

    for i, it in enumerate(items):
        it["num"] = str(i + 1)

    if args.list:
        tool._list_items(items)
        return 0

    n = len(items)
    if args.pairs:
        pairs = tool._parse_pairs_arg(args.pairs, n)
        if pairs is None:
            return 1
    else:
        # DEFAULT (also covers --all): consecutive pairs across all files,
        # so "a.xml b.xml" simply compares a vs b.
        if n < 2:
            print("[ReqDiff] only %d item(s) loaded - need at least 2 to compare." % n)
            return 1
        pairs = [(i, i + 1) for i in range(n - 1)]

    compared = 0
    for a, b in pairs:
        print("[ReqDiff] comparing #%d vs #%d ..." % (a + 1, b + 1))
        tool._compare(items[a], items[b])
        compared += 1
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
