#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Active Recon Markdown Generator - CLI Version
# (CLI port of the Burp Suite Jython extension "Recon To Markdown")
#
# Same processing logic and the exact same Markdown output as the Burp
# extension - with zero Burp / Swing / Java dependencies. Pure Python 3.
#
# Mapping from the extension:
#   "Export to Markdown"      -> run the CLI on your request/response files
#   "Change Output File..."   -> -o / --output flag
#   JFileChooser save dialog  -> -o / --output (default: recon_<timestamp>.md)

import argparse
import glob
import os
import re
import sys
import time
import traceback
from urllib.parse import unquote


GREEN, END = (
    "\033[1;32m",
    "\033[0m",
)

class ActiveReconCLI:

    def __init__(self):
        # Persistent state: the currently selected output file.
        self._output_file_path = None

        # Running counter of exported requests in the current output file.
        self._request_counter = 0

    # ---------- Safe helpers ----------

    def _s(self, v):
        """Always returns a string, never None."""
        if v is None:
            return u""
        if isinstance(v, bytes):
            try:
                return v.decode("utf-8", "replace")
            except Exception:
                return u""
        try:
            return str(v)
        except Exception:
            return u""

    def _safe_url_decode(self, text):
        """urlDecode that never returns None; falls back to the raw text."""
        text = self._s(text)
        if not text:
            return u""
        try:
            decoded = unquote(text)   # replaces self._helpers.urlDecode(text)
        except Exception:
            decoded = None
        return self._s(decoded) if decoded is not None else text

    def _is_json_like(self, text):
        s = self._s(text).strip()
        return s[:1] in (u"{", u"[")

    # ---------- Raw HTTP helpers (replaces Burp's IExtensionHelpers) ----------

    @staticmethod
    def _bytes_to_str(data):
        """Replaces helpers.bytesToString()."""
        if data is None:
            return u""
        if isinstance(data, bytes):
            return data.decode("utf-8", "replace")
        return str(data)

    @staticmethod
    def _split_headers_body(raw):
        """
        Splits raw HTTP bytes into (headers, body) at the first blank line.
        Byte-accurate equivalent of slicing at Burp's getBodyOffset().
        """
        if not raw:
            return b"", b""
        sep = raw.find(b"\r\n\r\n")
        if sep != -1:
            return raw[:sep], raw[sep + 4:]
        sep = raw.find(b"\n\n")
        if sep != -1:
            return raw[:sep], raw[sep + 2:]
        return raw, b""

    @staticmethod
    def _parse_request_line(headers_str):
        """Returns (method, path, version) from the request line."""
        first_line = headers_str.split(u"\n", 1)[0].strip()
        parts = first_line.split()
        if len(parts) >= 2:
            return parts[0], parts[1], (parts[2] if len(parts) > 2 else u"HTTP/1.1")
        return u"GET", u"/", u"HTTP/1.1"

    @staticmethod
    def _get_header_value(headers_str, header_name):
        m = re.search(r'(?im)^' + re.escape(header_name) + r':\s*([^\r\n]+)', headers_str)
        return m.group(1).strip() if m else u""

    def _build_url(self, scheme, domain, path):
        """Rebuilds the full URL the same way request_info.getUrl() does."""
        path = self._s(path)
        if path.startswith(u"http://") or path.startswith(u"https://"):
            return path  # absolute-form request target
        if not path.startswith(u"/"):
            path = u"/" + path
        if domain and domain != u"Unknown_Domain":
            return u"%s://%s%s" % (scheme, domain, path)
        return path

    # ---------- Parameter parsing (replaces request_info.getParameters()) ----------

    @staticmethod
    def _split_query_pairs(query):
        """Splits a raw query-string / form body into RAW (name, value) pairs."""
        pairs = []
        if not query:
            return pairs
        for chunk in query.split(u"&"):
            chunk = chunk.strip()
            if not chunk:
                continue
            if u"=" in chunk:
                name, value = chunk.split(u"=", 1)
            else:
                name, value = chunk, u""
            pairs.append((name, value))
        return pairs

    def _parse_cookie_params(self, headers_str):
        """Extracts cookie parameters from the Cookie header(s)."""
        params = []
        try:
            for m in re.finditer(r'(?im)^Cookie:\s*([^\r\n]+)', headers_str):
                cookie_str = m.group(1).strip()
                for pair in cookie_str.split(u";"):
                    pair = pair.strip()
                    if not pair:
                        continue
                    if u"=" in pair:
                        name, value = pair.split(u"=", 1)
                        params.append((name.strip(), value.strip()))
                    else:
                        params.append((pair, u""))
        except Exception as e:
            print("Error parsing cookies: " + str(e))
        return params

    def _parse_multipart_params(self, body, content_type):
        """Extracts (name, value) pairs from a multipart/form-data body."""
        params = []
        try:
            m = re.search(r'boundary="?([^";,]+)"?', content_type or u"")
            if not m:
                return params
            boundary = m.group(1)
            for part in re.split(u"--" + re.escape(boundary), body):
                part = part.strip(u"\r\n \t")
                if not part or part == u"--":
                    continue
                nm = re.search(r'\bname="([^"]*)"', part)
                if not nm:
                    continue
                name = self._s(nm.group(1))
                chunks = re.split(u"\r\n\r\n|\n\n", part, maxsplit=1)
                value = self._s(chunks[1]).strip() if len(chunks) > 1 else u""
                params.append((name, value))
        except Exception as e:
            print("Error parsing multipart body: " + str(e))
        return params

    def _get_burp_like_parameters(self, req_headers_str, req_data):
        """
        Replacement for request_info.getParameters().
        Returns RAW (name, value) pairs from (in order):
          1. URL query string
          2. body (form-urlencoded / multipart)
          3. Cookie header
        Values stay raw here - the caller URL-decodes them, exactly like
        the original extension did.
        """
        params = []

        # --- URL query parameters ---
        try:
            method, path, version = self._parse_request_line(req_headers_str)
            if u"?" in path:
                query = path.split(u"?", 1)[1]
                params.extend(self._split_query_pairs(query))
        except Exception as e:
            print("Error reading request parameters: " + str(e))

        # --- Body parameters ---
        try:
            content_type = self._get_header_value(req_headers_str, u"Content-Type") or u""
            ct = content_type.lower()
            if req_data:
                if u"application/x-www-form-urlencoded" in ct:
                    params.extend(self._split_query_pairs(req_data))
                elif u"multipart/form-data" in ct:
                    params.extend(self._parse_multipart_params(req_data, content_type))
                # JSON bodies are handled by the JSON extractors,
                # exactly like the original extension.
        except Exception as e:
            print("Error reading body parameters: " + str(e))

        # --- Cookie parameters ---
        params.extend(self._parse_cookie_params(req_headers_str))

        return params

    # ---------- File selection ----------

    def ensure_output_file(self):
        """
        Makes sure we have an output file path set.
        (CLI equivalent of the save dialog: -o/--output, or a default
        recon_<timestamp>.md in the current directory.)
        """
        if self._output_file_path is None:
            timestamp = int(time.time())
            suggested = "recon_" + str(timestamp) + ".md"
            self._output_file_path = suggested
            self._request_counter = 0
            print("Output file set to: " + suggested)
        return self._output_file_path

    # ---------- Core processing ----------

    def process_request(self, request_bytes, response_bytes=None, scheme=u"http"):
        try:
            request_bytes = request_bytes or b""

            if not request_bytes.strip():
                print("No messages selected.")
                return

            output_path = self.ensure_output_file()
            if output_path is None:
                return

            # Split raw request bytes at the body offset (byte-accurate).
            req_header_bytes, req_body_bytes = self._split_headers_body(request_bytes)

            req_headers_str = self._s(self._bytes_to_str(req_header_bytes)).strip()

            method, path, version = self._parse_request_line(req_headers_str)

            host_match = re.search(r'Host:\s*([^\r\n]+)', req_headers_str, re.IGNORECASE)
            domain = self._s(host_match.group(1)).strip() if host_match else u"Unknown_Domain"

            url = self._build_url(scheme, domain, path)
            method = self._s(method)

            req_data = u""
            if len(req_body_bytes) > 0:
                req_data = self._s(self._bytes_to_str(req_body_bytes)).strip()

            # REQ shows the full raw request: headers + original (raw) body
            if req_data:
                request_str = req_headers_str + u"\r\n\r\n" + req_data
            else:
                request_str = req_headers_str

            # URL Decode REQ-DATA (safe: never None)
            req_data_decoded = self._safe_url_decode(req_data)

            status_code = u"N/A"
            res_headers_only = u""
            res_data_decoded = u""

            if response_bytes:
                # Slice the RAW BYTE ARRAY at the body offset first,
                # then stringify each piece separately.
                res_header_bytes, res_body_bytes = self._split_headers_body(response_bytes)

                res_headers_only = self._s(self._bytes_to_str(res_header_bytes)).strip()

                sm = re.search(r'(?i)^HTTP/[0-9](?:\.[0-9])?\s+([0-9]{3})', res_headers_only)
                status_code = self._s(sm.group(1)) if sm else u"N/A"

                res_data = u""
                if len(res_body_bytes) > 0:
                    res_data = self._s(self._bytes_to_str(res_body_bytes)).strip()

                # If the response body is longer than 100 lines, skip it.
                if res_data and res_data.count(u"\n") + 1 > 100:
                    res_data = u""

                # URL Decode RES-DATA (safe: never None)
                res_data_decoded = self._safe_url_decode(res_data)

            self._request_counter += 1

            req_params = self.extract_request_parameters(req_headers_str, req_data, req_data_decoded)
            res_params = self.extract_response_parameters(res_data_decoded)

            # Merge + de-duplicate while preserving first-seen order
            seen = set()
            all_params = []
            for name in req_params + res_params:
                if name not in seen:
                    seen.add(name)
                    all_params.append(name)

            # name=value pairs (request + response)
            req_param_values = self.extract_request_parameter_values(req_headers_str, req_data, req_data_decoded)
            res_param_values = self.extract_response_parameter_values(res_data_decoded)

            seen_values = set()
            all_param_values = []
            for name, value in req_param_values + res_param_values:
                key = (name, value)
                if key not in seen_values:
                    seen_values.add(key)
                    all_param_values.append((name, value))

            md_content = self.build_markdown(
                self._request_counter, domain, url, method, status_code,
                request_str, req_data_decoded, res_headers_only,
                res_data_decoded, all_params, all_param_values
            )
            self.append_to_file(output_path, md_content)
        except Exception as e:
            print("Error processing request: " + str(e))
            print(traceback.format_exc())

    # ---------- JSON helpers ----------

    def extract_json_keys(self, text):
        """
        Best-effort extraction of JSON property names from a text blob.
        Falls back to a regex scan when the text isn't valid JSON.
        """
        names = []
        text = self._s(text)

        try:
            import json
            parsed = json.loads(text)
            self._walk_json_keys(parsed, names)
            if names:
                return names
        except Exception:
            pass

        for m in re.finditer(r'"([A-Za-z0-9_\-\.\[\]]+)"\s*:', text):
            names.append(self._s(m.group(1)))

        return names

    def _walk_json_keys(self, node, names):
        if isinstance(node, dict):
            for k, v in node.items():
                names.append(self._s(k))
                self._walk_json_keys(v, names)
        elif isinstance(node, list):
            for item in node:
                self._walk_json_keys(item, names)

    def extract_json_key_values(self, text):
        """
        Best-effort extraction of (key, value) pairs from a JSON text blob.
        Nested keys use dotted/bracket paths (e.g. "user.address.city",
        "items[0].id"). Falls back to regex when the text isn't valid JSON.
        """
        pairs = []
        text = self._s(text)

        try:
            import json
            parsed = json.loads(text)
            self._walk_json_key_values(parsed, u"", pairs)
            if pairs:
                return pairs
        except Exception:
            pass

        for m in re.finditer(r'"([A-Za-z0-9_\-\.\[\]]+)"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)', text):
            key = self._s(m.group(1))
            raw_value = self._s(m.group(2))
            if len(raw_value) >= 2 and raw_value[0] == '"' and raw_value[-1] == '"':
                raw_value = raw_value[1:-1]
            pairs.append((key, raw_value))

        return pairs

    def _walk_json_key_values(self, node, path, pairs):
        if isinstance(node, dict):
            for k, v in node.items():
                new_path = (path + u"." + self._s(k)) if path else self._s(k)
                self._walk_json_key_values(v, new_path, pairs)
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                new_path = u"%s[%d]" % (path, idx)
                self._walk_json_key_values(item, new_path, pairs)
        else:
            pairs.append((path, self._stringify_leaf(node)))

    def _stringify_leaf(self, value):
        if value is None:
            return u"null"
        if isinstance(value, bool):
            return u"true" if value else u"false"
        return self._s(value)

    # ---------- Parameter name extraction ----------

    def extract_request_parameters(self, req_headers_str, req_data, req_data_decoded):
        """
        Collects parameter/property names from the URL query string
        and the request body (form-encoded, multipart, or JSON).
        """
        names = []

        try:
            for name, value in self._get_burp_like_parameters(req_headers_str, req_data):
                names.append(self._s(name))
        except Exception as e:
            print("Error reading request parameters: " + str(e))

        if self._is_json_like(req_data_decoded):
            names.extend(self.extract_json_keys(req_data_decoded))

        return names

    def extract_response_parameters(self, res_data_decoded):
        """
        Collects property names found in the response body
        (JSON keys, or key=value style fields).
        """
        names = []

        if not res_data_decoded:
            return names

        if self._is_json_like(res_data_decoded):
            names.extend(self.extract_json_keys(res_data_decoded))
        else:
            for m in re.finditer(r'([A-Za-z0-9_\-\.]+)\s*=', self._s(res_data_decoded)):
                names.append(self._s(m.group(1)))

        return names

    # ---------- Parameter VALUE extraction ----------

    def extract_request_parameter_values(self, req_headers_str, req_data, req_data_decoded):
        """
        Collects (name, value) pairs from query/form params and from a
        JSON body (dotted-path keys).
        """
        pairs = []

        try:
            for name, value in self._get_burp_like_parameters(req_headers_str, req_data):
                pairs.append((self._s(name), self._safe_url_decode(value)))
        except Exception as e:
            print("Error reading request parameter values: " + str(e))

        if self._is_json_like(req_data_decoded):
            pairs.extend(self.extract_json_key_values(req_data_decoded))

        return pairs

    def extract_response_parameter_values(self, res_data_decoded):
        """
        Collects (name, value) pairs from the response body
        (JSON key/value pairs, or key=value style fields).
        """
        pairs = []

        if not res_data_decoded:
            return pairs

        if self._is_json_like(res_data_decoded):
            pairs.extend(self.extract_json_key_values(res_data_decoded))
        else:
            for m in re.finditer(r'([A-Za-z0-9_\-\.]+)\s*=\s*([^&\s]*)', self._s(res_data_decoded)):
                pairs.append((self._s(m.group(1)), self._s(m.group(2))))

        return pairs

    # ---------- Markdown ----------

    def build_markdown(self, request_number, domain, url, method, status, req, req_data, res, res_data, parameters, parameter_values):
        domain = self._s(domain)
        url = self._s(url)
        method = self._s(method)
        status = self._s(status)
        req = self._s(req)
        req_data = self._s(req_data)
        res = self._s(res)
        res_data = self._s(res_data)

        template = u"""
***
### [DOMAIN_PLACEHOLDER] Page:
### Request: REQUEST_NUMBER_PLACEHOLDER
**URL** : URL_PLACEHOLDER #URL
**METHODE**: `METHOD_PLACEHOLDER` #METHOD_PLACEHOLDER-req
**NOTE-REQ**: #note-req
> 

**STATUS**: `STATUS_PLACEHOLDER` #status_STATUS_PLACEHOLDER
**REQ**:
```python
REQ_PLACEHOLDER
```
**REQ-DATA**:
`decode`
```python
REQ_DATA_PLACEHOLDER
```
**RES**:
```python
RES_PLACEHOLDER
```
**RES-DATA**:
`decode`
```python
RES_DATA_PLACEHOLDER
```
**PARAMETERS**: #parameters
```python
PARAMETERS_PLACEHOLDER
```
**PARAMETER VALUES**: #parameter_values
```python
PARAMETER_VALUES_PLACEHOLDER
```
***
"""
        template = template.replace(u"REQUEST_NUMBER_PLACEHOLDER", self._s(request_number))
        template = template.replace(u"DOMAIN_PLACEHOLDER", domain)
        template = template.replace(u"URL_PLACEHOLDER", url)
        template = template.replace(u"METHOD_PLACEHOLDER", method)
        template = template.replace(u"STATUS_PLACEHOLDER", status)
        template = template.replace(u"REQ_PLACEHOLDER", req)
        template = template.replace(u"REQ_DATA_PLACEHOLDER", req_data)
        template = template.replace(u"RES_PLACEHOLDER", res)
        template = template.replace(u"RES_DATA_PLACEHOLDER", res_data)

        parameters_str = u", ".join([self._s(p) for p in parameters]) if parameters else u"(none found)"
        template = template.replace(u"PARAMETERS_PLACEHOLDER", parameters_str)

        if parameter_values:
            separator = u"#-------------------------------------"
            values_lines = []
            for name, value in parameter_values:
                values_lines.append(u"%s = %s" % (self._s(name), self._s(value)))
            parameter_values_str = (u"\n" + separator + u"\n").join(values_lines)
        else:
            parameter_values_str = u"(none found)"
        template = template.replace(u"PARAMETER_VALUES_PLACEHOLDER", parameter_values_str)

        return template

    def append_to_file(self, file_path, content):
        """
        Appends content to the persistent output file.
        Creates the file (and parent dirs) if it doesn't exist yet.
        """
        try:
            parent = os.path.dirname(os.path.abspath(file_path))
            if parent and not os.path.exists(parent):
                os.makedirs(parent)

            with open(file_path, "ab") as f:
                f.write(content.encode("utf-8"))

            print("SUCCESS: Markdown appended to: " + file_path)
        except Exception as e:
            print("ERROR saving file => " + str(e))
            print(traceback.format_exc())

    # ---------- Input loaders ----------

    def _decode_burp_xml_element(self, element):
        import base64
        text = element.text.strip()
        if element.attrib.get("base64", "false").lower() == "true":
            try:
                return base64.b64decode(text)
            except Exception:
                pass
        return self._s(text).encode("utf-8", "replace")

    def load_burp_xml(self, path):
        """
        Parses a Burp Suite "Save selected items" XML export.
        Returns a list of (request_bytes, response_bytes, scheme_or_None)
        - one entry per <item>.
        """
        import xml.etree.ElementTree as ET

        items = []
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except Exception as e:
            print("ERROR parsing Burp XML file => " + str(e))
            print(traceback.format_exc())
            return items

        for item in root.iter("item"):
            scheme = None
            host_el = item.find("host")
            if host_el is not None:
                scheme = u"https" if host_el.attrib.get("https", "false").lower() == "true" else u"http"

            req_bytes = b""
            res_bytes = b""

            req_el = item.find("request")
            if req_el is not None and req_el.text:
                req_bytes = self._decode_burp_xml_element(req_el)

            res_el = item.find("response")
            if res_el is not None and res_el.text:
                res_bytes = self._decode_burp_xml_element(res_el)

            items.append((req_bytes, res_bytes, scheme))

        print("Loaded " + str(len(items)) + " item(s) from Burp XML: " + path)
        return items


def main():
    parser = argparse.ArgumentParser(
        prog="active-recon-cli.py",
        description="Recon To Markdown - CLI version of the Burp Suite extension "
                    "(identical processing logic and identical Markdown output).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python active-recon-cli.py -r request.txt
  python active-recon-cli.py -r req1.txt req2.txt -R res1.txt res2.txt -o report.md
  python active-recon-cli.py -x burp_saved_items.xml -o report.md
  python active-recon-cli.py -x items1.xml items2.xml items3.xml -o report.md
  python active-recon-cli.py -x "burp_items_*.xml" -o report.md
  cat request.txt | python active-recon-cli.py -o report.md
"""
    )
    parser.add_argument("-r", "--requests", nargs="+", metavar="FILE",
                        help="raw HTTP request file(s); each file = one message")
    parser.add_argument("-R", "--responses", nargs="*", default=[], metavar="FILE",
                        help="raw HTTP response file(s), paired by order with the requests")
    parser.add_argument("-x", "--burp-xml", nargs="+", metavar="FILE",
                        help="Burp Suite 'Save selected items' XML export file(s). "
                             "Accepts multiple files and wildcards, e.g.: "
                             "-x items1.xml items2.xml or -x 'burp_*.xml'")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="markdown output file (default: recon_<timestamp>.md in current dir)")
    parser.add_argument("-s", "--https", action="store_true",
                        help="build URLs with https:// instead of http:// "
                             "(not needed for Burp XML files - scheme is auto-detected)")
    args = parser.parse_args()

    print("Recon To Markdown CLI Loaded Successfully!")

    recon = ActiveReconCLI()

    if args.output:
        recon._output_file_path = args.output
        recon._request_counter = 0
        print("Output file set to: " + args.output)

    scheme = u"https" if args.https else u"http"

    messages = []

    # --- Burp XML export(s) ---
    if args.burp_xml:
        # Expand wildcards (useful on Windows where the shell does NOT
        # expand globs, e.g. -x "burp_items_*.xml").
        xml_paths = []
        for pattern in args.burp_xml:
            if any(ch in pattern for ch in u"*?["):
                matches = sorted(glob.glob(pattern))
                if matches:
                    xml_paths.extend(matches)
                else:
                    print("WARNING: no files match pattern: " + pattern)
            else:
                xml_paths.append(pattern)

        if not xml_paths:
            print("No Burp XML files to process.")

        for xml_path in xml_paths:
            if not os.path.isfile(xml_path):
                print("ERROR: XML file not found, skipping: " + xml_path)
                continue
            # The request counter keeps incrementing across all XML files,
            # so numbering in the output file stays continuous.
            messages.extend(recon.load_burp_xml(xml_path))

    # --- raw request/response files ---
    if args.requests:
        if args.responses and len(args.responses) != len(args.requests):
            print("WARNING: number of response files (%d) != number of request files (%d); "
                  "pairing by order." % (len(args.responses), len(args.requests)))
        for i, req_path in enumerate(args.requests):
            req_bytes = b""
            res_bytes = b""
            try:
                with open(req_path, "rb") as f:
                    req_bytes = f.read()
            except Exception as e:
                print("ERROR reading request file " + req_path + " => " + str(e))
                continue
            if i < len(args.responses):
                try:
                    with open(args.responses[i], "rb") as f:
                        res_bytes = f.read()
                except Exception as e:
                    print("ERROR reading response file " + args.responses[i] + " => " + str(e))
            messages.append((req_bytes, res_bytes, None))

    # --- stdin (piped raw request) ---
    if not messages:
        try:
            stdin_is_tty = sys.stdin.isatty()
        except Exception:
            stdin_is_tty = True
        if not stdin_is_tty:
            data = sys.stdin.buffer.read()
            if data and data.strip():
                messages.append((data, b"", None))

    if not messages:
        print("No messages selected.")
        parser.print_help()
        return 1

    for req_bytes, res_bytes, xml_scheme in messages:
        msg_scheme = xml_scheme if xml_scheme else scheme
        recon.process_request(req_bytes, res_bytes, msg_scheme)

    return 0


if __name__ == "__main__":
    print(f"""{GREEN}
 █████╗ ██████╗ ████████╗ ██████╗
██╔══██╗██╔══██╗╚══██╔══╝██╔════╝
███████║██████╔╝   ██║   ██║     
██╔══██║██╔══██╗   ██║   ██║     
██║  ██║██║  ██║   ██║   ╚██████╗
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝
            CLI VE
{END}""")
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        sys.exit(130)
