# -*- coding: utf-8 -*-
# Burp Suite Jython Extension - Active Recon Markdown Generator
from burp import IBurpExtender, IContextMenuFactory
from java.awt.event import ActionListener
from javax.swing import JMenuItem, JFileChooser
from java.lang import System
from java.util import ArrayList
from java.io import File, FileOutputStream, OutputStreamWriter
import re
import time
import traceback


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Recon To Markdown")
        callbacks.registerContextMenuFactory(self)

        # Persistent state: the currently selected output file.
        self._output_file_path = None

        # Running counter of exported requests in the current output file.
        self._request_counter = 0

        print("Recon To Markdown Extension Loaded Successfully!")
        return

    def createMenuItems(self, invocation):
        menu_list = ArrayList()

        export_item = JMenuItem("Export to Markdown")
        export_item.addActionListener(MenuActionListener(self, invocation, "export"))
        menu_list.add(export_item)

        change_file_item = JMenuItem("Change Output File...")
        change_file_item.addActionListener(MenuActionListener(self, invocation, "change_file"))
        menu_list.add(change_file_item)

        return menu_list

    # ---------- Safe helpers ----------

    def _s(self, v):
        """Always returns a string, never None."""
        if v is None:
            return u""
        try:
            if isinstance(v, basestring):
                return v
            return unicode(v)
        except Exception:
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
            decoded = self._helpers.urlDecode(text)
        except Exception:
            decoded = None
        return self._s(decoded) if decoded is not None else text

    def _is_json_like(self, text):
        s = self._s(text).strip()
        return s[:1] in (u"{", u"[")

    # ---------- File selection ----------

    def choose_output_file(self, suggested_name=None):
        """
        Opens a save dialog for the user to pick/create the markdown file.
        Returns the chosen absolute path, or None if cancelled.
        """
        chooser = JFileChooser()
        chooser.setDialogTitle("Select Markdown Output File")

        home_dir = System.getProperty("user.home")
        default_dir = File(home_dir + "/Desktop/")
        if not default_dir.exists():
            default_dir = File(home_dir)
        chooser.setCurrentDirectory(default_dir)

        if suggested_name:
            chooser.setSelectedFile(File(default_dir, suggested_name))

        result = chooser.showSaveDialog(None)

        if result == JFileChooser.APPROVE_OPTION:
            selected = chooser.getSelectedFile()
            path = selected.getAbsolutePath()
            if not path.lower().endswith(".md"):
                path = path + ".md"
            return path
        else:
            return None

    def ensure_output_file(self):
        """
        Makes sure we have an output file path set.
        If none has been chosen yet, prompts the user once.
        """
        if self._output_file_path is None:
            timestamp = int(time.time())
            suggested = "recon_" + str(timestamp) + ".md"
            path = self.choose_output_file(suggested_name=suggested)
            if path:
                self._output_file_path = path
                self._request_counter = 0
                print("Output file set to: " + path)
            else:
                print("No output file selected. Export cancelled.")
                return None
        return self._output_file_path

    def change_output_file(self):
        path = self.choose_output_file()
        if path:
            self._output_file_path = path
            self._request_counter = 0
            print("Output file changed to: " + path)
        else:
            print("Change output file cancelled. Keeping previous file: " + str(self._output_file_path))

    # ---------- Core processing ----------

    def process_request(self, invocation):
        messages = invocation.getSelectedMessages()

        if not messages:
            print("No messages selected.")
            return

        output_path = self.ensure_output_file()
        if output_path is None:
            return

        for message in messages:
            try:
                request_info = self._helpers.analyzeRequest(message)

                request_bytes = message.getRequest()

                url = self._s(request_info.getUrl().toString())
                method = self._s(request_info.getMethod())

                # Split raw request bytes at the body offset (byte-accurate).
                req_body_offset = request_info.getBodyOffset()

                req_header_bytes = request_bytes[0:req_body_offset]
                req_body_bytes = request_bytes[req_body_offset:]

                req_headers_str = self._s(self._helpers.bytesToString(req_header_bytes)).strip()

                host_match = re.search(r'Host:\s*([^\r\n]+)', req_headers_str, re.IGNORECASE)
                domain = self._s(host_match.group(1)).strip() if host_match else u"Unknown_Domain"

                req_data = u""
                if len(req_body_bytes) > 0:
                    req_data = self._s(self._helpers.bytesToString(req_body_bytes)).strip()

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
                response_bytes = message.getResponse()

                if response_bytes:
                    response_info = self._helpers.analyzeResponse(response_bytes)
                    status_code = self._s(response_info.getStatusCode())

                    # Slice the RAW BYTE ARRAY at the body offset first,
                    # then stringify each piece separately.
                    res_body_offset = response_info.getBodyOffset()

                    header_bytes = response_bytes[0:res_body_offset]
                    body_bytes = response_bytes[res_body_offset:]

                    res_headers_only = self._s(self._helpers.bytesToString(header_bytes)).strip()

                    res_data = u""
                    if len(body_bytes) > 0:
                        res_data = self._s(self._helpers.bytesToString(body_bytes)).strip()

                    # If the response body is longer than 100 lines, skip it.
                    if res_data and res_data.count(u"\n") + 1 > 100:
                        res_data = u""

                    # URL Decode RES-DATA (safe: never None)
                    res_data_decoded = self._safe_url_decode(res_data)

                self._request_counter += 1

                req_params = self.extract_request_parameters(request_info, req_data_decoded)
                res_params = self.extract_response_parameters(res_data_decoded)

                # Merge + de-duplicate while preserving first-seen order
                seen = set()
                all_params = []
                for name in req_params + res_params:
                    if name not in seen:
                        seen.add(name)
                        all_params.append(name)

                # name=value pairs (request + response)
                req_param_values = self.extract_request_parameter_values(request_info, req_data_decoded)
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

    def extract_request_parameters(self, request_info, req_data_decoded):
        """
        Collects parameter/property names from the URL query string
        and the request body (form-encoded, multipart, or JSON).
        """
        names = []

        try:
            for param in request_info.getParameters():
                names.append(self._s(param.getName()))
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

    def extract_request_parameter_values(self, request_info, req_data_decoded):
        """
        Collects (name, value) pairs from query/form params (Burp's parser)
        and from a JSON body (dotted-path keys).
        """
        pairs = []

        try:
            for param in request_info.getParameters():
                name = self._s(param.getName())
                value = self._safe_url_decode(param.getValue())
                pairs.append((name, value))
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
            f = File(file_path)
            parent = f.getParentFile()
            if parent and not parent.exists():
                parent.mkdirs()

            fos = FileOutputStream(f, True)
            osw = OutputStreamWriter(fos, "UTF-8")
            osw.write(content)
            osw.close()
            fos.close()

            print("SUCCESS: Markdown appended to: " + file_path)
        except Exception as e:
            print("ERROR saving file => " + str(e))
            print(traceback.format_exc())


class MenuActionListener(ActionListener):
    def __init__(self, extender, invocation, action):
        self.extender = extender
        self.invocation = invocation
        self.action = action

    def actionPerformed(self, event):
        if self.action == "export":
            self.extender.process_request(self.invocation)
        elif self.action == "change_file":
            self.extender.change_output_file()
