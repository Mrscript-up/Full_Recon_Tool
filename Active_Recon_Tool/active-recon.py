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

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Recon To Markdown")
        callbacks.registerContextMenuFactory(self)

        # Persistent state: the currently selected output file.
        # Stays fixed across multiple "Export to Markdown" actions
        # until the user explicitly picks a new one via "Change Output File".
        self._output_file_path = None

        # Running counter of how many requests have been exported into the
        # current output file. Resets to 0 whenever the output file changes.
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

                url = request_info.getUrl().toString()
                method = request_info.getMethod()

                # Extract Request Headers (REQ) and Request Body (REQ-DATA) by
                # slicing the raw byte array at the body offset, same as the
                # response side, to keep the header/body split byte-accurate.
                req_body_offset = request_info.getBodyOffset()

                req_header_bytes = request_bytes[0:req_body_offset]
                req_body_bytes = request_bytes[req_body_offset:]

                req_headers_str = self._helpers.bytesToString(req_header_bytes).strip()

                host_match = re.search(r'Host:\s*([^\r\n]+)', req_headers_str, re.IGNORECASE)
                domain = host_match.group(1).strip() if host_match else "Unknown_Domain"

                req_data = ""
                if len(req_body_bytes) > 0:
                    req_data = self._helpers.bytesToString(req_body_bytes).strip()

                # REQ shows the full raw request: headers + original (raw) body
                if req_data:
                    request_str = req_headers_str + "\r\n\r\n" + req_data
                else:
                    request_str = req_headers_str

                # URL Decode REQ-DATA using Burp's native API
                req_data_decoded = self._helpers.urlDecode(req_data) if req_data else ""

                status_code = "N/A"
                res_headers_only = ""
                res_data_decoded = ""
                response_bytes = message.getResponse()

                if response_bytes:
                    response_info = self._helpers.analyzeResponse(response_bytes)
                    status_code = str(response_info.getStatusCode())

                    # Extract Response Headers (RES) and Response Body (RES-DATA).
                    # IMPORTANT: slice the RAW BYTE ARRAY at the body offset first,
                    # then stringify each piece separately. Slicing the already
                    # stringified response can misalign with the byte offset
                    # (binary/compressed bodies, encoding quirks), which is what
                    # was letting body/HTML content leak into the RES section.
                    res_body_offset = response_info.getBodyOffset()

                    header_bytes = response_bytes[0:res_body_offset]
                    body_bytes = response_bytes[res_body_offset:]

                    res_headers_only = self._helpers.bytesToString(header_bytes).strip()

                    res_data = ""
                    if len(body_bytes) > 0:
                        res_data = self._helpers.bytesToString(body_bytes).strip()

                    # If the response body is longer than 100 lines, skip it
                    # entirely and leave RES-DATA empty (too big to be useful
                    # in the markdown notes).
                    if res_data and res_data.count("\n") + 1 > 100:
                        res_data = ""

                    # URL Decode RES-DATA using Burp's native API
                    res_data_decoded = self._helpers.urlDecode(res_data) if res_data else ""

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

                md_content = self.build_markdown(self._request_counter, domain, url, method, status_code, request_str, req_data_decoded, res_headers_only, res_data_decoded, all_params)
                self.append_to_file(output_path, md_content)
            except Exception as e:
                print("Error processing request: " + str(e))

    def extract_json_keys(self, text):
        """
        Best-effort extraction of JSON property names from a text blob.
        Uses Jython's json module when the text parses as valid JSON
        (covers nested objects/arrays), and falls back to a regex scan
        for "key": patterns when it doesn't (partial/invalid JSON,
        JS-ish bodies, etc).
        """
        names = []

        try:
            import json
            parsed = json.loads(text)
            self._walk_json_keys(parsed, names)
            if names:
                return names
        except Exception:
            pass

        # Fallback: regex scan for "key": occurrences
        for m in re.finditer(r'"([A-Za-z0-9_\-\.\[\]]+)"\s*:', text):
            names.append(m.group(1))

        return names

    def _walk_json_keys(self, node, names):
        if isinstance(node, dict):
            for k, v in node.items():
                names.append(k)
                self._walk_json_keys(v, names)
        elif isinstance(node, list):
            for item in node:
                self._walk_json_keys(item, names)

    def extract_request_parameters(self, request_info, req_data_decoded):
        """
        Collects parameter/property names found in:
        - the URL query string
        - the request body (form-encoded, multipart, or JSON)
        """
        names = []

        try:
            for param in request_info.getParameters():
                names.append(str(param.getName()))
        except Exception as e:
            print("Error reading request parameters: " + str(e))

        # Catch JSON bodies that Burp's parameter parser may not fully expand
        # (nested objects/arrays), by scanning the raw decoded body too.
        if req_data_decoded:
            stripped = req_data_decoded.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                names.extend(self.extract_json_keys(req_data_decoded))

        return names

    def extract_response_parameters(self, res_data_decoded):
        """
        Collects property names found in the response body (JSON keys,
        or key=value style fields).
        """
        names = []

        if not res_data_decoded:
            return names

        stripped = res_data_decoded.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            names.extend(self.extract_json_keys(res_data_decoded))
        else:
            # key=value style bodies (e.g. form-encoded-ish responses)
            for m in re.finditer(r'([A-Za-z0-9_\-\.]+)\s*=', res_data_decoded):
                names.append(m.group(1))

        return names

    def build_markdown(self, request_number, domain, url, method, status, req, req_data, res, res_data, parameters):
        template = """
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
***
"""
        template = template.replace("REQUEST_NUMBER_PLACEHOLDER", str(request_number))
        template = template.replace("DOMAIN_PLACEHOLDER", domain)
        template = template.replace("URL_PLACEHOLDER", url)
        template = template.replace("METHOD_PLACEHOLDER", method)
        template = template.replace("STATUS_PLACEHOLDER", status)
        template = template.replace("REQ_PLACEHOLDER", req)
        template = template.replace("REQ_DATA_PLACEHOLDER", req_data)
        template = template.replace("RES_PLACEHOLDER", res)
        template = template.replace("RES_DATA_PLACEHOLDER", res_data)
        parameters_str = ", ".join(parameters) if parameters else "(none found)"
        template = template.replace("PARAMETERS_PLACEHOLDER", parameters_str)
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

            # append=True -> keeps adding to the same file across multiple exports
            fos = FileOutputStream(f, True)
            osw = OutputStreamWriter(fos, "UTF-8")
            osw.write(content)
            osw.close()
            fos.close()

            print("SUCCESS: Markdown appended to: " + file_path)
        except Exception as e:
            print("ERROR saving file: " + str(e))


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