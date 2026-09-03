# -*- coding: utf-8 -*-
# Burp Suite Jython Extension - Active Recon Markdown Generator
from burp import IBurpExtender, IContextMenuFactory
from java.awt.event import ActionListener
from javax.swing import JMenuItem
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
        print("Recon To Markdown Extension Loaded Successfully!")
        return

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_item = JMenuItem("Export to Markdown")
        listener = MenuActionListener(self, invocation)
        menu_item.addActionListener(listener)
        menu_list.add(menu_item)
        return menu_list

    def process_request(self, invocation):
        messages = invocation.getSelectedMessages()
        
        if not messages:
            print("No messages selected.")
            return

        for message in messages:
            try:
                request_info = self._helpers.analyzeRequest(message)
                
                request_bytes = message.getRequest()
                request_str = self._helpers.bytesToString(request_bytes)
                
                url = request_info.getUrl().toString()
                method = request_info.getMethod()
                
                host_match = re.search(r'Host:\s*([^\r\n]+)', request_str, re.IGNORECASE)
                domain = host_match.group(1).strip() if host_match else "Unknown_Domain"
                
                # Extract Request Body (REQ-DATA)
                req_body_offset = request_info.getBodyOffset()
                req_data = ""
                if len(request_str) > req_body_offset:
                    req_data = request_str[req_body_offset:].strip()
                
                # URL Decode REQ-DATA using Burp's native API
                req_data_decoded = self._helpers.urlDecode(req_data) if req_data else ""
                
                status_code = "N/A"
                res_headers_only = ""
                res_data = ""
                response_bytes = message.getResponse()
                
                if response_bytes:
                    response_str_full = self._helpers.bytesToString(response_bytes)
                    response_info = self._helpers.analyzeResponse(response_bytes)
                    status_code = str(response_info.getStatusCode())
                    
                    # Extract Response Headers (RES) and Response Body (RES-DATA)
                    res_body_offset = response_info.getBodyOffset()
                    res_headers_only = response_str_full[:res_body_offset].strip()
                    
                    if len(response_str_full) > res_body_offset:
                        res_data = response_str_full[res_body_offset:].strip()

                    # URL Decode RES-DATA using Burp's native API
                    res_data_decoded = self._helpers.urlDecode(res_data) if res_data else ""
                else:
                    res_data_decoded = ""

                md_content = self.build_markdown(domain, url, method, status_code, request_str, req_data_decoded, res_headers_only, res_data_decoded)
                self.save_to_file(domain, md_content)
            except Exception as e:
                print("Error processing request: " + str(e))

    def build_markdown(self, domain, url, method, status, req, req_data, res, res_data):
        template = """
### [DOMAIN_PLACEHOLDER] Page:
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
***
"""
        template = template.replace("DOMAIN_PLACEHOLDER", domain)
        template = template.replace("URL_PLACEHOLDER", url)
        template = template.replace("METHOD_PLACEHOLDER", method)
        template = template.replace("STATUS_PLACEHOLDER", status)
        template = template.replace("REQ_PLACEHOLDER", req)
        template = template.replace("REQ_DATA_PLACEHOLDER", req_data)
        template = template.replace("RES_PLACEHOLDER", res)
        template = template.replace("RES_DATA_PLACEHOLDER", res_data)
        return template

    def save_to_file(self, domain, content):
        try:
            timestamp = int(time.time())
            
            home_dir = System.getProperty("user.home")
            desktop_dir = home_dir + "/Desktop/"
            
            desktop_folder = File(desktop_dir)
            if not desktop_folder.exists():
                desktop_folder.mkdirs()
            
            safe_domain = re.sub(r'[^a-zA-Z0-9_\-\.]', '', domain)
            filename = "recon_" + safe_domain.replace(".", "_") + "_" + str(timestamp) + ".md"
            
            file_path = desktop_dir + filename
            
            f = File(file_path)
            fos = FileOutputStream(f)
            osw = OutputStreamWriter(fos, "UTF-8")
            osw.write(content)
            osw.close()
            fos.close()
            
            print("SUCCESS: Markdown saved to: " + file_path)
        except Exception as e:
            print("ERROR saving file: " + str(e))


class MenuActionListener(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
        self.extender.process_request(self.invocation)
        