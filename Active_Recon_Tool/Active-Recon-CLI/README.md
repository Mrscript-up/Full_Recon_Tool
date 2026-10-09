Recon To Markdown — CLI

A pure-Python CLI port of the Burp Suite extension "Recon To Markdown" (Active Recon Markdown Generator).It converts raw HTTP request/response captures into a structured Markdown recon report — no Burp, no Java, no external dependencies.
Requirements
```
    Python 3.x (standard library only)
```
Usage
```bash
# Single raw HTTP request (no response)
python active-recon-cli.py -r request.txt
# Multiple requests with paired responsespython :
active-recon-cli.py -r req1.txt req2.txt -R res1.txt res2.txt -o report.md
# Burp Suite "Save selected items" XML exportpython :
active-recon-cli.py -x burp_items.xml -o report.md
# Multiple Burp XML files (wildcards supported — great on Windows):
python active-recon-cli.py -x items1.xml items2.xml items3.xml -o report.md
python active-recon-cli.py -x "burp_exports/*.xml" -o report.md
# Mix Burp XML + raw request files in one report:
python active-recon-cli.py -x items1.xml -r req1.txt -o report.md
# Pipe a request via stdin:
cat request.txt | python active-recon-cli.py -o report.md
```

Options
```
Flag	Description
-r, --requests FILE...	Raw HTTP request file(s); each file = one message
-R, --responses FILE...	Raw HTTP response file(s), paired by order with the requests
-x, --burp-xml FILE...	Burp "Save selected items" XML file(s) — accepts multiple files and wildcards; the http/https scheme is auto-detected from the XML
-o, --output FILE	Markdown output file (default: recon_<timestamp>.md in current directory)
-s, --https	Build URLs with https:// instead of http:// (raw request mode only)
```
Output

Appends a per-request block to the output Markdown file containing:

    Domain, full URL, HTTP method, status code
    Raw request (headers + original body)
    URL-decoded request body (REQ-DATA)
    Response headers and URL-decoded response body (RES-DATA, skipped if > 100 lines)
    Extracted parameter names (URL query, form-encoded/multipart/JSON body, cookies, response JSON/key=value fields)
    Extracted parameter values as name = value pairs, de-duplicated and preserving first-seen order (JSON keys use dotted/bracket paths, e.g. user.address.city, items[0].id)

Content is appended incrementally (UTF-8), so multiple runs or multiple input files keep writing into the same report with a continuous request counter.
Notes

    Corrupt or missing input files are skipped with a warning; processing continues.
    Windows tip: prefer -r / -x files over piping, since cmd pipes may corrupt binary data.
    Markdown template is byte-identical to the original Burp extension.
