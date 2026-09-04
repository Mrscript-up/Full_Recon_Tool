# Recon To Markdown

> **Burp Suite Jython Extension for exporting selected HTTP traffic into structured Markdown notes.**

**Status:** 🚧 Work in Progress — the extension is functional, but the project is not yet feature-complete.

Recon To Markdown is a lightweight Burp Suite extension designed to turn selected HTTP requests and responses into a persistent Markdown reconnaissance/notes file. It is useful for organizing interesting endpoints, parameters, methods, response status codes, and request/response data during web security testing.

## Features

- Export selected Burp Suite messages to Markdown.
- Persistent output file across multiple exports.
- Choose a new output file at any time.
- Automatically adds the `.md` extension.
- Creates the output file and parent directories when necessary.
- Extracts:
  - Request URL
  - HTTP method
  - Host/domain
  - Request headers
  - Request body
  - URL-decoded request body
  - Response status code
  - Response headers
  - Response body
  - URL-decoded response body
  - Request and response parameter/property names
- Supports JSON key extraction, including nested objects and arrays.
- Includes a fallback regex-based JSON key extractor for malformed or partial JSON.
- De-duplicates discovered parameter names while preserving their first-seen order.
- Skips response bodies longer than 100 lines to keep Markdown notes manageable.
- Uses Burp's native helper APIs for request/response analysis and URL decoding.
- Appends exports to the same Markdown file instead of overwriting previous entries.

## Burp Context Menu

The extension currently adds two context-menu actions:

### Export to Markdown

Exports the currently selected Burp messages to the configured Markdown file.

If no output file has been selected yet, the extension opens a save dialog and asks you to choose one.

### Change Output File...

Selects a different Markdown output file.

Changing the output file also resets the internal request counter.

## Output Format

Each exported message is written as a Markdown section similar to:

```markdown
### example.com Page:
### Request: 1
**URL** : https://example.com/api/test #URL
**METHODE**: `POST` #POST-req
**NOTE-REQ**: #note-req
>

**STATUS**: `200` #status_200
**REQ**:
```python
POST /api/test HTTP/1.1
Host: example.com
Content-Type: application/json

{"user_id":123}
```

**REQ-DATA**:
`decode`
```python
{"user_id":123}
```

**RES**:
```python
HTTP/1.1 200 OK
Content-Type: application/json
```

**RES-DATA**:
`decode`
```python
{"id":123,"name":"test"}
```

**PARAMETERS**: #parameters
```python
user_id, id, name
```
***
```

## Parameter Extraction

The extension attempts to discover parameter/property names from both requests and responses.

### Request parameters

Request parameters can come from:

- URL query parameters
- Burp-parsed request parameters
- Form-encoded request bodies
- Multipart/form-data bodies
- JSON request bodies
- Nested JSON objects
- JSON arrays containing objects

For JSON, the extension first attempts to parse the body using Python's `json` module available to Jython. If parsing fails, it falls back to a regular-expression scan for JSON-style property names.

### Response parameters

Response property names are extracted from:

- JSON objects
- Nested JSON structures
- JSON arrays
- Key/value-style response bodies

Request and response names are then merged and de-duplicated.

## Response Body Limit

To prevent very large responses from making the Markdown notes unnecessarily large, response bodies containing more than **100 lines** are omitted from `RES-DATA`.

The response headers are still exported.

## Output File Behavior

The extension keeps the selected output file in memory while the Burp extension remains loaded.

The behavior is:

1. First export → choose an output file.
2. Subsequent exports → append to the same file.
3. `Change Output File...` → select another file.
4. Changing the file → reset the request counter.
5. Reloading/restarting the extension → the current output path is reset and must be selected again.

The default suggested filename is generated from the current Unix timestamp:

```text
recon_<timestamp>.md
```

The save dialog initially opens on the user's Desktop when that directory exists.

## Requirements

- Burp Suite
- Jython 2.x-compatible Burp extension environment
- A Burp Suite version that supports the APIs used by this extension

The extension currently uses the classic Burp Extender API interfaces:

```python
IBurpExtender
IContextMenuFactory
```

## Installation

1. Save the extension source as a Python file, for example:

   ```text
   recon_to_markdown.py
   ```

2. Open Burp Suite.

3. Go to:

   ```text
   Extensions → Installed
   ```

4. Add a new extension.

5. Select the Python extension type and provide the `.py` file.

6. Configure the Jython environment if your Burp/Jython setup requires it.

7. Confirm that Burp's extension output shows:

   ```text
   Recon To Markdown Extension Loaded Successfully!
   ```

## Usage

1. Capture or send HTTP traffic in Burp Suite.
2. Select one or more messages in a supported Burp message view.
3. Open the context menu.
4. Select **Export to Markdown**.
5. Choose the Markdown output file on the first export.
6. Continue exporting additional messages; they will be appended to the same file.
7. Use **Change Output File...** when you want to start writing to another Markdown file.

## Example Workflow

A simple reconnaissance workflow might look like:

```text
Burp Proxy / Repeater
        │
        ▼
Select interesting request
        │
        ▼
Export to Markdown
        │
        ▼
recon_XXXXXXXXXX.md
        │
        ├── URL
        ├── Method
        ├── Request
        ├── Request data
        ├── Response status
        ├── Response headers
        ├── Response data
        └── Parameters
```

The resulting Markdown file can then be used as a structured notebook for manual analysis, endpoint mapping, parameter discovery, and further testing.

## Current Limitations

This project is still under development. Known limitations include:

- No persistent configuration across Burp restarts.
- No GUI settings panel.
- The request counter is stored only in memory.
- The output format is currently hard-coded.
- JSON extraction is best-effort rather than a full protocol parser.
- Response bodies over 100 lines are intentionally omitted.
- Binary response bodies are not specially handled.
- There is currently no filtering system for exported requests.
- There is currently no tagging or categorization UI.
- There is currently no automatic grouping by domain, endpoint, or HTTP method.
- Error handling currently reports failures through Burp's extension output rather than a dedicated UI.

## Planned Improvements

Potential future features include:

- Persistent configuration.
- Custom Markdown templates.
- Per-domain and per-endpoint grouping.
- Request/response tagging.
- Export filters.
- Better content-type detection.
- Improved JSON and form-data parsing.
- Optional response-size limits.
- Binary-content detection.
- Automatic title generation.
- Automatic endpoint and parameter summaries.
- Searchable/exportable recon indexes.
- Better handling of multiple selected messages.
- Extension settings/preferences.
- More flexible note fields.
- Optional timestamps for each exported request.
- Improved error reporting.

## Project Structure

The current implementation is intentionally kept in a single Python file:

```text
recon-to-markdown/
└── recon_to_markdown.py
```

The main components are:

```text
BurpExtender
├── registerExtenderCallbacks()
├── createMenuItems()
├── choose_output_file()
├── ensure_output_file()
├── change_output_file()
├── process_request()
├── extract_json_keys()
├── _walk_json_keys()
├── extract_request_parameters()
├── extract_response_parameters()
├── build_markdown()
└── append_to_file()

MenuActionListener
└── actionPerformed()
```

## Security / Privacy Notes

This extension exports HTTP traffic into a local Markdown file. Depending on the selected requests, that file may contain sensitive information such as:

- Session cookies
- Authorization headers
- API keys or tokens
- Personal data
- Request bodies
- Response data

Treat generated Markdown files as sensitive security-testing artifacts.

Do not commit generated recon files containing secrets or private data to a public repository.

A suitable `.gitignore` entry might be:

```gitignore
recon_*.md
*.recon.md
```

## Development

The code is currently designed around Burp's classic Jython extension API.

When modifying the extension, pay particular attention to byte-level request/response handling. The current implementation intentionally slices the raw byte arrays at Burp's body offsets before converting the header and body portions to strings.

This helps keep the header/body boundary aligned with Burp's parsed message structure.

## Contributing

Contributions, bug reports, ideas, and improvements are welcome.

When reporting a bug, include:

- Burp Suite version
- Jython version
- Python extension version/code revision
- HTTP message characteristics
- Expected behavior
- Actual behavior
- Relevant Burp extension output

Avoid including real credentials, tokens, cookies, API keys, or other sensitive testing data in issue reports.

## Disclaimer

This tool is intended for authorized security testing, reconnaissance, debugging, and research.

Only use it against systems and traffic that you are authorized to test.

The project is provided as-is and is still under active development.

## License

No license has been specified yet.

Add an appropriate license before distributing the project publicly.
