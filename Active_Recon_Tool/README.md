# Recon To Markdown

A lightweight **Burp Suite Jython extension for Bug Bounty hunters**.

The extension exports selected HTTP requests and responses from Burp Suite into a structured **Markdown file**, designed to be opened and organized directly in **Obsidian**.

## Features

* Export selected Burp requests/responses to Markdown.
* Keep exporting into the same `.md` file.
* Extract:

  * URL
  * HTTP method
  * Domain
  * Request / Response
  * Status code
  * Request / Response data
  * Parameters and JSON keys
* Automatically URL-decode request and response data.
* Skip very large response bodies.
* Change the output file whenever needed.

## Workflow

```text
Burp Suite
    ↓
Select interesting request
    ↓
Export to Markdown
    ↓
Obsidian
    ↓
Recon & Bug Bounty Notes
```

## Installation

1. Open **Burp Suite → Extensions**.
2. Add the Python extension.
3. Select `recon_to_markdown.py`.
4. Make sure Jython is configured.
5. Right-click a request and select:

```text
Export to Markdown
```

## Output

The generated Markdown is intended to work naturally inside an **Obsidian vault**, making it easy to keep HTTP traffic, parameters, endpoints, and testing notes together during a bug bounty.

## Status

🚧 **Work in Progress**

The extension is functional but still under development. More features and improvements are planned.

## Disclaimer

For authorized security testing and bug bounty programs only.

## example :
### Main Request:
```
POST /api/census/button-render HTTP/2
Host: www.embark-studios.com
Cookie: crumb=BWNvoyDDh4SJZDdhYWFiYWQwNmQ5Yjg4NGY1Y2M1OTg5YWM0OTc3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
X-Csrf-Token: BWNvoyDDh4SJZDdhYWFiYWQwNmQ5Yjg4NGY1Y2M1OTg5YWM0OTc3
Content-Length: 400
Origin: https://www.embark-studios.com
Referer: https://www.embark-studios.com/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

{"id":"block-2c44670f67a2a7cd3986","buttonText":"\n    Join us\n  ","clickthroughUrl":"https://careers.embark-studios.com/","alignment":"","size":"large","newWindow":true,"context":1,"visitorCookie":"7c70bbeb-f1c3-429b-8736-2cfa3ba7668c|1788538122824|1788538122824|1788538122824|1","pagePermissionTypeValue":1,"pageTitle":"HOME","pageId":"61ae15f0069b5d5e122bd1a4","contentSource":"c","pagePath":"/"}


#---------------------------------------------------RES:
HTTP/2 200 OK
Age: 0
Content-Type: application/json;charset=utf-8
Date: Fri, 04 Sep 2026 16:08:44 GMT
Server: Squarespace
Strict-Transport-Security: max-age=0
X-Content-Type-Options: nosniff
X-Contextid: VFXDQRnN/kyzuSiQY
Content-Length: 17

{"success": true}
```

### output:
```
### [www.embark-studios.com] Page:
### Request: 1
**URL** : https://www.embark-studios.com:443/api/census/button-render #URL
**METHODE**: `POST` #POST-req
**NOTE-REQ**: #note-req
> 

**STATUS**: `200` #status_200
**REQ**:
```python
POST /api/census/button-render HTTP/2
Host: www.embark-studios.com
Cookie: crumb=BWNvoyDDh4SJZDdhYWFiYWQwNmQ5Yjg4NGY1Y2M1OTg5YWM0OTc3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
X-Csrf-Token: BWNvoyDDh4SJZDdhYWFiYWQwNmQ5Yjg4NGY1Y2M1OTg5YWM0OTc3
Content-Length: 400
Origin: https://www.embark-studios.com
Referer: https://www.embark-studios.com/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

{"id":"block-2c44670f67a2a7cd3986","buttonText":"\n    Join us\n  ","clickthroughUrl":"https://careers.embark-studios.com/","alignment":"","size":"large","newWindow":true,"context":1,"visitorCookie":"7c70bbeb-f1c3-429b-8736-2cfa3ba7668c|1788538122824|1788538122824|1788538122824|1","pagePermissionTypeValue":1,"pageTitle":"HOME","pageId":"61ae15f0069b5d5e122bd1a4","contentSource":"c","pagePath":"/"}
```
```
**REQ-DATA**:
`decode`
```python
{"id":"block-2c44670f67a2a7cd3986","buttonText":"\n    Join us\n  ","clickthroughUrl":"https://careers.embark-studios.com/","alignment":"","size":"large","newWindow":true,"context":1,"visitorCookie":"7c70bbeb-f1c3-429b-8736-2cfa3ba7668c|1788538122824|1788538122824|1788538122824|1","pagePermissionTypeValue":1,"pageTitle":"HOME","pageId":"61ae15f0069b5d5e122bd1a4","contentSource":"c","pagePath":"/"}
```
```
**RES**:
```python
HTTP/2 200 OK
Age: 0
Content-Type: application/json;charset=utf-8
Date: Fri, 04 Sep 2026 16:08:44 GMT
Server: Squarespace
Strict-Transport-Security: max-age=0
X-Content-Type-Options: nosniff
X-Contextid: VFXDQRnN/kyzuSiQY
Content-Length: 17
```
```
**RES-DATA**:
`decode`
```python
{"success": true}
```
```
**PARAMETERS**: #parameters
```python
crumb, id, buttonText, clickthroughUrl, alignment, size, newWindow, context, visitorCookie, pagePermissionTypeValue, pageTitle, pageId, contentSource, pagePath, success
```

### output photo:
![alt text](/Active_Recon_Tool/photos/image.png)
***
![alt text](/Active_Recon_Tool/photos/image-1.png)
***
![alt text](/Active_Recon_Tool/photos/image-2.png)
***

<p align="center"> <img src="https://capsule-render.vercel.app/api?type=waving&color=00FF00&height=120&section=footer"/> </p>