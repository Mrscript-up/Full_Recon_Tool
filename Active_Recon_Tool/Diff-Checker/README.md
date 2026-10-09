Diff-checker

Command-line version of the ReqDiff2Obsidian Burp Suite extension —compares exactly 2 requests by URL + Body only (headers/cookies areignored) and appends an Obsidian-friendly diff note to a .md file.

Fully non-interactive: give it the input, get the result. It never prompts.
Comparison rules (same as the original extension)
- JSON → key-by-key diff (max 10 lines)
- Non-JSON → skipped if longer than 15 lines, otherwise only the first10 differing lines
- Headers and cookies are ignored
- If nothing differs, nothing is saved

Requirements
```
Python 2.7 or 3.x only — no external libraries.
```
Usage
```
# Two files = compare them directly:
python Diff-checker.py userA.xml userB.xml
# One file with multiple items → consecutive pairs (1-2, 2-3, ...):
python Diff-checker.py export.xml
# Multiple files at once (item numbering is global across files):
python Diff-checker.py day1.xml day2.xml
# Manual pair selection:
python Diff-checker.py export.xml --pairs 1,3
python Diff-checker.py export.xml --pairs 1,2 4,7
# Just list items (with their numbers) and exit:
python Diff-checker.py export.xml --list
# label option :
python Diff-checker.py a.xml b.xml c.xml --labels "Admin,Guest,Service"
# nway option :
python Diff-checker.py export.xml --nway
```
Options
```
Option	Description
xml ...	One or more Burp Suite XML export files ("Save selected items")
-o, --output	Output .md file (default: ~/Desktop/burp-diffs.md)
--pairs A,B	Compare item A with item B (1-based) — repeatable
--all	Compare every consecutive pair (1-2, 2-3, ...) — already the default, kept for explicitness
--list	List loaded items with their numbers, then exit
--label-a / --label-b	Override labels (default: User A / User B)
```
Input XML
Standard Burp Suite "Save selected items" format:
```
<items>  <item>    <url>...</url>    <host post="false">example.com</host>    <method>POST</method>    <request base64="true">...</request>    <response base64="true">...</response>  </item>  ...</items>
```
Both plain-text and base64="true" request/response elements are supported.If <response> is missing, the RESPONSE section is skipped with(response not recorded on one side - skipped).
Output

Notes are appended to the .md file. Each note starts with ---,a #### ReqDiff | date time heading, and contains:

- REQ-ENDPOINT — method + path (or both sides if they differ)
- DATAS-ENDPOINT — query params + body diff (key-by-key forJSON/urlencoded, raw line diff otherwise)
- RESPONSE-DIFF — response body diff (same 10/15-line rules)
