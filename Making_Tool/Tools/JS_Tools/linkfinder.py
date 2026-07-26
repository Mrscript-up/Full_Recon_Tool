from __future__ import annotations
import sys
import json
import subprocess
from pathlib import Path
import argparse
import shlex
import time
import colorama
import hashlib
import cryptography
import os
from datetime import datetime
import re
import shutil
from collections import defaultdict
from matplotlib.pylab import require
import fnmatch
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Iterable, List, Dict, Optional, Pattern, Tuple, Set, Any
from urllib.parse import urljoin, urlparse, urlunparse
import urllib.request
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import escape
from bs4 import BeautifulSoup
import warnings
import math
import urllib.error                
try:
    from pyjsparser import parse as js_parse  # type: ignore
    _HAS_PARSER = True
except Exception:
    _HAS_PARSER = False



def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='LinkFinder - Discover endpoints and hidden links in JavaScript files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
    Examples:
    %(prog)s https://example.com
    %(prog)s app.js
    %(prog)s -u https://example.com
    %(prog)s -f app.js -o results.json
    %(prog)s -u https://example.com -d 2 -o report.html
    %(prog)s -u https://example.com --filter "/api/v[0-9]"
    """
    )

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('-u', '--url', help='Target URL to spider and analyze')
    input_group.add_argument('-f', '--file', help='Local JavaScript file to analyze')
    input_group.add_argument('-j', '--js-url', help='Direct URL to a JavaScript file')
    input_group.add_argument('input_target', nargs='?', help='Target URL, file, or JS URL')

    parser.add_argument('-o', '--output', help='Output file path (extension determines format: .json, .html, or .txt)')
    parser.add_argument('--no-dedupe', action='store_true', help='Disable deduplication of endpoints')
    parser.add_argument('--show-context', action='store_true', help='Show surrounding context for each endpoint')
    parser.add_argument('-d', '--depth', type=int, default=1, help='Crawling depth (default: 1)')
    parser.add_argument('-c', '--concurrency', type=int, default=10, help='Concurrent requests (default: 10)')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    parser.add_argument('-H', '--header', action='append', help='Custom header (format: "Name: Value")')
    parser.add_argument('-b', '--cookie', help='Cookie string (format: "name=value; name2=value2")')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')
    parser.add_argument('--filter', help='Regex pattern to filter results')

    return parser


def run_linkfinder(args=None):
    """
    LinkFinder - Python Implementation
    ===================================
    A tool to discover endpoints and hidden links in JavaScript files.

    Author: Mrscript
    Version: 1.0.0

    Features:
    - Parse JavaScript files for endpoints, URLs, and paths
    - Spider domains to find JS files automatically
    - Support for relative and absolute URLs
    - Multiple output formats (CLI, JSON, HTML)
    - Regex-based link extraction
    """
    # Suppress warnings
    warnings.filterwarnings('ignore')


    @dataclass
    class FoundEndpoint:
        """Data class to store discovered endpoints."""
        url: str
        source_file: str
        line_number: Optional[int] = None
        context: Optional[str] = None
        method: Optional[str] = None
        endpoint_type: str = "unknown"

        def to_dict(self) -> Dict:
            """Convert to dictionary for JSON serialization."""
            return {
                "url": self.url,
                "source_file": self.source_file,
                "line_number": self.line_number,
                "context": self.context,
                "method": self.method,
                "endpoint_type": self.endpoint_type
            }


    class LinkFinder:
        """
        Main LinkFinder class for discovering endpoints in JavaScript files.
        """

        # Regex patterns for finding various types of links
        URL_PATTERNS = [
            # Full URLs (http/https)
            (r'https?://[^\s"\'<>{}\[\]\\]+', 'absolute_url'),
            # API endpoints with quotes
            (r'["\']([/][^\s"\'<>{}\[\]\\]*(?:\.[a-zA-Z]{2,})?)[\"\']', 'relative_path'),
            # Template literals
            (r'`([^`]*?/[^`]*)`', 'template_literal'),
            # Path assignments
            (r'(?:url|path|endpoint|route|api)[\s]*[:=][\s]*["\']([^"\']+)["\']', 'assigned_path'),
            # Fetch/AJAX calls
            (r'(?:fetch|ajax|axios|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["\']([^"\']+)["\']', 'ajax_call'),
            # Import statements
            (r'(?:import|require)\s*\(?["\']([^"\']+)["\']', 'import_path'),
            # Window location
            (r'(?:window\.location|location\.href)\s*=\s*["\']([^"\']+)["\']', 'location_assign'),
            # API base URLs
            (r'(?:baseURL|BASE_URL|API_URL|apiUrl|baseUrl)[\s]*[:=][\s]*["\']([^"\']+)["\']', 'base_url'),
            # GraphQL endpoints
            (r'(?:graphql|gql)[\s]*[`"\']([^`"\']*)[`"\']', 'graphql'),
            # WebSocket connections
            (r'(?:ws|wss)://[^\s"\'<>{}\[\]\\]+', 'websocket'),
        ]

        # Patterns to filter out (false positives)
        FILTER_PATTERNS = [
            r'^javascript:',
            r'^data:',
            r'^#',
            r'^\s*$',
            r'\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)(\?|$)',
            r'\.(css)(\?|$)',
            r'^\{',
            r'^\}$',
            r'^\[$',
            r'^\]$',
            r'^[a-zA-Z]+:$',  # JSON-like keys
            r'^undefined$',
            r'^null$',
            r'^true$',
            r'^false$',
            r'^\d+$',
        ]

        # HTTP methods pattern
        METHOD_PATTERN = r'(?:(?:fetch|axios|\.request)\s*\(\s*\{[^}]*method\s*:\s*["\'](\w+)["\']|(\.(get|post|put|delete|patch))\s*\()'

        def __init__(self, target: str, depth: int = 1, concurrency: int = 10,
                    timeout: int = 30, headers: Optional[Dict] = None,
                    cookies: Optional[Dict] = None, verify_ssl: bool = True):
            """
            Initialize LinkFinder.

            Args:
                target: Target URL or file path
                depth: Crawling depth for spider mode
                concurrency: Number of concurrent requests
                timeout: Request timeout in seconds
                headers: Custom HTTP headers
                cookies: Custom cookies
                verify_ssl: Whether to verify SSL certificates
            """
            self.target = target
            self.depth = depth
            self.concurrency = concurrency
            self.timeout = timeout
            self.verify_ssl = verify_ssl
            self.found_endpoints: List[FoundEndpoint] = []
            self.visited_urls: Set[str] = set()
            self.js_files: Set[str] = set()
            self.session = self._create_session(headers, cookies)

            # Compile regex patterns
            self.url_regexes = [(re.compile(pattern, re.IGNORECASE), name)
                            for pattern, name in self.URL_PATTERNS]
            self.filter_regexes = [re.compile(pattern) for pattern in self.FILTER_PATTERNS]
            self.method_regex = re.compile(self.METHOD_PATTERN, re.IGNORECASE)

        def _create_session(self, headers: Optional[Dict], cookies: Optional[Dict]) -> requests.Session:
            """Create and configure requests session."""
            session = requests.Session()
            
            default_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            
            if headers:
                default_headers.update(headers)
            
            session.headers.update(default_headers)
            
            if cookies:
                session.cookies.update(cookies)
            
            return session

        def _is_valid_url(self, url: str) -> bool:
            """Check if URL is valid and not a false positive."""
            url = url.strip()
            
            if not url or len(url) < 2:
                return False
            
            # Check against filter patterns
            for pattern in self.filter_regexes:
                if pattern.match(url):
                    return False
            
            # Must contain at least one forward slash (for paths)
            if '/' not in url and not url.startswith(('http', 'ws')):
                return False
            
            return True

        def _normalize_url(self, url: str, base_url: str) -> str:
            """Normalize and resolve URL against base URL."""
            url = url.strip().rstrip('.,;:')
            
            # Handle protocol-relative URLs
            if url.startswith('//'):
                parsed_base = urlparse(base_url)
                url = f"{parsed_base.scheme}:{url}"
            
            # Resolve relative URLs
            if not url.startswith(('http://', 'https://', 'ws://', 'wss://')):
                url = urljoin(base_url, url)
            
            # Remove fragments
            parsed = urlparse(url)
            url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, parsed.query, ''))
            
            return url

        def _extract_method_from_context(self, content: str, match_start: int) -> Optional[str]:
            """Extract HTTP method from surrounding context."""
            # Look behind the match for method definition
            look_behind = content[max(0, match_start - 200):match_start]
            method_match = self.method_regex.search(look_behind)
            
            if method_match:
                if method_match.group(1):
                    return method_match.group(1).upper()
                if method_match.group(3):
                    return method_match.group(3).upper()
            
            return None

        def _extract_from_js_content(self, content: str, source: str) -> List[FoundEndpoint]:
            """Extract endpoints from JavaScript content."""
            endpoints = []
            lines = content.split('\n')
            
            for pattern, endpoint_type in self.url_regexes:
                for match in pattern.finditer(content):
                    url = match.group(1) if match.lastindex else match.group(0)
                    
                    if not self._is_valid_url(url):
                        continue
                    
                    # Normalize URL
                    normalized_url = self._normalize_url(url, source)
                    
                    if not self._is_valid_url(normalized_url):
                        continue
                    
                    # Find line number
                    line_number = None
                    pos = match.start()
                    line_count = 0
                    for i, line in enumerate(lines):
                        line_count += len(line) + 1
                        if line_count > pos:
                            line_number = i + 1
                            break
                    
                    # Extract context
                    context_start = max(0, match.start() - 50)
                    context_end = min(len(content), match.end() + 50)
                    context = content[context_start:context_end].replace('\n', ' ')
                    
                    # Extract HTTP method
                    method = self._extract_method_from_context(content, match.start())
                    
                    endpoint = FoundEndpoint(
                        url=normalized_url,
                        source_file=source,
                        line_number=line_number,
                        context=context,
                        method=method,
                        endpoint_type=endpoint_type
                    )
                    
                    endpoints.append(endpoint)
            
            return endpoints

        def fetch_content(self, url: str) -> Optional[str]:
            """Fetch content from a URL."""
            try:
                response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
                response.raise_for_status()
                return response.text
            except requests.RequestException as e:
                print(f"[-] Error fetching {url}: {e}", file=sys.stderr)
                return None

        def read_file(self, filepath: str) -> Optional[str]:
            """Read content from a local file."""
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            except IOError as e:
                print(f"[-] Error reading file {filepath}: {e}", file=sys.stderr)
                return None

        def find_js_files(self, html_content: str, base_url: str) -> Set[str]:
            """Find JavaScript file URLs in HTML content."""
            js_files = set()
            
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
            except Exception:
                # Fallback to regex if BeautifulSoup fails
                script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
                for match in script_pattern.finditer(html_content):
                    js_url = urljoin(base_url, match.group(1))
                    js_files.add(js_url)
                return js_files
            
            # Find script tags with src
            for script in soup.find_all('script', src=True):
                js_url = urljoin(base_url, script.get('src'))
                js_files.add(js_url)
            
            # Find inline scripts with URLs
            for script in soup.find_all('script'):
                if script.string:
                    inline_endpoints = self._extract_from_js_content(script.string, base_url)
                    self.found_endpoints.extend(inline_endpoints)
            
            # Find JavaScript in other attributes
            for tag in soup.find_all(['a', 'form', 'button', 'input', 'div', 'span']):
                for attr in ['onclick', 'onload', 'onerror', 'onmouseover']:
                    if tag.get(attr):
                        js_content = tag.get(attr)
                        inline_endpoints = self._extract_from_js_content(js_content, base_url)
                        self.found_endpoints.extend(inline_endpoints)
            
            return js_files

        def spider(self, url: str, current_depth: int = 0) -> Set[str]:
            """Spider a URL to find JavaScript files."""
            if current_depth > self.depth or url in self.visited_urls:
                return set()
            
            self.visited_urls.add(url)
            js_files = set()
            
            content = self.fetch_content(url)
            if content is None:
                return js_files
            
            # Find JS files in the page
            found_js = self.find_js_files(content, url)
            js_files.update(found_js)
            
            # Spider subpages if depth allows
            if current_depth < self.depth:
                try:
                    soup = BeautifulSoup(content, 'html.parser')
                    links = soup.find_all('a', href=True)
                    
                    for link in links:
                        href = link.get('href')
                        if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                            next_url = urljoin(url, href)
                            parsed = urlparse(next_url)
                            
                            # Stay on same domain
                            base_parsed = urlparse(url)
                            if parsed.netloc == base_parsed.netloc:
                                sub_js = self.spider(next_url, current_depth + 1)
                                js_files.update(sub_js)
                except Exception:
                    pass
            
            return js_files

        def analyze_url(self) -> List[FoundEndpoint]:
            """Analyze a URL for endpoints."""
            print(f"[*] Spidering {self.target} for JavaScript files...")
            
            # Find JS files
            js_files = self.spider(self.target)
            self.js_files.update(js_files)
            
            print(f"[+] Found {len(js_files)} JavaScript files")
            
            # Analyze each JS file
            self._analyze_js_files(js_files)
            
            return self.found_endpoints

        def analyze_file(self, filepath: str) -> List[FoundEndpoint]:
            """Analyze a local JavaScript file."""
            print(f"[*] Analyzing file: {filepath}")
            
            content = self.read_file(filepath)
            if content:
                endpoints = self._extract_from_js_content(content, filepath)
                self.found_endpoints.extend(endpoints)
                print(f"[+] Found {len(endpoints)} endpoints in {filepath}")
            
            return self.found_endpoints

        def analyze_js_url(self, js_url: str) -> List[FoundEndpoint]:
            """Analyze a JavaScript file URL."""
            print(f"[*] Analyzing: {js_url}")
            
            content = self.fetch_content(js_url)
            if content:
                endpoints = self._extract_from_js_content(content, js_url)
                self.found_endpoints.extend(endpoints)
                print(f"[+] Found {len(endpoints)} endpoints in {js_url}")
            
            return self.found_endpoints

        def _analyze_js_files(self, js_files: Set[str]) -> None:
            """Analyze multiple JS files concurrently."""
            with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                future_to_url = {executor.submit(self.analyze_js_url, url): url
                            for url in js_files}
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        future.result()
                    except Exception as e:
                        print(f"[-] Error analyzing {url}: {e}", file=sys.stderr)

        def deduplicate(self) -> List[FoundEndpoint]:
            """Remove duplicate endpoints."""
            seen = set()
            unique = []
            
            for endpoint in self.found_endpoints:
                # Create a dedup key (URL without query params for broader matching)
                key = endpoint.url.split('?')[0]
                if key not in seen:
                    seen.add(key)
                    unique.append(endpoint)
            
            return unique

        def filter_endpoints(self, pattern: str) -> List[FoundEndpoint]:
            """Filter endpoints by regex pattern."""
            regex = re.compile(pattern, re.IGNORECASE)
            return [e for e in self.found_endpoints if regex.search(e.url)]


    class OutputFormatter:
        """Handles output formatting for LinkFinder results."""

        @staticmethod
        def to_cli(endpoints: List[FoundEndpoint], show_context: bool = False) -> str:
            """Format output for CLI."""
            if not endpoints:
                return "[*] No endpoints found."
            
            lines = []
            lines.append(f"\n{'='*60}")
            lines.append(f"LinkFinder Results - {len(endpoints)} unique endpoints found")
            lines.append(f"{'='*60}\n")
            
            for i, endpoint in enumerate(endpoints, 1):
                method_str = f"[{endpoint.method}] " if endpoint.method else ""
                lines.append(f"{i:4d}. {method_str}{endpoint.url}")
                lines.append(f"     Source: {endpoint.source_file}")
                if endpoint.line_number:
                    lines.append(f"     Line: {endpoint.line_number}")
                if show_context and endpoint.context:
                    lines.append(f"     Context: {endpoint.context[:100]}...")
                lines.append("")
            
            return '\n'.join(lines)

        @staticmethod
        def to_json(endpoints: List[FoundEndpoint], pretty: bool = True) -> str:
            """Format output as JSON."""
            data = {
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "total_endpoints": len(endpoints),
                    "tool": "LinkFinder-Python",
                    "version": "1.0.0"
                },
                "endpoints": [e.to_dict() for e in endpoints]
            }
            
            if pretty:
                return json.dumps(data, indent=2, ensure_ascii=False)
            return json.dumps(data, ensure_ascii=False)

        @staticmethod
        def to_html(endpoints: List[FoundEndpoint], title: str = "LinkFinder Results") -> str:
            """Format output as HTML."""
            html = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{escape(title)}</title>
        <style>
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                color: #eee; min-height: 100vh; padding: 20px;
            }}
            .container {{ max-width: 1400px; margin: 0 auto; }}
            header {{ 
                text-align: center; padding: 30px; 
                background: rgba(255,255,255,0.05); border-radius: 15px;
                margin-bottom: 30px;
            }}
            header h1 {{ color: #00d9ff; font-size: 2.5em; margin-bottom: 10px; }}
            header .stats {{ color: #888; font-size: 1.1em; }}
            .controls {{
                background: rgba(255,255,255,0.05); padding: 20px;
                border-radius: 10px; margin-bottom: 20px;
                display: flex; gap: 15px; flex-wrap: wrap; align-items: center;
            }}
            .controls input {{
                flex: 1; min-width: 200px; padding: 12px 15px;
                border: 1px solid #333; border-radius: 8px;
                background: rgba(0,0,0,0.3); color: #fff; font-size: 1em;
            }}
            .controls input:focus {{ outline: none; border-color: #00d9ff; }}
            .method-badge {{
                display: inline-block; padding: 2px 8px; border-radius: 4px;
                font-size: 0.75em; font-weight: bold; margin-right: 8px;
            }}
            .method-GET {{ background: #28a745; color: #fff; }}
            .method-POST {{ background: #ffc107; color: #000; }}
            .method-PUT {{ background: #17a2b8; color: #fff; }}
            .method-DELETE {{ background: #dc3545; color: #fff; }}
            .method-PATCH {{ background: #6f42c1; color: #fff; }}
            .method-default {{ background: #6c757d; color: #fff; }}
            table {{
                width: 100%; border-collapse: collapse;
                background: rgba(255,255,255,0.03); border-radius: 10px;
                overflow: hidden;
            }}
            th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.05); }}
            th {{ background: rgba(0,217,255,0.1); color: #00d9ff; font-weight: 600; }}
            tr:hover {{ background: rgba(0,217,255,0.05); }}
            .endpoint-url {{ 
                font-family: 'Consolas', 'Monaco', monospace; 
                word-break: break-all;
                color: #7bed9f;
            }}
            .source-file {{ color: #888; font-size: 0.9em; }}
            .type-badge {{
                display: inline-block; padding: 2px 8px; border-radius: 12px;
                font-size: 0.75em; background: rgba(255,255,255,0.1);
            }}
            .context {{ 
                font-family: monospace; font-size: 0.85em; 
                color: #666; max-width: 400px; overflow: hidden;
                text-overflow: ellipsis; white-space: nowrap;
            }}
            .copy-btn {{
                background: none; border: 1px solid #444; color: #888;
                padding: 5px 10px; border-radius: 5px; cursor: pointer;
                font-size: 0.8em; transition: all 0.3s;
            }}
            .copy-btn:hover {{ border-color: #00d9ff; color: #00d9ff; }}
            .no-results {{ text-align: center; padding: 50px; color: #666; }}
            footer {{ 
                text-align: center; padding: 20px; margin-top: 30px;
                color: #555; font-size: 0.9em;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🔗 LinkFinder Results</h1>
                <p class="stats">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total: {len(endpoints)} endpoints</p>
            </header>
            
            <div class="controls">
                <input type="text" id="search" placeholder="🔍 Filter endpoints..." oninput="filterTable()">
                <select id="typeFilter" onchange="filterTable()" style="padding: 12px; background: rgba(0,0,0,0.3); color: #fff; border: 1px solid #333; border-radius: 8px;">
                    <option value="">All Types</option>
                    <option value="absolute_url">Absolute URL</option>
                    <option value="relative_path">Relative Path</option>
                    <option value="ajax_call">AJAX Call</option>
                    <option value="api_path">API Path</option>
                    <option value="websocket">WebSocket</option>
                    <option value="graphql">GraphQL</option>
                </select>
            </div>
            
            <table id="resultsTable">
                <thead>
                    <tr>
                        <th style="width: 5%">#</th>
                        <th style="width: 10%">Method</th>
                        <th style="width: 40%">Endpoint</th>
                        <th style="width: 20%">Source</th>
                        <th style="width: 10%">Type</th>
                        <th style="width: 10%">Line</th>
                        <th style="width: 5%">Copy</th>
                    </tr>
                </thead>
                <tbody>
    """
            
            if not endpoints:
                html += '<tr><td colspan="7" class="no-results">No endpoints found</td></tr>'
            else:
                for i, ep in enumerate(endpoints, 1):
                    method_class = f"method-{ep.method}" if ep.method else "method-default"
                    method_display = ep.method if ep.method else "N/A"
                    
                    html += f"""                <tr class="result-row" data-url="{escape(ep.url.lower())}" data-type="{ep.endpoint_type}">
                        <td>{i}</td>
                        <td><span class="method-badge {method_class}">{method_display}</span></td>
                        <td class="endpoint-url" title="{escape(ep.context or '')}">{escape(ep.url)}</td>
                        <td class="source-file" title="{escape(ep.source_file)}">{escape(ep.source_file[:50])}</td>
                        <td><span class="type-badge">{ep.endpoint_type}</span></td>
                        <td>{ep.line_number or '-'}</td>
                        <td><button class="copy-btn" onclick="copyUrl('{escape(ep.url)}')">📋</button></td>
                    </tr>
    """
            
            html += """            </tbody>
            </table>
            
            <footer>
                <p>LinkFinder-Python v1.0.0 | Generated automatically</p>
            </footer>
        </div>
        
        <script>
            function filterTable() {
                const searchTerm = document.getElementById('search').value.toLowerCase();
                const typeFilter = document.getElementById('typeFilter').value;
                const rows = document.querySelectorAll('.result-row');
                
                rows.forEach(row => {
                    const url = row.getAttribute('data-url');
                    const type = row.getAttribute('data-type');
                    const matchSearch = url.includes(searchTerm);
                    const matchType = !typeFilter || type === typeFilter;
                    
                    row.style.display = (matchSearch && matchType) ? '' : 'none';
                });
            }
            
            function copyUrl(url) {
                navigator.clipboard.writeText(url).then(() => {
                    event.target.textContent = '✓';
                    setTimeout(() => event.target.textContent = '📋', 1000);
                });
            }
        </script>
    </body>
    </html>
    """
            
            return html


    def run_from_args(parsed_args):
        target = (
            parsed_args.url
            or parsed_args.file
            or parsed_args.js_url
            or parsed_args.input_target
        )

        if not target:
            print("[!] No target provided. Use --url, --file, --js-url, or provide a target directly.")
            return

        headers = None
        if parsed_args.header:
            headers = {}
            for h in parsed_args.header:
                if ':' in h:
                    name, value = h.split(':', 1)
                    headers[name.strip()] = value.strip()

        cookies = None
        if parsed_args.cookie:
            cookies = {}
            for c in parsed_args.cookie.split(';'):
                if '=' in c:
                    name, value = c.split('=', 1)
                    cookies[name.strip()] = value.strip()

        try:
            finder = LinkFinder(
                target=target,
                depth=parsed_args.depth,
                concurrency=parsed_args.concurrency,
                timeout=parsed_args.timeout,
                headers=headers,
                cookies=cookies,
                verify_ssl=not parsed_args.no_verify_ssl
            )
        except Exception as e:
            print(f"[-] Error initializing LinkFinder: {e}", file=sys.stderr)
            sys.exit(1)

        print("[*] LinkFinder-Python v1.0.0")
        print("="*50)

        try:
            if parsed_args.url:
                endpoints = finder.analyze_url()
            elif parsed_args.file:
                endpoints = finder.analyze_file(parsed_args.file)
            elif parsed_args.js_url:
                endpoints = finder.analyze_js_url(parsed_args.js_url)
            else:
                if target.startswith(('http://', 'https://', 'ws://', 'wss://')):
                    endpoints = finder.analyze_url()
                elif os.path.isfile(target):
                    endpoints = finder.analyze_file(target)
                else:
                    endpoints = finder.analyze_js_url(target)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            sys.exit(0)

        if not parsed_args.no_dedupe:
            endpoints = finder.deduplicate()

        if parsed_args.filter:
            endpoints = finder.filter_endpoints(parsed_args.filter)

        if parsed_args.output:
            output_lower = parsed_args.output.lower()

            if output_lower.endswith('.json'):
                output = OutputFormatter.to_json(endpoints)
            elif output_lower.endswith('.html'):
                output = OutputFormatter.to_html(endpoints, title=f"LinkFinder - {finder.target}")
            else:
                output = OutputFormatter.to_cli(endpoints, parsed_args.show_context)

            try:
                with open(parsed_args.output, 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"\n[+] Results saved to {parsed_args.output}")
            except IOError as e:
                print(f"[-] Error writing to file: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print(OutputFormatter.to_cli(endpoints, parsed_args.show_context))

        print(f"\n[+] Total unique endpoints: {len(endpoints)}")

        type_counts = {}
        for ep in endpoints:
            type_counts[ep.endpoint_type] = type_counts.get(ep.endpoint_type, 0) + 1

        if type_counts:
            print("\n[*] Breakdown by type:")
            for ep_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                print(f"    - {ep_type}: {count}")

        method_counts = {}
        for ep in endpoints:
            method = ep.method or 'Unknown'
            method_counts[method] = method_counts.get(method, 0) + 1

        if method_counts:
            print("\n[*] Breakdown by HTTP method:")
            for method, count in sorted(method_counts.items(), key=lambda x: -x[1]):
                print(f"    - {method}: {count}")

    def run_interactive_loop(initial_input=None):
        parser = create_parser()
        print("\nLinkFinder interactive mode")
        print("Type 'help' for usage or 'exit' to quit.")
        print("Examples:")
        print("  https://example.com")
        print("  ./app.js")
        print("  -u https://example.com -d 2")

        while True:
            if initial_input is not None:
                command = str(initial_input).strip()
                initial_input = None
                print(f"linkfinder> {command}")
            else:
                try:
                    command = input("linkfinder> ").strip()
                except KeyboardInterrupt:
                    print("\nGoodbye!")
                    break
                except EOFError:
                    print("\nGoodbye!")
                    break

            if not command:
                continue

            if command.lower() in {'exit', 'quit'}:
                print("Exiting LinkFinder.")
                break

            if command.lower() in {'help', '?'}:
                parser.print_help()
                continue

            try:
                tokens = shlex.split(command)
            except ValueError as exc:
                print(f"[ERROR] Invalid input: {exc}")
                continue

            try:
                parsed_args = parser.parse_args(tokens)
            except SystemExit:
                continue

            run_from_args(parsed_args)

    def main(args=None):
        if args is None:
            run_interactive_loop()
            return

        if isinstance(args, str):
            run_interactive_loop(initial_input=args)
            return

        run_from_args(args)

    main(args)

