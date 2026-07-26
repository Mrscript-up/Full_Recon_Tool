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
        description='JS Extractor - Professional JavaScript Static Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
    Examples:
    %(prog)s file.js                          Analyze a single file
    %(prog)s ./src/ -r                        Recursively analyze directory
    %(prog)s https://example.com/app.js       Analyze remote JS file
    %(prog)s ./bundle.js -o results.json      Export results to JSON
    %(prog)s ./src/ -c secrets,api_endpoints  Extract specific categories
    %(prog)s file.js --confidence high        Show only high+ confidence
    %(prog)s file.js -v                       Verbose output with context
    %(prog)s file.js --custom 'pattern:myRegex:high'  Add custom regex
            """
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        'input',
        nargs='?',
        help='Input file, directory, or URL'
    )
    input_group.add_argument(
        '--stdin',
        action='store_true',
        help='Read JavaScript from stdin'
    )

    parser.add_argument(
        '-r', '--recursive',
        action='store_true',
        help='Recursively process directories'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file (JSON, CSV, or MD based on extension)'
    )
    parser.add_argument(
        '-c', '--categories',
        help='Comma-separated categories to extract (e.g., secrets,api_endpoints,urls)'
    )
    parser.add_argument(
        '--confidence',
        choices=['critical', 'high', 'medium', 'low'],
        help='Minimum confidence level to display'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output with context and line numbers'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode, only output results'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    parser.add_argument(
        '--min-length',
        type=int,
        default=3,
        help='Minimum string length (default: 3)'
    )
    parser.add_argument(
        '--max-length',
        type=int,
        default=500,
        help='Maximum string length (default: 500)'
    )
    parser.add_argument(
        '--exclude',
        help='Regex pattern to exclude from results'
    )
    parser.add_argument(
        '--extensions',
        default='.js,.mjs,.cjs,.jsx,.ts,.tsx,.vue,.svelte',
        help='File extensions to process (default: .js,.mjs,.cjs,.jsx,.ts,.tsx,.vue,.svelte)'
    )
    parser.add_argument(
        '--custom',
        action='append',
        help='Custom regex pattern (format: name:pattern:confidence)'
    )
    parser.add_argument(
        '--list-categories',
        action='store_true',
        help='List all available extraction categories'
    )
    parser.add_argument(
        '--stats-only',
        action='store_true',
        help='Only show statistics, not individual findings'
    )

    return parser


def run_taking_information_tool(args=None):
    print('run taking inforamtion')

    if isinstance(args, str):
        args = create_parser().parse_args([args])

    """
    JS Extractor - Professional JavaScript Static Analysis Tool
    Extracts paths, parameters, files, secrets, and more from JS files.

    Author: Mrscript
    Version: 2.0.0
    """
    try:
        from colorama import init, Fore, Style, Back
        init(autoreset=True)
        HAS_COLORAMA = True
    except ImportError:
        HAS_COLORAMA = False

    # ============================================================================
    # DATA CLASSES FOR STRUCTURED OUTPUT
    # ============================================================================

    @dataclass
    class ExtractedItem:
        value: str
        line_number: int
        context: str
        confidence: str = "medium"  # low, medium, high
        category: str = ""

    @dataclass
    class ExtractionResult:
        file_path: str
        file_size: int
        analysis_time: float
        
        # Extraction categories
        api_endpoints: List[ExtractedItem] = field(default_factory=list)
        file_paths: List[ExtractedItem] = field(default_factory=list)
        parameters: List[ExtractedItem] = field(default_factory=list)
        secrets: List[ExtractedItem] = field(default_factory=list)
        urls: List[ExtractedItem] = field(default_factory=list)
        function_names: List[ExtractedItem] = field(default_factory=list)
        class_names: List[ExtractedItem] = field(default_factory=list)
        imports: List[ExtractedItem] = field(default_factory=list)
        comments: List[ExtractedItem] = field(default_factory=list)
        dom_selectors: List[ExtractedItem] = field(default_factory=list)
        event_handlers: List[ExtractedItem] = field(default_factory=list)
        ajax_calls: List[ExtractedItem] = field(default_factory=list)
        websockets: List[ExtractedItem] = field(default_factory=list)
        local_storage_keys: List[ExtractedItem] = field(default_factory=list)
        cookies: List[ExtractedItem] = field(default_factory=list)
        headers: List[ExtractedItem] = field(default_factory=list)
        regex_patterns: List[ExtractedItem] = field(default_factory=list)
        error_messages: List[ExtractedItem] = field(default_factory=list)
        debug_info: List[ExtractedItem] = field(default_factory=list)
        custom_patterns: List[ExtractedItem] = field(default_factory=list)

        def to_dict(self) -> dict:
            return asdict(self)
        
        def get_all_items(self) -> List[ExtractedItem]:
            items = []
            for field_name in self.__dataclass_fields__:
                if field_name not in ['file_path', 'file_size', 'analysis_time']:
                    items.extend(getattr(self, field_name))
            return items
        
        def get_stats(self) -> Dict[str, int]:
            stats = {}
            for field_name in self.__dataclass_fields__:
                if field_name not in ['file_path', 'file_size', 'analysis_time']:
                    stats[field_name] = len(getattr(self, field_name))
            return stats


    # ============================================================================
    # MAIN EXTRACTOR CLASS
    # ============================================================================

    class JSExtractor:
        """
        Professional JavaScript static analysis extractor.
        """
        
        def __init__(self, config: Optional[Dict] = None):
            self.config = config or {}
            self.min_string_length = self.config.get('min_string_length', 3)
            self.max_string_length = self.config.get('max_string_length', 500)
            self.exclude_patterns = self.config.get('exclude_patterns', [])
            self.custom_regex_patterns = self.config.get('custom_patterns', [])
            
            # Compile regex patterns
            self._compile_patterns()
            
            # Results storage
            self.results: List[ExtractionResult] = []
            self.global_dedup: Set[str] = set()
        
        def _compile_patterns(self):
            """Pre-compile all regex patterns for performance."""
            
            # API Endpoints
            self.patterns = {
                # API Endpoints - Various formats
                'api_endpoints': [
                    # Quoted strings with path patterns
                    (r'["\']([/][a-zA-Z0-9_\-./{}:]+(?:api|v[0-9]+|rest|graphql|endpoint)[a-zA-Z0-9_\-./{}:]*)["\']', 'high'),
                    (r'["\']([/][a-zA-Z0-9_\-./{}:]+)["\']\s*[,\)]', 'medium'),  # Strings ending with , or )
                    (r'(?:url|path|endpoint|route|href|src|action)\s*[:=]\s*["\']([^"\']+)["\']', 'high'),
                    (r'(?:fetch|axios|request|get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'high'),
                    (r'\.url\s*=\s*["\']([^"\']+)["\']', 'high'),
                    (r'baseURL\s*[:=]\s*["\']([^"\']+)["\']', 'high'),
                    (r'["\'](?:/api/|/v[0-9]+/|/rest/|/graphql)[^"\']*["\']', 'high'),
                    (r'path:\s*["\']([^"\']+)["\']', 'high'),
                    (r'route:\s*["\']([^"\']+)["\']', 'high'),
                ],
                
                # File Paths
                'file_paths': [
                    (r'["\']([a-zA-Z]:\\[^\"]+)["\']', 'high'),  # Windows paths
                    (r'["\'](?:\.\./|\./|/)[a-zA-Z0-9_\-./]+\.[a-zA-Z]{2,5}["\']', 'high'),  # Relative paths
                    (r'["\'](/[a-zA-Z0-9_\-./]+\.[a-zA-Z]{2,5})["\']', 'high'),  # Absolute paths
                    (r'(?:require|import|include)\s*\(\s*["\']([^"\']+)["\']\s*\)', 'high'),
                    (r'from\s+["\']([^"\']+)["\']', 'high'),
                    (r'src\s*[:=]\s*["\']([^"\']+\.[a-zA-Z]{2,5})["\']', 'medium'),
                    (r'href\s*[:=]\s*["\']([^"\']+\.[a-zA-Z]{2,5})["\']', 'medium'),
                ],
                
                # Parameters (function params, query params, etc.)
                'parameters': [
                    (r'function\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(([^)]+)\)', 'high'),
                    (r'(?:const|let|var)\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*\(([^)]+)\)\s*=>', 'high'),
                    (r'\(\s*([a-zA-Z_$][a-zA-Z0-9_$,\s]*)\s*\)\s*=>', 'high'),
                    (r'(?:params|query|body|data|options|config|args)\s*[:=]\s*\{([^}]+)\}', 'high'),
                    (r'\?[a-zA-Z_][a-zA-Z0-9_]*=', 'medium'),  # Query params in URLs
                    (r'(?:this\.)?[a-zA-Z_$][a-zA-Z0-9_$]*\.params\.[a-zA-Z_$][a-zA-Z0-9_$]*', 'high'),
                    (r'(?:req|request|ctx)\.(?:query|body|params)\.[a-zA-Z_$][a-zA-Z0-9_$]*', 'high'),
                ],
                
                # Secrets and Credentials
                'secrets': [
                    (r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'critical'),
                    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', 'critical'),
                    (r'(?:secret|token|auth)[_-]?(?:key)?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', 'critical'),
                    (r'(?:Bearer|Token|Basic)\s+["\']?([a-zA-Z0-9_\-\.]+)', 'high'),
                    (r'(?:AWS|aws)[_-]?(?:SECRET|secret)[_-]?(?:ACCESS|access)[_-]?(?:KEY|key)\s*[:=]\s*["\']([^"\']+)["\']', 'critical'),
                    (r'(?:PRIVATE|private)[_-]?(?:KEY|key)\s*[:=]\s*["\']-----BEGIN[^"\']+["\']', 'critical'),
                    (r'["\'](?:sk|pk|rk)_[a-zA-Z0-9]{20,}["\']', 'critical'),  # Stripe-like keys
                    (r'ghp_[a-zA-Z0-9]{36,}', 'critical'),  # GitHub tokens
                    (r'gho_[a-zA-Z0-9]{36,}', 'critical'),  # GitHub OAuth
                    (r'glpat-[a-zA-Z0-9\-]{20,}', 'critical'),  # GitLab tokens
                    (r'xox[bpsa]-[a-zA-Z0-9\-]{10,}', 'critical'),  # Slack tokens
                    (r'AKIA[0-9A-Z]{16}', 'critical'),  # AWS Access Key ID
                    (r'["\']eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+["\']', 'high'),  # JWT
                    (r'client[_-]?secret\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'critical'),
                    (r'refresh[_-]?token\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', 'critical'),
                    (r'firebase[_-]?key\s*[:=]\s*["\']([^"\']+)["\']', 'high'),
                    (r'maps[_-]?api[_-]?key\s*[:=]\s*["\']([^"\']+)["\']', 'high'),
                ],
                
                # URLs
                'urls': [
                    (r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', 'high'),
                    (r'wss?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', 'high'),
                    (r'ftp://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', 'high'),
                ],
                
                # Function Names
                'function_names': [
                    (r'(?:function|async\s+function)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', 'high'),
                    (r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?\(', 'high'),
                    (r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)', 'high'),
                    (r'(["\'])([a-zA-Z_$][a-zA-Z0-9_$]*)\1\s*:\s*(?:async\s+)?function', 'high'),  # Object methods
                    (r'(?:export\s+)?(?:default\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', 'high'),
                    (r'["\']([a-zA-Z_$][a-zA-Z0-9_$]*)["\']\s*:\s*\(', 'medium'),  # Object method shorthand
                ],
                
                # Class Names
                'class_names': [
                    (r'class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', 'high'),
                    (r'extends\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', 'high'),
                    (r'new\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(', 'medium'),
                ],
                
                # Imports
                'imports': [
                    (r'import\s+(?:\{[^}]*\}|\*\s+as\s+[a-zA-Z_$][a-zA-Z0-9_$]*|[a-zA-Z_$][a-zA-Z0-9_$]*)\s+from\s+["\']([^"\']+)["\']', 'high'),
                    (r'import\s+["\']([^"\']+)["\']', 'high'),
                    (r'(?:require|import)\s*\(\s*["\']([^"\']+)["\']\s*\)', 'high'),
                    (r'dynamic\s+import\s*\(\s*["\']([^"\']+)["\']\s*\)', 'high'),
                ],
                
                # Comments
                'comments': [
                    (r'//[^\n]*', 'medium'),
                    (r'/\*[\s\S]*?\*/', 'medium'),
                    (r'<!\-\-[\s\S]*?\-\->', 'medium'),
                ],
                
                # DOM Selectors
                'dom_selectors': [
                    (r'(?:getElementById|querySelector|querySelectorAll)\s*\(\s*["\']([^"\']+)["\']', 'high'),
                    (r'(?:getElementsByClassName|getElementsByTagName)\s*\(\s*["\']([^"\']+)["\']', 'high'),
                    (r'\$\s*\(\s*["\']([^"\']+)["\']', 'high'),  # jQuery
                    (r'\$\$\s*\(\s*["\']([^"\']+)["\']', 'high'),  # Multiple selector
                    (r'document\.[a-zA-Z]+\s*=\s*["\']([^"\']+)["\']', 'medium'),
                ],
                
                # Event Handlers
                'event_handlers': [
                    (r'\.on\s*\(\s*["\']([a-zA-Z]+)["\']', 'high'),
                    (r'\.addEventListener\s*\(\s*["\']([a-zA-Z]+)["\']', 'high'),
                    (r'\.once\s*\(\s*["\']([a-zA-Z]+)["\']', 'high'),
                    (r'on[a-zA-Z]+\s*=\s*(?:function|[a-zA-Z_$])', 'medium'),
                    (r'@([a-zA-Z]+\.[a-zA-Z]+)', 'medium'),  # Vue events
                    (r'\.(click|submit|change|input|keyup|keydown|mouseover|mouseout|load|error|focus|blur)\s*=', 'high'),
                ],
                
                # AJAX Calls
                'ajax_calls': [
                    (r'(?:fetch|axios|XMLHttpRequest|\.ajax|\.get|\.post|\.put|\.delete|\.patch)\s*\(', 'high'),
                    (r'\$\.ajax\s*\(\s*\{', 'high'),
                    (r'new\s+XMLHttpRequest', 'high'),
                    (r'axios\.(?:create|get|post|put|delete|patch|request|all|spread)', 'high'),
                ],
                
                # WebSockets
                'websockets': [
                    (r'new\s+(?:WebSocket|SockJS|Socket\.IO|io)\s*\(\s*["\']([^"\']+)["\']', 'high'),
                    (r'(?:socket|ws|wss)\.?(?:connect|on|emit|send)\s*\(', 'medium'),
                    (r'io\s*\(\s*["\']([^"\']+)["\']', 'high'),
                ],
                
                # Local Storage Keys
                'local_storage_keys': [
                    (r'localStorage\.(?:getItem|setItem|removeItem)\s*\(\s*["\']([^"\']+)["\']', 'high'),
                    (r'sessionStorage\.(?:getItem|setItem|removeItem)\s*\(\s*["\']([^"\']+)["\']', 'high'),
                    (r'localStorage\["\']([^"\']+)["\']', 'high'),
                    (r'sessionStorage\["\']([^"\']+)["\']', 'high'),
                ],
                
                # Cookies
                'cookies': [
                    (r'document\.cookie\s*=?\s*["\']?([^"\';\n]+)', 'medium'),
                    (r'Cookies\.(?:get|set|remove)\s*\(\s*["\']([^"\']+)["\']', 'high'),
                    (r'jscookie|cookie-parser|universal-cookie', 'low'),
                    (r'(?:set|get)Cookie\s*\(\s*["\']([^"\']+)["\']', 'high'),
                ],
                
                # HTTP Headers
                'headers': [
                    (r'(?:headers|Headers)\s*[:=]\s*\{([^}]+)\}', 'high'),
                    (r'\.setHeader\s*\(\s*["\']([^"\']+)["\']', 'high'),
                    (r'["\'](?:Authorization|Content-Type|X-[^"\']+)["\']', 'high'),
                    (r'(?:Authorization|Content-Type|Accept|x-[^:]+):\s*["\']([^"\']+)["\']', 'high'),
                ],
                
                # Regex Patterns
                'regex_patterns': [
                    (r'/([^/\\]|\\.)+/[gimsuy]*', 'high'),  # Standard regex
                    (r'new\s+RegExp\s*\(\s*["\']([^"\']+)["\']', 'high'),
                ],
                
                # Error Messages
                'error_messages': [
                    (r'(?:throw\s+(?:new\s+)?(?:Error|TypeError|RangeError|ReferenceError|SyntaxError))\s*\(\s*["\']([^"\']+)["\']', 'high'),
                    (r'console\.(?:error|warn)\s*\(\s*["\']([^"\']+)["\']', 'high'),
                    (r'(?:reject|Error)\s*\(\s*["\']([^"\']+)["\']', 'high'),
                ],
                
                # Debug Information
                'debug_info': [
                    (r'console\.(?:log|debug|info|trace|table|dir|time|timeEnd)\s*\(', 'medium'),
                    (r'debugger', 'high'),
                    (r'//\s*(?:TODO|FIXME|HACK|XXX|BUG|NOTE)', 'medium'),
                    (r'/\*\s*(?:TODO|FIXME|HACK|XXX|BUG|NOTE)', 'medium'),
                    (r'__DEBUG__|__DEV__|development|staging', 'low'),
                ],
            }
            
            # Pre-compile all patterns
            self.compiled_patterns = {}
            for category, patterns in self.patterns.items():
                self.compiled_patterns[category] = [
                    (re.compile(pattern, re.IGNORECASE if category == 'secrets' else re.DOTALL), confidence)
                    for pattern, confidence in patterns
                ]
            
            # Compile custom patterns
            if self.custom_regex_patterns:
                self.compiled_patterns['custom_patterns'] = [
                    (re.compile(p['pattern'], re.DOTALL), p.get('confidence', 'medium'))
                    for p in self.custom_regex_patterns
                ]
        
        def _get_context(self, lines: List[str], line_num: int, context_size: int = 1) -> str:
            """Extract surrounding context for a match."""
            start = max(0, line_num - context_size)
            end = min(len(lines), line_num + context_size + 1)
            return '\n'.join(lines[start:end]).strip()
        
        def _clean_value(self, value: str) -> str:
            """Clean and normalize extracted values."""
            # Remove trailing/leading whitespace
            value = value.strip()
            
            # Remove quotes if present
            if len(value) >= 2 and value[0] in '"\'`' and value[-1] == value[0]:
                value = value[1:-1]
            
            # Limit length
            if len(value) > self.max_string_length:
                value = value[:self.max_string_length] + '...'
            
            return value
        
        def _should_exclude(self, value: str) -> bool:
            """Check if value should be excluded based on patterns."""
            for pattern in self.exclude_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    return True
            return False
        
        def _extract_from_content(self, content: str, file_path: str) -> ExtractionResult:
            """Main extraction logic for a single file's content."""
            start_time = datetime.now()
            
            lines = content.split('\n')
            result = ExtractionResult(
                file_path=file_path,
                file_size=len(content),
                analysis_time=0
            )
            
            # Process each category
            for category, compiled_patterns in self.compiled_patterns.items():
                if category == 'comments':  # Handle multi-line separately
                    self._extract_multiline(content, lines, category, compiled_patterns, result)
                    continue
                
                for line_idx, line in enumerate(lines):
                    for pattern, confidence in compiled_patterns:
                        matches = pattern.finditer(line)
                        for match in matches:
                            # Get the first capturing group if it exists, otherwise the full match
                            value = match.group(1) if match.groups() else match.group(0)
                            value = self._clean_value(value)
                            
                            if not value or len(value) < self.min_string_length:
                                continue
                            
                            if self._should_exclude(value):
                                continue
                            
                            # Create dedup key
                            dedup_key = f"{category}:{value}"
                            if dedup_key in self.global_dedup:
                                continue
                            
                            self.global_dedup.add(dedup_key)
                            
                            item = ExtractedItem(
                                value=value,
                                line_number=line_idx + 1,
                                context=self._get_context(lines, line_idx),
                                confidence=confidence,
                                category=category
                            )
                            getattr(result, category).append(item)
            
            result.analysis_time = (datetime.now() - start_time).total_seconds()
            return result
        
        def _extract_multiline(self, content: str, lines: List[str], category: str, 
                            compiled_patterns: List, result: ExtractionResult):
            """Handle multi-line pattern extraction (like comments)."""
            for pattern, confidence in compiled_patterns:
                matches = pattern.finditer(content)
                for match in matches:
                    value = match.group(0).strip()
                    if not value:
                        continue
                    
                    # Calculate line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    if self._should_exclude(value):
                        continue
                    
                    # Truncate long comments
                    if len(value) > self.max_string_length:
                        value = value[:self.max_string_length] + '...'
                    
                    item = ExtractedItem(
                        value=value,
                        line_number=line_num,
                        context=value[:200] + '...' if len(value) > 200 else value,
                        confidence=confidence,
                        category=category
                    )
                    getattr(result, category).append(item)
        
        def extract_from_file(self, file_path: str) -> Optional[ExtractionResult]:
            """Extract data from a single JS file."""
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                if not content.strip():
                    return None
                
                return self._extract_from_content(content, file_path)
                
            except Exception as e:
                print(f"{self._color('red', '[ERROR]')} Failed to process {file_path}: {e}")
                return None
        
        def extract_from_string(self, content: str, source_name: str = "<string>") -> ExtractionResult:
            """Extract data from a JS string."""
            return self._extract_from_content(content, source_name)
        
        def extract_from_url(self, url: str) -> Optional[ExtractionResult]:
            """Extract data from a JS file at a URL."""
            try:
                import requests
                response = requests.get(url, timeout=30, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                response.raise_for_status()
                
                return self._extract_from_content(response.text, url)
                
            except ImportError:
                print(f"{self._color('red', '[ERROR]')} 'requests' library required for URL extraction")
                return None
            except Exception as e:
                print(f"{self._color('red', '[ERROR]')} Failed to fetch {url}: {e}")
                return None
        
        def extract_from_directory(self, directory: str, recursive: bool = True, 
                                    extensions: List[str] = None) -> List[ExtractionResult]:
            """Extract data from all JS files in a directory."""
            if extensions is None:
                extensions = ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.vue', '.svelte']
            
            results = []
            dir_path = Path(directory)
            
            if not dir_path.exists():
                print(f"{self._color('red', '[ERROR]')} Directory not found: {directory}")
                return results
            
            pattern = '**/*' if recursive else '*'
            
            for ext in extensions:
                for file_path in dir_path.glob(f"{pattern}{ext}"):
                    if file_path.is_file():
                        result = self.extract_from_file(str(file_path))
                        if result:
                            results.append(result)
            
            # Also check .js.map files
            for file_path in dir_path.glob(f"{pattern}.js.map"):
                if file_path.is_file():
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            map_data = json.load(f)
                        if 'sourcesContent' in map_data:
                            for idx, source in enumerate(map_data.get('sources', [])):
                                if idx < len(map_data['sourcesContent']) and map_data['sourcesContent'][idx]:
                                    result = self._extract_from_content(
                                        map_data['sourcesContent'][idx], 
                                        f"{file_path} -> {source}"
                                    )
                                    results.append(result)
                    except:
                        pass
            
            return results
        
        def _color(self, color: str, text: str) -> str:
            """Apply color to text if colorama is available."""
            if not HAS_COLORAMA:
                return text
            
            colors = {
                'red': Fore.RED,
                'green': Fore.GREEN,
                'yellow': Fore.YELLOW,
                'blue': Fore.BLUE,
                'magenta': Fore.MAGENTA,
                'cyan': Fore.CYAN,
                'white': Fore.WHITE,
                'black': Fore.BLACK,
            }
            
            return f"{colors.get(color, '')}{text}{Style.RESET_ALL}"
        
        def print_results(self, results: List[ExtractionResult], verbose: bool = False, 
                        categories: List[str] = None, filter_confidence: str = None):
            """Pretty print extraction results."""
            
            if not results:
                print(f"\n{self._color('yellow', '[!]')} No results found.")
                return
            
            # Category display names and colors
            category_info = {
                'api_endpoints': ('API Endpoints', 'cyan'),
                'file_paths': ('File Paths', 'blue'),
                'parameters': ('Parameters', 'green'),
                'secrets': ('SECRETS/CREDENTIALS', 'red'),
                'urls': ('URLs', 'magenta'),
                'function_names': ('Function Names', 'white'),
                'class_names': ('Class Names', 'white'),
                'imports': ('Imports', 'yellow'),
                'comments': ('Comments', 'white'),
                'dom_selectors': ('DOM Selectors', 'green'),
                'event_handlers': ('Event Handlers', 'yellow'),
                'ajax_calls': ('AJAX Calls', 'cyan'),
                'websockets': ('WebSockets', 'cyan'),
                'local_storage_keys': ('LocalStorage Keys', 'yellow'),
                'cookies': ('Cookies', 'yellow'),
                'headers': ('HTTP Headers', 'magenta'),
                'regex_patterns': ('Regex Patterns', 'white'),
                'error_messages': ('Error Messages', 'red'),
                'debug_info': ('Debug Info', 'yellow'),
                'custom_patterns': ('Custom Patterns', 'white'),
            }
            
            confidence_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            
            # Aggregate all results
            aggregated = defaultdict(list)
            for result in results:
                for field_name in result.__dataclass_fields__:
                    if field_name not in ['file_path', 'file_size', 'analysis_time']:
                        items = getattr(result, field_name)
                        for item in items:
                            if categories and field_name not in categories:
                                continue
                            if filter_confidence and confidence_order.get(item.confidence, 99) > confidence_order.get(filter_confidence, 99):
                                continue
                            item.category = field_name
                            aggregated[field_name].append((item, result.file_path))
            
            # Print header
            total_items = sum(len(items) for items in aggregated.values())
            print(f"\n{self._color('cyan', '='*70)}")
            print(f"{self._color('cyan', '  JAVASCRIPT EXTRACTION RESULTS')}")
            print(f"{self._color('cyan', '='*70)}")
            print(f"  Files analyzed: {self._color('white', str(len(results)))}")
            print(f"  Total findings: {self._color('white', str(total_items))}")
            print(f"{self._color('cyan', '='*70)}\n")
            
            # Print each category
            for category, items in aggregated.items():
                if not items:
                    continue
                
                display_name, color = category_info.get(category, (category, 'white'))
                is_secret = category == 'secrets'
                
                if is_secret:
                    print(f"{self._color('red', '╔' + '═'*68 + '╗')}")
                    print(f"{self._color('red', '║')} {self._color('white', f'⚠ {display_name} ({len(items)} found)'):^66} {self._color('red', '║')}")
                    print(f"{self._color('red', '╚' + '═'*68 + '╝')}")
                else:
                    print(f"{self._color(color, f'[{display_name}]')} ({len(items)} found)")
                    print(f"{self._color(color, '-'*70)}")
                
                # Sort by confidence
                items.sort(key=lambda x: confidence_order.get(x[0].confidence, 99))
                
                for item, source in items:
                    conf_color = {
                        'critical': 'red',
                        'high': 'yellow', 
                        'medium': 'white',
                        'low': 'white'
                    }.get(item.confidence, 'white')
                    
                    source_short = source.split('/')[-1] if '/' in source else source
                    if len(source_short) > 30:
                        source_short = '...' + source_short[-27:]
                    
                    print(f"  {self._color(conf_color, f'[{item.confidence.upper():8}]')} {item.value[:100]}")
                    if verbose:
                        print(f"           {self._color('white', f'Source: {source_short}:{item.line_number}')}")
                        if item.context and len(item.context) < 200:
                            print(f"           {self._color('white', f'Context: {item.context[:100]}...')}")
                
                print()
        
        def export_json(self, results: List[ExtractionResult], output_file: str, 
                        pretty: bool = True):
            """Export results to JSON file."""
            data = {
                'metadata': {
                    'tool': 'JS Extractor',
                    'version': '2.0.0',
                    'timestamp': datetime.now().isoformat(),
                    'files_analyzed': len(results),
                    'total_findings': sum(len(r.get_all_items()) for r in results)
                },
                'results': [r.to_dict() for r in results]
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                if pretty:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                else:
                    json.dump(data, f, ensure_ascii=False)
            
            print(f"{self._color('green', '[+]')} Results exported to: {output_file}")
        
        def export_csv(self, results: List[ExtractionResult], output_file: str):
            """Export results to CSV file."""
            import csv
            
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Category', 'Value', 'Confidence', 'Line Number', 'Source File'])
                
                for result in results:
                    for item in result.get_all_items():
                        writer.writerow([
                            item.category,
                            item.value,
                            item.confidence,
                            item.line_number,
                            result.file_path
                        ])
            
            print(f"{self._color('green', '[+]')} Results exported to: {output_file}")
        
        def export_markdown(self, results: List[ExtractionResult], output_file: str):
            """Export results to Markdown file."""
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# JavaScript Extraction Report\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Files Analyzed:** {len(results)}\n\n")
                
                category_info = {
                    'api_endpoints': 'API Endpoints',
                    'file_paths': 'File Paths',
                    'parameters': 'Parameters',
                    'secrets': '🚨 Secrets/Credentials',
                    'urls': 'URLs',
                    'function_names': 'Function Names',
                    'class_names': 'Class Names',
                    'imports': 'Imports',
                    'comments': 'Comments',
                    'dom_selectors': 'DOM Selectors',
                    'event_handlers': 'Event Handlers',
                    'ajax_calls': 'AJAX Calls',
                    'websockets': 'WebSockets',
                    'local_storage_keys': 'LocalStorage Keys',
                    'cookies': 'Cookies',
                    'headers': 'HTTP Headers',
                    'regex_patterns': 'Regex Patterns',
                    'error_messages': 'Error Messages',
                    'debug_info': 'Debug Info',
                    'custom_patterns': 'Custom Patterns',
                }
                
                for result in results:
                    f.write(f"\n## {result.file_path}\n\n")
                    
                    for field_name in result.__dataclass_fields__:
                        if field_name in ['file_path', 'file_size', 'analysis_time']:
                            continue
                        
                        items = getattr(result, field_name)
                        if not items:
                            continue
                        
                        display_name = category_info.get(field_name, field_name)
                        f.write(f"### {display_name}\n\n")
                        
                        for item in items:
                            f.write(f"- `{item.value}` (Line {item.line_number}, {item.confidence})\n")
                        
                        f.write("\n")
            
            print(f"{self._color('green', '[+]')} Results exported to: {output_file}")


    # ============================================================================
    # CLI INTERFACE
    # ============================================================================

    def list_categories():
        """Print available extraction categories."""
        categories = {
            'api_endpoints': 'API endpoints and routes',
            'file_paths': 'File system paths and references',
            'parameters': 'Function and query parameters',
            'secrets': 'API keys, tokens, passwords, and credentials',
            'urls': 'HTTP/HTTPS/WebSocket URLs',
            'function_names': 'Function declarations and expressions',
            'class_names': 'Class definitions and instantiations',
            'imports': 'Import/require statements',
            'comments': 'Code comments (single and multi-line)',
            'dom_selectors': 'DOM element selectors',
            'event_handlers': 'Event listener registrations',
            'ajax_calls': 'AJAX and HTTP request calls',
            'websockets': 'WebSocket connections',
            'local_storage_keys': 'LocalStorage and SessionStorage keys',
            'cookies': 'Cookie operations',
            'headers': 'HTTP headers',
            'regex_patterns': 'Regular expression patterns',
            'error_messages': 'Error and warning messages',
            'debug_info': 'Debug statements and TODOs',
            'custom_patterns': 'User-defined patterns',
        }
        
        print("\nAvailable extraction categories:\n")
        for name, desc in categories.items():
            print(f"  {name:20} - {desc}")
        print()


    def run_from_args(args):
        if args is None:
            args = create_parser().parse_args([])

        if isinstance(args, str):
            args = create_parser().parse_args([args])

        if args.list_categories:
            list_categories()
            return
        
        if args.no_color and HAS_COLORAMA:
            import colorama
            colorama.init(strip=True)
        
        # Build configuration
        config = {
            'min_string_length': args.min_length,
            'max_string_length': args.max_length,
            'exclude_patterns': [args.exclude] if args.exclude else [],
        }
        
        # Parse custom patterns
        if args.custom:
            config['custom_patterns'] = []
            for custom in args.custom:
                parts = custom.split(':', 2)
                if len(parts) >= 2:
                    config['custom_patterns'].append({
                        'name': parts[0],
                        'pattern': parts[1],
                        'confidence': parts[2] if len(parts) > 2 else 'medium'
                    })
        
        # Create extractor
        extractor = JSExtractor(config)
        
        # Get input
        results = []

        if not args.stdin and not getattr(args, 'input', None):
            prompt_value = input('Enter JS file, directory, or URL to analyze\n=> ').strip()
            if not prompt_value:
                print(f"{extractor._color('red', '[ERROR]')} Input cannot be empty.")
                sys.exit(1)
            args.input = prompt_value
        
        if args.stdin:
            content = sys.stdin.read()
            if content.strip():
                result = extractor.extract_from_string(content, '<stdin>')
                results.append(result)
        elif args.input:
            input_path = args.input
            
            if input_path.startswith(('http://', 'https://', 'wss://', 'ws://')):
                if not args.quiet:
                    print(f"{extractor._color('cyan', '[*]')} Fetching: {input_path}")
                result = extractor.extract_from_url(input_path)
                if result:
                    results.append(result)
            elif os.path.isfile(input_path):
                if not args.quiet:
                    print(f"{extractor._color('cyan', '[*]')} Analyzing: {input_path}")
                result = extractor.extract_from_file(input_path)
                if result:
                    results.append(result)
            elif os.path.isdir(input_path):
                if not args.quiet:
                    print(f"{extractor._color('cyan', '[*]')} Scanning directory: {input_path}")
                extensions = [e.strip() for e in args.extensions.split(',')]
                results = extractor.extract_from_directory(input_path, args.recursive, extensions)
            else:
                print(f"{extractor._color('red', '[ERROR]')} Input not found: {input_path}")
                sys.exit(1)
        
        if not results:
            print(f"{extractor._color('yellow', '[!]')} No results to display.")
            sys.exit(0)
        
        # Parse categories filter
        categories = None
        if args.categories:
            categories = [c.strip() for c in args.categories.split(',')]
        
        # Output
        if args.stats_only:
            print(f"\n{extractor._color('cyan', '='*50)}")
            print(f"{extractor._color('cyan', '  EXTRACTION STATISTICS')}")
            print(f"{extractor._color('cyan', '='*50)}")
            
            total_stats = defaultdict(int)
            for result in results:
                for cat, count in result.get_stats().items():
                    total_stats[cat] += count
            
            for cat, count in sorted(total_stats.items(), key=lambda x: -x[1]):
                if count > 0:
                    print(f"  {cat:25} : {count}")
            print()
        else:
            extractor.print_results(results, args.verbose, categories, args.confidence)
        
        # Export if requested
        if args.output:
            ext = Path(args.output).suffix.lower()
            if ext == '.json':
                extractor.export_json(results, args.output)
            elif ext == '.csv':
                extractor.export_csv(results, args.output)
            elif ext in ('.md', '.markdown'):
                extractor.export_markdown(results, args.output)
            else:
                extractor.export_json(results, args.output)

    def run_interactive_loop(initial_input=None):
        parser = create_parser()

        def color_text(color: str, text: str) -> str:
            if not HAS_COLORAMA:
                return text
            colors = {
                'red': '\033[31m',
                'green': '\033[32m',
                'yellow': '\033[33m',
                'blue': '\033[34m',
                'magenta': '\033[35m',
                'cyan': '\033[36m',
                'white': '\033[37m',
                'black': '\033[30m',
            }
            return f"{colors.get(color, '')}{text}\033[0m"

        print("\nJS extractor interactive mode")
        print("Type 'help' for usage or 'exit' to quit.")
        print("Examples:")
        print("  file.js")
        print("  ./src -r")
        print("  -c secrets,api_endpoints file.js")

        while True:
            if initial_input is not None:
                print(f"js-tool> {initial_input}")
                command = str(initial_input).strip()
                initial_input = None
            else:
                try:
                    command = input("js-tool> ").strip()
                except KeyboardInterrupt:
                    print("\nGoodbye!")
                    break
                except EOFError:
                    print("\nGoodbye!")
                    break

            if not command:
                continue

            if command.lower() in {'exit', 'quit'}:
                print("Exiting JS extractor.")
                break

            if command.lower() in {'help', '?'}:
                parser.print_help()
                continue

            try:
                tokens = shlex.split(command)
            except ValueError as exc:
                print(f"{color_text('red', '[ERROR]')} Invalid input: {exc}")
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


if __name__ == "__main__":
    args = create_parser().parse_args()
    run_taking_information_tool(args)
    