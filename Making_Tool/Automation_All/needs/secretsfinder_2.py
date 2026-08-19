#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecretsFinder Pro - Personal Secrets Detection Tool
====================================================
A defensive security tool to identify accidentally exposed credentials,
API keys, tokens, and other sensitive data in codebases.

Author : Mrscript
Version: 2.1.0 (CLI Edition)

Usage:
    python secretsfinder.py -h
    python secretsfinder.py .
    python secretsfinder.py /path/to/project -o report.html
    python secretsfinder.py . --severity critical,high --min-confidence 0.8
    python secretsfinder.py --list-patterns
    python secretsfinder.py -i          # interactive mode (legacy)
"""

from __future__ import annotations

import sys
import json
import re
import math
import enum
import shlex
import argparse
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Pattern
from html import escape

__version__ = "2.1.0"


# =============================================================================
# CLI ARGUMENT PARSER
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='secretsfinder.py',
        description='SecretsFinder Pro - Detect exposed credentials, API keys, '
                    'tokens and secrets in files and codebases',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s -h
  %(prog)s .
  %(prog)s /path/to/project
  %(prog)s . -o report.json
  %(prog)s . -o report.html --severity critical,high
  %(prog)s . --category api_key,auth_token --min-confidence 0.8
  %(prog)s . --exclude "test_|spec_" --include "config|\\.env"
  %(prog)s --list-patterns
  %(prog)s -i        (interactive mode)
"""
    )

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument('-p', '--path', help='File or directory to scan')
    target_group.add_argument('input_target', nargs='?',
                              help='File or directory to scan (positional argument)')

    parser.add_argument('-o', '--output',
                        help='Output file (.json, .sarif, .html, or .txt)')
    parser.add_argument('--format', choices=['console', 'json', 'sarif', 'html'],
                        help='Force output format (default: inferred from -o extension, or console)')
    parser.add_argument('--severity', metavar='LIST',
                        help='Filter by severity (comma-separated): critical,high,medium,low,info')
    parser.add_argument('--category', metavar='LIST',
                        help='Filter by category (comma-separated): api_key,auth_token,password,...')
    parser.add_argument('--min-confidence', type=float, default=0.0, metavar='X',
                        help='Minimum confidence threshold 0.0-1.0 (default: 0.0)')
    parser.add_argument('--context', type=int, default=2, metavar='N',
                        help='Context lines around each finding (default: 2)')
    parser.add_argument('--no-context', action='store_true', help='Hide context lines')
    parser.add_argument('--exclude', action='append', metavar='REGEX',
                        help='Regex to skip files/directories (repeatable)')
    parser.add_argument('--include', action='append', metavar='REGEX',
                        help='Only scan files matching regex (repeatable)')
    parser.add_argument('--follow-symlinks', action='store_true',
                        help='Follow symbolic links during directory scan')
    parser.add_argument('--max-file-size', type=int, default=10, metavar='MB',
                        help='Maximum file size to scan in MB (default: 10)')
    parser.add_argument('--list-patterns', action='store_true',
                        help='List all detection patterns and exit')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output (errors, category breakdown)')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Start interactive mode (legacy behaviour)')
    parser.add_argument('-V', '--version', action='version',
                        version='%(prog)s ' + __version__)

    return parser


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecretCategory(enum.Enum):
    API_KEY = "api_key"
    AUTH_TOKEN = "auth_token"
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    DATABASE = "database"
    CLOUD = "cloud"
    ENCRYPTION = "encryption"
    WEBHOOK = "webhook"
    CERTIFICATE = "certificate"
    GENERIC_SECRET = "generic_secret"


@dataclass
class SecretPattern:
    """Defines a pattern for detecting a specific type of secret."""
    name: str
    pattern: str
    category: SecretCategory
    severity: Severity
    description: str
    example_redacted: str
    allowlist: List[str] = field(default_factory=list)
    verify_entropy: bool = False
    min_entropy: float = 3.5
    compiled_pattern: Optional[Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        flags = re.IGNORECASE | re.DOTALL
        self.compiled_pattern = re.compile(self.pattern, flags)


@dataclass
class SecretMatch:
    """Represents a single secret match found in a file."""
    file_path: str
    line_number: int
    line_content: str
    pattern_name: str
    category: SecretCategory
    severity: Severity
    matched_value: str
    redacted_value: str
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)
    entropy: float = 0.0
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content.rstrip(),
            "pattern_name": self.pattern_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "matched_value": self.redacted_value,
            "entropy": round(self.entropy, 2),
            "confidence": round(self.confidence, 2),
            "context_before": [l.rstrip() for l in self.context_before],
            "context_after": [l.rstrip() for l in self.context_after],
        }


@dataclass
class ScanResult:
    """Contains all results from a scan operation."""
    scan_path: str
    start_time: datetime
    end_time: Optional[datetime] = None
    files_scanned: int = 0
    files_skipped: int = 0
    total_matches: int = 0
    matches_by_severity: Dict[str, int] = field(default_factory=dict)
    matches_by_category: Dict[str, int] = field(default_factory=dict)
    matches: List[SecretMatch] = field(default_factory=list)
    skipped_files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def recompute_summary(self) -> None:
        """Recalculate summary statistics (useful after filtering)."""
        self.total_matches = len(self.matches)
        self.matches_by_severity = {}
        self.matches_by_category = {}
        for match in self.matches:
            sev = match.severity.value
            cat = match.category.value
            self.matches_by_severity[sev] = self.matches_by_severity.get(sev, 0) + 1
            self.matches_by_category[cat] = self.matches_by_category.get(cat, 0) + 1

    def to_dict(self) -> dict:
        duration = None
        if self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        return {
            "scan_path": self.scan_path,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": round(duration, 2) if duration else None,
            "summary": {
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "total_matches": self.total_matches,
                "matches_by_severity": self.matches_by_severity,
                "matches_by_category": self.matches_by_category,
            },
            "findings": [m.to_dict() for m in self.matches],
            "skipped_files": self.skipped_files,
            "errors": self.errors,
        }


# =============================================================================
# PATTERN DATABASE
# =============================================================================

class PatternDatabase:
    """Comprehensive database of secret detection patterns."""

    def __init__(self):
        self.patterns: List[SecretPattern] = []
        self._load_patterns()

    def _load_patterns(self):
        """Load all secret detection patterns."""

        # =========================================================================
        # API KEYS
        # =========================================================================
        self.patterns.extend([
            SecretPattern(
                name="AWS Access Key ID",
                pattern=r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
                category=SecretCategory.API_KEY,
                severity=Severity.CRITICAL,
                description="AWS Access Key Identifier",
                example_redacted="AKIA********************XXXX",
                verify_entropy=False,  # AWS keys have fixed format
            ),
            SecretPattern(
                name="AWS Secret Access Key",
                pattern=r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
                category=SecretCategory.API_KEY,
                severity=Severity.CRITICAL,
                description="AWS Secret Access Key",
                example_redacted="****************************************",
                verify_entropy=True,
                min_entropy=4.0,
            ),
            SecretPattern(
                name="GitHub Personal Access Token",
                pattern=r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}',
                category=SecretCategory.API_KEY,
                severity=Severity.CRITICAL,
                description="GitHub Personal/OAuth/App Token",
                example_redacted="ghp_************************************",
            ),
            SecretPattern(
                name="GitLab Personal Access Token",
                pattern=r'glpat-[A-Za-z0-9\-_]{20,255}',
                category=SecretCategory.API_KEY,
                severity=Severity.CRITICAL,
                description="GitLab Personal Access Token",
                example_redacted="glpat-*********************",
            ),
            SecretPattern(
                name="GitLab OAuth Token",
                pattern=r'gl-oauth-[A-Za-z0-9\-_]{20,255}',
                category=SecretCategory.API_KEY,
                severity=Severity.CRITICAL,
                description="GitLab OAuth Token",
                example_redacted="gl-oauth-*********************",
            ),
            SecretPattern(
                name="Google API Key",
                pattern=r'AIza[0-9A-Za-z\-_]{35}',
                category=SecretCategory.API_KEY,
                severity=Severity.HIGH,
                description="Google Cloud API Key",
                example_redacted="AIza***********************************",
            ),
            SecretPattern(
                name="Google OAuth Token",
                pattern=r'ya29\.[0-9A-Za-z\-_]+',
                category=SecretCategory.API_KEY,
                severity=Severity.HIGH,
                description="Google OAuth 2.0 Access Token",
                example_redacted="ya29.**********************",
            ),
            SecretPattern(
                name="Slack Token",
                pattern=r'xox[baprs]-[0-9]{10,13}-[0-9A-Za-z]{24,}',
                category=SecretCategory.API_KEY,
                severity=Severity.HIGH,
                description="Slack Bot/User/App Token",
                example_redacted="xoxb-**********-**********************",
            ),
            SecretPattern(
                name="Slack Webhook",
                pattern=r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
                category=SecretCategory.WEBHOOK,
                severity=Severity.HIGH,
                description="Slack Webhook URL",
                example_redacted="https://hooks.slack.com/services/T*****/B*****/*****",
            ),
            SecretPattern(
                name="Stripe API Key (Secret)",
                pattern=r'sk_live_[0-9a-zA-Z]{24,99}',
                category=SecretCategory.API_KEY,
                severity=Severity.CRITICAL,
                description="Stripe Secret API Key",
                example_redacted="sk_live_**************************",
            ),
            SecretPattern(
                name="Stripe API Key (Publishable)",
                pattern=r'pk_live_[0-9a-zA-Z]{24,99}',
                category=SecretCategory.API_KEY,
                severity=Severity.MEDIUM,
                description="Stripe Publishable API Key (lower risk but should be verified)",
                example_redacted="pk_live_**************************",
            ),
            SecretPattern(
                name="Twilio API Key",
                pattern=r'SK[0-9a-fA-F]{32}',
                category=SecretCategory.API_KEY,
                severity=Severity.HIGH,
                description="Twilio API Key SID",
                example_redacted="SK********************************",
            ),
            SecretPattern(
                name="SendGrid API Key",
                pattern=r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
                category=SecretCategory.API_KEY,
                severity=Severity.HIGH,
                description="SendGrid API Key",
                example_redacted="SG.**********************.*********************************************",
            ),
            SecretPattern(
                name="Mailgun API Key",
                pattern=r'key-[0-9a-zA-Z]{32}',
                category=SecretCategory.API_KEY,
                severity=Severity.HIGH,
                description="Mailgun API Key",
                example_redacted="key-********************************",
            ),
            SecretPattern(
                name="PagerDuty Token",
                pattern=r'PD_[A-Za-z0-9]{30,}',
                category=SecretCategory.API_KEY,
                severity=Severity.HIGH,
                description="PagerDuty API Token",
                example_redacted="PD******************************",
            ),
            SecretPattern(
                name="OpenAI API Key",
                pattern=r'sk-[A-Za-z0-9]{48,}',
                category=SecretCategory.API_KEY,
                severity=Severity.CRITICAL,
                description="OpenAI API Key",
                example_redacted="sk-************************************************",
            ),
            SecretPattern(
                name="Anthropic API Key",
                pattern=r'sk-ant-[A-Za-z0-9\-_]{80,}',
                category=SecretCategory.API_KEY,
                severity=Severity.CRITICAL,
                description="Anthropic API Key",
                example_redacted="sk-ant-********************************************************************************",
            ),
            SecretPattern(
                name="Azure API Key",
                pattern=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                category=SecretCategory.API_KEY,
                severity=Severity.MEDIUM,
                description="Azure GUID (potential API key - verify context)",
                example_redacted="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                allowlist=["00000000-0000-0000-0000-000000000000"],
            ),
            SecretPattern(
                name="Shopify API Key",
                pattern=r'shyp_[a-fA-F0-9]{32}',
                category=SecretCategory.API_KEY,
                severity=Severity.HIGH,
                description="Shopify Private App API Key",
                example_redacted="shyp_********************************",
            ),
            SecretPattern(
                name="Square Access Token",
                pattern=r'sq0atp-[0-9A-Za-z\-_]{22}',
                category=SecretCategory.API_KEY,
                severity=Severity.HIGH,
                description="Square Access Token",
                example_redacted="sq0atp-**********************",
            ),
        ])

        # =========================================================================
        # AUTH TOKENS
        # =========================================================================
        self.patterns.extend([
            SecretPattern(
                name="Bearer Token",
                pattern=r'(?:Bearer|TOKEN)\s+[A-Za-z0-9\-._~+/]+=*',
                category=SecretCategory.AUTH_TOKEN,
                severity=Severity.HIGH,
                description="Bearer Token in Authorization header",
                example_redacted="Bearer *************************************",
                verify_entropy=True,
                min_entropy=3.0,
            ),
            SecretPattern(
                name="JWT Token",
                pattern=r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
                category=SecretCategory.AUTH_TOKEN,
                severity=Severity.HIGH,
                description="JSON Web Token (JWT)",
                example_redacted="eyJ********************************.eyJ********************************.*****",
            ),
            SecretPattern(
                name="OAuth Token",
                pattern=r'(?:oauth_token|access_token)\s*[:=]\s*["\']?([A-Za-z0-9\-._~+/]{20,})["\']?',
                category=SecretCategory.AUTH_TOKEN,
                severity=Severity.HIGH,
                description="OAuth Access Token",
                example_redacted="oauth_token=********************",
                verify_entropy=True,
                min_entropy=3.0,
            ),
            SecretPattern(
                name="Heroku API Token",
                pattern=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                category=SecretCategory.AUTH_TOKEN,
                severity=Severity.HIGH,
                description="Heroku API Token (UUID format in heroku context)",
                example_redacted="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            ),
            SecretPattern(
                name="npm Token",
                pattern=r'npm_[A-Za-z0-9]{36}',
                category=SecretCategory.AUTH_TOKEN,
                severity=Severity.HIGH,
                description="npm Authentication Token",
                example_redacted="npm_************************************",
            ),
            SecretPattern(
                name="PyPI Token",
                pattern=r'pypi-[A-Za-z0-9-]+',
                category=SecretCategory.AUTH_TOKEN,
                severity=Severity.HIGH,
                description="PyPI API Token",
                example_redacted="pypi-*********************",
            ),
            SecretPattern(
                name="DotNet NuGet API Key",
                pattern=r'oy2[a-z0-9]{43}',
                category=SecretCategory.AUTH_TOKEN,
                severity=Severity.HIGH,
                description=".NET NuGet API Key",
                example_redacted="oy2***********************************************",
            ),
        ])

        # =========================================================================
        # PASSWORDS
        # =========================================================================
        self.patterns.extend([
            SecretPattern(
                name="Password Assignment",
                pattern=r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
                category=SecretCategory.PASSWORD,
                severity=Severity.CRITICAL,
                description="Password in assignment/config",
                example_redacted="password=\"********\"",
                verify_entropy=True,
                min_entropy=2.5,
            ),
            SecretPattern(
                name="Password URL Parameter",
                pattern=r'[?&](?:password|passwd|pwd)=([^&\s"\']{8,})',
                category=SecretCategory.PASSWORD,
                severity=Severity.CRITICAL,
                description="Password in URL parameter",
                example_redacted="?password=********",
                verify_entropy=True,
                min_entropy=2.5,
            ),
            SecretPattern(
                name="Connection String Password",
                pattern=r'(?:Password|Pwd)\s*=\s*([^;]{8,})',
                category=SecretCategory.PASSWORD,
                severity=Severity.CRITICAL,
                description="Password in database connection string",
                example_redacted="Password=********;",
                verify_entropy=True,
                min_entropy=2.0,
            ),
        ])

        # =========================================================================
        # PRIVATE KEYS
        # =========================================================================
        self.patterns.extend([
            SecretPattern(
                name="RSA Private Key",
                pattern=r'-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----',
                category=SecretCategory.PRIVATE_KEY,
                severity=Severity.CRITICAL,
                description="RSA Private Key in PEM format",
                example_redacted="-----BEGIN RSA PRIVATE KEY-----\n***REDACTED***\n-----END RSA PRIVATE KEY-----",
            ),
            SecretPattern(
                name="Private Key",
                pattern=r'-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----',
                category=SecretCategory.PRIVATE_KEY,
                severity=Severity.CRITICAL,
                description="Generic Private Key in PEM format",
                example_redacted="-----BEGIN PRIVATE KEY-----\n***REDACTED***\n-----END PRIVATE KEY-----",
            ),
            SecretPattern(
                name="EC Private Key",
                pattern=r'-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----',
                category=SecretCategory.PRIVATE_KEY,
                severity=Severity.CRITICAL,
                description="Elliptic Curve Private Key",
                example_redacted="-----BEGIN EC PRIVATE KEY-----\n***REDACTED***\n-----END EC PRIVATE KEY-----",
            ),
            SecretPattern(
                name="OpenSSH Private Key",
                pattern=r'-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----',
                category=SecretCategory.PRIVATE_KEY,
                severity=Severity.CRITICAL,
                description="OpenSSH Private Key",
                example_redacted="-----BEGIN OPENSSH PRIVATE KEY-----\n***REDACTED***\n-----END OPENSSH PRIVATE KEY-----",
            ),
            SecretPattern(
                name="PGP Private Key",
                pattern=r'-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----',
                category=SecretCategory.PRIVATE_KEY,
                severity=Severity.CRITICAL,
                description="PGP Private Key Block",
                example_redacted="-----BEGIN PGP PRIVATE KEY BLOCK-----\n***REDACTED***\n-----END PGP PRIVATE KEY BLOCK-----",
            ),
            SecretPattern(
                name="SSH Private Key (putty)",
                pattern=r'PuTTY-User-Key-File-[\s\S]*?Private-MAC:',
                category=SecretCategory.PRIVATE_KEY,
                severity=Severity.CRITICAL,
                description="PuTTY Format Private Key",
                example_redacted="PuTTY-User-Key-File-***REDACTED***",
            ),
        ])

        # =========================================================================
        # DATABASE
        # =========================================================================
        self.patterns.extend([
            SecretPattern(
                name="MongoDB Connection String",
                pattern=r'mongodb(?:\+srv)?://[^\s"\']+',
                category=SecretCategory.DATABASE,
                severity=Severity.HIGH,
                description="MongoDB Connection URI with credentials",
                example_redacted="mongodb://user:****@host:port/db",
            ),
            SecretPattern(
                name="PostgreSQL Connection String",
                pattern=r'postgres(?:ql)?://[^\s"\']+:[^\s"\']+@[^\s"\']+',
                category=SecretCategory.DATABASE,
                severity=Severity.HIGH,
                description="PostgreSQL Connection URI with credentials",
                example_redacted="postgresql://user:****@host:5432/db",
            ),
            SecretPattern(
                name="MySQL Connection String",
                pattern=r'mysql://[^\s"\']+:[^\s"\']+@[^\s"\']+',
                category=SecretCategory.DATABASE,
                severity=Severity.HIGH,
                description="MySQL Connection URI with credentials",
                example_redacted="mysql://user:****@host:3306/db",
            ),
            SecretPattern(
                name="Redis Connection String",
                pattern=r'redis://[^\s"\']+:[^\s"\']+@[^\s"\']+',
                category=SecretCategory.DATABASE,
                severity=Severity.HIGH,
                description="Redis Connection URI with credentials",
                example_redacted="redis://:****@host:6379",
            ),
            SecretPattern(
                name="JDBC Connection String",
                pattern=r'jdbc:[a-z]+://[^\s"\']+:[^\s"\']+@[^\s"\']+',
                category=SecretCategory.DATABASE,
                severity=Severity.HIGH,
                description="JDBC Connection String with credentials",
                example_redacted="jdbc:mysql://user:****@host:3306/db",
            ),
        ])

        # =========================================================================
        # CLOUD PROVIDERS
        # =========================================================================
        self.patterns.extend([
            SecretPattern(
                name="Google Cloud Service Account Key",
                pattern=r'"type":\s*"service_account"[\s\S]*?"private_key":\s*"-----BEGIN',
                category=SecretCategory.CLOUD,
                severity=Severity.CRITICAL,
                description="Google Cloud Service Account JSON Key",
                example_redacted='{"type": "service_account", ... "private_key": "***REDACTED***"}',
            ),
            SecretPattern(
                name="Azure Client Secret",
                pattern=r'(?:AZURE_CLIENT_SECRET|azure_client_secret)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{30,})["\']?',
                category=SecretCategory.CLOUD,
                severity=Severity.CRITICAL,
                description="Azure Client Secret",
                example_redacted="AZURE_CLIENT_SECRET=******************************",
                verify_entropy=True,
                min_entropy=3.0,
            ),
            SecretPattern(
                name="Azure Storage Key",
                pattern=r'(?:AccountKey=)([A-Za-z0-9+/]{88})',
                category=SecretCategory.CLOUD,
                severity=Severity.CRITICAL,
                description="Azure Storage Account Key",
                example_redacted="AccountKey=****************************************************************************************",
            ),
            SecretPattern(
                name="DigitalOcean Token",
                pattern=r'dop_v1_[a-f0-9]{64}',
                category=SecretCategory.CLOUD,
                severity=Severity.HIGH,
                description="DigitalOcean API Token / Personal Access Token",
                example_redacted="dop_v1_****************************************************************",
            ),
            SecretPattern(
                name="Linode Token",
                pattern=r'linode_LINODE_[A-Za-z0-9]{64}',
                category=SecretCategory.CLOUD,
                severity=Severity.HIGH,
                description="Linode API Token",
                example_redacted="linode_LINODE_****************************************************************",
            ),
            SecretPattern(
                name="Cloudflare API Token",
                pattern=r'(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{40})["\']?',
                category=SecretCategory.CLOUD,
                severity=Severity.HIGH,
                description="Cloudflare API Token",
                example_redacted="CF_API_TOKEN=****************************************",
                verify_entropy=True,
                min_entropy=4.0,
            ),
            SecretPattern(
                name="Cloudflare Global API Key",
                pattern=r'(?:CF_API_KEY|CLOUDFLARE_API_KEY)\s*[:=]\s*["\']?([a-f0-9]{37})["\']?',
                category=SecretCategory.CLOUD,
                severity=Severity.HIGH,
                description="Cloudflare Global API Key",
                example_redacted="CF_API_KEY=*************************************",
            ),
            SecretPattern(
                name="Terraform Cloud Token",
                pattern=r'[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_]{50,}',
                category=SecretCategory.CLOUD,
                severity=Severity.HIGH,
                description="Terraform Cloud/Atlas API Token",
                example_redacted="**************.atlasv1.**************************************************",
            ),
        ])

        # =========================================================================
        # ENCRYPTION KEYS
        # =========================================================================
        self.patterns.extend([
            SecretPattern(
                name="Encryption Key Assignment",
                pattern=r'(?:encryption_key|encrypt_key|secret_key|SECRET_KEY)\s*[:=]\s*["\']([A-Za-z0-9+/=]{32,})["\']',
                category=SecretCategory.ENCRYPTION,
                severity=Severity.HIGH,
                description="Encryption/Secret Key Assignment",
                example_redacted="SECRET_KEY=\"********************************\"",
                verify_entropy=True,
                min_entropy=3.5,
            ),
            SecretPattern(
                name="Fernet Key",
                pattern=r'(?i)fernet\s*[:=]\s*["\']?[A-Za-z0-9+/=]{44}["\']?',
                category=SecretCategory.ENCRYPTION,
                severity=Severity.HIGH,
                description="Python Fernet Encryption Key",
                example_redacted="fernet=\"********************************************\"",
            ),
            SecretPattern(
                name="Signing Secret",
                pattern=r'(?:signing_secret|SIGNING_SECRET|slack_signing_secret)\s*[:=]\s*["\']?([A-Za-z0-9]{24,})["\']?',
                category=SecretCategory.ENCRYPTION,
                severity=Severity.HIGH,
                description="Signing Secret (Slack, etc.)",
                example_redacted="SIGNING_SECRET=************************",
                verify_entropy=True,
                min_entropy=3.5,
            ),
            SecretPattern(
                name="HMAC Secret",
                pattern=r'(?:hmac_secret|HMAC_SECRET|hmac_key)\s*[:=]\s*["\']?([A-Za-z0-9+/=]{32,})["\']?',
                category=SecretCategory.ENCRYPTION,
                severity=Severity.HIGH,
                description="HMAC Secret Key",
                example_redacted="HMAC_SECRET=\"********************************\"",
                verify_entropy=True,
                min_entropy=3.5,
            ),
        ])

        # =========================================================================
        # CERTIFICATES
        # =========================================================================
        self.patterns.extend([
            SecretPattern(
                name="Certificate",
                pattern=r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----',
                category=SecretCategory.CERTIFICATE,
                severity=Severity.MEDIUM,
                description="X.509 Certificate (may contain sensitive info)",
                example_redacted="-----BEGIN CERTIFICATE-----\n***REDACTED***\n-----END CERTIFICATE-----",
            ),
        ])

        # =========================================================================
        # GENERIC SECRETS (lower confidence, higher false positive rate)
        # =========================================================================
        self.patterns.extend([
            SecretPattern(
                name="Generic Secret Key Assignment",
                pattern=r'(?:secret|token|api_key|apikey|access_key)\s*[:=]\s*["\']([A-Za-z0-9\-_+/=]{20,})["\']',
                category=SecretCategory.GENERIC_SECRET,
                severity=Severity.MEDIUM,
                description="Generic Secret/Token/Key Assignment",
                example_redacted="secret=\"********************\"",
                verify_entropy=True,
                min_entropy=3.5,
            ),
            SecretPattern(
                name="High Entropy String",
                pattern=r'["\']([A-Za-z0-9+/=]{40,})["\']',
                category=SecretCategory.GENERIC_SECRET,
                severity=Severity.LOW,
                description="High Entropy String (potential secret)",
                example_redacted="\"****************************************\"",
                verify_entropy=True,
                min_entropy=4.5,
            ),
        ])

    def get_patterns_by_severity(self, severity: Severity) -> List[SecretPattern]:
        """Get all patterns matching a specific severity level."""
        return [p for p in self.patterns if p.severity == severity]

    def get_patterns_by_category(self, category: SecretCategory) -> List[SecretPattern]:
        """Get all patterns matching a specific category."""
        return [p for p in self.patterns if p.category == category]


# =============================================================================
# CORE SCANNER
# =============================================================================

class SecretsScanner:
    """Main scanner engine for detecting secrets in files."""

    # Files that should always be skipped
    DEFAULT_SKIP_EXTENSIONS = frozenset({
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.wav',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
        '.exe', '.dll', '.so', '.dylib', '.o', '.a', '.lib',
        '.pyc', '.pyo', '.class', '.jar', '.war', '.ear',
        '.woff', '.woff2', '.ttf', '.otf', '.eot',
        '.bin', '.dat', '.db', '.sqlite', '.sqlite3',
    })

    DEFAULT_SKIP_DIRECTORIES = frozenset({
        '.git', '.svn', '.hg', '__pycache__', 'node_modules',
        'venv', '.venv', 'env', '.env', 'virtualenv',
        '.idea', '.vscode', '.vs',
        'dist', 'build', '.tox', '.eggs',
        '.mypy_cache', '.pytest_cache', '.ruff_cache',
        'vendor', '.bundle', 'coverage',
    })

    DEFAULT_SKIP_FILES = frozenset({
        'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
        'Cargo.lock', 'go.sum', 'composer.lock',
        '.gitmodules', '.gitattributes',
    })

    def __init__(
        self,
        pattern_db: PatternDatabase,
        context_lines: int = 2,
        min_confidence: float = 0.0,
        additional_skip_patterns: Optional[List[str]] = None,
        additional_include_patterns: Optional[List[str]] = None,
        max_file_size_mb: int = 10,
    ):
        self.pattern_db = pattern_db
        self.context_lines = context_lines
        self.min_confidence = min_confidence
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.additional_skip_patterns = additional_skip_patterns or []
        self.additional_include_patterns = additional_include_patterns or []
        self._compiled_skip = [re.compile(p) for p in self.additional_skip_patterns]
        self._compiled_include = [re.compile(p) for p in self.additional_include_patterns]

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0

        freq = defaultdict(int)
        for char in data:
            freq[char] += 1

        length = len(data)
        entropy = 0.0

        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def redact_value(self, value: str, visible_chars: int = 4) -> str:
        """Redact a secret value, showing only first and last few chars."""
        if len(value) <= visible_chars * 2:
            return '*' * len(value)
        return value[:visible_chars] + '*' * (len(value) - visible_chars * 2) + value[-visible_chars:]

    def calculate_confidence(self, pattern: SecretPattern, matched_value: str, entropy: float) -> float:
        """Calculate confidence score for a match (0.0 to 1.0)."""
        confidence = 0.5  # Base confidence

        # Fixed-format patterns get higher confidence
        if not pattern.verify_entropy:
            confidence = 0.9
        else:
            # Entropy-based confidence
            if entropy >= pattern.min_entropy:
                confidence += 0.2
            if entropy >= 4.0:
                confidence += 0.1
            if entropy >= 4.5:
                confidence += 0.1

        # Longer values are more likely real secrets
        if len(matched_value) >= 32:
            confidence += 0.05
        if len(matched_value) >= 64:
            confidence += 0.05

        # Category-based adjustments
        high_confidence_categories = {
            SecretCategory.PRIVATE_KEY,
            SecretCategory.CERTIFICATE,
        }
        if pattern.category in high_confidence_categories:
            confidence = min(confidence + 0.1, 1.0)

        # Generic patterns get lower confidence
        if pattern.category == SecretCategory.GENERIC_SECRET:
            confidence -= 0.2

        return max(0.0, min(1.0, confidence))

    def should_skip_file(self, file_path: Path) -> bool:
        """Determine if a file should be skipped."""
        # Check extension
        if file_path.suffix.lower() in self.DEFAULT_SKIP_EXTENSIONS:
            return True

        # Check filename
        if file_path.name in self.DEFAULT_SKIP_FILES:
            return True

        # Check additional skip patterns
        file_str = str(file_path)
        for pattern in self._compiled_skip:
            if pattern.search(file_str):
                return True

        # If include patterns specified, only scan matching files
        if self._compiled_include:
            matches_include = any(p.search(file_str) for p in self._compiled_include)
            if not matches_include:
                return True

        # Check file size (single stat call)
        try:
            size = file_path.stat().st_size
        except OSError:
            return True

        if size == 0 or size > self.max_file_size:
            return True

        return False

    def should_skip_directory(self, dir_path: Path) -> bool:
        """Determine if a directory should be skipped."""
        if dir_path.name in self.DEFAULT_SKIP_DIRECTORIES:
            return True

        dir_str = str(dir_path)
        for pattern in self._compiled_skip:
            if pattern.search(dir_str):
                return True

        return False

    def scan_line(
        self,
        line: str,
        file_path: str,
        line_number: int,
        lines: List[str],
    ) -> List[SecretMatch]:
        """Scan a single line for all patterns."""
        matches = []

        for pattern in self.pattern_db.patterns:
            match = pattern.compiled_pattern.search(line)
            if not match:
                continue

            # Get the matched value (group 1 if exists, else full match)
            matched_value = match.group(1) if match.groups() else match.group(0)

            # Check allowlist
            if matched_value in pattern.allowlist:
                continue

            # Verify entropy if required
            entropy = self.calculate_entropy(matched_value)
            if pattern.verify_entropy and entropy < pattern.min_entropy:
                continue

            # Calculate confidence
            confidence = self.calculate_confidence(pattern, matched_value, entropy)

            # Filter by minimum confidence
            if confidence < self.min_confidence:
                continue

            # Get context
            context_before = []
            context_after = []
            if self.context_lines > 0:
                start = max(0, line_number - self.context_lines - 1)
                context_before = lines[start:line_number - 1]
                end = min(len(lines), line_number + self.context_lines)
                context_after = lines[line_number:end]

            secret_match = SecretMatch(
                file_path=file_path,
                line_number=line_number,
                line_content=line,
                pattern_name=pattern.name,
                category=pattern.category,
                severity=pattern.severity,
                matched_value=matched_value,
                redacted_value=self.redact_value(matched_value),
                context_before=context_before,
                context_after=context_after,
                entropy=entropy,
                confidence=confidence,
            )
            matches.append(secret_match)

        return matches

    def scan_file(self, file_path: Path) -> List[SecretMatch]:
        """Scan a single file for secrets."""
        matches = []

        try:
            # Try to detect encoding
            content = None
            for encoding in ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']:
                try:
                    content = file_path.read_text(encoding=encoding)
                    break
                except (UnicodeDecodeError, UnicodeError):
                    continue

            if content is None:
                return matches

            lines = content.splitlines()

            for line_num, line in enumerate(lines, start=1):
                line_matches = self.scan_line(line, str(file_path), line_num, lines)
                matches.extend(line_matches)

        except Exception:
            # Don't crash on individual file errors
            pass

        return matches

    def scan_path(self, path: Path, follow_symlinks: bool = False) -> ScanResult:
        """Scan a file or directory for secrets."""
        result = ScanResult(
            scan_path=str(path),
            start_time=datetime.now(),
        )

        path = path.resolve()

        if path.is_file():
            if not self.should_skip_file(path):
                matches = self.scan_file(path)
                result.matches.extend(matches)
                result.files_scanned = 1
            else:
                result.files_skipped = 1
                result.skipped_files.append(str(path))
        elif path.is_dir():
            self._scan_directory(path, result, follow_symlinks)
        else:
            result.errors.append(f"Path does not exist: {path}")

        result.recompute_summary()
        result.end_time = datetime.now()
        return result

    def _scan_directory(
        self,
        directory: Path,
        result: ScanResult,
        follow_symlinks: bool,
    ):
        """Recursively scan a directory."""
        try:
            entries = sorted(directory.iterdir())
        except PermissionError:
            result.errors.append(f"Permission denied: {directory}")
            return

        for entry in entries:
            if entry.is_symlink() and not follow_symlinks:
                result.files_skipped += 1
                continue

            if entry.is_file():
                if self.should_skip_file(entry):
                    result.files_skipped += 1
                    result.skipped_files.append(str(entry))
                else:
                    matches = self.scan_file(entry)
                    result.matches.extend(matches)
                    result.files_scanned += 1
            elif entry.is_dir():
                if not self.should_skip_directory(entry):
                    self._scan_directory(entry, result, follow_symlinks)
                else:
                    result.files_skipped += 1
                    result.skipped_files.append(str(entry))


# =============================================================================
# REPORTERS
# =============================================================================

class BaseReporter:
    """Base class for report output formatters."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "\033[91m",  # Red
        Severity.HIGH: "\033[93m",      # Yellow
        Severity.MEDIUM: "\033[96m",    # Cyan
        Severity.LOW: "\033[94m",       # Blue
        Severity.INFO: "\033[90m",      # Gray
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    def __init__(self, colored: bool = False):
        self.colored = colored

    def _color(self, text: str, color_code: str) -> str:
        if self.colored:
            return f"{color_code}{text}{self.RESET}"
        return text

    def _severity_text(self, severity: Severity) -> str:
        return self._color(severity.value.upper(), self.SEVERITY_COLORS[severity])


class ConsoleReporter(BaseReporter):
    """Outputs scan results to the console with colors and formatting."""

    def __init__(self, show_context: bool = True, verbose: bool = False, colored: bool = False):
        super().__init__(colored=colored)
        self.show_context = show_context
        self.verbose = verbose

    def render(self, result: ScanResult) -> str:
        """Build the full report as a string."""
        return '\n'.join(self._build_lines(result)) + '\n'

    def report(self, result: ScanResult):
        """Print a formatted report to stdout."""
        print(self.render(result), end='')

    def _build_lines(self, result: ScanResult) -> List[str]:
        out = []

        # Header
        out.append("")
        out.append(self._color("═" * 70, self.DIM))
        out.append(self._color("  SecretsFinder Pro - Scan Results", self.BOLD))
        out.append(self._color("═" * 70, self.DIM))
        out.append(f"[*]  Path:          {result.scan_path}")
        out.append(f"[*]  Started:       {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        if result.end_time:
            duration = (result.end_time - result.start_time).total_seconds()
            out.append(f"[*]  Duration:      {duration:.2f}s")

        # Summary
        out.append("")
        out.append(self._color("[*]  Summary", self.BOLD))
        out.append(self._color("  " + "─" * 30, self.DIM))
        out.append(f"[*]  Files Scanned:  {result.files_scanned}")
        out.append(f"[*]  Files Skipped:  {result.files_skipped}")

        total = result.total_matches
        if total == 0:
            total_str = self._color(str(total), "\033[92m")
        elif total < 5:
            total_str = self._color(str(total), "\033[93m")
        else:
            total_str = self._color(str(total), "\033[91m")
        out.append(f"[*]  Secrets Found:  {total_str}")

        if result.matches_by_severity:
            out.append("")
            out.append("[*]  By Severity:")
            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                count = result.matches_by_severity.get(sev.value, 0)
                if count > 0:
                    out.append(f"    {self._severity_text(sev):12} {count}")

        if result.matches_by_category and self.verbose:
            out.append("")
            out.append("[*]  By Category:")
            for cat, count in sorted(result.matches_by_category.items(), key=lambda x: -x[1]):
                out.append(f"    {cat:20} {count}")

        # Findings
        if result.matches:
            out.append("")
            out.extend(self._findings_lines(result))
        else:
            out.append("")
            out.append(self._color("[!] No secrets found!", "\033[92m"))

        # Errors
        if result.errors and self.verbose:
            out.append("")
            out.append(self._color("[!]  Errors", self.BOLD))
            for error in result.errors:
                out.append(f"    {self._color(error, '\033[91m')}")

        return out

    def _findings_lines(self, result: ScanResult) -> List[str]:
        """Build detailed findings output, grouped by file, sorted by severity."""
        out = []
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4,
        }
        sorted_matches = sorted(
            result.matches,
            key=lambda m: (severity_order.get(m.severity, 5), m.file_path, m.line_number)
        )

        current_file = None
        for match in sorted_matches:
            if match.file_path != current_file:
                current_file = match.file_path
                out.append("")
                out.append(self._color(f"  [*] {current_file}", self.BOLD))
                out.append(self._color("  " + "─" * 60, self.DIM))

            sev_badge = self._severity_text(match.severity)

            out.append(f"       {sev_badge} Line {match.line_number} | {match.pattern_name}")
            out.append(f"           {self._color(match.line_content.strip()[:100], self.DIM)}")
            out.append(f"           Matched: {match.redacted_value} "
                       f"(entropy: {match.entropy:.2f}, confidence: {match.confidence:.0%})")

            if self.show_context:
                for ctx_line in match.context_before:
                    out.append(f"           {self._color(ctx_line.strip()[:90], self.DIM)}")
                for ctx_line in match.context_after:
                    out.append(f"           {self._color(ctx_line.strip()[:90], self.DIM)}")

            out.append("")

        return out


class JsonReporter(BaseReporter):
    """Outputs scan results as JSON."""

    def render(self, result: ScanResult, pretty: bool = True) -> str:
        indent = 2 if pretty else None
        return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)

    def report(self, result: ScanResult, pretty: bool = True):
        print(self.render(result, pretty))


class SarifReporter(BaseReporter):
    """Outputs scan results in SARIF 2.1.0 format for CI/CD integration."""

    SEVERITY_TO_LEVEL = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }

    @staticmethod
    def _rule_id(name: str) -> str:
        return "SF-" + re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')

    def render(self, result: ScanResult) -> str:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecretsFinder Pro",
                            "version": __version__,
                            "rules": self._generate_rules(result),
                        }
                    },
                    "results": self._generate_results(result),
                }
            ]
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def report(self, result: ScanResult):
        print(self.render(result))

    def _generate_rules(self, result: ScanResult) -> List[dict]:
        rules, seen = [], set()
        for m in result.matches:
            if m.pattern_name in seen:
                continue
            seen.add(m.pattern_name)
            rules.append({
                "id": self._rule_id(m.pattern_name),
                "name": m.pattern_name,
                "shortDescription": {"text": m.pattern_name},
                "properties": {
                    "category": m.category.value,
                    "severity": m.severity.value,
                },
                "defaultConfiguration": {
                    "level": self.SEVERITY_TO_LEVEL.get(m.severity, "note"),
                },
            })
        return rules

    def _generate_results(self, result: ScanResult) -> List[dict]:
        return [
            {
                "ruleId": self._rule_id(m.pattern_name),
                "level": self.SEVERITY_TO_LEVEL.get(m.severity, "note"),
                "message": {"text": f"{m.pattern_name} detected (confidence: {m.confidence:.0%})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": Path(m.file_path).as_posix()},
                            "region": {"startLine": m.line_number},
                        }
                    }
                ],
            }
            for m in result.matches
        ]


class HtmlReporter(BaseReporter):
    """Renders scan results as a standalone dark-theme HTML report."""

    SEVERITY_BG = {
        Severity.CRITICAL: "#dc3545",
        Severity.HIGH: "#ffc107",
        Severity.MEDIUM: "#17a2b8",
        Severity.LOW: "#6f42c1",
        Severity.INFO: "#6c757d",
    }

    def render(self, result: ScanResult) -> str:
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4,
        }
        sorted_matches = sorted(
            result.matches,
            key=lambda m: (severity_order.get(m.severity, 5), m.file_path, m.line_number),
        )

        rows = []
        for i, m in enumerate(sorted_matches, 1):
            bg = self.SEVERITY_BG[m.severity]
            text_color = "#000" if m.severity == Severity.HIGH else "#fff"
            rows.append(f"""        <tr>
            <td>{i}</td>
            <td><span class="badge" style="background:{bg};color:{text_color}">{m.severity.value.upper()}</span></td>
            <td>{escape(m.pattern_name)}<div class="sub">{m.category.value}</div></td>
            <td class="path">{escape(m.file_path)}<div class="sub">line {m.line_number}</div></td>
            <td class="mono">{escape(m.redacted_value)}</td>
            <td>{m.entropy:.2f}</td>
            <td>{m.confidence:.0%}</td>
        </tr>""")

        if not rows:
            rows = ['        <tr><td colspan="7" class="empty">No secrets found ✓</td></tr>']

        pills = " ".join(
            f'<span class="pill" style="background:{self.SEVERITY_BG[sev]}">'
            f'{sev.value}: {result.matches_by_severity.get(sev.value, 0)}</span>'
            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            if result.matches_by_severity.get(sev.value, 0)
        )

        duration = ""
        if result.end_time:
            duration = f" | Duration: {(result.end_time - result.start_time).total_seconds():.2f}s"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecretsFinder Pro - Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee; min-height: 100vh; padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{
            text-align: center; padding: 30px;
            background: rgba(255,255,255,0.05); border-radius: 15px;
            margin-bottom: 20px;
        }}
        header h1 {{ color: #00d9ff; font-size: 2.2em; margin-bottom: 10px; }}
        header .stats {{ color: #888; font-size: 1.05em; }}
        .pills {{ text-align: center; margin-bottom: 20px; }}
        .pill {{
            display: inline-block; padding: 5px 14px; border-radius: 20px;
            margin: 0 5px; font-size: 0.85em; font-weight: 600; color: #fff;
        }}
        table {{
            width: 100%; border-collapse: collapse;
            background: rgba(255,255,255,0.03); border-radius: 10px; overflow: hidden;
        }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 0.9em; }}
        th {{ background: rgba(0,217,255,0.1); color: #00d9ff; font-weight: 600; }}
        tr:hover {{ background: rgba(0,217,255,0.05); }}
        .badge {{ display: inline-block; padding: 3px 9px; border-radius: 4px; font-size: 0.75em; font-weight: 700; }}
        .mono {{ font-family: Consolas, Monaco, monospace; word-break: break-all; color: #7bed9f; }}
        .path {{ font-family: Consolas, Monaco, monospace; word-break: break-all; color: #aaa; }}
        .sub {{ color: #666; font-size: 0.85em; }}
        .empty {{ text-align: center; padding: 40px; color: #7bed9f; }}
        footer {{ text-align: center; padding: 20px; margin-top: 25px; color: #555; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 SecretsFinder Pro</h1>
            <p class="stats">Path: {escape(result.scan_path)} | Files scanned: {result.files_scanned} | Skipped: {result.files_skipped} | Matches: {result.total_matches}{duration}</p>
            <p class="stats">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        <div class="pills">{pills}</div>
        <table>
            <thead>
                <tr>
                    <th style="width:4%">#</th>
                    <th style="width:9%">Severity</th>
                    <th style="width:17%">Pattern</th>
                    <th style="width:31%">Location</th>
                    <th style="width:25%">Matched (redacted)</th>
                    <th style="width:7%">Entropy</th>
                    <th style="width:7%">Confidence</th>
                </tr>
            </thead>
            <tbody>
{chr(10).join(rows)}
            </tbody>
        </table>
        <footer>SecretsFinder Pro v{__version__} | Values are redacted — full secrets are never written to reports</footer>
    </div>
</body>
</html>
"""


# =============================================================================
# HELPERS
# =============================================================================

def _parse_enum_list(value: str, enum_cls, option_name: str):
    """Parse a comma-separated list of enum values with validation."""
    items = set()
    for part in value.split(','):
        part = part.strip().lower()
        if not part:
            continue
        try:
            items.add(enum_cls(part))
        except ValueError:
            valid = ', '.join(e.value for e in enum_cls)
            print(f"[!] Invalid {option_name}: '{part}'. Valid values: {valid}", file=sys.stderr)
            sys.exit(1)
    return items or None


def _print_pattern_list() -> None:
    """Print all detection patterns grouped by category."""
    db = PatternDatabase()
    print(f"[*] SecretsFinder Pro v{__version__} — {len(db.patterns)} detection patterns\n")

    by_cat = defaultdict(list)
    for p in db.patterns:
        by_cat[p.category].append(p)

    for cat in SecretCategory:
        pats = by_cat.get(cat)
        if not pats:
            continue
        print(f"=== {cat.value.upper().replace('_', ' ')} ({len(pats)}) ===")
        for p in pats:
            print(f"  [{p.severity.value.upper():8}] {p.name}")
            print(f"             {p.description}")
        print()


# =============================================================================
# RUNNER
# =============================================================================

def run_from_args(args: argparse.Namespace) -> None:
    """Run a single scan based on parsed CLI arguments."""
    if getattr(args, 'list_patterns', False):
        _print_pattern_list()
        return

    target = args.path or args.input_target

    if not target:
        print("[!] No target provided. Use -p/--path or pass a path directly.")
        print("[!] Run 'python secretsfinder.py -h' for help.")
        sys.exit(1)

    # Parse severity/category filters (validated)
    severities = _parse_enum_list(args.severity, Severity, 'severity') if args.severity else None
    categories = _parse_enum_list(args.category, SecretCategory, 'category') if args.category else None

    pattern_db = PatternDatabase()

    scanner = SecretsScanner(
        pattern_db=pattern_db,
        context_lines=0 if args.no_context else args.context,
        min_confidence=max(0.0, min(1.0, args.min_confidence)),
        additional_skip_patterns=args.exclude,
        additional_include_patterns=args.include,
        max_file_size_mb=args.max_file_size,
    )

    path = Path(target)
    if not path.exists():
        print(f"[!] Path does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] SecretsFinder Pro v{__version__}")
    print(f"[*] Scanning: {path.resolve()}")
    print(f"[*] Patterns loaded: {len(pattern_db.patterns)}")
    print("=" * 50)

    try:
        result = scanner.scan_path(path, follow_symlinks=args.follow_symlinks)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)

    # Post-scan filtering
    if severities:
        result.matches = [m for m in result.matches if m.severity in severities]
    if categories:
        result.matches = [m for m in result.matches if m.category in categories]
    if severities or categories:
        result.recompute_summary()

    # ------------------------------------------------------------------
    # Determine output format
    # ------------------------------------------------------------------
    fmt = args.format
    if not fmt and args.output:
        lower = args.output.lower()
        if lower.endswith('.json'):
            fmt = 'json'
        elif lower.endswith('.sarif'):
            fmt = 'sarif'
        elif lower.endswith(('.html', '.htm')):
            fmt = 'html'
        elif lower.endswith('.txt'):
            fmt = 'console'
    if not fmt:
        fmt = 'console'

    show_context = (not args.no_context) and args.context > 0

    if fmt == 'json':
        content = JsonReporter().render(result)
    elif fmt == 'sarif':
        content = SarifReporter().render(result)
    elif fmt == 'html':
        content = HtmlReporter().render(result)
    else:
        content = ConsoleReporter(
            show_context=show_context,
            verbose=args.verbose,
            colored=False,
        ).render(result)

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"\n[+] Report saved to {args.output}")
        except IOError as e:
            print(f"[!] Error writing to file: {e}", file=sys.stderr)
            sys.exit(1)

        # Short console summary
        print(f"[+] Files scanned: {result.files_scanned} | "
              f"Files skipped: {result.files_skipped} | "
              f"Secrets found: {result.total_matches}")
        if result.matches_by_severity:
            breakdown = ', '.join(f"{sev}={cnt}" for sev, cnt in result.matches_by_severity.items())
            print(f"[*] By severity: {breakdown}")
    else:
        if fmt == 'console':
            ConsoleReporter(
                show_context=show_context,
                verbose=args.verbose,
                colored=sys.stdout.isatty(),
            ).report(result)
        else:
            print(content)


# =============================================================================
# INTERACTIVE MODE (optional, legacy behaviour)
# =============================================================================

def run_interactive_loop() -> None:
    parser = create_parser()
    print("\n[-] SecretsFinder Pro interactive mode")
    print("[-] Type 'help' for usage or 'exit' to quit.")
    print("[-] Examples:")
    print("[-]   .")
    print("[-]   /path/to/project -o report.json")
    print("[-]   . --severity critical,high")

    while True:
        try:
            command = input("secretsfinder> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Goodbye!")
            break

        if not command:
            continue

        if command.lower() in {'exit', 'quit'}:
            print("[!] Exiting SecretsFinder.")
            break

        if command.lower() in {'help', '?'}:
            parser.print_help()
            continue

        try:
            tokens = shlex.split(command)
        except ValueError as exc:
            print(f"[!][ERROR] Invalid input: {exc}")
            continue

        try:
            parsed_args = parser.parse_args(tokens)
        except SystemExit:
            continue

        if parsed_args.list_patterns:
            _print_pattern_list()
            continue

        try:
            run_from_args(parsed_args)
        except SystemExit:
            # keep the interactive loop alive after errors
            pass


# =============================================================================
# ENTRY POINT
# =============================================================================

def main(argv=None) -> None:
    parser = create_parser()

    if argv is None:
        argv = sys.argv[1:]
    elif isinstance(argv, str):
        argv = shlex.split(argv)

    # No arguments at all → print help and exit with error code
    if not argv:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args(argv)

    if args.list_patterns:
        _print_pattern_list()
        return

    has_target = bool(args.path or args.input_target)

    # Enter interactive mode only with -i and no target
    if args.interactive and not has_target:
        run_interactive_loop()
        return

    if not has_target:
        print("[!] No target provided.\n")
        parser.print_help()
        sys.exit(1)

    run_from_args(args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)