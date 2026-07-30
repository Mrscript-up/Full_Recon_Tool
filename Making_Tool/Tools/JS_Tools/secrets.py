# Madules:
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
import enum
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


print('[-] run secrets finder')

#!/usr/bin/env python3
"""
SecretsFinder Pro - Personal Secrets Detection Tool

A defensive security tool to identify accidentally exposed credentials,
API keys, tokens, and other sensitive data in codebases.

Author: Mrscript
Version: 2.0.0
"""

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
                description="GitHub Personal Access Token",
                example_redacted="ghp_************************************",
            ),
            SecretPattern(
                name="GitHub OAuth Access Token",
                pattern=r'gho_[A-Za-z0-9_]{36,255}',
                category=SecretCategory.API_KEY,
                severity=Severity.CRITICAL,
                description="GitHub OAuth Access Token",
                example_redacted="gho_************************************",
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
                description="DigitalOcean API Token v1",
                example_redacted="dop_v1_****************************************************************",
            ),
            SecretPattern(
                name="DigitalOcean PAT",
                pattern=r'dop_v1_[a-f0-9]{64}',
                category=SecretCategory.CLOUD,
                severity=Severity.HIGH,
                description="DigitalOcean Personal Access Token",
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
                example_redacted="\"****************************************\"\"",
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
        'dist', 'build', '.tox', '.eggs', '*.egg-info',
        '.mypy_cache', '.pytest_cache', '.ruff_cache',
        'vendor', '.bundle', 'coverage',
    })

    DEFAULT_SKIP_FILES = frozenset({
        'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
        'Cargo.lock', 'go.sum', 'composer.lock',
        '.gitmodules', '.gitattributes',
    })

    # Maximum file size to scan (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def __init__(
        self,
        pattern_db: PatternDatabase,
        context_lines: int = 2,
        min_confidence: float = 0.0,
        additional_skip_patterns: List[str] = None,
        additional_include_patterns: List[str] = None,
    ):
        self.pattern_db = pattern_db
        self.context_lines = context_lines
        self.min_confidence = min_confidence
        self.additional_skip_patterns = additional_skip_patterns or []
        self.additional_include_patterns = additional_include_patterns or []
        self._compiled_skip = [re.compile(p) for p in self.additional_skip_patterns]
        self._compiled_include = [re.compile(p) for p in self.additional_include_patterns]

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        
        # Count character frequencies
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
        
        # Check file size
        try:
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                return True
            if file_path.stat().st_size == 0:
                return True
        except OSError:
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
                
        except Exception as e:
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
        
        # Calculate summary stats
        result.total_matches = len(result.matches)
        for match in result.matches:
            sev = match.severity.value
            cat = match.category.value
            result.matches_by_severity[sev] = result.matches_by_severity.get(sev, 0) + 1
            result.matches_by_category[cat] = result.matches_by_category.get(cat, 0) + 1
        
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
    
    def _color(self, text: str, color_code: str) -> str:
        if sys.stdout.isatty():
            return f"{color_code}{text}{self.RESET}"
        return text
    
    def _severity_text(self, severity: Severity) -> str:
        return self._color(severity.value.upper(), self.SEVERITY_COLORS[severity])


class ConsoleReporter(BaseReporter):
    """Outputs scan results to the console with colors and formatting."""
    
    def __init__(self, show_context: bool = True, verbose: bool = False):
        self.show_context = show_context
        self.verbose = verbose
    
    def report(self, result: ScanResult):
        """Print a formatted report to stdout."""
        self._print_header(result)
        self._print_summary(result)
        
        if result.matches:
            print()
            self._print_findings(result)
        else:
            print()
            print(self._color("[!] No secrets found!", "\033[92m"))
        
        if result.errors and self.verbose:
            print()
            self._print_errors(result)
    
    def _print_header(self, result: ScanResult):
        """Print scan header."""
        print()
        print(self._color("═" * 70, self.DIM))
        print(self._color("  SecretsFinder Pro - Scan Results", self.BOLD))
        print(self._color("═" * 70, self.DIM))
        print(f"[*]  Path:          {result.scan_path}")
        print(f"[*]  Started:       {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        if result.end_time:
            duration = (result.end_time - result.start_time).total_seconds()
            print(f"[*]  Duration:      {duration:.2f}s")
    
    def _print_summary(self, result: ScanResult):
        """Print scan summary."""
        print()
        print(self._color("[*]  Summary", self.BOLD))
        print(self._color("  " + "─" * 30, self.DIM))
        print(f"[*]  Files Scanned:  {result.files_scanned}")
        print(f"[*]  Files Skipped:  {result.files_skipped}")
        
        # Color-code total matches
        total = result.total_matches
        if total == 0:
            total_str = self._color(str(total), "\033[92m")
        elif total < 5:
            total_str = self._color(str(total), "\033[93m")
        else:
            total_str = self._color(str(total), "\033[91m")
        print(f"[**]  Secrets Found:  {total_str}")
        
        # By severity
        if result.matches_by_severity:
            print()
            print(f"[*]  By Severity:")
            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                count = result.matches_by_severity.get(sev.value, 0)
                if count > 0:
                    print(f"    {self._severity_text(sev):12} {count}")
        
        # By category
        if result.matches_by_category and self.verbose:
            print()
            print(f"[*]  By Category:")
            for cat, count in sorted(result.matches_by_category.items(), key=lambda x: -x[1]):
                print(f"    {cat:20} {count}")
    
    def _print_findings(self, result: ScanResult):
        """Print detailed findings."""
        # Sort by severity (critical first), then file, then line
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        sorted_matches = sorted(
            result.matches,
            key=lambda m: (severity_order.get(m.severity, 5), m.file_path, m.line_number)
        )
        
        # Group by file
        current_file = None
        for match in sorted_matches:
            if match.file_path != current_file:
                current_file = match.file_path
                print()
                print(self._color(f"  [*] {current_file}", self.BOLD))
                print(self._color("  " + "─" * 60, self.DIM))
            
            # Severity badge
            sev_badge = self._severity_text(match.severity)
            
            # Line info
            print(f"[*]    {sev_badge} Line {match.line_number} | {match.pattern_name}")
            print(f"[*]        {self._color(match.line_content.strip()[:100], self.DIM)}")
            print(f"[*]         Matched: {match.redacted_value} (entropy: {match.entropy:.2f}, confidence: {match.confidence:.0%})")
            
            # Context
            if self.show_context:
                for ctx_line in match.context_before:
                    print(f"           {self._color(ctx_line.strip()[:90], self.DIM)}")
                for ctx_line in match.context_after:
                    print(f"           {self._color(ctx_line.strip()[:90], self.DIM)}")
            
            print()
    
    def _print_errors(self, result: ScanResult):
        """Print any errors encountered."""
        print(self._color("[!]  Errors", self.BOLD))
        for error in result.errors:
            print(f"    {self._color(error, '\033[91m')}")


class JsonReporter(BaseReporter):
    """Outputs scan results as JSON."""
    
    def report(self, result: ScanResult, pretty: bool = True):
        """Output JSON report."""
        indent = 2 if pretty else None
        output = json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)
        print(output)


class SarifReporter(BaseReporter):
    """Outputs scan results in SARIF format for CI/CD integration."""
    
    def report(self, result: ScanResult):
        """Output SARIF report."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecretsFinder Pro",
                            "version": "2.0.0",
                            "rules": self._generate_rules(result),
                        }
                    },
                    "results": self._generate_results(result),
                }
            ]
        }
        print(json.dumps(sarif, indent=2))
    
    def _generate_rules(self, result: ScanResult) -> list:
        """Generate SARIF rules from patterns used in matches."""
        rules = {}
        for match in result.matches:
            if match.pattern_name not in rules:
                severity_map = {
                    Severity.CRITICAL: "error",
                    Severity.HIGH: "error",
                    Severity.MEDIUM: "warning",
                    Severity.LOW: "note",
                    Severity.INFO: "note",
                }
                rules[match.pattern_name] = {
                    "id": match.pattern_name.replace(" ", "-").lower(),
                    "name": match.pattern_name,
                    "shortDescription": {"text": match.pattern_name},
                    "defaultConfiguration": {
                        "level": severity_map.get(match.severity, "warning")
                    },
                    "properties": {
                        "category": match.category.value,
                    }
                }
        return list(rules.values())
    
    def _generate_results(self, result: ScanResult) -> list:
        """Generate SARIF results from matches."""
        results = []
        for match in result.matches:
            result_entry = {
                "ruleId": match.pattern_name.replace(" ", "-").lower(),
                "level": {
                    Severity.CRITICAL: "error",
                    Severity.HIGH: "error",
                    Severity.MEDIUM: "warning",
                    Severity.LOW: "note",
                    Severity.INFO: "note",
                }.get(match.severity, "warning"),
                "message": {
                    "text": f"Potential {match.category.value} found: {match.pattern_name}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": match.file_path},
                            "region": {
                                "startLine": match.line_number,
                                "startColumn": 1,
                            }
                        }
                    }
                ],
                "properties": {
                    "matchedValue": match.redacted_value,
                    "entropy": match.entropy,
                    "confidence": match.confidence,
                }
            }
            results.append(result_entry)
        return results


# =============================================================================
# GITIGNORE PARSER
# =============================================================================

class GitignoreParser:
    """Parse .gitignore files to get additional skip patterns."""
    
    def __init__(self, gitignore_path: Path = None):
        self.patterns: List[str] = []
        if gitignore_path and gitignore_path.exists():
            self._parse(gitignore_path)
    
    def _parse(self, path: Path):
        """Parse a .gitignore file."""
        try:
            content = path.read_text(encoding='utf-8')
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Convert gitignore pattern to regex
                pattern = self._gitignore_to_regex(line)
                if pattern:
                    self.patterns.append(pattern)
        except Exception:
            pass
    
    def _gitignore_to_regex(self, pattern: str) -> Optional[str]:
        """Convert a gitignore pattern to a regex pattern."""
        # Handle negation
        if pattern.startswith('!'):
            return None  # Skip negation patterns for simplicity
        
        # Handle directory markers
        if pattern.endswith('/'):
            pattern = pattern[:-1]
        
        # Escape special regex chars except * and ?
        pattern = re.escape(pattern)
        pattern = pattern.replace(r'\*', '.*').replace(r'\?', '.')
        
        return pattern


# =============================================================================
# MAIN CLI
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog='secrets_finder',
        description='SecretsFinder Pro - Detect accidentally exposed secrets in your codebase',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
%(prog)s .                                    Scan current directory
%(prog)s /path/to/project                     Scan specific directory
%(prog)s src/ --severity critical,high        Only show critical and high
%(prog)s . --json > report.json               Output as JSON
%(prog)s . --sarif > results.sarif            Output as SARIF for CI/CD
%(prog)s . --no-context                       Hide context lines
%(prog)s . --min-confidence 0.7               Only show high-confidence matches
%(prog)s . --skip "test_.*\\.py"              Skip test files
%(prog)s . --include "\\.py$|\\.js$"           Only scan Python and JS files

Severity Levels:
critical  - Immediate credential exposure (API keys, private keys, passwords)
high      - Likely credential exposure (tokens, connection strings)
medium    - Possible credential exposure (generic secrets, publishable keys)
low       - Low confidence matches (high entropy strings)
info      - Informational findings
        """,
    )
    
    parser.add_argument(
        'path',
        type=str,
        nargs='?',
        default='.',
        help='Path to file or directory to scan (default: current directory)'
    )
    
    # Output format
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )
    output_group.add_argument(
        '--sarif',
        action='store_true',
        help='Output results in SARIF format (for CI/CD integration)'
    )
    output_group.add_argument(
        '--no-context',
        action='store_true',
        help='Do not show context lines around matches'
    )
    output_group.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress all output except errors'
    )
    output_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show verbose output including categories and errors'
    )
    
    # Filtering
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument(
        '--severity',
        type=str,
        default=None,
        help='Comma-separated list of severities to include (e.g., "critical,high")'
    )
    filter_group.add_argument(
        '--category',
        type=str,
        default=None,
        help='Comma-separated list of categories to include (e.g., "api_key,private_key")'
    )
    filter_group.add_argument(
        '--min-confidence',
        type=float,
        default=0.0,
        help='Minimum confidence threshold (0.0 to 1.0, default: 0.0)'
    )
    
    # File selection
    file_group = parser.add_argument_group('File Selection')
    file_group.add_argument(
        '--skip',
        type=str,
        action='append',
        default=[],
        help='Regex pattern for files/dirs to skip (can be used multiple times)'
    )
    file_group.add_argument(
        '--include',
        type=str,
        action='append',
        default=[],
        help='Regex pattern for files to include (can be used multiple times)'
    )
    file_group.add_argument(
        '--follow-symlinks',
        action='store_true',
        help='Follow symbolic links when scanning directories'
    )
    file_group.add_argument(
        '--use-gitignore',
        action='store_true',
        help='Respect .gitignore patterns'
    )
    file_group.add_argument(
        '--context-lines',
        type=int,
        default=2,
        help='Number of context lines to show around matches (default: 2)'
    )
    
    # List options
    list_group = parser.add_argument_group('Information Options')
    list_group.add_argument(
        '--list-patterns',
        action='store_true',
        help='List all detection patterns and exit'
    )
    list_group.add_argument(
        '--list-severities',
        action='store_true',
        help='List all severity levels and exit'
    )
    list_group.add_argument(
        '--list-categories',
        action='store_true',
        help='List all secret categories and exit'
    )
    
    return parser


def parse_severity_filter(severity_str: str) -> Optional[Set[Severity]]:
    """Parse comma-separated severity string into a set."""
    if not severity_str:
        return None
    
    severities = set()
    for s in severity_str.split(','):
        s = s.strip().lower()
        try:
            severities.add(Severity(s))
        except ValueError:
            print(f"[!] Warning: Unknown severity level '{s}'", file=sys.stderr)
    return severities if severities else None


def parse_category_filter(category_str: str) -> Optional[Set[SecretCategory]]:
    """Parse comma-separated category string into a set."""
    if not category_str:
        return None
    
    categories = set()
    for c in category_str.split(','):
        c = c.strip().lower()
        try:
            categories.add(SecretCategory(c))
        except ValueError:
            print(f"[!] Warning: Unknown category '{c}'", file=sys.stderr)
    return categories if categories else None


def filter_results(
    result: ScanResult,
    severities: Optional[Set[Severity]] = None,
    categories: Optional[Set[SecretCategory]] = None,
) -> ScanResult:
    """Filter scan results by severity and/or category."""
    if not severities and not categories:
        return result
    
    filtered_matches = []
    for match in result.matches:
        if severities and match.severity not in severities:
            continue
        if categories and match.category not in categories:
            continue
        filtered_matches.append(match)
    
    # Recreate result with filtered matches
    filtered_result = ScanResult(
        scan_path=result.scan_path,
        start_time=result.start_time,
        end_time=result.end_time,
        files_scanned=result.files_scanned,
        files_skipped=result.files_skipped,
        skipped_files=result.skipped_files,
        errors=result.errors,
        matches=filtered_matches,
    )
    
    # Recalculate stats
    filtered_result.total_matches = len(filtered_matches)
    for match in filtered_matches:
        sev = match.severity.value
        cat = match.category.value
        filtered_result.matches_by_severity[sev] = filtered_result.matches_by_severity.get(sev, 0) + 1
        filtered_result.matches_by_category[cat] = filtered_result.matches_by_category.get(cat, 0) + 1
    
    return filtered_result


def list_patterns(pattern_db: PatternDatabase):
    """Print all detection patterns."""
    print("\n" + "=" * 80)
    print("  SecretsFinder Pro - Detection Patterns")
    print("=" * 80)
    
    # Group by category
    by_category = defaultdict(list)
    for p in pattern_db.patterns:
        by_category[p.category].append(p)
    
    for category, patterns in by_category.items():
        print(f"\n  {category.value.upper().replace('_', ' ')}")
        print("  " + "-" * 60)
        for p in patterns:
            sev_color = {
                Severity.CRITICAL: "\033[91m",
                Severity.HIGH: "\033[93m",
                Severity.MEDIUM: "\033[96m",
                Severity.LOW: "\033[94m",
                Severity.INFO: "\033[90m",
            }.get(p.severity, "")
            reset = "\033[0m"
            print(f"    • {p.name}")
            print(f"      {sev_color}{p.severity.value.upper()}{reset} | {p.description}")
            print(f"      Example: {p.example_redacted}")
            print(f"      Pattern: {p.pattern[:80]}{'...' if len(p.pattern) > 80 else ''}")
            if p.verify_entropy:
                print(f"      Entropy check: min={p.min_entropy}")
            print()


def run_from_args(args):
    """Run the secrets scanner from a parsed argument namespace."""
    pattern_db = PatternDatabase()

    if args.list_patterns:
        list_patterns(pattern_db)
        return 0

    if args.list_severities:
        print("\n[-] Severity Levels:")
        for sev in Severity:
            print(f"  • {sev.value.upper():12} - {sev.name}")
        return 0

    if args.list_categories:
        print("\n[-] Secret Categories:")
        for cat in SecretCategory:
            print(f"  • {cat.value:20} - {cat.name.replace('_', ' ')}")
        return 0

    scan_path = Path(args.path)
    if not scan_path.exists():
        print(f"[-] Error: Path does not exist: {args.path}", file=sys.stderr)
        return 1

    skip_patterns = list(args.skip)
    if args.use_gitignore:
        gitignore_path = scan_path / '.gitignore' if scan_path.is_dir() else scan_path.parent / '.gitignore'
        gitignore_parser = GitignoreParser(gitignore_path)
        skip_patterns.extend(gitignore_parser.patterns)

    scanner = SecretsScanner(
        pattern_db=pattern_db,
        context_lines=args.context_lines,
        min_confidence=args.min_confidence,
        additional_skip_patterns=skip_patterns,
        additional_include_patterns=args.include,
    )

    result = scanner.scan_path(scan_path, follow_symlinks=args.follow_symlinks)

    severity_filter = parse_severity_filter(args.severity)
    category_filter = parse_category_filter(args.category)
    result = filter_results(result, severity_filter, category_filter)

    if args.quiet:
        pass
    elif args.sarif:
        reporter = SarifReporter()
        reporter.report(result)
    elif args.json:
        reporter = JsonReporter()
        reporter.report(result, pretty=True)
    else:
        reporter = ConsoleReporter(
            show_context=not args.no_context,
            verbose=args.verbose,
        )
        reporter.report(result)

    critical_high = sum(
        result.matches_by_severity.get(s.value, 0)
        for s in [Severity.CRITICAL, Severity.HIGH]
    )

    return 1 if critical_high > 0 else 0


def run_interactive_loop(initial_input=None):
    parser = create_parser()
    print("\n[-] SecretsFinder interactive mode")
    print("[-] Type 'help' for usage or 'exit' to quit.")
    print("[-] Examples:")
    print("[-]  .")
    print("[-]  ./src")
    print("[-]  . --severity critical,high")

    while True:
        if initial_input is not None:
            command = str(initial_input).strip()
            initial_input = None
            print(f"[-] secrets> {command}")
        else:
            try:
                command = input("secrets> ").strip()
            except KeyboardInterrupt:
                print("\n[!] Goodbye!")
                break
            except EOFError:
                print("\n[!] Goodbye!")
                break

        if not command:
            continue

        if command.lower() in {"exit", "quit"}:
            print("[!] Exiting SecretsFinder.")
            break

        if command.lower() in {"help", "?"}:
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

        run_from_args(parsed_args)

    return 0


def run_secrets_tool(args=None):
    if args is None:
        return run_interactive_loop()

    if isinstance(args, str):
        return run_interactive_loop(initial_input=args)

    if isinstance(args, (list, tuple)):
        return run_from_args(create_parser().parse_args(list(args)))

    return run_from_args(args)


def main(argv=None):
    if argv is None:
        return run_secrets_tool(None)

    if isinstance(argv, str):
        return run_secrets_tool(argv)

    return run_from_args(create_parser().parse_args(argv))


if __name__ == '__main__':
    sys.exit(main())

else:
    print('[!] unknow option\nplease select right option.')

