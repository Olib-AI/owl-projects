"""
Deep Sniff Analyzer.

Advanced network traffic and content analysis for exposed credentials,
API keys, secrets in JavaScript files, API responses, and configuration leaks.

Implements entropy-based validation to reduce false positives and provides
comprehensive coverage across multiple secret types and exposure vectors.
"""

from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity

if TYPE_CHECKING:
    from collections.abc import Iterator


class SecretCategory(StrEnum):
    """Categories of secrets for classification."""

    API_KEY = "api_key"
    JWT_TOKEN = "jwt_token"
    DATABASE_CREDENTIAL = "database_credential"
    PRIVATE_KEY = "private_key"
    GENERIC_SECRET = "generic_secret"
    ENVIRONMENT_LEAK = "environment_leak"
    BEARER_TOKEN = "bearer_token"


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """Immutable secret detection pattern with metadata."""

    name: str
    pattern: str
    category: SecretCategory
    severity: Severity
    cwe_id: str
    cwe_name: str
    cvss_score: float
    min_entropy: float = 3.5
    requires_context: bool = False


@dataclass(slots=True)
class DetectedSecret:
    """Represents a detected secret with context."""

    pattern: SecretPattern
    matched_value: str
    context: str
    source: str
    entropy: float
    confidence: float
    is_decoded: bool = False
    decoded_content: str = ""


class DeepSniffAnalyzer(BaseAnalyzer):
    """
    Advanced secret detection analyzer.

    Performs deep inspection of:
    - Network requests/responses for exposed credentials
    - JavaScript files for hardcoded API keys and secrets
    - API responses for sensitive field exposure
    - Environment variable leaks
    - Database connection strings with credentials
    - Private key material exposure
    - JWT token analysis with claim inspection

    Uses Shannon entropy calculation to reduce false positives
    by filtering out low-entropy matches that are unlikely to be secrets.
    """

    analyzer_type = AnalyzerType.DEEP_SNIFF

    # Minimum entropy thresholds by category
    ENTROPY_THRESHOLDS: Final[dict[SecretCategory, float]] = {
        SecretCategory.API_KEY: 3.5,
        SecretCategory.JWT_TOKEN: 4.0,
        SecretCategory.DATABASE_CREDENTIAL: 3.0,
        SecretCategory.PRIVATE_KEY: 4.5,
        SecretCategory.GENERIC_SECRET: 4.0,
        SecretCategory.ENVIRONMENT_LEAK: 3.0,
        SecretCategory.BEARER_TOKEN: 3.5,
    }

    # Comprehensive secret patterns with full metadata
    SECRET_PATTERNS: Final[tuple[SecretPattern, ...]] = (
        # AWS Credentials
        SecretPattern(
            name="AWS Access Key ID",
            pattern=r"AKIA[0-9A-Z]{16}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.8,
            min_entropy=3.5,
        ),
        SecretPattern(
            name="AWS Secret Access Key",
            pattern=r"(?:aws_secret_access_key|AWS_SECRET_KEY|aws_secret|secret_access_key|SecretAccessKey)"
            r'[\s:=]+[\'"]?([0-9a-zA-Z/+]{40})[\'"]?',
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.8,
            min_entropy=4.0,
            requires_context=True,
        ),
        # Google API Key
        SecretPattern(
            name="Google API Key",
            pattern=r"AIza[0-9A-Za-z_-]{35}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.0,
        ),
        # Stripe Keys
        SecretPattern(
            name="Stripe Secret Key",
            pattern=r"sk_live_[0-9a-zA-Z]{24,}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.8,
            min_entropy=3.5,
        ),
        SecretPattern(
            name="Stripe Publishable Key",
            pattern=r"pk_live_[0-9a-zA-Z]{24,}",
            category=SecretCategory.API_KEY,
            severity=Severity.MEDIUM,
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information",
            cvss_score=5.3,
            min_entropy=3.5,
        ),
        SecretPattern(
            name="Stripe Test Secret Key",
            pattern=r"sk_test_[0-9a-zA-Z]{24,}",
            category=SecretCategory.API_KEY,
            severity=Severity.MEDIUM,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=5.3,
            min_entropy=3.5,
        ),
        # GitHub Tokens
        SecretPattern(
            name="GitHub Personal Access Token",
            pattern=r"ghp_[0-9a-zA-Z]{36}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1,
            min_entropy=4.0,
        ),
        SecretPattern(
            name="GitHub OAuth Access Token",
            pattern=r"gho_[0-9a-zA-Z]{36}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1,
            min_entropy=4.0,
        ),
        SecretPattern(
            name="GitHub App Token",
            pattern=r"ghu_[0-9a-zA-Z]{36}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1,
            min_entropy=4.0,
        ),
        SecretPattern(
            name="GitHub Refresh Token",
            pattern=r"ghr_[0-9a-zA-Z]{36}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1,
            min_entropy=4.0,
        ),
        SecretPattern(
            name="GitHub Server Token",
            pattern=r"ghs_[0-9a-zA-Z]{36}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1,
            min_entropy=4.0,
        ),
        # Slack Tokens
        SecretPattern(
            name="Slack Bot Token",
            pattern=r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=3.5,
        ),
        SecretPattern(
            name="Slack App Token",
            pattern=r"xoxa-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=3.5,
        ),
        SecretPattern(
            name="Slack User Token",
            pattern=r"xoxp-[0-9]{10,13}-[0-9]{10,13}(-[0-9]{10,13})?-[a-zA-Z0-9]{32}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=3.5,
        ),
        SecretPattern(
            name="Slack Refresh Token",
            pattern=r"xoxr-[0-9]{10,48}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=3.0,
        ),
        SecretPattern(
            name="Slack Legacy Token",
            pattern=r"xoxs-[0-9]{10,48}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=3.0,
        ),
        SecretPattern(
            name="Slack Webhook URL",
            pattern=r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[a-zA-Z0-9]{24}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=3.0,
        ),
        # Firebase
        SecretPattern(
            name="Firebase Server Key",
            pattern=r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.5,
        ),
        SecretPattern(
            name="Firebase Database URL",
            pattern=r"https://[a-z0-9-]+\.firebaseio\.com",
            category=SecretCategory.API_KEY,
            severity=Severity.MEDIUM,
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information",
            cvss_score=5.3,
            min_entropy=2.0,
        ),
        # Azure
        SecretPattern(
            name="Azure Storage Account Key",
            pattern=r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.8,
            min_entropy=4.5,
        ),
        SecretPattern(
            name="Azure Shared Access Signature",
            pattern=r"sv=\d{4}-\d{2}-\d{2}&s[a-z]=\w+&s[a-z]{2}=[^&]+&sig=[A-Za-z0-9%+/=]+",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.0,
        ),
        SecretPattern(
            name="Azure AD Client Secret",
            pattern=r"(?:client_secret|clientSecret|AZURE_CLIENT_SECRET)[\s:=]+['\"]?([a-zA-Z0-9_~.-]{34,})['\"]?",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1,
            min_entropy=4.0,
            requires_context=True,
        ),
        # Twilio
        SecretPattern(
            name="Twilio Account SID",
            pattern=r"AC[a-f0-9]{32}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.0,
        ),
        SecretPattern(
            name="Twilio Auth Token",
            pattern=r"(?:TWILIO_AUTH_TOKEN|twilio_auth_token|auth_token)[\s:=]+['\"]?([a-f0-9]{32})['\"]?",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1,
            min_entropy=4.0,
            requires_context=True,
        ),
        # SendGrid
        SecretPattern(
            name="SendGrid API Key",
            pattern=r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.5,
        ),
        # Mailgun
        SecretPattern(
            name="Mailgun API Key",
            pattern=r"key-[a-f0-9]{32}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.0,
        ),
        SecretPattern(
            name="Mailgun Private API Key",
            pattern=r"(?:MAILGUN_API_KEY|mailgun_api_key)[\s:=]+['\"]?([a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8})['\"]?",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.0,
            requires_context=True,
        ),
        # JWT Tokens
        SecretPattern(
            name="JWT Token",
            pattern=r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            category=SecretCategory.JWT_TOKEN,
            severity=Severity.HIGH,
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information",
            cvss_score=7.5,
            min_entropy=4.0,
        ),
        # Database Connection Strings
        SecretPattern(
            name="PostgreSQL Connection String",
            pattern=r"postgres(?:ql)?://([^:]+):([^@]+)@([^/:]+)(?::\d+)?/\w+",
            category=SecretCategory.DATABASE_CREDENTIAL,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.8,
            min_entropy=3.0,
        ),
        SecretPattern(
            name="MySQL Connection String",
            pattern=r"mysql://([^:]+):([^@]+)@([^/:]+)(?::\d+)?/\w+",
            category=SecretCategory.DATABASE_CREDENTIAL,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.8,
            min_entropy=3.0,
        ),
        SecretPattern(
            name="MongoDB Connection String",
            pattern=r"mongodb(?:\+srv)?://([^:]+):([^@]+)@([^/]+)/?\w*",
            category=SecretCategory.DATABASE_CREDENTIAL,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.8,
            min_entropy=3.0,
        ),
        SecretPattern(
            name="Redis Connection String",
            pattern=r"redis://(?:([^:]+):)?([^@]+)@([^/:]+)(?::\d+)?",
            category=SecretCategory.DATABASE_CREDENTIAL,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=3.0,
        ),
        SecretPattern(
            name="JDBC Connection String",
            pattern=r"jdbc:(?:mysql|postgresql|oracle|sqlserver)://[^?]+\?.*(?:user|password)=[^&]+",
            category=SecretCategory.DATABASE_CREDENTIAL,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.8,
            min_entropy=3.0,
        ),
        # Private Keys
        SecretPattern(
            name="RSA Private Key",
            pattern=r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
            category=SecretCategory.PRIVATE_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-321",
            cwe_name="Use of Hard-coded Cryptographic Key",
            cvss_score=9.8,
            min_entropy=4.5,
        ),
        SecretPattern(
            name="OpenSSH Private Key",
            pattern=r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
            category=SecretCategory.PRIVATE_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-321",
            cwe_name="Use of Hard-coded Cryptographic Key",
            cvss_score=9.8,
            min_entropy=4.5,
        ),
        SecretPattern(
            name="EC Private Key",
            pattern=r"-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----",
            category=SecretCategory.PRIVATE_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-321",
            cwe_name="Use of Hard-coded Cryptographic Key",
            cvss_score=9.8,
            min_entropy=4.5,
        ),
        SecretPattern(
            name="DSA Private Key",
            pattern=r"-----BEGIN DSA PRIVATE KEY-----[\s\S]+?-----END DSA PRIVATE KEY-----",
            category=SecretCategory.PRIVATE_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-321",
            cwe_name="Use of Hard-coded Cryptographic Key",
            cvss_score=9.8,
            min_entropy=4.5,
        ),
        SecretPattern(
            name="PGP Private Key Block",
            pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----",
            category=SecretCategory.PRIVATE_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-321",
            cwe_name="Use of Hard-coded Cryptographic Key",
            cvss_score=9.8,
            min_entropy=4.5,
        ),
        # Generic Secrets with context
        SecretPattern(
            name="API Key Assignment",
            pattern=r"(?:api[_-]?key|apikey|api[_-]?token|apiToken)[\s]*[=:][\s]*['\"]([a-zA-Z0-9_-]{20,})['\"]",
            category=SecretCategory.GENERIC_SECRET,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.0,
            requires_context=True,
        ),
        SecretPattern(
            name="Secret Assignment",
            pattern=r"(?:secret|client_secret|clientSecret)[\s]*[=:][\s]*['\"]([a-zA-Z0-9_-]{16,})['\"]",
            category=SecretCategory.GENERIC_SECRET,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.0,
            requires_context=True,
        ),
        SecretPattern(
            name="Password Assignment",
            pattern=r"(?:password|passwd|pwd)[\s]*[=:][\s]*['\"]([^'\"]{8,})['\"]",
            category=SecretCategory.GENERIC_SECRET,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=3.5,
            requires_context=True,
        ),
        SecretPattern(
            name="Token Assignment",
            pattern=r"(?:auth_token|authToken|access_token|accessToken|bearer_token|bearerToken)"
            r"[\s]*[=:][\s]*['\"]([a-zA-Z0-9_.-]{20,})['\"]",
            category=SecretCategory.GENERIC_SECRET,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.0,
            requires_context=True,
        ),
        # Bearer Tokens
        SecretPattern(
            name="Bearer Token in Authorization",
            pattern=r"[Bb]earer\s+([a-zA-Z0-9_.-]{20,})",
            category=SecretCategory.BEARER_TOKEN,
            severity=Severity.HIGH,
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information",
            cvss_score=7.5,
            min_entropy=3.5,
        ),
        SecretPattern(
            name="X-API-Key Header Value",
            pattern=r"[xX]-[aA][pP][iI]-[kK][eE][yY][\s]*[=:][\s]*['\"]?([a-zA-Z0-9_-]{16,})['\"]?",
            category=SecretCategory.BEARER_TOKEN,
            severity=Severity.HIGH,
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information",
            cvss_score=7.5,
            min_entropy=3.5,
            requires_context=True,
        ),
        # Environment Variable Patterns
        SecretPattern(
            name="Process Env Access",
            pattern=r"process\.env\.([A-Z_][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)[A-Z0-9_]*)",
            category=SecretCategory.ENVIRONMENT_LEAK,
            severity=Severity.MEDIUM,
            cwe_id="CWE-526",
            cwe_name="Cleartext Storage of Sensitive Information in an Environment Variable",
            cvss_score=5.3,
            min_entropy=0.0,
        ),
        SecretPattern(
            name="Exposed .env File",
            pattern=r"(?:^|\n)([A-Z_][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)[A-Z0-9_]*)=([^\n]+)",
            category=SecretCategory.ENVIRONMENT_LEAK,
            severity=Severity.CRITICAL,
            cwe_id="CWE-538",
            cwe_name="Insertion of Sensitive Information into Externally-Accessible File or Directory",
            cvss_score=9.1,
            min_entropy=3.0,
        ),
        # Additional API providers
        SecretPattern(
            name="Heroku API Key",
            pattern=r"(?:HEROKU_API_KEY|heroku_api_key)[\s:=]+['\"]?([0-9a-fA-F-]{36})['\"]?",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=3.5,
            requires_context=True,
        ),
        SecretPattern(
            name="NPM Token",
            pattern=r"npm_[A-Za-z0-9]{36}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.0,
        ),
        SecretPattern(
            name="PyPI Token",
            pattern=r"pypi-[A-Za-z0-9_-]{100,}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.5,
        ),
        SecretPattern(
            name="DigitalOcean Token",
            pattern=r"dop_v1_[a-f0-9]{64}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1,
            min_entropy=4.5,
        ),
        SecretPattern(
            name="Datadog API Key",
            pattern=r"(?:DD_API_KEY|datadog_api_key)[\s:=]+['\"]?([a-f0-9]{32})['\"]?",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.0,
            requires_context=True,
        ),
        SecretPattern(
            name="Square Access Token",
            pattern=r"sq0atp-[0-9A-Za-z_-]{22}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1,
            min_entropy=4.0,
        ),
        SecretPattern(
            name="Square OAuth Secret",
            pattern=r"sq0csp-[0-9A-Za-z_-]{43}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1,
            min_entropy=4.5,
        ),
        SecretPattern(
            name="Shopify Access Token",
            pattern=r"shpat_[a-fA-F0-9]{32}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1,
            min_entropy=4.0,
        ),
        SecretPattern(
            name="Shopify Shared Secret",
            pattern=r"shpss_[a-fA-F0-9]{32}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1,
            min_entropy=4.0,
        ),
        # OpenAI Tokens
        SecretPattern(
            name="OpenAI API Key",
            pattern=r"sk-[a-zA-Z0-9]{48}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.8,
            min_entropy=4.0,
        ),
        SecretPattern(
            name="OpenAI Project Key",
            pattern=r"sk-proj-[a-zA-Z0-9]{48}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.8,
            min_entropy=4.0,
        ),
        SecretPattern(
            name="OpenAI API Key (Legacy)",
            pattern=r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
            category=SecretCategory.API_KEY,
            severity=Severity.CRITICAL,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.8,
            min_entropy=4.5,
        ),
        SecretPattern(
            name="OpenAI Session Token",
            pattern=r"sess-[a-zA-Z0-9]{40}",
            category=SecretCategory.API_KEY,
            severity=Severity.HIGH,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=7.5,
            min_entropy=4.0,
        ),
    )

    # Patterns for JSON response sensitive fields
    SENSITIVE_JSON_FIELDS: Final[tuple[str, ...]] = (
        "password",
        "passwd",
        "pwd",
        "secret",
        "api_key",
        "apiKey",
        "api_secret",
        "apiSecret",
        "access_token",
        "accessToken",
        "refresh_token",
        "refreshToken",
        "auth_token",
        "authToken",
        "private_key",
        "privateKey",
        "secret_key",
        "secretKey",
        "credential",
        "credentials",
        "client_secret",
        "clientSecret",
        "encryption_key",
        "encryptionKey",
        "signing_key",
        "signingKey",
        "bearer",
        "token",
        "ssn",
        "social_security",
        "credit_card",
        "creditCard",
        "cvv",
        "cvc",
    )

    # Sensitive JWT claims
    SENSITIVE_JWT_CLAIMS: Final[tuple[str, ...]] = (
        "password",
        "secret",
        "private_key",
        "api_key",
        "ssn",
        "credit_card",
        "admin",
        "role",
        "permissions",
        "scope",
        "email",
        "phone",
    )

    # Webpack/bundle indicators
    BUNDLE_INDICATORS: Final[tuple[str, ...]] = (
        "webpackJsonp",
        "__webpack_require__",
        "__webpack_modules__",
        "webpackChunk",
        "!function(e,t)",
        "!function(t,e)",
        'use strict";!function',
        ".chunk.js",
        ".bundle.js",
        "sourceMappingURL=",
        "//# sourceURL=",
    )

    # False positive indicators
    FALSE_POSITIVE_INDICATORS: Final[tuple[str, ...]] = (
        "your_",
        "your-",
        "<your",
        "replace_",
        "replace-",
        "xxx",
        "yyy",
        "zzz",
        "change_me",
        "changeme",
        "insert_",
        "put_your",
        "enter_your",
        "placeholder",
        "example_",
        "sample_",
        "my_secret",
        "my_password",
        "my_api_key",
        "undefined",
        "null",
        "none",
        "empty",
        "test_",
        "demo_",
        "fake_",
        "mock_",
        "dummy_",
        "${",
        "{{",
        "<%",
    )

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Analyze page data for exposed secrets and credentials.

        Args:
            url: Current page URL
            page_data: Dictionary containing:
                - html: Page HTML content
                - headers: Response headers
                - cookies: Cookie list
                - forms: Extracted form data
                - scripts: JavaScript sources
                - network_log: Network request log

        Returns:
            List of security findings
        """
        findings: list[Finding] = []
        html = page_data.get("html", "")
        scripts = page_data.get("scripts", [])
        network_log = page_data.get("network_log", [])
        headers = page_data.get("headers", {})

        # Analyze HTML content
        if html:
            findings.extend(self._scan_content(url, html, source="HTML"))
            findings.extend(self._check_api_response_fields(url, html))

        # Analyze JavaScript files and inline scripts
        if scripts:
            for script in scripts:
                if isinstance(script, str) and script.strip():
                    is_bundle = self._is_javascript_bundle(script)
                    source = "JavaScript Bundle" if is_bundle else "JavaScript"
                    findings.extend(
                        self._scan_content(url, script, source=source, is_bundle=is_bundle)
                    )
                    findings.extend(self._check_source_map_exposure(url, script))

        # Analyze network log
        if network_log:
            findings.extend(self._analyze_network_traffic(url, network_log))

        # Analyze response headers
        if headers:
            findings.extend(self._check_header_leaks(url, headers))

        return findings

    def _calculate_entropy(self, data: str) -> float:
        """
        Calculate Shannon entropy in bits per character.

        Higher entropy indicates more randomness, suggesting
        the string is more likely to be a secret.

        Args:
            data: Input string to analyze

        Returns:
            Entropy value in bits per character (0.0 to 8.0 for ASCII)
        """
        if not data or len(data) < 4:
            return 0.0

        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _is_high_entropy(
        self,
        value: str,
        category: SecretCategory,
        min_override: float | None = None,
    ) -> bool:
        """
        Check if value has sufficient entropy for its category.

        Args:
            value: String to analyze
            category: Secret category for threshold lookup
            min_override: Optional minimum entropy override

        Returns:
            True if entropy exceeds category threshold
        """
        threshold = min_override or self.ENTROPY_THRESHOLDS.get(category, 3.5)
        return self._calculate_entropy(value) >= threshold

    def _is_false_positive(self, value: str, context: str) -> bool:
        """
        Check if a match is likely a false positive.

        Args:
            value: Matched secret value
            context: Surrounding text context

        Returns:
            True if likely a false positive
        """
        value_lower = value.lower()
        context_lower = context.lower()

        # Check for placeholder/example indicators
        for indicator in self.FALSE_POSITIVE_INDICATORS:
            if indicator in value_lower or indicator in context_lower:
                return True

        # Check for repetitive patterns (e.g., "xxxxxxxxxxxx")
        if len(value) > 8 and len(set(value.lower())) <= 3:
            return True

        # Check for sequential patterns
        if re.match(r"^[a-z]+$", value.lower()) or re.match(r"^\d+$", value):
            if len(value) > 10:
                return True

        # Check for common code patterns that aren't secrets
        code_patterns = [
            r"function\s*\(",
            r"=>\s*\{",
            r"return\s+",
            r"import\s+",
            r"export\s+",
            r"const\s+",
            r"let\s+",
            r"var\s+",
        ]
        for pattern in code_patterns:
            if re.search(pattern, context[:50]):
                return True

        return False

    def _is_javascript_bundle(self, content: str) -> bool:
        """
        Detect if content is a minified JavaScript bundle.

        Args:
            content: Content to analyze

        Returns:
            True if content appears to be a JS bundle
        """
        content_start = content[:5000]
        return any(indicator in content_start for indicator in self.BUNDLE_INDICATORS)

    def _mask_secret(self, secret: str, visible_chars: int = 4) -> str:
        """
        Mask a secret for safe display in findings.

        Args:
            secret: Secret value to mask
            visible_chars: Number of characters to show at start/end

        Returns:
            Masked secret string
        """
        if len(secret) <= visible_chars * 2:
            return "*" * len(secret)
        return secret[:visible_chars] + "*" * (len(secret) - visible_chars * 2) + secret[-visible_chars:]

    def _get_context(self, content: str, match: re.Match[str], context_size: int = 100) -> str:
        """
        Extract context around a regex match.

        Args:
            content: Full content string
            match: Regex match object
            context_size: Characters to include before/after

        Returns:
            Context string around the match
        """
        start = max(0, match.start() - context_size)
        end = min(len(content), match.end() + context_size)
        return content[start:end]

    def _scan_content(
        self,
        url: str,
        content: str,
        source: str = "HTML",
        is_bundle: bool = False,
    ) -> list[Finding]:
        """
        Scan content for secret patterns.

        Args:
            url: Source URL
            content: Content to scan
            source: Content source description
            is_bundle: Whether content is a JS bundle

        Returns:
            List of findings
        """
        findings: list[Finding] = []
        seen_secrets: set[str] = set()

        for pattern in self.SECRET_PATTERNS:
            try:
                for match in re.finditer(pattern.pattern, content, re.IGNORECASE | re.MULTILINE):
                    # Extract the actual secret value
                    if match.groups():
                        secret_value = next((g for g in match.groups() if g), "")
                    else:
                        secret_value = match.group(0)

                    if not secret_value or len(secret_value) < 8:
                        continue

                    # Deduplicate
                    secret_hash = f"{pattern.name}:{secret_value[:20]}"
                    if secret_hash in seen_secrets:
                        continue
                    seen_secrets.add(secret_hash)

                    # Get context
                    context = self._get_context(content, match)

                    # Check for false positives
                    if self._is_false_positive(secret_value, context):
                        continue

                    # Calculate entropy
                    entropy = self._calculate_entropy(secret_value)

                    # Skip low entropy matches unless pattern has low threshold
                    if not self._is_high_entropy(secret_value, pattern.category, pattern.min_entropy):
                        continue

                    # Calculate confidence
                    confidence = self._calculate_confidence(
                        pattern, secret_value, entropy, is_bundle
                    )

                    # Adjust severity for bundles (higher false positive rate)
                    severity = pattern.severity
                    if is_bundle and severity in (Severity.CRITICAL, Severity.HIGH):
                        severity = Severity.MEDIUM

                    masked = self._mask_secret(secret_value)

                    findings.append(
                        self._create_finding(
                            severity=severity,
                            title=f"Exposed {pattern.name}",
                            description=(
                                f"A {pattern.name} was detected in {source} content. "
                                f"Entropy: {entropy:.2f} bits/char. "
                                f"Confidence: {confidence:.0%}. "
                                "This credential may be compromised and should be rotated immediately."
                            ),
                            cwe_id=pattern.cwe_id,
                            cwe_name=pattern.cwe_name,
                            url=url,
                            evidence=f"Found in {source}: {masked}",
                            remediation=self._get_remediation(pattern),
                            cvss_score=pattern.cvss_score,
                            references=self._get_references(pattern),
                            metadata={
                                "secret_type": pattern.name,
                                "category": pattern.category.value,
                                "source": source,
                                "entropy": round(entropy, 2),
                                "confidence": round(confidence, 2),
                                "is_bundle": is_bundle,
                            },
                        )
                    )

            except re.error as e:
                self.logger.debug(
                    "regex_error",
                    pattern_name=pattern.name,
                    error=str(e),
                )
                continue

        return findings

    def _calculate_confidence(
        self,
        pattern: SecretPattern,
        value: str,
        entropy: float,
        is_bundle: bool,
    ) -> float:
        """
        Calculate confidence score for a detected secret.

        Args:
            pattern: Secret pattern that matched
            value: Matched secret value
            entropy: Calculated entropy
            is_bundle: Whether found in a bundle

        Returns:
            Confidence score between 0.0 and 1.0
        """
        base_confidence = 0.7

        # Entropy bonus
        if entropy > 4.5:
            base_confidence += 0.15
        elif entropy > 4.0:
            base_confidence += 0.1
        elif entropy < 3.0:
            base_confidence -= 0.2

        # Length bonus
        if len(value) > 32:
            base_confidence += 0.05

        # Bundle penalty
        if is_bundle:
            base_confidence -= 0.15

        # Pattern-specific confidence
        if pattern.category == SecretCategory.PRIVATE_KEY:
            base_confidence += 0.2
        elif pattern.category == SecretCategory.DATABASE_CREDENTIAL:
            base_confidence += 0.15

        return max(0.1, min(1.0, base_confidence))

    def _get_remediation(self, pattern: SecretPattern) -> str:
        """Generate remediation guidance based on pattern category."""
        remediation_map: dict[SecretCategory, str] = {
            SecretCategory.API_KEY: (
                "1. Immediately revoke and rotate the exposed API key. "
                "2. Remove the key from source code and version control. "
                "3. Use environment variables or a secrets management service. "
                "4. Audit access logs for unauthorized usage."
            ),
            SecretCategory.JWT_TOKEN: (
                "1. Invalidate the exposed JWT token. "
                "2. Review token generation to ensure sensitive data is not embedded. "
                "3. Implement token rotation and short expiration times. "
                "4. Use secure storage for tokens on the client side."
            ),
            SecretCategory.DATABASE_CREDENTIAL: (
                "1. Immediately change the database password. "
                "2. Audit database access logs for unauthorized queries. "
                "3. Use connection pooling with secrets management. "
                "4. Implement network-level access controls."
            ),
            SecretCategory.PRIVATE_KEY: (
                "1. Immediately revoke the compromised key pair. "
                "2. Generate new key pairs with strong entropy. "
                "3. Never commit private keys to version control. "
                "4. Use hardware security modules (HSM) for critical keys."
            ),
            SecretCategory.GENERIC_SECRET: (
                "1. Rotate the exposed credential. "
                "2. Remove hardcoded secrets from source code. "
                "3. Implement proper secrets management. "
                "4. Add pre-commit hooks to detect secrets before commit."
            ),
            SecretCategory.ENVIRONMENT_LEAK: (
                "1. Review and secure .env file permissions. "
                "2. Ensure .env files are in .gitignore. "
                "3. Use proper environment variable injection in deployment. "
                "4. Consider using a secrets management service."
            ),
            SecretCategory.BEARER_TOKEN: (
                "1. Invalidate the exposed bearer token. "
                "2. Review authorization flows for token exposure. "
                "3. Implement token rotation and short lifetimes. "
                "4. Use secure, httpOnly cookies for session management."
            ),
        }
        return remediation_map.get(
            pattern.category,
            "Rotate the exposed credential and implement proper secrets management."
        )

    def _get_references(self, pattern: SecretPattern) -> list[str]:
        """Get relevant reference URLs for a pattern."""
        base_refs = [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Session_Management_Schema",
            f"https://cwe.mitre.org/data/definitions/{pattern.cwe_id.split('-')[1]}.html",
        ]

        category_refs: dict[SecretCategory, list[str]] = {
            SecretCategory.API_KEY: [
                "https://cloud.google.com/docs/authentication/api-keys",
                "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html",
            ],
            SecretCategory.JWT_TOKEN: [
                "https://jwt.io/introduction",
                "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            ],
            SecretCategory.DATABASE_CREDENTIAL: [
                "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
            ],
            SecretCategory.PRIVATE_KEY: [
                "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",
            ],
        }

        return base_refs + category_refs.get(pattern.category, [])

    def _check_api_response_fields(self, url: str, content: str) -> list[Finding]:
        """
        Check for sensitive fields in JSON API responses.

        Args:
            url: Source URL
            content: Content to analyze

        Returns:
            List of findings for sensitive field exposure
        """
        findings: list[Finding] = []

        # Find JSON-like structures
        json_pattern = r"\{[^{}]*(?:\"[^\"]+\"\s*:\s*\"[^\"]*\"[^{}]*)+\}"
        json_matches = re.findall(json_pattern, content, re.DOTALL)

        for json_str in json_matches[:10]:  # Limit to prevent performance issues
            try:
                # Try to parse as JSON
                data = json.loads(json_str)
                if isinstance(data, dict):
                    sensitive_fields = self._find_sensitive_fields(data)
                    for field_name, field_value in sensitive_fields:
                        if self._is_false_positive(str(field_value), json_str):
                            continue

                        # Check entropy for string values
                        if isinstance(field_value, str) and len(field_value) > 0:
                            entropy = self._calculate_entropy(field_value)
                            if entropy < 2.5 and len(field_value) < 20:
                                continue

                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title=f"Sensitive Field in API Response: {field_name}",
                                description=(
                                    f"API response contains sensitive field '{field_name}' with a value. "
                                    "This may expose credentials or sensitive user data."
                                ),
                                cwe_id="CWE-200",
                                cwe_name="Exposure of Sensitive Information",
                                url=url,
                                evidence=f"Field: {field_name}",
                                remediation=(
                                    "1. Review API response payloads to remove sensitive fields. "
                                    "2. Implement proper data filtering before sending responses. "
                                    "3. Use DTOs to control what data is exposed."
                                ),
                                cvss_score=7.5,
                                metadata={
                                    "field_name": field_name,
                                    "source": "API Response",
                                },
                            )
                        )
            except (json.JSONDecodeError, TypeError):
                continue

        return findings

    def _find_sensitive_fields(
        self,
        data: dict[str, Any],
        prefix: str = "",
    ) -> "Iterator[tuple[str, Any]]":
        """
        Recursively find sensitive fields in a dictionary.

        Args:
            data: Dictionary to search
            prefix: Current key prefix for nested fields

        Yields:
            Tuples of (field_path, value) for sensitive fields
        """
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            key_lower = key.lower()

            # Check if key matches sensitive patterns
            if any(sensitive in key_lower for sensitive in self.SENSITIVE_JSON_FIELDS):
                if value and str(value).strip():
                    yield (full_key, value)

            # Recurse into nested dictionaries
            if isinstance(value, dict):
                yield from self._find_sensitive_fields(value, full_key)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        yield from self._find_sensitive_fields(item, f"{full_key}[{i}]")

    def _analyze_jwt_token(self, token: str) -> dict[str, Any]:
        """
        Decode and analyze a JWT token for sensitive claims.

        Args:
            token: JWT token string

        Returns:
            Dictionary with decoded payload and analysis results
        """
        result: dict[str, Any] = {
            "valid": False,
            "payload": {},
            "sensitive_claims": [],
            "issues": [],
        }

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return result

            # Decode header and payload (without signature verification)
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)

            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            result["valid"] = True
            result["payload"] = payload

            # Check for weak algorithms
            alg = header.get("alg", "")
            if alg.lower() in ("none", "hs256"):
                result["issues"].append(f"Weak algorithm: {alg}")

            # Check for sensitive claims
            for claim in self.SENSITIVE_JWT_CLAIMS:
                if claim in payload:
                    result["sensitive_claims"].append(claim)

            # Check expiration
            if "exp" not in payload:
                result["issues"].append("No expiration claim")

        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            pass

        return result

    def _check_source_map_exposure(self, url: str, content: str) -> list[Finding]:
        """
        Check for exposed source maps that may reveal source code.

        Args:
            url: Source URL
            content: JavaScript content

        Returns:
            List of findings for source map exposure
        """
        findings: list[Finding] = []

        # Check for sourceMappingURL
        source_map_patterns = [
            r"//[#@]\s*sourceMappingURL=([^\s]+)",
            r"/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*/",
        ]

        for pattern in source_map_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if not match.startswith("data:"):
                    findings.append(
                        self._create_finding(
                            severity=Severity.MEDIUM,
                            title="Source Map Exposed",
                            description=(
                                "A JavaScript source map reference was found. "
                                "Source maps can expose original source code, "
                                "including comments with sensitive information."
                            ),
                            cwe_id="CWE-540",
                            cwe_name="Inclusion of Sensitive Information in Source Code",
                            url=url,
                            evidence=f"Source map: {match[:100]}",
                            remediation=(
                                "1. Remove source map references from production builds. "
                                "2. If source maps are needed, restrict access via authentication. "
                                "3. Use separate builds for development and production."
                            ),
                            cvss_score=5.3,
                            metadata={
                                "source_map_url": match,
                            },
                        )
                    )
                    break

        return findings

    def _analyze_network_traffic(
        self,
        url: str,
        network_log: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Analyze network traffic for credential leaks.

        Args:
            url: Base URL
            network_log: List of network request/response entries

        Returns:
            List of findings from network analysis
        """
        findings: list[Finding] = []
        seen_issues: set[str] = set()

        sensitive_params = [
            "password", "passwd", "pwd", "secret", "token", "api_key",
            "apikey", "key", "auth", "credential", "private_key", "access_token",
        ]

        for entry in network_log[:100]:
            request_url = entry.get("url", "")
            method = entry.get("method", "").upper()

            # Check for sensitive data in URL parameters
            for param in sensitive_params:
                if f"{param}=" in request_url.lower():
                    issue_key = f"param:{param}"
                    if issue_key not in seen_issues:
                        seen_issues.add(issue_key)
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title=f"Sensitive Parameter in URL: {param}",
                                description=(
                                    f"Sensitive parameter '{param}' found in URL query string. "
                                    "This data may be logged in server logs, browser history, "
                                    "and proxy logs."
                                ),
                                cwe_id="CWE-598",
                                cwe_name="Use of GET Request Method With Sensitive Query Strings",
                                url=url,
                                evidence=f"Parameter '{param}' in {method} request",
                                remediation=(
                                    "1. Use POST requests for sensitive data. "
                                    "2. Never include credentials in URLs. "
                                    "3. Use request body or headers for sensitive data."
                                ),
                                cvss_score=6.5,
                                metadata={
                                    "parameter": param,
                                    "method": method,
                                },
                            )
                        )

        return findings

    def _check_header_leaks(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """
        Check response headers for credential leaks.

        Args:
            url: Source URL
            headers: Response headers

        Returns:
            List of findings from header analysis
        """
        findings: list[Finding] = []

        sensitive_headers = [
            "authorization",
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "x-secret-key",
            "proxy-authorization",
        ]

        for header_name, header_value in headers.items():
            header_lower = header_name.lower()

            # Check for sensitive header exposure
            if header_lower in sensitive_headers:
                if header_value and len(header_value) > 10:
                    findings.append(
                        self._create_finding(
                            severity=Severity.HIGH,
                            title=f"Sensitive Header Exposed: {header_name}",
                            description=(
                                f"Response includes sensitive header '{header_name}' "
                                "which may expose authentication credentials."
                            ),
                            cwe_id="CWE-200",
                            cwe_name="Exposure of Sensitive Information",
                            url=url,
                            evidence=f"Header: {header_name}",
                            remediation=(
                                "1. Review why sensitive headers are being reflected. "
                                "2. Ensure authentication headers are not leaked in responses."
                            ),
                            cvss_score=7.5,
                            metadata={
                                "header_name": header_name,
                            },
                        )
                    )

            # Check for bearer tokens in headers
            if "bearer" in header_value.lower():
                bearer_match = re.search(r"bearer\s+([a-zA-Z0-9_.-]{20,})", header_value, re.I)
                if bearer_match:
                    token = bearer_match.group(1)
                    entropy = self._calculate_entropy(token)
                    if entropy > 3.5:
                        masked = self._mask_secret(token)
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title="Bearer Token in Response Header",
                                description=(
                                    f"A bearer token was found in response header '{header_name}'. "
                                    "This may indicate credential leakage."
                                ),
                                cwe_id="CWE-200",
                                cwe_name="Exposure of Sensitive Information",
                                url=url,
                                evidence=f"Token in {header_name}: {masked}",
                                remediation=(
                                    "1. Review why bearer tokens are in response headers. "
                                    "2. Ensure tokens are only transmitted as needed."
                                ),
                                cvss_score=7.5,
                                metadata={
                                    "header_name": header_name,
                                    "entropy": round(entropy, 2),
                                },
                            )
                        )

        return findings
