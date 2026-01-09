"""
Security analyzers for SecureProbe scanner.

Each analyzer is responsible for detecting specific vulnerability classes
with CWE references and CVSS-aligned severity ratings.
"""

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.analyzers.header import HeaderAnalyzer
from secureprobe.analyzers.cookie import CookieAnalyzer
from secureprobe.analyzers.form import FormAnalyzer
from secureprobe.analyzers.tls import TLSAnalyzer
from secureprobe.analyzers.info_leak import InfoLeakAnalyzer
from secureprobe.analyzers.endpoint import EndpointAnalyzer
from secureprobe.analyzers.session_security import SessionSecurityAnalyzer
from secureprobe.analyzers.input_validation import InputValidationAnalyzer
from secureprobe.analyzers.access_control import AccessControlAnalyzer
from secureprobe.analyzers.crypto_analysis import CryptoAnalyzer
from secureprobe.analyzers.api_security import APISecurityAnalyzer
from secureprobe.analyzers.chaos_attacks import ChaosAttacksAnalyzer
from secureprobe.analyzers.apt_attacks import APTAttacksAnalyzer
from secureprobe.analyzers.js_library_cve import JSLibraryCVEAnalyzer
from secureprobe.analyzers.novel_attacks import NovelAttacksAnalyzer
from secureprobe.analyzers.bloody_mary import BloodyMaryAnalyzer
from secureprobe.analyzers.memory_assault import MemoryAssaultAnalyzer
from secureprobe.analyzers.chaos_teen import ChaosTeenAnalyzer
from secureprobe.analyzers.credential_spray import CredentialSprayAnalyzer
from secureprobe.analyzers.deep_sniff import DeepSniffAnalyzer

__all__ = [
    "BaseAnalyzer",
    "HeaderAnalyzer",
    "CookieAnalyzer",
    "FormAnalyzer",
    "TLSAnalyzer",
    "InfoLeakAnalyzer",
    "EndpointAnalyzer",
    "SessionSecurityAnalyzer",
    "InputValidationAnalyzer",
    "AccessControlAnalyzer",
    "CryptoAnalyzer",
    "APISecurityAnalyzer",
    "ChaosAttacksAnalyzer",
    "APTAttacksAnalyzer",
    "JSLibraryCVEAnalyzer",
    "NovelAttacksAnalyzer",
    "BloodyMaryAnalyzer",
    "MemoryAssaultAnalyzer",
    "ChaosTeenAnalyzer",
    "CredentialSprayAnalyzer",
    "DeepSniffAnalyzer",
]
