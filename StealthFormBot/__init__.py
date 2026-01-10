"""
StealthFormBot - Enterprise Form Submission with Anti-Detection

This Apify actor automates form submissions with sophisticated anti-detection
measures. It handles complex multi-step forms, file uploads, CAPTCHAs (via
third-party services), and dynamic JavaScript forms.

Features:
- Simple contact forms
- Multi-step wizards
- Dynamic forms (fields appear based on selections)
- Forms with file uploads
- Forms with dropdowns, checkboxes, radio buttons, date pickers
- Forms with validation
- Forms behind login
- Anti-detection and fingerprint rotation
"""

__version__ = "1.0.0"
__author__ = "Olib AI"

from .models import (
    ActorInput,
    ActorOutput,
    FieldType,
    FormField,
    FormStep,
    FormSubmissionStatus,
    LoginConfig,
    ProxyConfig,
    WaitCondition,
)
from .form_handler import FormHandler
from .main import run_actor

__all__ = [
    "ActorInput",
    "ActorOutput",
    "FieldType",
    "FormField",
    "FormHandler",
    "FormStep",
    "FormSubmissionStatus",
    "LoginConfig",
    "ProxyConfig",
    "WaitCondition",
    "run_actor",
]
