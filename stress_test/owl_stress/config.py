"""Configuration, branding, and constants for Owl Stress."""

import os
from pathlib import Path
from dataclasses import dataclass, field

# Paths
PROJECT_ROOT = Path(__file__).parent.parent
ASSETS_DIR = PROJECT_ROOT / "assets"
FLOWS_DIR = PROJECT_ROOT / "flows"
REPORTS_DIR = PROJECT_ROOT / "reports"

# Batch sizes for stress test escalation
BATCH_SIZES = [1, 5, 10, 25, 50, 75, 100]


# ── Branding ──────────────────────────────────────────────────────────────────

class Brand:
    """Owl Browser brand colors and fonts for PDF reports."""

    # Primary palette
    PRIMARY = "#10B981"
    PRIMARY_LIGHT = "#34D399"
    PRIMARY_DARK = "#059669"

    # Secondary palette
    SECONDARY = "#9EBE8F"
    SECONDARY_LIGHT = "#B5CFA9"
    SECONDARY_DARK = "#87AD75"

    # Night theme
    NIGHT = "#0A1628"
    NIGHT_LIGHT = "#1A2A44"
    NIGHT_SKY = "#0D1F3C"

    # Accents
    GOLD = "#FFD700"
    MOON = "#F5F3C1"

    # Status colors
    SUCCESS = "#27ca40"
    WARNING = "#ffbd2e"
    ERROR = "#ff5f56"

    # Text
    TEXT_PRIMARY = "#fafafa"
    TEXT_SECONDARY = "#a3a3a3"
    TEXT_MUTED = "#737373"

    # Report-specific (light background PDF)
    REPORT_BG = "#FFFFFF"
    REPORT_TEXT = "#1a1a1a"
    REPORT_SUBTITLE = "#4a4a4a"
    REPORT_BORDER = "#E5E7EB"

    # Fonts
    FONT_DISPLAY = "Helvetica"
    FONT_BODY = "Helvetica"
    FONT_MONO = "Courier"

    # Logo
    LOGO_SVG = ASSETS_DIR / "owl-logo.svg"
    LOGO_PNG = ASSETS_DIR / "owl-logo.png"


# ── Runner config ─────────────────────────────────────────────────────────────

@dataclass
class StressConfig:
    """Configuration for a stress test run."""

    flow_path: str
    target_name: str = "Unknown Target"
    target_url: str = ""
    batch_sizes: list[int] = field(default_factory=lambda: list(BATCH_SIZES))
    max_concurrent: int = 100
    timeout_per_step: int = 30000  # ms
    delay_between_batches: float = 5.0  # seconds
    cooldown_between_flows: float = 0.05  # seconds within a batch (minimal stagger)
    owl_endpoint: str = ""
    owl_token: str = ""
    report_output: str = ""

    def __post_init__(self):
        if not self.owl_endpoint:
            self.owl_endpoint = os.environ.get("OWL_ENDPOINT", "")
        if not self.owl_token:
            self.owl_token = os.environ.get("OWL_TOKEN", "")
        if not self.report_output:
            REPORTS_DIR.mkdir(exist_ok=True)
            self.report_output = str(
                REPORTS_DIR / f"{self.target_name.replace(' ', '_').lower()}_report.pdf"
            )
