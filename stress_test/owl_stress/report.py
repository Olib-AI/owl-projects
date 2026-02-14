"""Professional PDF report generation with Owl Browser branding."""

import io
import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak, HRFlowable, KeepTogether, Flowable,
)

from .config import Brand
from .metrics import StressTestResult, BatchResult

WIDTH, HEIGHT = A4
CONTENT_WIDTH = WIDTH - 30 * mm  # 15mm margins each side


# ── Color helpers ─────────────────────────────────────────────────────────────

def _hex(h: str) -> colors.Color:
    h = h.lstrip("#")
    return colors.Color(int(h[:2], 16) / 255, int(h[2:4], 16) / 255, int(h[4:6], 16) / 255)

def _hex_alpha(h: str, alpha: float) -> colors.Color:
    h = h.lstrip("#")
    return colors.Color(int(h[:2], 16) / 255, int(h[2:4], 16) / 255, int(h[4:6], 16) / 255, alpha)

# Core palette - aligned with brand
NIGHT = _hex("#0A1628")
NIGHT_LIGHT = _hex("#1A2A44")
PRIMARY = _hex(Brand.PRIMARY)
PRIMARY_DARK = _hex(Brand.PRIMARY_DARK)
PRIMARY_LIGHT = _hex(Brand.PRIMARY_LIGHT)
SECONDARY = _hex(Brand.SECONDARY)

# Chart palette (muted, professional, derived from brand #10B981 / #059669)
CHART_GREEN = "#059669"       # Brand dark - for success bars
CHART_AMBER = "#C8913A"       # Warm amber - for warning bars
CHART_RED = "#B85450"         # Muted brick red - for error/fail bars
CHART_PRIMARY = "#10B981"     # Brand primary
CHART_SAGE = "#34D399"        # Brand light
CHART_SLATE = "#5A6B7A"       # Cool gray-blue
CHART_CORAL = "#C07264"       # Muted warm red for P99

# Report colors
BORDER = _hex("#E2E8F0")
BORDER_LIGHT = _hex("#F1F5F9")
TEXT_DARK = _hex("#0F172A")
TEXT_BODY = _hex("#334155")
TEXT_MUTED = _hex("#64748B")
TEXT_FAINT = _hex("#94A3B8")
CARD_BG = _hex("#F8FAFC")
WHITE = colors.white


# ── Custom flowables ──────────────────────────────────────────────────────────

class ColorBar(Flowable):
    """A thin colored accent bar."""
    def __init__(self, width, height=2, color=PRIMARY):
        super().__init__()
        self.bar_width = width
        self.bar_height = height
        self.color = color

    def wrap(self, availWidth, availHeight):
        return (self.bar_width, self.bar_height)

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0, 0, self.bar_width, self.bar_height, 1, fill=True, stroke=False)


class CalloutBox(Flowable):
    """A left-bordered callout box for verdicts and highlights."""
    def __init__(self, text, border_color, bg_color, text_color, width, font_size=10):
        super().__init__()
        self.text = text
        self.border_color = border_color
        self.bg_color = bg_color
        self.text_color = text_color
        self.box_width = width
        self.font_size = font_size
        self._para = None

    def wrap(self, availWidth, availHeight):
        style = ParagraphStyle(
            "callout", fontName="Helvetica", fontSize=self.font_size,
            leading=self.font_size + 6, textColor=self.text_color,
        )
        self._para = Paragraph(self.text, style)
        w, h = self._para.wrap(self.box_width - 20 * mm, availHeight)
        self._height = h + 12 * mm
        return (self.box_width, self._height)

    def draw(self):
        # Background
        self.canv.setFillColor(self.bg_color)
        self.canv.roundRect(0, 0, self.box_width, self._height, 3, fill=True, stroke=False)
        # Left accent border
        self.canv.setFillColor(self.border_color)
        self.canv.roundRect(0, 0, 3.5, self._height, 1.5, fill=True, stroke=False)
        # Text
        self._para.drawOn(self.canv, 14 * mm, 5 * mm)


# ── Styles ────────────────────────────────────────────────────────────────────

def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "OwlTitle", parent=base["Title"],
            fontSize=30, leading=36, textColor=NIGHT,
            fontName="Helvetica-Bold", spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "OwlSubtitle", parent=base["Normal"],
            fontSize=12, leading=16, textColor=TEXT_MUTED,
            fontName="Helvetica", spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "OwlH2", parent=base["Heading2"],
            fontSize=16, leading=20, textColor=NIGHT,
            fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=8,
            borderWidth=0, borderPadding=0,
        ),
        "h3": ParagraphStyle(
            "OwlH3", parent=base["Heading3"],
            fontSize=11, leading=14, textColor=TEXT_MUTED,
            fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=4,
            leftIndent=0,
        ),
        "body": ParagraphStyle(
            "OwlBody", parent=base["Normal"],
            fontSize=9.5, leading=14, textColor=TEXT_BODY,
            fontName="Helvetica",
        ),
        "body_bold": ParagraphStyle(
            "OwlBodyBold", parent=base["Normal"],
            fontSize=9.5, leading=14, textColor=TEXT_DARK,
            fontName="Helvetica-Bold",
        ),
        "info_label": ParagraphStyle(
            "InfoLabel", parent=base["Normal"],
            fontSize=8, leading=11, textColor=TEXT_FAINT,
            fontName="Helvetica", spaceBefore=0, spaceAfter=0,
        ),
        "info_value": ParagraphStyle(
            "InfoValue", parent=base["Normal"],
            fontSize=9.5, leading=13, textColor=TEXT_DARK,
            fontName="Helvetica", spaceBefore=0, spaceAfter=0,
        ),
        "small": ParagraphStyle(
            "OwlSmall", parent=base["Normal"],
            fontSize=7.5, leading=10, textColor=TEXT_FAINT,
            fontName="Helvetica",
        ),
        "metric_value": ParagraphStyle(
            "MetricValue", parent=base["Normal"],
            fontSize=24, leading=28, textColor=NIGHT,
            fontName="Helvetica-Bold", alignment=TA_CENTER,
        ),
        "metric_label": ParagraphStyle(
            "MetricLabel", parent=base["Normal"],
            fontSize=8, leading=10, textColor=TEXT_MUTED,
            fontName="Helvetica", alignment=TA_CENTER,
        ),
        "table_header": ParagraphStyle(
            "TableHeader", parent=base["Normal"],
            fontSize=7.5, leading=10, textColor=TEXT_FAINT,
            fontName="Helvetica-Bold",
        ),
    }


# ── Chart helpers ─────────────────────────────────────────────────────────────

def _apply_chart_style(ax: plt.Axes):
    """Clean, minimal chart styling."""
    ax.set_facecolor("white")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#E2E8F0")
    ax.spines["bottom"].set_color("#E2E8F0")
    ax.tick_params(colors="#94A3B8", labelsize=7.5, length=0, pad=6)
    ax.grid(axis="y", color="#F1F5F9", linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)


def _fig_to_image(fig: plt.Figure, width_cm: float = 17.9) -> Image:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=180, bbox_inches="tight",
                facecolor="white", edgecolor="none", pad_inches=0.15)
    plt.close(fig)
    buf.seek(0)
    aspect = fig.get_size_inches()[1] / fig.get_size_inches()[0]
    w = width_cm * cm
    return Image(buf, width=w, height=w * aspect)


# ── Chart generators ─────────────────────────────────────────────────────────

def _chart_response_times(result: StressTestResult) -> Image:
    """Line chart: avg / median / p95 / p99 response times per batch."""
    batches = [b.batch_size for b in result.batch_results]
    avg = [b.avg_duration_ms for b in result.batch_results]
    med = [b.median_duration_ms for b in result.batch_results]
    p95 = [b.p95_duration_ms for b in result.batch_results]
    p99 = [b.p99_duration_ms for b in result.batch_results]

    fig, ax = plt.subplots(figsize=(8.5, 3.6))
    _apply_chart_style(ax)

    # Shaded area between median and p95
    ax.fill_between(batches, med, p95, alpha=0.06, color=CHART_PRIMARY, zorder=2)

    ax.plot(batches, avg, marker="o", color=CHART_PRIMARY, linewidth=2, label="Average",
            markersize=4.5, markeredgecolor="white", markeredgewidth=1, zorder=4)
    ax.plot(batches, med, marker="s", color=CHART_SAGE, linewidth=1.8, label="Median",
            markersize=4, markeredgecolor="white", markeredgewidth=1, zorder=4)
    ax.plot(batches, p95, marker="^", color=CHART_AMBER, linewidth=1.8, label="P95",
            markersize=4.5, markeredgecolor="white", markeredgewidth=1, zorder=4)
    ax.plot(batches, p99, marker="D", color=CHART_CORAL, linewidth=1.8, label="P99",
            markersize=4, markeredgecolor="white", markeredgewidth=1, zorder=4)

    ax.set_xlabel("Concurrent Users", fontsize=8, color="#94A3B8", labelpad=8)
    ax.set_ylabel("Response Time (ms)", fontsize=8, color="#94A3B8", labelpad=8)
    ax.legend(fontsize=7.5, frameon=True, fancybox=False, edgecolor="#E2E8F0",
              framealpha=1, loc="upper left", borderpad=0.6, handlelength=1.5)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))

    return _fig_to_image(fig)


def _chart_success_rate(result: StressTestResult) -> Image:
    """Bar chart: success rate per batch with refined colors."""
    batches = [str(b.batch_size) for b in result.batch_results]
    rates = [b.success_rate for b in result.batch_results]

    fig, ax = plt.subplots(figsize=(8.5, 3.2))
    _apply_chart_style(ax)

    bar_colors = [
        CHART_GREEN if r >= 90 else CHART_AMBER if r >= 70 else CHART_RED
        for r in rates
    ]
    bars = ax.bar(batches, rates, color=bar_colors, width=0.55,
                  edgecolor="white", linewidth=0.8, zorder=3)

    for bar, rate in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                f"{rate:.1f}%", ha="center", va="bottom", fontsize=7.5,
                fontweight="bold", color="#334155")

    ax.set_xlabel("Concurrent Users", fontsize=8, color="#94A3B8", labelpad=8)
    ax.set_ylabel("Success Rate (%)", fontsize=8, color="#94A3B8", labelpad=8)
    ax.set_ylim(0, 115)

    return _fig_to_image(fig)


def _chart_throughput(result: StressTestResult) -> Image:
    """Bar chart: flows completed per second per batch."""
    batches = [str(b.batch_size) for b in result.batch_results]
    throughput = []
    for b in result.batch_results:
        wall_s = b.wall_time_ms / 1000 if b.wall_time_ms > 0 else 1
        throughput.append(b.successful_flows / wall_s)

    fig, ax = plt.subplots(figsize=(8.5, 3.2))
    _apply_chart_style(ax)

    ax.bar(batches, throughput, color=CHART_PRIMARY, width=0.55,
           edgecolor="white", linewidth=0.8, zorder=3)

    for i, v in enumerate(throughput):
        ax.text(i, v + max(throughput) * 0.02, f"{v:.2f}", ha="center", va="bottom",
                fontsize=7.5, fontweight="bold", color="#334155")

    ax.set_xlabel("Concurrent Users", fontsize=8, color="#94A3B8", labelpad=8)
    ax.set_ylabel("Flows / sec", fontsize=8, color="#94A3B8", labelpad=8)

    return _fig_to_image(fig)


def _chart_duration_distribution(result: StressTestResult) -> Image:
    """Box plot: duration distribution per batch."""
    data = []
    labels = []
    for b in result.batch_results:
        durations = b.durations_ms
        if durations:
            data.append(durations)
            labels.append(str(b.batch_size))

    fig, ax = plt.subplots(figsize=(8.5, 3.2))
    _apply_chart_style(ax)

    if not data:
        ax.text(0.5, 0.5, "No successful flows to display", transform=ax.transAxes,
                ha="center", va="center", fontsize=10, color="#94A3B8")
        return _fig_to_image(fig)

    bp = ax.boxplot(data, labels=labels, patch_artist=True, widths=0.45,
                    medianprops=dict(color=CHART_GREEN, linewidth=2),
                    whiskerprops=dict(color="#CBD5E1", linewidth=1),
                    capprops=dict(color="#CBD5E1", linewidth=1),
                    flierprops=dict(marker="o", markersize=2.5,
                                    markerfacecolor=CHART_CORAL, alpha=0.6,
                                    markeredgecolor="none"))

    for patch in bp["boxes"]:
        patch.set_facecolor(CHART_PRIMARY)
        patch.set_alpha(0.18)
        patch.set_edgecolor(CHART_PRIMARY)
        patch.set_linewidth(1.2)

    ax.set_xlabel("Concurrent Users", fontsize=8, color="#94A3B8", labelpad=8)
    ax.set_ylabel("Duration (ms)", fontsize=8, color="#94A3B8", labelpad=8)

    return _fig_to_image(fig)


# ── Table helpers ─────────────────────────────────────────────────────────────

def _branded_table_style() -> TableStyle:
    return TableStyle([
        # Header row
        ("BACKGROUND", (0, 0), (-1, 0), NIGHT),
        ("TEXTCOLOR", (0, 0), (-1, 0), _hex("#CBD5E1")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7.5),
        # Data rows
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("TEXTCOLOR", (0, 1), (-1, -1), TEXT_BODY),
        # Alignment
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        # Padding
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 1), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        # Alternating rows
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, CARD_BG]),
        # Borders - horizontal only for clean look
        ("LINEBELOW", (0, 0), (-1, 0), 0, NIGHT),  # hide (merged with bg)
        ("LINEBELOW", (0, 1), (-1, -2), 0.4, BORDER),
        ("LINEBELOW", (0, -1), (-1, -1), 0.8, BORDER),
        # Outer frame
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
    ])


def _summary_table(result: StressTestResult) -> Table:
    """Main results table: one row per batch size."""
    header = [
        "Concurrent", "Total", "Passed", "Failed", "Success %",
        "Avg (ms)", "Median (ms)", "P95 (ms)", "Max (ms)", "Wall (ms)",
    ]
    rows = [header]
    for b in result.batch_results:
        rows.append([
            str(b.batch_size),
            str(b.total_flows),
            str(b.successful_flows),
            str(b.failed_flows),
            f"{b.success_rate:.1f}%",
            f"{b.avg_duration_ms:,.0f}",
            f"{b.median_duration_ms:,.0f}",
            f"{b.p95_duration_ms:,.0f}",
            f"{b.max_duration_ms:,.0f}",
            f"{b.wall_time_ms:,.0f}",
        ])

    col_widths = [62, 40, 45, 45, 52, 52, 56, 52, 52, 52]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(_branded_table_style())
    return t


def _scalability_table(result: StressTestResult) -> Table | None:
    """Scalability analysis: degradation vs single-user baseline."""
    if not result.batch_results:
        return None

    baseline = result.batch_results[0]
    baseline_avg = baseline.avg_duration_ms if baseline.avg_duration_ms > 0 else 1

    header = [
        "Concurrent", "Avg (ms)", "vs Baseline",
        "Std Dev (ms)", "Min (ms)", "Max (ms)",
        "Spread (ms)", "Efficiency",
    ]
    rows = [header]
    for b in result.batch_results:
        multiplier = b.avg_duration_ms / baseline_avg if baseline_avg else 0
        spread = b.max_duration_ms - b.min_duration_ms
        wall_s = b.wall_time_ms / 1000 if b.wall_time_ms > 0 else 1
        efficiency = (b.successful_flows / wall_s) / b.batch_size if b.batch_size > 0 else 0

        rows.append([
            str(b.batch_size),
            f"{b.avg_duration_ms:,.0f}",
            f"{multiplier:.2f}x",
            f"{b.std_dev_ms:,.0f}",
            f"{b.min_duration_ms:,.0f}",
            f"{b.max_duration_ms:,.0f}",
            f"{spread:,.0f}",
            f"{efficiency:.2f}",
        ])

    col_widths = [62, 62, 66, 66, 58, 58, 66, 70]
    t = Table(rows, colWidths=col_widths, repeatRows=1)

    # Start with base branded style
    style_cmds = list(_branded_table_style().getCommands())

    # Color-code the "vs Baseline" column based on degradation
    for row_idx in range(1, len(rows)):
        multiplier = result.batch_results[row_idx - 1].avg_duration_ms / baseline_avg
        if multiplier <= 1.2:
            cell_color = _hex_alpha(CHART_GREEN, 0.12)
        elif multiplier <= 2.0:
            cell_color = _hex_alpha(CHART_AMBER, 0.12)
        else:
            cell_color = _hex_alpha(CHART_RED, 0.12)
        style_cmds.append(("BACKGROUND", (2, row_idx), (2, row_idx), cell_color))

    t.setStyle(TableStyle(style_cmds))
    return t


def _step_breakdown_table(result: StressTestResult) -> Table | None:
    """Per-step performance breakdown table."""
    breakdown = result.get_step_breakdown()
    if not breakdown:
        return None

    header = ["Step", "Executions", "Failures", "Avg (ms)", "Median (ms)", "P95 (ms)", "Max (ms)"]
    rows = [header]
    for name, data in breakdown.items():
        display_name = name.replace("browser_", "")
        rows.append([
            display_name,
            str(data["total"]),
            str(data["failures"]),
            f"{data['avg_ms']:,.0f}",
            f"{data['median_ms']:,.0f}",
            f"{data['p95_ms']:,.0f}",
            f"{data['max_ms']:,.0f}",
        ])

    col_widths = [126, 64, 58, 64, 68, 64, 64]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(_branded_table_style())
    return t


# ── Header / footer ──────────────────────────────────────────────────────────

def _header_footer(canvas, doc):
    canvas.saveState()

    # Header - dark navy bar
    canvas.setFillColor(NIGHT)
    canvas.rect(0, HEIGHT - 11 * mm, WIDTH, 11 * mm, fill=True, stroke=False)

    # Thin accent line below header
    canvas.setFillColor(PRIMARY)
    canvas.rect(0, HEIGHT - 11.6 * mm, WIDTH, 0.6 * mm, fill=True, stroke=False)

    # Header text - high contrast on dark navy
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawString(15 * mm, HEIGHT - 8 * mm,
                      "OWL BROWSER")
    canvas.setFillColor(_hex("#CBD5E1"))
    canvas.setFont("Helvetica", 7)
    canvas.drawString(15 * mm + canvas.stringWidth("OWL BROWSER", "Helvetica-Bold", 7), HEIGHT - 8 * mm,
                      "  |  Stress Test Report")
    canvas.setFillColor(_hex("#CBD5E1"))
    canvas.setFont("Helvetica", 6.5)
    canvas.drawRightString(WIDTH - 15 * mm, HEIGHT - 8 * mm, "CONFIDENTIAL")

    # Footer - subtle line and text
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.4)
    canvas.line(15 * mm, 14 * mm, WIDTH - 15 * mm, 14 * mm)
    canvas.setFillColor(TEXT_FAINT)
    canvas.setFont("Helvetica", 6.5)
    canvas.drawString(15 * mm, 9.5 * mm,
                      f"Generated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}  |  owlbrowser.net")
    canvas.drawRightString(WIDTH - 15 * mm, 9.5 * mm, f"Page {doc.page}")

    canvas.restoreState()


# ── Metric cards ──────────────────────────────────────────────────────────────

def _metric_cards(result: StressTestResult, styles: dict) -> Table:
    """Create polished summary metric cards row."""
    cards_data = [
        (f"{result.total_flows_executed}", "Total Flows", PRIMARY),
        (f"{result.overall_success_rate:.1f}%", "Success Rate", _hex(CHART_GREEN)),
        (f"{result.total_wall_time_s:.1f}s", "Total Duration", _hex(CHART_SLATE)),
        (f"{len(result.batch_results)}", "Batch Levels", _hex(CHART_AMBER)),
    ]

    card_tables = []
    for value, label, accent in cards_data:
        val_style = ParagraphStyle(
            f"mv_{label}", fontName="Helvetica-Bold", fontSize=22,
            leading=26, textColor=NIGHT, alignment=TA_CENTER,
        )
        lbl_style = ParagraphStyle(
            f"ml_{label}", fontName="Helvetica", fontSize=7.5,
            leading=10, textColor=TEXT_MUTED, alignment=TA_CENTER,
            spaceBefore=2,
        )

        mini = Table(
            [[Paragraph(value, val_style)], [Paragraph(label, lbl_style)]],
            colWidths=[120],
        )
        mini.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (0, 0), 14),
            ("BOTTOMPADDING", (0, -1), (0, -1), 10),
            ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
            ("LINEABOVE", (0, 0), (-1, 0), 2.5, accent),
            ("BOX", (0, 0), (-1, -1), 0.4, BORDER),
        ]))
        card_tables.append(mini)

    row = Table([card_tables], colWidths=[130] * 4)
    row.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    return row


# ── Info card ─────────────────────────────────────────────────────────────────

def _info_card(result: StressTestResult, styles: dict) -> Table:
    """Styled info card with test parameters."""
    fields = [
        ("TARGET", result.target_name),
        ("URL", result.target_url),
        ("FLOW", result.flow_name),
        ("DATE", datetime.datetime.now().strftime("%B %d, %Y  %H:%M")),
        ("DURATION", f"{result.total_wall_time_s:.1f} seconds"),
    ]

    rows = []
    for label, value in fields:
        rows.append([
            Paragraph(label, styles["info_label"]),
            Paragraph(value, styles["info_value"]),
        ])

    t = Table(rows, colWidths=[60, CONTENT_WIDTH - 80])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (0, -1), 12),
        ("LEFTPADDING", (1, 0), (1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, BORDER_LIGHT),
        ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
        ("BOX", (0, 0), (-1, -1), 0.4, BORDER),
    ]))
    return t


# ── Main report builder ──────────────────────────────────────────────────────

def generate_report(result: StressTestResult, output_path: str) -> str:
    """Generate a branded PDF stress test report.

    Returns the output file path.
    """
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path = str(output_path)
    styles = _build_styles()

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=18 * mm, bottomMargin=20 * mm,
        leftMargin=15 * mm, rightMargin=15 * mm,
    )

    story = []

    # ── Cover section ──
    story.append(Spacer(1, 8 * mm))

    # Logo (smaller, more refined)
    logo_path = Brand.LOGO_PNG
    if logo_path.exists():
        story.append(Image(str(logo_path), width=32 * mm, height=32 * mm))
        story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Stress Test Report", styles["title"]))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        f"{result.target_name}  &bull;  {datetime.datetime.now().strftime('%B %d, %Y')}",
        styles["subtitle"],
    ))

    # Accent bar (left-aligned, short)
    story.append(ColorBar(60 * mm, 2.5, PRIMARY))
    story.append(Spacer(1, 8 * mm))

    # Info card
    story.append(_info_card(result, styles))
    story.append(Spacer(1, 8 * mm))

    # Metric cards
    story.append(_metric_cards(result, styles))
    story.append(Spacer(1, 8 * mm))

    # ── Executive Summary ──
    overall = result.overall_success_rate
    if overall >= 95:
        verdict = "The target application handled all concurrency levels with excellent reliability."
        border_c = _hex(CHART_GREEN)
        bg_c = _hex_alpha(CHART_GREEN, 0.06)
    elif overall >= 80:
        verdict = "The target application showed acceptable performance with some degradation at higher concurrency levels."
        border_c = _hex(CHART_AMBER)
        bg_c = _hex_alpha(CHART_AMBER, 0.06)
    else:
        verdict = "The target application showed significant degradation under load. Performance optimizations are recommended."
        border_c = _hex(CHART_RED)
        bg_c = _hex_alpha(CHART_RED, 0.06)

    story.append(KeepTogether([
        Paragraph("Executive Summary", styles["h2"]),
        CalloutBox(verdict, border_c, bg_c, TEXT_BODY, CONTENT_WIDTH, font_size=9.5),
        Spacer(1, 8 * mm),
    ]))

    # ── Results table (keep heading + table together) ──
    story.append(KeepTogether([
        Paragraph("Results by Concurrency Level", styles["h2"]),
        _summary_table(result),
        Spacer(1, 4 * mm),
    ]))

    # ── Scalability analysis table ──
    scalability = _scalability_table(result)
    if scalability:
        story.append(KeepTogether([
            Paragraph("Scalability Analysis", styles["h2"]),
            Paragraph(
                "Performance change relative to single-user baseline. "
                "Lower multipliers and higher efficiency indicate better scalability.",
                styles["body"],
            ),
            Spacer(1, 3 * mm),
            scalability,
            Spacer(1, 4 * mm),
        ]))

    # ── Charts page ──
    story.append(PageBreak())
    story.append(Paragraph("Performance Analysis", styles["h2"]))

    story.append(KeepTogether([
        Paragraph("RESPONSE TIME TREND", styles["h3"]),
        _chart_response_times(result),
        Spacer(1, 4 * mm),
    ]))

    story.append(KeepTogether([
        Paragraph("SUCCESS RATE BY CONCURRENCY", styles["h3"]),
        _chart_success_rate(result),
    ]))

    story.append(KeepTogether([
        Paragraph("THROUGHPUT", styles["h3"]),
        _chart_throughput(result),
        Spacer(1, 4 * mm),
    ]))

    story.append(KeepTogether([
        Paragraph("DURATION DISTRIBUTION", styles["h3"]),
        _chart_duration_distribution(result),
        Spacer(1, 6 * mm),
    ]))

    # ── Step breakdown (keep heading + table together) ──
    step_table = _step_breakdown_table(result)
    if step_table:
        story.append(KeepTogether([
            Paragraph("Per-Step Performance", styles["h2"]),
            step_table,
        ]))

    # ── Footer notes (keep together to avoid orphan page) ──
    story.append(KeepTogether([
        Spacer(1, 10 * mm),
        HRFlowable(width="100%", thickness=0.4, color=BORDER, spaceAfter=4 * mm),
        Paragraph(
            "This report was generated by <b>Owl Stress</b>, powered by "
            "<font color='#10B981'>Owl Browser</font>. Each concurrent user operates "
            "in an isolated browser context with a unique fingerprint, simulating "
            "real-world traffic patterns.",
            styles["small"],
        ),
        Spacer(1, 1.5 * mm),
        Paragraph(
            "For questions or to schedule additional testing, visit owlbrowser.net",
            styles["small"],
        ),
    ]))

    # Build
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return output_path
