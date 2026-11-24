"""
MARSAD | مَــرصــــد  -  Enterprise SOC dashboard
===============================================

Streamlit front-end for the Lightweight Network Intrusion Detection System.

Run with:   streamlit run app.py        (or double-click Marsad.bat)

Architecture notes
------------------
* One master ``st.empty()`` placeholder holds the whole dashboard.  Switching
  between Live and Demo flushes it, bumps ``view_epoch`` and reruns, so no
  stale element of the previous mode can survive in the DOM.
* Exactly one body is rendered inside the placeholder: the Bento grid with
  charts + telemetry table, OR the full-height radar empty state.
* Every chart, table and download button is keyed with
  ``<name>_<mode>_<view_epoch>``.
"""

import base64
import functools
import html
import io
import re
import time
from datetime import datetime, timedelta
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from database import (
    ALERT_COLUMNS,
    clear_alerts,
    fetch_alerts,
    get_db_name,
    init_db,
    seed_random_alerts,
)
from sniffer import (
    get_available_interfaces,
    is_sniffer_active,
    sniffer_state,
    start_or_restart_sniffer,
)

# ---------------------------------------------------------------------------
# Brand, constants & logo
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
LOGO_PATH = BASE_DIR / "logo.png"

BRAND_EN = "MARSAD"
BRAND_AR = "مَــرصــــد"
BRAND_FULL = f"{BRAND_EN} | {BRAND_AR}"
APP_VERSION = "2.0"

LIVE_LABEL = "● Live Mode (Real Traffic)"
DEMO_LABEL = "◆ Demo Mode (Simulation)"
BOLT = "\u26a1\ufe0e"  # text-presentation selector keeps the symbol monochrome

ATTACK_TYPES = ["ARP Spoofing", "Port Scanning", "SYN Flood"]
SEVERITIES = ["High", "Medium", "Low"]
SEV_COLORS = ["#ef4444", "#f59e0b", "#10b981"]
SEV_RANK = {"High": 0, "Medium": 1, "Low": 2}

TIME_WINDOWS = {
    "Last 15 Minutes": timedelta(minutes=15),
    "Last 1 Hour": timedelta(hours=1),
    "Last 24 Hours": timedelta(hours=24),
    "Last 7 Days": timedelta(days=7),
    "All Time": None,
}

MAX_ROWS = 20000
REFRESH_SECONDS = 2
CHART_HEIGHT = 235
MONO = "JetBrains Mono"
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

esc = html.escape


@functools.lru_cache(maxsize=1)
def load_logo_assets():
    """Return (sidebar_png_base64, square_page_icon) cropped to the visible artwork."""
    if not LOGO_PATH.exists():
        return None, None
    try:
        from PIL import Image

        img = Image.open(LOGO_PATH).convert("RGBA")
        bbox = img.getchannel("A").point(lambda a: 255 if a > 8 else 0).getbbox()
        if bbox:
            pad = int(0.03 * max(img.size))
            left, top, right, bottom = bbox
            img = img.crop(
                (
                    max(left - pad, 0),
                    max(top - pad, 0),
                    min(right + pad, img.width),
                    min(bottom + pad, img.height),
                )
            )
        resample = getattr(Image, "Resampling", Image).LANCZOS

        side = max(img.size)
        icon = Image.new("RGBA", (side, side), (0, 0, 0, 0))
        icon.paste(img, ((side - img.width) // 2, (side - img.height) // 2))
        icon = icon.resize((192, 192), resample)

        sidebar_img = img
        if img.width > 520:
            ratio = 520 / img.width
            sidebar_img = img.resize((520, max(1, int(img.height * ratio))), resample)
        buffer = io.BytesIO()
        sidebar_img.save(buffer, format="PNG", optimize=True)
        return base64.b64encode(buffer.getvalue()).decode("ascii"), icon
    except Exception:
        try:
            return base64.b64encode(LOGO_PATH.read_bytes()).decode("ascii"), None
        except OSError:
            return None, None


LOGO_B64, LOGO_ICON = load_logo_assets()
HAS_LOGO_FILE = LOGO_B64 is not None

st.set_page_config(
    page_title=BRAND_FULL,
    page_icon=LOGO_ICON,
    layout="wide",
    initial_sidebar_state="expanded",
)


def h(markup):
    """Flatten indentation and blank lines so Markdown never turns HTML into a code block."""
    return "\n".join(line.strip() for line in markup.strip().splitlines() if line.strip())


def get_logo_html(width=150):
    """Render user's logo.png if available, otherwise render built-in MARSAD eye-calligraphy SVG."""
    shadow_css = (
        "filter: drop-shadow(0 0 10px rgba(56, 189, 248, 0.50)) "
        "drop-shadow(-4px 0 10px rgba(14, 165, 233, 0.45));"
    )
    if HAS_LOGO_FILE:
        return (
            f'<img src="data:image/png;base64,{LOGO_B64}" width="{width}" alt="{BRAND_EN}" '
            f'style="{shadow_css} display: block; margin: 0 auto;" />'
        )

    return h(
        f'''
        <svg width="{width}" viewBox="0 0 320 150" xmlns="http://www.w3.org/2000/svg" style="{shadow_css} display: block; margin: 0 auto;">
          <defs>
            <linearGradient id="marsadGrad" x1="0%" y1="50%" x2="100%" y2="50%">
              <stop offset="0%" stop-color="#0b3c68"/>
              <stop offset="50%" stop-color="#065f88"/>
              <stop offset="100%" stop-color="#38bdf8"/>
            </linearGradient>
          </defs>
          <path d="M 35 82 C 70 18, 235 15, 292 68 C 240 28, 85 32, 42 82 Z" fill="url(#marsadGrad)"/>
          <path d="M 40 96 C 95 142, 205 138, 228 84 L 216 84 C 196 126, 102 128, 40 96 Z" fill="url(#marsadGrad)"/>
          <path d="M 42 82 C 32 92, 48 102, 78 96 L 92 96 L 75 56 L 86 50 L 106 94 L 136 94 C 142 66, 185 64, 188 86 C 190 102, 152 104, 136 94 L 112 94"
                stroke="url(#marsadGrad)" stroke-width="11" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
          <ellipse cx="164" cy="84" rx="24" ry="15" stroke="url(#marsadGrad)" stroke-width="10" fill="none"/>
          <path d="M 222 76 L 222 88 C 236 88, 248 84, 258 74 C 266 66, 282 68, 282 82 C 282 92, 266 92, 258 82"
                stroke="url(#marsadGrad)" stroke-width="11" stroke-linecap="round" fill="none"/>
        </svg>
        '''
    )


def compat(fn, *args, key=None, stretch=False, **kwargs):
    """Call a Streamlit element across API generations (width= vs use_container_width=, optional key=)."""
    width_options = [{"width": "stretch"}, {"use_container_width": True}] if stretch else [{}]
    attempts = []
    if key is not None:
        attempts += [{**w, "key": key} for w in width_options]
    attempts += [dict(w) for w in width_options]

    last_error = None
    for extra in attempts:
        try:
            return fn(*args, **kwargs, **extra)
        except TypeError as exc:
            last_error = exc
    raise last_error


def columns_centered(spec):
    try:
        return st.columns(spec, vertical_alignment="center")
    except TypeError:
        return st.columns(spec)


# ---------------------------------------------------------------------------
# Enterprise SOC theme (CSS)
# ---------------------------------------------------------------------------
SOC_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Cairo:wght@600;700;800&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

:root {
    --primary-color: #065f88 !important;
    --marsad: #065f88;
    --cyan: #38bdf8;
    --cyan-deep: #0ea5e9;
    --glass: rgba(13, 22, 36, 0.78);
}

html, body, .stApp, [class*="css"] {
    font-family: 'Inter', 'Cairo', system-ui, -apple-system, 'Segoe UI', sans-serif;
}

.stApp {
    background:
        linear-gradient(rgba(56, 189, 248, 0.035) 1px, transparent 1px) 0 0 / 46px 46px,
        linear-gradient(90deg, rgba(56, 189, 248, 0.035) 1px, transparent 1px) 0 0 / 46px 46px,
        radial-gradient(circle at 15% 10%, #091628 0%, #050b14 60%, #03070e 100%);
    background-attachment: fixed;
    color: #e2e8f0;
}

/* Keep stHeader AND stToolbar present but transparent so the native >> expand-sidebar arrow stays alive */
header[data-testid="stHeader"] {
    background: transparent !important;
    background-color: transparent !important;
    border: none !important;
    box-shadow: none !important;
    height: 2.2rem !important;
    pointer-events: none !important;
    z-index: 999999 !important;
}

[data-testid="stToolbar"] {
    background: transparent !important;
    visibility: visible !important;
    display: flex !important;
    pointer-events: none !important;
}

/* Hide ONLY the Deploy button, main menu, status widget, decoration bar and footer */
[data-testid="stDeployButton"],
[data-testid="stAppDeployButton"],
[data-testid="stToolbarActions"],
.stDeployButton,
.stAppDeployButton,
button[title="Deploy"],
[data-testid="stMainMenu"],
#MainMenu,
[data-testid="stStatusWidget"],
[data-testid="stDecoration"],
footer {
    display: none !important;
    visibility: hidden !important;
}

/* Native >> expand-sidebar button: pinned top-left, always clickable */
[data-testid="collapsedControl"],
[data-testid="stSidebarCollapsedControl"],
[data-testid="stExpandSidebarButton"] {
    position: fixed !important;
    top: 14px !important;
    left: 14px !important;
    z-index: 9999999 !important;
    pointer-events: auto !important;
    visibility: visible !important;
    opacity: 1 !important;
    background: rgba(13, 24, 41, 0.92) !important;
    border: 1px solid rgba(56, 189, 248, 0.65) !important;
    color: #38bdf8 !important;
    border-radius: 6px !important;
    box-shadow: 0 0 10px rgba(56, 189, 248, 0.25) !important;
    transition: all 0.15s ease !important;
}

[data-testid="stSidebarCollapseButton"] button,
header[data-testid="stHeader"] button[kind="header"],
header[data-testid="stHeader"] button[kind="headerNoPadding"] {
    pointer-events: auto !important;
    visibility: visible !important;
    opacity: 1 !important;
    background: rgba(13, 24, 41, 0.92) !important;
    border: 1px solid rgba(56, 189, 248, 0.65) !important;
    color: #38bdf8 !important;
    border-radius: 6px !important;
    box-shadow: 0 0 10px rgba(56, 189, 248, 0.25) !important;
    transition: all 0.15s ease !important;
}

[data-testid="collapsedControl"]:hover,
[data-testid="stSidebarCollapsedControl"]:hover,
[data-testid="stExpandSidebarButton"]:hover,
[data-testid="stSidebarCollapseButton"] button:hover,
header[data-testid="stHeader"] button[kind="header"]:hover,
header[data-testid="stHeader"] button[kind="headerNoPadding"]:hover {
    background: #065f88 !important;
    border-color: #7dd3fc !important;
    color: #ffffff !important;
    box-shadow: 0 0 14px rgba(56, 189, 248, 0.55) !important;
}

[data-testid="collapsedControl"] svg,
[data-testid="stSidebarCollapsedControl"] svg,
[data-testid="stExpandSidebarButton"] svg,
[data-testid="stSidebarCollapseButton"] svg {
    fill: #38bdf8 !important;
    color: #38bdf8 !important;
}

/* Auto-refresh without flicker: never dim elements that are about to be replaced */
[data-stale="true"],
[data-testid="stElementContainer"][data-stale="true"],
div.element-container[data-stale="true"],
.stale-element {
    opacity: 1 !important;
    filter: none !important;
    transition: none !important;
}

.block-container {
    padding-top: 0.5rem !important;
    padding-left: 1.2rem !important;
    padding-right: 1.2rem !important;
    padding-bottom: 1rem !important;
    max-width: 100% !important;
}

div[data-testid="stHorizontalBlock"] {
    gap: 0.75rem !important;
}

hr {
    border-color: rgba(56, 189, 248, 0.14) !important;
}

* {
    scrollbar-width: thin;
    scrollbar-color: rgba(56, 189, 248, 0.35) transparent;
}

button:focus-visible,
input:focus-visible,
[role="radio"]:focus-visible,
[role="checkbox"]:focus-visible {
    outline: 2px solid #38bdf8 !important;
    outline-offset: 2px !important;
}

/* ---------------------------------------------------------------- Sidebar */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #040811 0%, #07101e 100%) !important;
    border-right: 1px solid rgba(56, 189, 248, 0.18);
}

section[data-testid="stSidebar"] [data-testid="stSidebarHeader"] {
    padding-bottom: 0.2rem !important;
}

section[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p,
section[data-testid="stSidebar"] label p {
    color: #94a3b8;
    font-size: 0.78rem;
}

section[data-testid="stSidebar"] div[role="radiogroup"] label p {
    color: #cbd5e1;
    font-weight: 500;
}

/* Dark brand plate: left-illuminated so a dark-blue arch still pops */
.sidebar-brand-box {
    text-align: center;
    padding: 16px 12px 14px 12px;
    background: linear-gradient(90deg, rgba(30, 64, 100, 0.45) 0%, rgba(10, 17, 28, 0.95) 75%);
    border-radius: 10px;
    border: 1px solid rgba(56, 189, 248, 0.28);
    border-left: 3px solid #38bdf8;
    margin-bottom: 16px;
    box-shadow: inset 14px 0 24px rgba(14, 165, 233, 0.14), 0 6px 18px rgba(0, 0, 0, 0.45);
}

.sidebar-brand-title {
    font-weight: 800;
    font-size: 1.1rem;
    color: #ffffff;
    margin-top: 10px;
    letter-spacing: 1.2px;
}

.sidebar-brand-title .ar {
    color: #7dd3fc;
    font-family: 'Cairo', 'Inter', sans-serif;
}

.sidebar-brand-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    color: #38bdf8;
    font-weight: 600;
    letter-spacing: 1.5px;
    margin-top: 2px;
    text-transform: uppercase;
}

.sidebar-section-label {
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.1px;
    color: #94a3b8;
    margin: 10px 0 6px 0;
    display: flex;
    align-items: center;
    gap: 6px;
}

.sidebar-confirm {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: #fca5a5;
    background: rgba(239, 68, 68, 0.10);
    border: 1px solid rgba(239, 68, 68, 0.40);
    border-radius: 6px;
    padding: 8px 10px;
    margin: 4px 0 8px 0;
}

.sidebar-footer {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.66rem;
    line-height: 1.7;
    color: #64748b;
    border-top: 1px solid rgba(56, 189, 248, 0.14);
    margin-top: 14px;
    padding-top: 10px;
}

.sidebar-footer b {
    color: #7dd3fc;
    font-weight: 600;
}

/* ------------------- Force-override Streamlit's coral-red (#FF4B4B) accents */
html body span[data-baseweb="tag"],
html body div[data-baseweb="select"] span[data-baseweb="tag"],
html body section[data-testid="stSidebar"] span[data-baseweb="tag"] {
    background-color: rgba(14, 165, 233, 0.18) !important;
    border: 1px solid rgba(56, 189, 248, 0.55) !important;
    color: #38bdf8 !important;
    border-radius: 4px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.75rem !important;
    font-weight: 500 !important;
}

html body span[data-baseweb="tag"] span,
html body span[data-baseweb="tag"] svg {
    color: #e0f2fe !important;
    fill: #38bdf8 !important;
}

html body span[data-baseweb="tag"]:hover {
    background-color: rgba(14, 165, 233, 0.30) !important;
}

/* radio */
html body div[role="radiogroup"] label[data-baseweb="radio"] > div:first-child {
    border-color: rgba(56, 189, 248, 0.70) !important;
    background-color: rgba(6, 95, 136, 0.25) !important;
}

html body div[role="radiogroup"] label[data-baseweb="radio"]:has(input:checked) > div:first-child {
    background-color: #0ea5e9 !important;
    border-color: #38bdf8 !important;
    box-shadow: 0 0 8px rgba(56, 189, 248, 0.55) !important;
}

/* checkbox */
html body label[data-baseweb="checkbox"] > span:first-child {
    background-color: rgba(6, 95, 136, 0.25) !important;
    border-color: rgba(56, 189, 248, 0.70) !important;
}

html body label[data-baseweb="checkbox"]:has(input:checked) > span:first-child {
    background-color: #0ea5e9 !important;
    border-color: #38bdf8 !important;
    box-shadow: 0 0 8px rgba(56, 189, 248, 0.45) !important;
}

html body div[data-testid="stCheckbox"] label span[data-baseweb="checkbox"] > div:first-child {
    border-color: #38bdf8 !important;
}

/* select, multiselect & text input shells */
html body div[data-baseweb="select"] > div,
html body div[data-testid="stTextInput"] div[data-baseweb="input"],
html body div[data-testid="stTextInput"] div[data-baseweb="base-input"] {
    background-color: rgba(13, 22, 36, 0.88) !important;
    border-color: rgba(56, 189, 248, 0.25) !important;
    color: #e2e8f0 !important;
}

html body div[data-baseweb="select"] > div:focus-within,
html body div[data-testid="stTextInput"] div[data-baseweb="input"]:focus-within {
    border-color: #38bdf8 !important;
    box-shadow: 0 0 0 1px #38bdf8, 0 0 14px rgba(56, 189, 248, 0.20) !important;
}

html body div[data-testid="stTextInput"] input {
    color: #e2e8f0 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.80rem !important;
    caret-color: #38bdf8 !important;
}

html body div[data-testid="stTextInput"] input::placeholder {
    color: #64748b !important;
}

html body div[data-baseweb="popover"] ul[role="listbox"],
html body div[data-baseweb="popover"] > div {
    background-color: #0b1626 !important;
    border-color: rgba(56, 189, 248, 0.30) !important;
}

html body div[data-baseweb="popover"] li[role="option"] {
    color: #cbd5e1 !important;
    background-color: transparent !important;
}

html body div[data-baseweb="popover"] li[role="option"]:hover,
html body div[data-baseweb="popover"] li[role="option"][aria-selected="true"] {
    background-color: rgba(14, 165, 233, 0.20) !important;
    color: #e0f2fe !important;
}

/* ------------------------------------------------------ Button hierarchy */
button[kind="primary"],
button[data-testid="stBaseButton-primary"] {
    background: linear-gradient(90deg, rgba(6, 95, 136, 0.88) 0%, rgba(14, 165, 233, 0.78) 100%) !important;
    color: #f8fafc !important;
    border: 1px solid rgba(56, 189, 248, 0.55) !important;
    border-radius: 6px !important;
    font-size: 0.80rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.3px !important;
    box-shadow: 0 2px 12px rgba(14, 165, 233, 0.18) !important;
    transition: all 0.15s ease !important;
}

button[kind="primary"]:hover,
button[data-testid="stBaseButton-primary"]:hover {
    background: linear-gradient(90deg, #0873a3 0%, #0ea5e9 100%) !important;
    border-color: #7dd3fc !important;
    box-shadow: 0 4px 16px rgba(56, 189, 248, 0.30) !important;
}

button[kind="primary"]:active,
button[data-testid="stBaseButton-primary"]:active {
    transform: translateY(1px);
}

button[kind="secondary"],
button[data-testid="stBaseButton-secondary"] {
    background: transparent !important;
    color: #fca5a5 !important;
    border: 1px solid rgba(239, 68, 68, 0.40) !important;
    border-radius: 6px !important;
    font-size: 0.80rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.3px !important;
    transition: all 0.15s ease !important;
}

button[kind="secondary"]:hover,
button[data-testid="stBaseButton-secondary"]:hover {
    background: rgba(239, 68, 68, 0.14) !important;
    border-color: rgba(248, 113, 113, 0.75) !important;
    color: #fecaca !important;
}

div[data-testid="stDownloadButton"] button,
div.stDownloadButton > button {
    background: linear-gradient(90deg, rgba(6, 95, 136, 0.88) 0%, rgba(14, 165, 233, 0.78) 100%) !important;
    color: #f8fafc !important;
    border: 1px solid rgba(56, 189, 248, 0.55) !important;
    border-radius: 6px !important;
    font-size: 0.80rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.3px !important;
    box-shadow: 0 2px 12px rgba(14, 165, 233, 0.18) !important;
    transition: all 0.15s ease !important;
}

div[data-testid="stDownloadButton"] button:hover,
div.stDownloadButton > button:hover {
    background: linear-gradient(90deg, #0873a3 0%, #0ea5e9 100%) !important;
    border-color: #7dd3fc !important;
    color: #ffffff !important;
    box-shadow: 0 4px 16px rgba(56, 189, 248, 0.30) !important;
}

/* ------------------------------------------------ Top SOC command bar */
.soc-command-bar {
    width: 100%;
    box-sizing: border-box;
    background: linear-gradient(90deg, #070d19 0%, #0d1829 50%, #070d19 100%);
    border: 1px solid rgba(56, 189, 248, 0.14);
    border-bottom: 1px solid rgba(56, 189, 248, 0.25);
    border-left: 4px solid #065f88;
    border-radius: 6px;
    padding: 12px 24px 12px 48px !important;
    margin-bottom: 14px;
    display: flex;
    flex-wrap: nowrap;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    box-shadow: 0 6px 22px rgba(0, 0, 0, 0.45);
}

.soc-brand-title {
    font-size: 1.18rem;
    font-weight: 800;
    letter-spacing: 0.8px;
    color: #ffffff;
    display: flex;
    align-items: center;
    gap: 10px;
    white-space: nowrap;
}

.soc-brand-title span.divider {
    color: #38bdf8;
    font-weight: 400;
}

.soc-brand-title span.arabic {
    color: #7dd3fc;
    font-family: 'Cairo', 'Inter', sans-serif;
    font-weight: 800;
    letter-spacing: 0;
}

.soc-pills-group {
    display: flex;
    flex-wrap: nowrap;
    align-items: center;
    gap: 10px;
    min-width: 0;
}

.soc-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 30px;
    padding: 0 12px;
    border-radius: 5px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.73rem;
    font-weight: 600;
    letter-spacing: 0.4px;
    white-space: nowrap;
}

.posture-secure {
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.45);
    color: #34d399;
}

.posture-elevated {
    background: rgba(245, 158, 11, 0.14);
    border: 1px solid rgba(245, 158, 11, 0.55);
    color: #fbbf24;
}

.posture-critical {
    background: rgba(239, 68, 68, 0.18);
    border: 1px solid rgba(239, 68, 68, 0.65);
    color: #f87171;
    animation: criticalPulse 1.6s infinite ease-in-out;
}

@keyframes criticalPulse {
    0%, 100% { box-shadow: 0 0 6px rgba(239, 68, 68, 0.20); }
    50% { box-shadow: 0 0 16px rgba(239, 68, 68, 0.55); }
}

.iface-pill {
    background: rgba(15, 23, 42, 0.90);
    border: 1px solid rgba(56, 189, 248, 0.25);
    color: #cbd5e1;
    max-width: 280px;
    overflow: hidden;
    text-overflow: ellipsis;
    display: inline-block;
    line-height: 28px;
}

.sniffer-active {
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.50);
    color: #34d399;
}

.sniffer-stopped {
    background: rgba(239, 68, 68, 0.14);
    border: 1px solid rgba(239, 68, 68, 0.50);
    color: #f87171;
}

.sniffer-demo {
    background: rgba(6, 95, 136, 0.28);
    border: 1px solid rgba(56, 189, 248, 0.50);
    color: #7dd3fc;
}

.pulse-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background-color: #10b981;
    box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.8);
    animation: pulseDot 1.8s infinite;
}

@keyframes pulseDot {
    0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.8); }
    70% { box-shadow: 0 0 0 7px rgba(16, 185, 129, 0); }
    100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}

.soc-alert-banner {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    background: rgba(239, 68, 68, 0.10);
    border: 1px solid rgba(239, 68, 68, 0.45);
    border-left: 3px solid #ef4444;
    border-radius: 6px;
    padding: 10px 14px;
    margin-bottom: 12px;
}

.soc-alert-icon {
    color: #f87171;
    font-size: 1rem;
    line-height: 1.4;
}

.soc-alert-title {
    font-size: 0.82rem;
    font-weight: 700;
    color: #fecaca;
}

.soc-alert-text {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.74rem;
    color: #fca5a5;
    margin-top: 2px;
    word-break: break-word;
}

/* ------------------------------------------------ Bento cards & KPI row */
div[data-testid="stVerticalBlockBorderWrapper"] {
    background: rgba(13, 22, 36, 0.75) !important;
    border: 1px solid rgba(56, 189, 248, 0.14) !important;
    border-radius: 10px !important;
    padding: 16px !important;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.40) !important;
    backdrop-filter: blur(10px);
}

.kpi-card {
    background: rgba(13, 22, 36, 0.78);
    border: 1px solid rgba(56, 189, 248, 0.14);
    border-radius: 10px;
    padding: 14px 16px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.40);
    transition: transform 0.15s ease, border-color 0.15s ease;
    height: 106px;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}

.kpi-card:hover {
    transform: translateY(-2px);
    border-color: rgba(56, 189, 248, 0.45);
}

.kpi-glow-cyan {
    border-top: 2px solid #065f88;
    box-shadow: inset 0 12px 20px -12px rgba(14, 165, 233, 0.35), 0 4px 20px rgba(0, 0, 0, 0.40);
}

.kpi-glow-red {
    border-top: 2px solid #ef4444;
    box-shadow: inset 0 12px 20px -12px rgba(239, 68, 68, 0.38), 0 4px 20px rgba(0, 0, 0, 0.40);
}

.kpi-glow-amber {
    border-top: 2px solid #f59e0b;
    box-shadow: inset 0 12px 20px -12px rgba(245, 158, 11, 0.35), 0 4px 20px rgba(0, 0, 0, 0.40);
}

.kpi-glow-emerald {
    border-top: 2px solid #10b981;
    box-shadow: inset 0 12px 20px -12px rgba(16, 185, 129, 0.35), 0 4px 20px rgba(0, 0, 0, 0.40);
}

.kpi-glow-sky {
    border-top: 2px solid #38bdf8;
    box-shadow: inset 0 12px 20px -12px rgba(56, 189, 248, 0.35), 0 4px 20px rgba(0, 0, 0, 0.40);
}

.kpi-glow-purple {
    border-top: 2px solid #818cf8;
    box-shadow: inset 0 12px 20px -12px rgba(129, 140, 248, 0.35), 0 4px 20px rgba(0, 0, 0, 0.40);
}

.kpi-label {
    font-size: 0.70rem;
    text-transform: uppercase;
    letter-spacing: 0.9px;
    color: #94a3b8;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
}

.kpi-value {
    font-family: 'JetBrains Mono', monospace;
    font-variant-numeric: tabular-nums;
    font-size: 1.62rem;
    font-weight: 700;
    color: #ffffff;
    line-height: 1.15;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.kpi-value-ip {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.06rem;
    font-weight: 700;
    color: #e0f2fe;
    line-height: 1.25;
    letter-spacing: -0.3px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.kpi-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    color: #64748b;
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.bento-title {
    font-size: 0.84rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.9px;
    color: #e2e8f0;
    border-left: 3px solid #065f88;
    padding-left: 10px;
    margin: 2px 0 12px 0;
    display: flex;
    align-items: center;
    height: 28px;
}

.bento-meta {
    margin-left: auto;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.66rem;
    font-weight: 500;
    letter-spacing: 0.3px;
    text-transform: none;
    color: #64748b;
}

.table-meta {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    color: #64748b;
    margin: 0 0 8px 0;
}

.table-meta b {
    color: #94a3b8;
    font-weight: 600;
}

.table-empty {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #94a3b8;
    text-align: center;
    padding: 34px 12px;
    border: 1px dashed rgba(56, 189, 248, 0.25);
    border-radius: 8px;
}

/* ---------------------------------------------------------- IP inspector */
.ip-inspector {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 16px;
    padding: 9px 14px;
    margin: 0 0 12px 0;
    background: linear-gradient(90deg, rgba(6, 95, 136, 0.30), rgba(13, 22, 36, 0.60));
    border: 1px solid rgba(56, 189, 248, 0.30);
    border-left: 3px solid #38bdf8;
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: #94a3b8;
}

.ip-inspector .ip-tag {
    color: #38bdf8;
    font-weight: 700;
    letter-spacing: 0.8px;
}

.ip-inspector .ip-addr {
    color: #ffffff;
    font-weight: 700;
    font-size: 0.82rem;
}

.ip-inspector b {
    color: #e2e8f0;
    font-weight: 600;
}

.sev-chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 20px;
    padding: 0 8px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 0.66rem;
    letter-spacing: 0.5px;
}

.sev-chip.high { background: rgba(239, 68, 68, 0.18); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.50); }
.sev-chip.medium { background: rgba(245, 158, 11, 0.18); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.50); }
.sev-chip.low { background: rgba(16, 185, 129, 0.16); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.50); }

/* ------------------------------------------- Radar / shield empty state */
.soc-radar-card {
    background: rgba(13, 22, 36, 0.75);
    border: 1px solid rgba(56, 189, 248, 0.16);
    border-radius: 10px;
    min-height: calc(100vh - 235px);
    padding: 52px 28px;
    margin-top: 14px;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.40);
}

.soc-radar-card.radar-live { --radar: 16, 185, 129; }
.soc-radar-card.radar-demo { --radar: 56, 189, 248; border-color: rgba(56, 189, 248, 0.28); }
.soc-radar-card.radar-filter { --radar: 245, 158, 11; border-color: rgba(245, 158, 11, 0.28); }

.radar-wrap {
    position: relative;
    width: 156px;
    height: 156px;
    margin: 0 auto 24px auto;
    border-radius: 50%;
    border: 1px solid rgba(var(--radar), 0.55);
    background: radial-gradient(circle, rgba(var(--radar), 0.12) 0%, rgba(3, 7, 14, 0) 72%);
    box-shadow: 0 0 34px rgba(var(--radar), 0.20), inset 0 0 22px rgba(var(--radar), 0.10);
    overflow: hidden;
}

.radar-rings {
    position: absolute;
    inset: 0;
    background: repeating-radial-gradient(circle at center, transparent 0 25px, rgba(var(--radar), 0.22) 25px 26px);
}

.radar-cross::before,
.radar-cross::after {
    content: "";
    position: absolute;
    background: rgba(var(--radar), 0.22);
}

.radar-cross::before { left: 50%; top: 0; width: 1px; height: 100%; }
.radar-cross::after { top: 50%; left: 0; height: 1px; width: 100%; }

.radar-sweep {
    position: absolute;
    inset: 0;
    border-radius: 50%;
    background: conic-gradient(from 0deg, rgba(var(--radar), 0) 0deg, rgba(var(--radar), 0) 255deg, rgba(var(--radar), 0.50) 360deg);
    animation: radarSpin 3.8s linear infinite;
}

@keyframes radarSpin {
    to { transform: rotate(360deg); }
}

.radar-core {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
}

.radar-core svg {
    filter: drop-shadow(0 0 6px rgba(var(--radar), 0.70));
}

.soc-radar-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: #f8fafc;
    letter-spacing: 0.4px;
    margin-bottom: 8px;
}

.soc-radar-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.80rem;
    color: #94a3b8;
    max-width: 600px;
    margin: 0 auto;
    line-height: 1.7;
}

.soc-radar-sub b {
    color: #e2e8f0;
    font-weight: 600;
}

.radar-chips {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 8px;
    margin-top: 22px;
}

.radar-chip {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    height: 26px;
    padding: 0 11px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.5px;
    color: rgb(var(--radar));
    background: rgba(var(--radar), 0.10);
    border: 1px solid rgba(var(--radar), 0.40);
}

@media (max-width: 1100px) {
    .soc-command-bar { flex-wrap: wrap; }
    .soc-pills-group { flex-wrap: wrap; }
}

@media (prefers-reduced-motion: reduce) {
    .radar-sweep, .pulse-dot, .posture-critical { animation: none !important; }
    .kpi-card { transition: none !important; }
}
</style>
"""

st.markdown(SOC_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Session state & one-time sniffer boot
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def boot_sniffer_once():
    """Start the capture engine once per server process (not once per browser tab)."""
    start_or_restart_sniffer("Default (Auto)")
    return True


boot_sniffer_once()

st.session_state.setdefault("last_mode", "live")
st.session_state.setdefault("view_epoch", 0)
st.session_state.setdefault("confirm_clear", False)


def bump_epoch():
    st.session_state["view_epoch"] += 1


# ---------------------------------------------------------------------------
# Sidebar branding & controls
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        h(
            f'''
            <div class="sidebar-brand-box">
                {get_logo_html(176)}
                <div class="sidebar-brand-title">{BRAND_EN} | <span class="ar" lang="ar">{BRAND_AR}</span></div>
                <div class="sidebar-brand-sub">Enterprise NIDS Sensor</div>
            </div>
            '''
        ),
        unsafe_allow_html=True,
    )

    st.markdown('<div class="sidebar-section-label">◈ Operation Mode</div>', unsafe_allow_html=True)
    system_mode = st.radio(
        "Select Mode:",
        options=[LIVE_LABEL, DEMO_LABEL],
        label_visibility="collapsed",
        key="system_mode",
    )

    current_mode = "live" if system_mode == LIVE_LABEL else "demo"
    init_db(current_mode)

    if current_mode == "live":
        st.divider()
        st.markdown('<div class="sidebar-section-label">◈ Network Adapter</div>', unsafe_allow_html=True)
        interfaces_dict = get_available_interfaces()
        iface_options = list(interfaces_dict.keys())
        current_idx = (
            iface_options.index(sniffer_state["current_iface"])
            if sniffer_state["current_iface"] in iface_options
            else 0
        )
        selected_iface = st.selectbox(
            "Monitored Interface:",
            options=iface_options,
            index=current_idx,
        )
        if selected_iface != sniffer_state["current_iface"]:
            start_or_restart_sniffer(selected_iface)
            bump_epoch()
            st.rerun()

    st.divider()
    st.markdown('<div class="sidebar-section-label">◈ Sensor Controls</div>', unsafe_allow_html=True)
    if compat(st.button, "⟳ Refresh Telemetry", type="primary", stretch=True, key="btn_refresh"):
        bump_epoch()
        st.rerun()

    if current_mode == "demo":
        if compat(st.button, "▸ Inject Simulated Alerts (1-3)", type="primary", stretch=True, key="btn_inject"):
            seed_random_alerts()
            bump_epoch()
            st.rerun()
        auto_refresh = False
    else:
        auto_refresh = st.checkbox(f"{BOLT} Live Auto-Refresh ({REFRESH_SECONDS}s)", value=True, key="auto_refresh")

    if st.session_state["confirm_clear"]:
        st.markdown(
            f'<div class="sidebar-confirm">▲ Permanently delete every {current_mode} alert?</div>',
            unsafe_allow_html=True,
        )
        confirm_col, cancel_col = st.columns(2)
        with confirm_col:
            confirmed = compat(st.button, "✕ Delete", type="secondary", stretch=True, key="btn_clear_yes")
        with cancel_col:
            cancelled = compat(st.button, "Cancel", type="primary", stretch=True, key="btn_clear_no")
        if confirmed:
            clear_alerts(current_mode)
            st.session_state["confirm_clear"] = False
            bump_epoch()
            st.rerun()
        if cancelled:
            st.session_state["confirm_clear"] = False
            st.rerun()
    elif compat(st.button, "✕ Clear Alert Database", type="secondary", stretch=True, key="btn_clear"):
        st.session_state["confirm_clear"] = True
        st.rerun()

    st.divider()
    st.markdown('<div class="sidebar-section-label">◈ Threat & Time Filters</div>', unsafe_allow_html=True)

    time_window = st.selectbox("Time Window:", options=list(TIME_WINDOWS.keys()), index=2)

    selected_attacks = st.multiselect(
        "Threat Vectors:",
        options=ATTACK_TYPES,
        default=ATTACK_TYPES,
    )
    selected_severity = st.multiselect(
        "Severity Tiers:",
        options=SEVERITIES,
        default=SEVERITIES,
    )

    st.markdown(
        h(
            f'''
            <div class="sidebar-footer">
                Active store <b>{esc(get_db_name(current_mode))}</b><br>
                {BRAND_EN} v{APP_VERSION} - silent observer, early warning
            </div>
            '''
        ),
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# Master top-level dashboard placeholder (right after the sidebar)
# ---------------------------------------------------------------------------
dashboard_placeholder = st.empty()

# Flush the placeholder DOM before anything else when the operation mode changes
if current_mode != st.session_state["last_mode"]:
    dashboard_placeholder.empty()
    st.session_state["last_mode"] = current_mode
    st.session_state["confirm_clear"] = False
    st.session_state["alert_search"] = ""
    bump_epoch()
    st.rerun()

epoch = st.session_state["view_epoch"]


# ---------------------------------------------------------------------------
# Data access & filtering
# ---------------------------------------------------------------------------
def load_alerts(mode):
    rows = fetch_alerts(mode, limit=MAX_ROWS)
    return pd.DataFrame(rows, columns=list(ALERT_COLUMNS))


def apply_filters(raw, window, attacks, severities, now_dt):
    """Time window first, then threat vector + severity. Returns (window_df, filtered_df)."""
    if raw.empty:
        empty = pd.DataFrame(columns=list(ALERT_COLUMNS) + ["_ts"])
        return empty, empty

    df = raw.copy()
    df["_ts"] = pd.to_datetime(df["timestamp"], errors="coerce")

    delta = TIME_WINDOWS[window]
    if delta is not None:
        df = df[df["_ts"] >= now_dt - delta]

    filtered = df[df["attack_type"].isin(attacks) & df["severity"].isin(severities)]
    return df, filtered


def apply_search(df, query):
    """Case-insensitive AND search over every column; full IPv4 tokens match whole addresses only."""
    tokens = [t for t in query.lower().split() if t]
    if not tokens or df.empty:
        return df

    haystack = (
        df["timestamp"].astype(str)
        + " "
        + df["attack_type"].astype(str)
        + " "
        + df["source_ip"].astype(str)
        + " "
        + df["severity"].astype(str)
        + " "
        + df["details"].astype(str)
    ).str.lower()

    mask = pd.Series(True, index=df.index)
    for token in tokens:
        if IPV4_RE.match(token):
            pattern = r"(?<!\d)(?<!\d\.)" + re.escape(token) + r"(?!\d)(?!\.\d)"
            mask &= haystack.str.contains(pattern, regex=True)
        else:
            mask &= haystack.str.contains(token, regex=False)
    return df[mask]


now_dt = datetime.now()
raw_df = load_alerts(current_mode)
window_df, filtered_df = apply_filters(raw_df, time_window, selected_attacks, selected_severity, now_dt)

# ---------------------------------------------------------------------------
# Metrics (always computed from the filtered frame)
# ---------------------------------------------------------------------------
total_alerts = len(filtered_df)
high_count = int((filtered_df["severity"] == "High").sum()) if total_alerts else 0
med_count = int((filtered_df["severity"] == "Medium").sum()) if total_alerts else 0
low_count = int((filtered_df["severity"] == "Low").sum()) if total_alerts else 0
unique_ips = int(filtered_df["source_ip"].nunique()) if total_alerts else 0
pkts_val = f"{sniffer_state['packets_inspected']:,}" if current_mode == "live" else "SIMULATED"

if total_alerts:
    top_ip_series = filtered_df["source_ip"].value_counts()
    top_attacker_ip = str(top_ip_series.index[0])
    top_attacker_hits = f"{int(top_ip_series.iloc[0])} Recorded Events"
else:
    top_attacker_ip = "None"
    top_attacker_hits = "0 Active Threats"

real_active_status = is_sniffer_active()

if high_count > 0:
    posture_pill = '<div class="soc-pill posture-critical">■ CRITICAL THREAT</div>'
elif med_count > 0:
    posture_pill = '<div class="soc-pill posture-elevated">▲ ELEVATED RISK</div>'
else:
    posture_pill = '<div class="soc-pill posture-secure">● SYSTEM SECURE</div>'

full_iface = sniffer_state["current_iface"] if current_mode == "live" else "SANDBOX"
iface_short = full_iface.split(" - ")[0]
if len(iface_short) > 28:
    iface_short = iface_short[:27] + "…"
interface_pill = f'<div class="soc-pill iface-pill" title="{esc(full_iface)}">INTERFACE: {esc(iface_short)}</div>'

if current_mode == "live":
    if real_active_status:
        sniffer_pill = '<div class="soc-pill sniffer-active"><span class="pulse-dot"></span>SNIFFER ACTIVE</div>'
    else:
        sniffer_pill = '<div class="soc-pill sniffer-stopped">● SNIFFER STOPPED</div>'
else:
    sniffer_pill = '<div class="soc-pill sniffer-demo">◆ DEMO SIMULATION</div>'


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------
def kpi_card(glow, label_html, value, sub, value_class="kpi-value", value_style="", sub_style=""):
    value_attr = f' style="{value_style}"' if value_style else ""
    sub_attr = f' style="{sub_style}"' if sub_style else ""
    return h(
        f'''
        <div class="kpi-card {glow}">
            <div class="kpi-label">{label_html}</div>
            <div class="{value_class}"{value_attr}>{value}</div>
            <div class="kpi-sub"{sub_attr}>{sub}</div>
        </div>
        '''
    )


def bento_title(text, meta=""):
    meta_html = f'<span class="bento-meta">{esc(meta)}</span>' if meta else ""
    return f'<div class="bento-title">{text}{meta_html}</div>'


def radar_card(variant, title, subtitle_html, chips=()):
    chips_html = "".join(f'<span class="radar-chip">{chip}</span>' for chip in chips)
    chips_block = f'<div class="radar-chips">{chips_html}</div>' if chips_html else ""
    return h(
        f'''
        <div class="soc-radar-card radar-{variant}">
            <div class="radar-wrap">
                <div class="radar-rings"></div>
                <div class="radar-cross"></div>
                <div class="radar-sweep"></div>
                <div class="radar-core">
                    <svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="rgb(var(--radar))" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <circle cx="12" cy="11" r="2.2"/>
                        <path d="M7.6 11c1.2-1.9 2.8-2.9 4.4-2.9s3.2 1 4.4 2.9"/>
                    </svg>
                </div>
            </div>
            <div class="soc-radar-title">{title}</div>
            <div class="soc-radar-sub">{subtitle_html}</div>
            {chips_block}
        </div>
        '''
    )


def severity_chip(severity):
    glyph = {"High": "■", "Medium": "▲", "Low": "●"}.get(severity, "●")
    return f'<span class="sev-chip {severity.lower()}">{glyph} {esc(severity.upper())}</span>'


# ---------------------------------------------------------------------------
# Altair charts
# ---------------------------------------------------------------------------
SEV_SCALE = alt.Scale(domain=SEVERITIES, range=SEV_COLORS)


def style_chart(chart, height=CHART_HEIGHT):
    return (
        chart.properties(height=height, background="transparent")
        .configure_view(strokeWidth=0)
        .configure_axis(
            labelColor="#94a3b8",
            titleColor="#64748b",
            labelFont=MONO,
            titleFont=MONO,
            labelFontSize=10,
            titleFontSize=10,
            gridColor="rgba(148, 163, 184, 0.12)",
            domainColor="rgba(148, 163, 184, 0.25)",
            tickColor="rgba(148, 163, 184, 0.25)",
        )
        .configure_legend(
            labelColor="#cbd5e1",
            titleColor="#94a3b8",
            labelFont=MONO,
            titleFont=MONO,
            labelFontSize=10,
        )
    )


def render_chart(chart, key):
    compat(st.altair_chart, chart, theme=None, stretch=True, key=key)


def build_vector_chart(df, attacks):
    counts = df["attack_type"].value_counts()
    data = pd.DataFrame(
        {
            "Attack Type": list(attacks),
            "Count": [int(counts.get(name, 0)) for name in attacks],
        }
    )
    hover = alt.selection_point(name="vec_hover", fields=["Attack Type"], on="mouseover", clear="mouseout", empty=False)
    bars = (
        alt.Chart(data)
        .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, size=44)
        .encode(
            x=alt.X("Attack Type:N", sort=list(attacks), axis=alt.Axis(labelAngle=0, labelColor="#cbd5e1", title=None)),
            y=alt.Y("Count:Q", axis=alt.Axis(title="Alerts", tickMinStep=1)),
            color=alt.condition(hover, alt.value("#38bdf8"), alt.value("#065f88")),
            tooltip=["Attack Type", "Count"],
        )
        .add_params(hover)
    )
    labels = (
        alt.Chart(data)
        .mark_text(dy=-8, color="#e2e8f0", font=MONO, fontSize=11, fontWeight=600)
        .encode(x=alt.X("Attack Type:N", sort=list(attacks)), y="Count:Q", text="Count:Q")
    )
    return style_chart(alt.layer(bars, labels))


def build_severity_chart(df):
    counts = df["severity"].value_counts()
    data = pd.DataFrame(
        {
            "Severity": SEVERITIES,
            "Count": [int(counts.get(name, 0)) for name in SEVERITIES],
        }
    )
    data = data[data["Count"] > 0]
    arc = (
        alt.Chart(data)
        .mark_arc(innerRadius=56, outerRadius=90, stroke="#091322", strokeWidth=2)
        .encode(
            theta=alt.Theta("Count:Q"),
            color=alt.Color(
                "Severity:N",
                scale=SEV_SCALE,
                legend=alt.Legend(title=None, orient="right"),
            ),
            tooltip=["Severity", "Count"],
        )
    )
    total_label = (
        alt.Chart(pd.DataFrame({"t": [str(int(data["Count"].sum()))]}))
        .mark_text(font=MONO, fontSize=26, fontWeight=700, color="#ffffff", dy=-6)
        .encode(text="t:N")
    )
    caption = (
        alt.Chart(pd.DataFrame({"t": ["ALERTS"]}))
        .mark_text(font=MONO, fontSize=9, color="#64748b", dy=14)
        .encode(text="t:N")
    )
    return style_chart(alt.layer(arc, total_label, caption))


def bucket_minutes(span):
    minutes = span.total_seconds() / 60.0
    if minutes <= 20:
        return 1
    if minutes <= 120:
        return 5
    if minutes <= 30 * 60:
        return 60
    if minutes <= 10 * 24 * 60:
        return 360
    return 1440


BUCKET_LABELS = {1: "1-minute buckets", 5: "5-minute buckets", 60: "hourly buckets", 360: "6-hour buckets", 1440: "daily buckets"}


def build_timeline(df, window, now_ts):
    """Return (chart, bucket_minutes) for the stacked severity timeline, or (None, None)."""
    stamps = df.dropna(subset=["_ts"])
    if stamps.empty:
        return None, None

    delta = TIME_WINDOWS[window]
    now_ts = pd.Timestamp(now_ts)
    first_alert = stamps["_ts"].min()

    # Zoom to the data (never wider than the selected window, never narrower than 10 minutes)
    start = first_alert if delta is None else max(now_ts - delta, first_alert)
    start = min(start, now_ts - pd.Timedelta(minutes=10))
    if delta is not None:
        start = max(start, now_ts - delta)

    minutes = bucket_minutes(now_ts - start)
    step = pd.Timedelta(minutes=minutes)
    freq = f"{minutes}min"

    bucket = stamps["_ts"].dt.floor(freq)
    counts = (
        pd.DataFrame({"bucket": bucket, "severity": stamps["severity"]})
        .groupby(["bucket", "severity"])
        .size()
        .unstack(fill_value=0)
        .reindex(columns=SEVERITIES, fill_value=0)
    )
    full_index = pd.date_range(start.floor(freq), now_ts.floor(freq), freq=step)
    counts = counts.reindex(full_index, fill_value=0)
    counts.index.name = "bucket"

    wide = counts.reset_index()
    wide["Total"] = wide[SEVERITIES].sum(axis=1)

    stamp_fmt = "%H:%M" if minutes <= 60 else ("%d %b %H:%M" if minutes < 1440 else "%d %b")
    wide["readout"] = wide.apply(
        lambda r: f"{r['bucket']:{stamp_fmt}}   H {int(r['High'])}   M {int(r['Medium'])}   L {int(r['Low'])}",
        axis=1,
    )

    long = wide.melt(id_vars="bucket", value_vars=SEVERITIES, var_name="severity", value_name="alerts")
    long["sev_rank"] = long["severity"].map(SEV_RANK)

    hover = alt.selection_point(
        name="time_hover", fields=["bucket"], nearest=True, on="mouseover", clear="mouseout", empty=False
    )
    x_axis = alt.Axis(format=stamp_fmt, title=None, labelOverlap=True, labelColor="#94a3b8")

    area = (
        alt.Chart(long)
        .mark_area(interpolate="monotone", opacity=0.55, line={"strokeWidth": 1.6})
        .encode(
            x=alt.X("bucket:T", axis=x_axis),
            y=alt.Y("alerts:Q", stack="zero", axis=alt.Axis(title="Alerts", tickMinStep=1)),
            color=alt.Color(
                "severity:N",
                scale=SEV_SCALE,
                legend=alt.Legend(title=None, orient="top", direction="horizontal"),
            ),
            order=alt.Order("sev_rank:Q", sort="ascending"),
        )
    )
    selectors = (
        alt.Chart(wide)
        .mark_point(opacity=0)
        .encode(x="bucket:T")
        .add_params(hover)
    )
    rule = (
        alt.Chart(wide)
        .mark_rule(color="#7dd3fc", strokeWidth=1, strokeDash=[3, 3], opacity=0.85)
        .encode(x="bucket:T")
        .transform_filter(hover)
    )

    half = max(1, len(wide) // 2)
    readout_style = {"font": MONO, "fontSize": 11, "fontWeight": 600, "color": "#e0f2fe", "baseline": "top"}
    readout_left = (
        alt.Chart(wide.iloc[:half])
        .mark_text(align="left", dx=8, **readout_style)
        .encode(x="bucket:T", y=alt.value(2), text="readout:N")
        .transform_filter(hover)
    )
    readout_right = (
        alt.Chart(wide.iloc[half:])
        .mark_text(align="right", dx=-8, **readout_style)
        .encode(x="bucket:T", y=alt.value(2), text="readout:N")
        .transform_filter(hover)
    )
    return style_chart(alt.layer(area, selectors, rule, readout_left, readout_right)), minutes


def build_top_ips_chart(df, limit=6):
    grouped = df.groupby(["source_ip", "severity"]).size().reset_index(name="alerts")
    totals = grouped.groupby("source_ip")["alerts"].sum().sort_values(ascending=False).head(limit)
    order = [str(ip) for ip in totals.index]
    grouped = grouped[grouped["source_ip"].isin(order)].copy()
    grouped["sev_rank"] = grouped["severity"].map(SEV_RANK)
    total_df = pd.DataFrame({"source_ip": order, "total": [int(totals[ip]) for ip in order]})

    bars = (
        alt.Chart(grouped)
        .mark_bar(size=16, cornerRadiusEnd=3)
        .encode(
            y=alt.Y(
                "source_ip:N",
                sort=order,
                axis=alt.Axis(title=None, labelColor="#e2e8f0", labelLimit=150, ticks=False, domain=False),
            ),
            x=alt.X("alerts:Q", stack="zero", axis=alt.Axis(title=None, tickMinStep=1)),
            color=alt.Color("severity:N", scale=SEV_SCALE, legend=None),
            order=alt.Order("sev_rank:Q", sort="ascending"),
            tooltip=[alt.Tooltip("source_ip:N", title="Source IP"), alt.Tooltip("severity:N", title="Severity"), alt.Tooltip("alerts:Q", title="Alerts")],
        )
    )
    labels = (
        alt.Chart(total_df)
        .mark_text(align="left", dx=6, color="#94a3b8", font=MONO, fontSize=11, fontWeight=600)
        .encode(y=alt.Y("source_ip:N", sort=order), x=alt.X("total:Q"), text="total:Q")
    )
    return style_chart(alt.layer(bars, labels))


# ---------------------------------------------------------------------------
# Telemetry table styling
# ---------------------------------------------------------------------------
def style_telemetry_table(df_in):
    def severity_badge(val):
        if val == "High":
            return "background-color: rgba(239, 68, 68, 0.20); color: #fca5a5; font-weight: 700; font-family: 'JetBrains Mono', monospace;"
        if val == "Medium":
            return "background-color: rgba(245, 158, 11, 0.20); color: #fcd34d; font-weight: 700; font-family: 'JetBrains Mono', monospace;"
        if val == "Low":
            return "background-color: rgba(16, 185, 129, 0.18); color: #6ee7b7; font-weight: 700; font-family: 'JetBrains Mono', monospace;"
        return ""

    mono_cols = "font-family: 'JetBrains Mono', monospace; color: #e2e8f0;"
    styler = df_in.style.set_properties(**{"background-color": "#0b1626", "color": "#e2e8f0"})
    apply_cells = getattr(styler, "map", None) or styler.applymap
    styler = apply_cells(severity_badge, subset=["severity"])
    return apply_cells(lambda _: mono_cols, subset=["id", "timestamp", "source_ip"])


# ---------------------------------------------------------------------------
# Render the ENTIRE main dashboard strictly inside the master placeholder
# ---------------------------------------------------------------------------
with dashboard_placeholder.container():
    # 1) Flush top SOC command bar (left padding keeps the native >> arrow clear of the brand)
    st.markdown(
        h(
            f'''
            <div class="soc-command-bar">
                <div class="soc-brand-title">
                    <span>{BRAND_EN}</span>
                    <span class="divider">|</span>
                    <span class="arabic" lang="ar">{BRAND_AR}</span>
                </div>
                <div class="soc-pills-group">
                    {posture_pill}
                    {interface_pill}
                    {sniffer_pill}
                </div>
            </div>
            '''
        ),
        unsafe_allow_html=True,
    )

    if current_mode == "live" and not real_active_status:
        err_msg = esc(str(sniffer_state["error"] or "Sniffer thread is not running."))
        st.markdown(
            h(
                f'''
                <div class="soc-alert-banner">
                    <span class="soc-alert-icon">▲</span>
                    <div>
                        <div class="soc-alert-title">Capture engine inactive</div>
                        <div class="soc-alert-text">{err_msg}</div>
                    </div>
                </div>
                '''
            ),
            unsafe_allow_html=True,
        )
        if compat(st.button, "⟳ Restart Packet Capture Engine", type="primary", key=f"restart_{epoch}"):
            start_or_restart_sniffer(sniffer_state["current_iface"])
            st.rerun()

    # 2) Six-column Bento KPI row
    k1, k2, k3, k4, k5, k6 = st.columns(6)

    with k1:
        st.markdown(
            kpi_card("kpi-glow-cyan", "◈ Total Alerts", total_alerts, "Total Recorded Events"),
            unsafe_allow_html=True,
        )
    with k2:
        st.markdown(
            kpi_card(
                "kpi-glow-red",
                '<span style="color:#ef4444;">■</span> High Severity',
                high_count,
                "Critical MitM / Floods",
                value_style="color: #f87171;",
                sub_style="color: #fca5a5;",
            ),
            unsafe_allow_html=True,
        )
    with k3:
        st.markdown(
            kpi_card(
                "kpi-glow-amber",
                '<span style="color:#f59e0b;">▲</span> Medium Severity',
                med_count,
                "Active Scans / Bursts",
                value_style="color: #fbbf24;",
                sub_style="color: #fde68a;",
            ),
            unsafe_allow_html=True,
        )
    with k4:
        st.markdown(
            kpi_card(
                "kpi-glow-emerald",
                '<span style="color:#10b981;">●</span> Low Severity',
                low_count,
                "Early Recon Probes",
                value_style="color: #34d399;",
                sub_style="color: #a7f3d0;",
            ),
            unsafe_allow_html=True,
        )
    with k5:
        st.markdown(
            kpi_card(
                "kpi-glow-sky",
                '<span style="color:#38bdf8;">◈</span> Packets Inspected',
                pkts_val,
                f"{unique_ips} Distinct Source IPs",
            ),
            unsafe_allow_html=True,
        )
    with k6:
        st.markdown(
            kpi_card(
                "kpi-glow-purple",
                '<span style="color:#818cf8;">▸</span> Top Attacker IP',
                esc(top_attacker_ip),
                esc(top_attacker_hits),
                value_class="kpi-value-ip",
            ),
            unsafe_allow_html=True,
        )

    st.write("")

    # 3) Strictly mutually exclusive body: EITHER (charts + table) OR (radar / shield empty state)
    if not filtered_df.empty:
        # --- Row 1: vector distribution + severity breakdown ---
        c_left, c_right = st.columns([3, 2])

        with c_left:
            with st.container(border=True):
                st.markdown(bento_title("◈ Threat Vector Distribution"), unsafe_allow_html=True)
                vector_order = [a for a in ATTACK_TYPES if a in selected_attacks] or ATTACK_TYPES
                render_chart(build_vector_chart(filtered_df, vector_order), f"bar_{current_mode}_{epoch}")

        with c_right:
            with st.container(border=True):
                st.markdown(bento_title("◈ Multi-Tier Severity Breakdown"), unsafe_allow_html=True)
                render_chart(build_severity_chart(filtered_df), f"donut_{current_mode}_{epoch}")

        # --- Row 2: interactive timeline + top offending IPs ---
        t_left, t_right = st.columns([3, 2])

        with t_left:
            with st.container(border=True):
                timeline_chart, timeline_minutes = build_timeline(filtered_df, time_window, now_dt)
                st.markdown(
                    bento_title("◈ Threat Activity Timeline", BUCKET_LABELS.get(timeline_minutes, "")),
                    unsafe_allow_html=True,
                )
                if timeline_chart is not None:
                    render_chart(timeline_chart, f"timeline_{current_mode}_{epoch}")
                else:
                    st.markdown('<div class="table-empty">No timestamped events to plot.</div>', unsafe_allow_html=True)

        with t_right:
            with st.container(border=True):
                st.markdown(bento_title("◈ Top Offending Source IPs", "top 6 by alert volume"), unsafe_allow_html=True)
                render_chart(build_top_ips_chart(filtered_df), f"topips_{current_mode}_{epoch}")

        # --- Telemetry table with IP inspector / quick search ---
        with st.container(border=True):
            head_col, search_col, export_col = columns_centered([3, 3, 2])

            with head_col:
                st.markdown(bento_title("◈ Live Intrusion Alert Telemetry"), unsafe_allow_html=True)

            with search_col:
                search_query = st.text_input(
                    "Search alerts",
                    key="alert_search",
                    placeholder="Search IP or keyword (e.g. 192.168.10.55 high)",
                    label_visibility="collapsed",
                )

            search_query = (search_query or "").strip()[:120]
            table_df = apply_search(filtered_df, search_query)
            view_df = table_df[list(ALERT_COLUMNS)]

            with export_col:
                csv_bytes = view_df.to_csv(index=False).encode("utf-8")
                compat(
                    st.download_button,
                    label="▸ Export Telemetry (CSV)",
                    data=csv_bytes,
                    file_name=f"marsad_telemetry_{current_mode}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    stretch=True,
                    key=f"csv_{current_mode}_{epoch}",
                )

            # IP Inspector: a single, complete IPv4 address in the search box
            if IPV4_RE.match(search_query):
                ip_events = filtered_df[filtered_df["source_ip"] == search_query]
                if not ip_events.empty:
                    worst = min(ip_events["severity"], key=lambda s: SEV_RANK.get(s, 9))
                    vectors = ", ".join(sorted(ip_events["attack_type"].unique()))
                    stamps = ip_events["timestamp"].astype(str)
                    st.markdown(
                        h(
                            f'''
                            <div class="ip-inspector">
                                <span class="ip-tag">◈ IP INSPECTOR</span>
                                <span class="ip-addr">{esc(search_query)}</span>
                                {severity_chip(worst)}
                                <span><b>{len(ip_events)}</b> events</span>
                                <span>vectors <b>{esc(vectors)}</b></span>
                                <span>first seen <b>{esc(stamps.min())}</b></span>
                                <span>last seen <b>{esc(stamps.max())}</b></span>
                            </div>
                            '''
                        ),
                        unsafe_allow_html=True,
                    )

            shown = len(view_df)
            st.markdown(
                f'<div class="table-meta">Showing <b>{shown}</b> of <b>{total_alerts}</b> events in <b>{esc(time_window)}</b></div>',
                unsafe_allow_html=True,
            )

            if view_df.empty:
                st.markdown(
                    f'<div class="table-empty">No alerts match <b>{esc(search_query)}</b>. Clear the search box to see all events.</div>',
                    unsafe_allow_html=True,
                )
            else:
                compat(
                    st.dataframe,
                    style_telemetry_table(view_df),
                    stretch=True,
                    hide_index=True,
                    height=420,
                    key=f"table_{current_mode}_{epoch}",
                    column_config={
                        "id": st.column_config.NumberColumn("Event ID", width="small"),
                        "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                        "attack_type": st.column_config.TextColumn("Threat Vector", width="medium"),
                        "source_ip": st.column_config.TextColumn("Source IPv4", width="medium"),
                        "severity": st.column_config.TextColumn("Severity Tier", width="small"),
                        "details": st.column_config.TextColumn("Matched Rule & Telemetry Details", width="large"),
                    },
                )

    else:
        hidden_by_filters = len(window_df)
        if hidden_by_filters > 0:
            st.markdown(
                radar_card(
                    "filter",
                    "◈ No Events Match the Active Filters",
                    f"<b>{hidden_by_filters}</b> stored event(s) in <b>{esc(time_window)}</b> are hidden by the "
                    "Threat Vector / Severity Tier selection.<br>Re-enable the missing tiers in the sidebar to bring them back.",
                ),
                unsafe_allow_html=True,
            )
        elif current_mode == "live":
            st.markdown(
                radar_card(
                    "live",
                    "● Active Monitoring — Zero Intrusion Signatures Detected",
                    f"Listening on interface <b>{esc(sniffer_state['current_iface'])}</b> ({pkts_val} packets inspected).<br>"
                    f"No anomalous ARP replies, port sweeps, or SYN floods recorded in <b>{esc(time_window)}</b>.",
                    chips=("● ARP SPOOFING ARMED", "● PORT SCAN ARMED", "● SYN FLOOD ARMED"),
                ),
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                radar_card(
                    "demo",
                    "◆ Sandbox Simulation Standby",
                    f"No simulated events recorded in <b>{esc(time_window)}</b>.<br>"
                    "Click <b>▸ Inject Simulated Alerts (1-3)</b> in the sidebar to generate multi-tier sandbox telemetry.",
                    chips=("◆ DEMO DATABASE ISOLATED", "◆ NO LIVE TRAFFIC USED"),
                ),
                unsafe_allow_html=True,
            )

# ---------------------------------------------------------------------------
# Clean non-blocking auto-refresh after the master placeholder has rendered
# ---------------------------------------------------------------------------
if current_mode == "live" and auto_refresh:
    time.sleep(REFRESH_SECONDS)
    st.rerun()