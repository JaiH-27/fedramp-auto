"""
fedramp_auto.dashboard.render
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Builds the dashboard as one self-contained HTML file: styles, scripts and scan
data are all inlined, and a Content-Security-Policy stops the page from making
any network request.  IaC findings never leave the machine.

Scan data comes from user files, so it is escaped for embedding in a ``<script>``
element here and only ever written to the DOM as text by the page's scripts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ASSETS = Path(__file__).parent / "assets"

# Load order: tabs appear in this order
VIEWS: tuple[str, ...] = ("overview", "ksi", "remediation", "history",)

_SLOT = re.compile(r"__(STYLES|DATA|SCRIPTS)__")
_UNSAFE_IN_SCRIPT = {
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    " ": "\\u2028",
    " ": "\\u2029",
}


def _asset(name: str) -> str:
    return (ASSETS / name).read_text(encoding="utf-8")


def _embed_json(data: Any) -> str:
    """JSON that cannot close the ``<script>`` element it is embedded in."""
    text = json.dumps(data, ensure_ascii=False)
    return re.sub("[<>&  ]", lambda m: _UNSAFE_IN_SCRIPT[m.group()], text)


def render_page(view_model: dict[str, Any]) -> str:
    """The complete dashboard page for *view_model*."""
    styles = [_asset("core.css"), *(_asset(f"{view}.css") for view in VIEWS)]
    scripts = [_asset("core.js"), *(_asset(f"{view}.js") for view in VIEWS), "Dash.start();"]
    slots = {
        "STYLES": "\n".join(styles),
        "DATA": _embed_json(view_model),
        "SCRIPTS": "\n".join(scripts),
    }
    # One pass, so text inside the scan data can never be taken for a slot
    return _SLOT.sub(lambda m: slots[m.group(1)], _asset("page.html"))
