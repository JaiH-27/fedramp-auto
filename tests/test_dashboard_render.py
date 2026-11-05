"""The dashboard page: self-contained, offline and safe with hostile scan data"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fedramp_auto.dashboard.render import ASSETS, VIEWS, render_page

SVG_NAMESPACE = "http://www.w3.org/2000/svg"


def _embedded_data(page: str) -> dict:
    match = re.search(r'<script type="application/json" id="scan-data">(.*?)</script>', page, re.S)
    assert match
    return json.loads(match.group(1))


def _model(text: str = "value") -> dict:
    return {"groups": [{"key": text, "target": text, "baseline": "low", "scans": []}]}


def test_data_round_trips_through_the_page():
    model = _model("infra · ünïcode")
    assert _embedded_data(render_page(model)) == model


def test_scan_data_cannot_close_the_script_element():
    hostile = "</script><script>alert(1)</script><!--"
    page = render_page(_model(hostile))
    assert hostile not in page
    assert _embedded_data(page) == _model(hostile)


def test_text_in_scan_data_is_not_taken_for_a_template_slot():
    page = render_page(_model("__SCRIPTS__"))
    assert _embedded_data(page) == _model("__SCRIPTS__")


def test_page_blocks_all_network_requests():
    assert "default-src 'none'" in render_page(_model())


def test_assets_reference_nothing_outside_the_page():
    for asset in ASSETS.iterdir():
        text = asset.read_text(encoding="utf-8").replace(SVG_NAMESPACE, "")
        assert not re.search(r"https?://|//cdn|@import|url\(", text), asset.name


def test_scripts_never_build_html_from_strings():
    for asset in ASSETS.glob("*.js"):
        text = asset.read_text(encoding="utf-8")
        assert "innerHTML" not in text and "insertAdjacentHTML" not in text, asset.name


def test_every_view_registers_itself():
    page = render_page(_model())
    for view in VIEWS:
        assert f'id: "{view}"' in page
