"""The KSI counts the README advertises must match the catalogue"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fedramp_auto.gaps.detector import all_ksi_ids

README = Path(__file__).parent.parent / "README.md"


def test_readme_states_the_real_ksi_counts():
    low, moderate = len(all_ksi_ids("low")), len(all_ksi_ids("moderate"))
    assert f"{low} (Low) / {moderate} (Moderate) FedRAMP KSIs" in README.read_text(encoding="utf-8")
