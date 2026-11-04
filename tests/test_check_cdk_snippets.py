"""Tests for scripts/check_cdk_snippets.py (the full Node.js run is opt-in)"""

import importlib.util
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "check_cdk_snippets", ROOT / "scripts" / "check_cdk_snippets.py"
)
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)


def test_wrap_hoists_imports_into_a_stack():
    snippet = "import * as s3 from 'aws-cdk-lib/aws-s3';\n\nnew s3.Bucket(this, 'B');"
    wrapped = check._wrap("KSI-SC-2", snippet)
    lines = wrapped.splitlines()
    assert lines[0] == "import * as s3 from 'aws-cdk-lib/aws-s3';"
    assert "export class SnippetSC2 extends __cdk.Stack {" in lines
    body = lines.index("    new s3.Bucket(this, 'B');")
    assert body > lines.index("    super(scope, id);")


def test_stack_class_names_are_unique():
    from fedramp_auto.advisor.remediation import _STATIC_REMEDIATIONS_CDK

    names = [check._stack_class(k) for k in _STATIC_REMEDIATIONS_CDK]
    assert len(set(names)) == len(names)


@pytest.mark.skipif(
    os.getenv("FEDRAMP_CHECK_CDK") != "1" or shutil.which("npm") is None,
    reason="set FEDRAMP_CHECK_CDK=1 (needs Node.js + network) to compile and synth snippets",
)
def test_cdk_snippets_compile_synth_and_close_their_ksi(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["check_cdk_snippets.py", "--workdir", str(tmp_path)])
    assert check.main() == 0
