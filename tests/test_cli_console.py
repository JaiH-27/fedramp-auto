"""CLI output must not crash on legacy (non-UTF-8) console encodings such as cp1252."""

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fedramp_auto.cli.main import _harden_stream, _spinner_name


def _stream(encoding: str) -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(), encoding=encoding)


def test_cp1252_stream_replaces_unencodable_chars():
    stream = _stream("cp1252")
    _harden_stream(stream)
    stream.write("⠋ Parsing… ✓ done — ok")  # braille spinner + check mark: not in cp1252
    stream.flush()
    out = stream.buffer.getvalue().decode("cp1252")
    assert out == "? Parsing… ? done — ok"


def test_utf8_stream_left_strict():
    stream = _stream("utf-8")
    _harden_stream(stream)
    assert stream.errors == "strict"


def test_stream_without_reconfigure_is_ignored():
    _harden_stream(io.StringIO())  # no encoding / reconfigure: must not raise


def test_spinner_falls_back_to_ascii():
    assert _spinner_name(_stream("cp1252")) == "line"
    assert _spinner_name(_stream("utf-8")) == "dots"
