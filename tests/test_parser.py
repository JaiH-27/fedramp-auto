"""Tests for fedramp_auto.parser.terraform"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from fedramp_auto.parser.terraform import (
    ParseResult,
    ParsedResource,
    _sanitize_value,
    parse_directory,
    parse_file,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "terraform"


# ── Sanitization unit tests ───────────────────────────────────────────────────

def test_redacts_password_attr_name():
    assert _sanitize_value("password", "hunter2") == "<REDACTED>"

def test_redacts_secret_attr_name():
    assert _sanitize_value("secret", "abc123") == "<REDACTED>"

def test_redacts_aws_key_pattern():
    assert _sanitize_value("value", "AKIAIOSFODNN7EXAMPLE") == "<REDACTED>"

def test_preserves_safe_string():
    assert _sanitize_value("bucket", "my-company-audit-logs") == "my-company-audit-logs"

def test_preserves_bool():
    assert _sanitize_value("enabled", True) is True

def test_preserves_int():
    assert _sanitize_value("retention", 35) == 35

def test_redacts_nested_password():
    result = _sanitize_value("config", {"password": "secret123"})
    assert result["password"] == "<REDACTED>"

def test_redacts_list_of_secrets():
    result = _sanitize_value("tokens", ["AKIAIOSFODNN7EXAMPLE", "safe-value"])
    assert result[0] == "<REDACTED>"
    assert result[1] == "safe-value"


# ── Integration tests against fixture ────────────────────────────────────────

@pytest.fixture(scope="module")
def parsed() -> ParseResult:
    return parse_directory(FIXTURE_DIR)

def test_finds_resources(parsed):
    assert len(parsed.resources) > 0

def test_finds_s3_bucket(parsed):
    buckets = parsed.by_type("aws_s3_bucket")
    assert len(buckets) >= 1

def test_finds_iam_role(parsed):
    assert parsed.by_type("aws_iam_role")

def test_finds_kms_key(parsed):
    assert parsed.by_type("aws_kms_key")

def test_finds_cloudtrail(parsed):
    assert parsed.by_type("aws_cloudtrail")

def test_password_is_redacted(parsed):
    db = parsed.by_type("aws_db_instance")
    assert db, "aws_db_instance not found"
    assert db[0].attributes.get("password") == "<REDACTED>"

def test_username_preserved(parsed):
    """Username is not a secret attr name — should survive."""
    db = parsed.by_type("aws_db_instance")
    assert db[0].attributes.get("username") is not None

def test_no_parse_errors(parsed):
    assert parsed.errors == [], f"Parse errors: {parsed.errors}"

def test_resource_identifier(parsed):
    db = parsed.by_type("aws_db_instance")[0]
    assert db.identifier == "aws_db_instance.app_db"

def test_resource_types_list(parsed):
    types = parsed.resource_types
    assert "aws_s3_bucket" in types
    assert "aws_kms_key" in types

def test_parse_file_single(tmp_path):
    tf = tmp_path / "single.tf"
    tf.write_text(
        'resource "aws_sqs_queue" "q" { name = "test-queue" delay_seconds = 0 }\n'
    )
    result = parse_file(tf)
    assert len(result.resources) == 1
    assert result.resources[0].resource_type == "aws_sqs_queue"

def test_parse_missing_dir_raises():
    with pytest.raises(FileNotFoundError):
        parse_directory("/nonexistent/path/xyz")

def test_parse_empty_dir(tmp_path):
    result = parse_directory(tmp_path)
    assert result.resources == []
