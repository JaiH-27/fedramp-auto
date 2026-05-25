"""
fedramp_auto.parser.terraform
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Parses Terraform HCL files into a sanitized, structured representation
suitable for passing to the LLM analysis layer.

Key design decisions:
  - Raw string *values* that look like secrets are redacted before any
    data leaves this module.  Resource *types* and *attribute names* are
    always preserved because the compliance mapper needs them.
  - Returns a list of ParsedResource dataclasses, not raw dicts, so the
    rest of the pipeline has a stable contract to program against.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import hcl2

log = logging.getLogger(__name__)

# ── Secret-detection patterns ──────────────────────────────────────────────────
# These are applied to string *values* only.  A match causes the value to be
# replaced with the placeholder below.
_SECRET_PLACEHOLDER = "<REDACTED>"

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key"
        r"|auth[_-]?key|client[_-]?secret|db[_-]?pass|db[_-]?password)",
        # AWS key shapes
        r"AKIA[0-9A-Z]{16}",
        # Long base64 blobs (>40 chars of base64) — likely encoded secrets
        r"^[A-Za-z0-9+/]{40,}={0,2}$",
        # PEM headers
        r"-----BEGIN .* KEY-----",
    ]
]

# Attribute *names* whose values should always be redacted regardless of content
_SECRET_ATTR_NAMES: frozenset[str] = frozenset(
    {
        "password", "passwd", "secret", "token", "api_key", "access_key",
        "secret_key", "private_key", "auth_token", "client_secret",
        "db_password", "master_password", "kms_key_id", "certificate_body",
        "private_key_pem", "certificate_pem",
    }
)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ParsedResource:
    """A single Terraform resource after parsing and sanitization."""

    resource_type: str          # e.g. "aws_s3_bucket"
    resource_name: str          # e.g. "my_bucket"
    attributes: dict[str, Any]  # sanitized attribute map
    source_file: str            # relative path of the originating .tf file

    @property
    def identifier(self) -> str:
        return f"{self.resource_type}.{self.resource_name}"


@dataclass
class ParseResult:
    """Aggregate result of parsing a directory of .tf files."""

    resources: list[ParsedResource] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def resource_types(self) -> list[str]:
        return sorted({r.resource_type for r in self.resources})

    def by_type(self, resource_type: str) -> list[ParsedResource]:
        return [r for r in self.resources if r.resource_type == resource_type]


# ── Sanitization helpers ──────────────────────────────────────────────────────

def _looks_like_secret_value(value: str) -> bool:
    """Return True if a string value matches any known secret pattern."""
    return any(p.search(value) for p in _SECRET_PATTERNS)


def _sanitize_value(attr_name: str, value: Any, depth: int = 0) -> Any:
    """
    Recursively walk a value tree and redact anything that looks like a secret.
    Depth limit prevents infinite recursion on pathological inputs.
    """
    if depth > 8:
        return value

    if isinstance(value, str):
        if attr_name in _SECRET_ATTR_NAMES or _looks_like_secret_value(value):
            return _SECRET_PLACEHOLDER
        return value

    if isinstance(value, dict):
        return {
            k: _sanitize_value(k, v, depth + 1)
            for k, v in value.items()
        }

    if isinstance(value, list):
        return [_sanitize_value(attr_name, item, depth + 1) for item in value]

    # int, float, bool — safe to pass through as-is
    return value


def _sanitize_attributes(raw: dict[str, Any]) -> dict[str, Any]:
    return {k: _sanitize_value(k, v) for k, v in raw.items()}


# ── HCL parsing ───────────────────────────────────────────────────────────────

def _parse_file(path: Path) -> tuple[list[ParsedResource], list[str]]:
    """Parse a single .tf file.  Returns (resources, errors)."""
    resources: list[ParsedResource] = []
    errors: list[str] = []

    try:
        with path.open("r", encoding="utf-8") as fh:
            tf = hcl2.load(fh)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{path}: {exc}")
        return resources, errors

    raw_resources: dict[str, Any] = tf.get("resource", {})

    # hcl2 gives us:  {"resource": [{"aws_s3_bucket": {"my_bucket": {...}}}]}
    # It can be a list of dicts (one per block) or a single dict.
    if isinstance(raw_resources, list):
        blocks = raw_resources
    else:
        blocks = [raw_resources]

    for block in blocks:
        for resource_type_raw, instances in block.items():
            # hcl2 sometimes wraps keys in extra quotes — strip them
            resource_type = resource_type_raw.strip('"')
            if not isinstance(instances, dict):
                continue
            for resource_name_raw, attrs in instances.items():
                resource_name = resource_name_raw.strip('"')
                if not isinstance(attrs, dict):
                    continue
                sanitized = _sanitize_attributes(attrs)
                resources.append(
                    ParsedResource(
                        resource_type=resource_type,
                        resource_name=resource_name,
                        attributes=sanitized,
                        source_file=str(path),
                    )
                )

    log.debug("Parsed %d resource(s) from %s", len(resources), path)
    return resources, errors


# ── Public API ────────────────────────────────────────────────────────────────

def parse_directory(directory: str | Path) -> ParseResult:
    """
    Recursively parse all *.tf files under *directory*.

    Returns a ParseResult containing every resource found across all files,
    plus a list of per-file error strings for any files that failed to parse.

    Example
    -------
    >>> result = parse_directory("./infra")
    >>> for r in result.resources:
    ...     print(r.identifier, r.attributes)
    """
    root = Path(directory).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Directory not found: {root}")

    result = ParseResult()
    tf_files = sorted(root.rglob("*.tf"))

    if not tf_files:
        log.warning("No .tf files found under %s", root)
        return result

    log.info("Parsing %d .tf file(s) under %s", len(tf_files), root)

    for tf_path in tf_files:
        resources, errors = _parse_file(tf_path)
        result.resources.extend(resources)
        result.errors.extend(errors)

    log.info(
        "Parsed %d resource(s) across %d file(s); %d error(s)",
        len(result.resources),
        len(tf_files),
        len(result.errors),
    )
    return result


def parse_file(path: str | Path) -> ParseResult:
    """Parse a single .tf file."""
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    resources, errors = _parse_file(p)
    return ParseResult(resources=resources, errors=errors)
