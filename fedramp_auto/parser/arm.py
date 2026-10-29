"""
fedramp_auto.parser.arm
~~~~~~~~~~~~~~~~~~~~~~~
Parses Azure Resource Manager (ARM) JSON templates into the same sanitized
ParsedResource representation used for Terraform, so the mapper, gap
detector, and OSCAL generator work unchanged.

Key design decisions:
  - Only JSON files whose $schema is an ARM deploymentTemplate are parsed.
    Other JSON in the tree (package.json, parameter files, etc.) is skipped.
  - Nested child resources are flattened, with their type expanded to the
    full form (e.g. "blobServices" under a storage account becomes
    "Microsoft.Storage/storageAccounts/blobServices").
  - Simple "[parameters('x')]" / "[variables('x')]" expressions are resolved
    from defaultValue / variables so static rules can see real settings.
    secureString / secureObject parameters are never resolved.
  - Sanitization reuses the Terraform parser's secret redaction.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from fedramp_auto.parser.terraform import ParsedResource, ParseResult, _sanitize_attributes

log = logging.getLogger(__name__)

_ARM_SCHEMA_MARKER = "deploymenttemplate.json"

# Keys that describe the resource itself rather than its configuration
_STRUCTURAL_KEYS = frozenset({"type", "resources", "dependsOn", "apiVersion", "condition", "copy"})

_PARAM_REF = re.compile(r"^\[\s*parameters\(\s*'([^']+)'\s*\)\s*\]$", re.IGNORECASE)
_VAR_REF = re.compile(r"^\[\s*variables\(\s*'([^']+)'\s*\)\s*\]$", re.IGNORECASE)

_SECURE_PARAM_TYPES = frozenset({"securestring", "secureobject"})


# ── Template detection ────────────────────────────────────────────────────────

def is_arm_template(doc: Any) -> bool:
    """Return True if a loaded JSON document is an ARM deployment template."""
    if not isinstance(doc, dict):
        return False
    schema = str(doc.get("$schema", "")).lower()
    return _ARM_SCHEMA_MARKER in schema and "resources" in doc


# ── Expression resolution ─────────────────────────────────────────────────────

def _build_lookup(template: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    params: dict[str, Any] = {}
    for name, spec in (template.get("parameters") or {}).items():
        if not isinstance(spec, dict) or "defaultValue" not in spec:
            continue
        if str(spec.get("type", "")).lower() in _SECURE_PARAM_TYPES:
            continue
        params[name.lower()] = spec["defaultValue"]

    variables = {
        k.lower(): v for k, v in (template.get("variables") or {}).items() if k != "copy"
    }
    return params, variables


def _resolve(value: Any, params: dict[str, Any], variables: dict[str, Any], depth: int = 0) -> Any:
    """Substitute whole-value parameter/variable references; leave other expressions as-is."""
    if depth > 8:
        return value

    if isinstance(value, str):
        m = _PARAM_REF.match(value)
        if m and m.group(1).lower() in params:
            return _resolve(params[m.group(1).lower()], params, variables, depth + 1)
        m = _VAR_REF.match(value)
        if m and m.group(1).lower() in variables:
            return _resolve(variables[m.group(1).lower()], params, variables, depth + 1)
        return value

    if isinstance(value, dict):
        return {k: _resolve(v, params, variables, depth + 1) for k, v in value.items()}

    if isinstance(value, list):
        return [_resolve(v, params, variables, depth + 1) for v in value]

    return value


# ── Resource extraction ───────────────────────────────────────────────────────

def _iter_resources(raw: Any) -> list[tuple[str | None, dict[str, Any]]]:
    """
    ARM templates hold resources as a list; languageVersion 2.0 (Bicep output)
    uses a dict keyed by symbolic name.  Returns (symbolic_name, resource) pairs.
    """
    if isinstance(raw, list):
        return [(None, r) for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        return [(k, r) for k, r in raw.items() if isinstance(r, dict)]
    return []


def _collect(
    raw_resources: Any,
    parent_type: str | None,
    params: dict[str, Any],
    variables: dict[str, Any],
    source_file: str,
    out: list[ParsedResource],
) -> None:
    for symbolic, res in _iter_resources(raw_resources):
        rtype = str(res.get("type", "")).strip()
        if not rtype:
            continue
        # Nested child resources may use a relative type ("blobServices");
        # fully-qualified types always start with a provider namespace ("Microsoft.X")
        if parent_type and "." not in rtype.split("/", 1)[0]:
            rtype = f"{parent_type}/{rtype}"

        resolved = _resolve(res, params, variables)
        attrs = {k: v for k, v in resolved.items() if k not in _STRUCTURAL_KEYS}
        name = symbolic or str(resolved.get("name", "unnamed"))

        out.append(
            ParsedResource(
                resource_type=rtype,
                resource_name=name,
                attributes=_sanitize_attributes(attrs),
                source_file=source_file,
            )
        )

        if res.get("resources"):
            _collect(res["resources"], rtype, params, variables, source_file, out)


def _parse_template(path: Path) -> tuple[list[ParsedResource], list[str], bool]:
    """Parse a single JSON file.  Returns (resources, errors, was_arm_template)."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        return [], [f"{path}: {exc}"], False

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        # Only worth a warning if the broken file was meant to be a template
        if _ARM_SCHEMA_MARKER in text.lower():
            return [], [f"{path}: {exc}"], False
        return [], [], False

    if not is_arm_template(doc):
        return [], [], False

    params, variables = _build_lookup(doc)
    resources: list[ParsedResource] = []
    _collect(doc["resources"], None, params, variables, str(path), resources)
    log.debug("Parsed %d ARM resource(s) from %s", len(resources), path)
    return resources, [], True


# ── Public API ────────────────────────────────────────────────────────────────

def parse_directory(directory: str | Path) -> ParseResult:
    """
    Recursively parse all ARM templates (*.json) under *directory*.

    JSON files that are not ARM deployment templates are skipped silently.
    Malformed JSON is only reported as an error if it references the ARM
    deploymentTemplate schema.
    """
    root = Path(directory).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Directory not found: {root}")

    result = ParseResult()
    json_files = sorted(
        p for p in root.rglob("*.json")
        if "node_modules" not in p.parts and not p.name.endswith(".parameters.json")
    )

    templates = 0
    for path in json_files:
        resources, errors, was_template = _parse_template(path)
        result.resources.extend(resources)
        result.errors.extend(errors)
        templates += was_template

    log.info(
        "Parsed %d ARM resource(s) across %d template(s); %d error(s)",
        len(result.resources),
        templates,
        len(result.errors),
    )
    return result


def parse_file(path: str | Path) -> ParseResult:
    """Parse a single ARM template file."""
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    resources, errors, _ = _parse_template(p)
    return ParseResult(resources=resources, errors=errors)
