"""
fedramp_auto.parser.cloudformation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Parses AWS CloudFormation JSON templates — including the synthesized output
of AWS CDK apps (``cdk.out/*.template.json``) — into the same sanitized
ParsedResource representation used for Terraform and ARM.

Scanning a CDK app
------------------
CDK code (TypeScript, Python, Java, Go, C#) is not analysed directly.  Run
``cdk synth`` first; every CDK construct is then a plain CloudFormation
resource in ``cdk.out``, which is exactly what gets deployed.

Key design decisions:
  - Only JSON documents with a ``Resources`` map of ``AWS::*`` / ``Custom::*``
    types are parsed.  CDK's manifest.json, tree.json, *.assets.json and any
    other JSON are skipped silently.
  - ``AWS::CDK::Metadata`` resources are bookkeeping and are dropped.
  - When a resource carries CDK metadata (``aws:cdk:path``), the construct
    path is used as the resource name (``MyStack/AuditBucket``) — far more
    readable than the hashed logical ID (``AuditBucketA1B2C3D4``).
  - Whole-value ``{"Ref": "Param"}`` references are resolved from the
    parameter's ``Default``.  ``NoEcho`` parameters are never resolved.
    Other intrinsics (Fn::GetAtt, Fn::Join, ...) are kept verbatim.
  - Attributes are the resource's ``Properties`` (PascalCase, as written by
    CloudFormation) plus ``DeletionPolicy`` when set.
  - Sanitization reuses the Terraform parser's secret redaction.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fedramp_auto.parser.terraform import ParsedResource, ParseResult, _sanitize_attributes

log = logging.getLogger(__name__)

_CDK_METADATA_TYPE = "AWS::CDK::Metadata"
_CDK_PATH_KEY = "aws:cdk:path"

# Raw-text hint that a file which failed to parse was meant to be a template
_CFN_TEXT_MARKER = '"awstemplateformatversion"'


# ── Template detection ────────────────────────────────────────────────────────

def _is_cfn_type(rtype: Any) -> bool:
    return isinstance(rtype, str) and (rtype.startswith("AWS::") or rtype.startswith("Custom::"))


def is_cloudformation_template(doc: Any) -> bool:
    """Return True if a loaded JSON document is a CloudFormation template."""
    if not isinstance(doc, dict):
        return False
    resources = doc.get("Resources")
    if not isinstance(resources, dict) or not resources:
        return False
    if "AWSTemplateFormatVersion" in doc:
        return True
    # CDK templates omit AWSTemplateFormatVersion; require real CFN types
    return all(
        isinstance(r, dict) and _is_cfn_type(r.get("Type")) for r in resources.values()
    )


# ── Ref resolution ────────────────────────────────────────────────────────────

def _build_param_defaults(template: dict[str, Any]) -> dict[str, Any]:
    defaults: dict[str, Any] = {}
    for name, spec in (template.get("Parameters") or {}).items():
        if not isinstance(spec, dict) or "Default" not in spec:
            continue
        if str(spec.get("NoEcho", "")).lower() == "true":
            continue
        defaults[name] = spec["Default"]
    return defaults


def _resolve(value: Any, params: dict[str, Any], depth: int = 0) -> Any:
    """Substitute whole-value {"Ref": param} references; leave other intrinsics as-is."""
    if depth > 8:
        return value

    if isinstance(value, dict):
        if len(value) == 1 and isinstance(value.get("Ref"), str) and value["Ref"] in params:
            return params[value["Ref"]]
        return {k: _resolve(v, params, depth + 1) for k, v in value.items()}

    if isinstance(value, list):
        return [_resolve(v, params, depth + 1) for v in value]

    return value


# ── Resource extraction ───────────────────────────────────────────────────────

def _resource_name(logical_id: str, res: dict[str, Any]) -> str:
    """Prefer the CDK construct path; fall back to the logical ID."""
    metadata = res.get("Metadata")
    if isinstance(metadata, dict):
        path = metadata.get(_CDK_PATH_KEY)
        if isinstance(path, str) and path:
            # L1 resources inside an L2 construct are always named "Resource"
            return path[: -len("/Resource")] if path.endswith("/Resource") else path
    return logical_id


def _collect(template: dict[str, Any], source_file: str) -> list[ParsedResource]:
    params = _build_param_defaults(template)
    out: list[ParsedResource] = []

    for logical_id, res in template["Resources"].items():
        if not isinstance(res, dict):
            continue
        rtype = res.get("Type")
        if not isinstance(rtype, str) or not rtype or rtype == _CDK_METADATA_TYPE:
            continue

        props = res.get("Properties")
        attrs: dict[str, Any] = dict(props) if isinstance(props, dict) else {}
        if isinstance(res.get("DeletionPolicy"), str):
            attrs["DeletionPolicy"] = res["DeletionPolicy"]

        out.append(
            ParsedResource(
                resource_type=rtype,
                resource_name=_resource_name(logical_id, res),
                attributes=_sanitize_attributes(_resolve(attrs, params)),
                source_file=source_file,
            )
        )
    return out


def _parse_template(path: Path) -> tuple[list[ParsedResource], list[str], bool]:
    """Parse a single JSON file.  Returns (resources, errors, was_cfn_template)."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        return [], [f"{path}: {exc}"], False

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        # Only worth a warning if the broken file was meant to be a template
        if path.name.endswith(".template.json") or _CFN_TEXT_MARKER in text.lower():
            return [], [f"{path}: {exc}"], False
        return [], [], False

    if not is_cloudformation_template(doc):
        return [], [], False

    resources = _collect(doc, str(path))
    log.debug("Parsed %d CloudFormation resource(s) from %s", len(resources), path)
    return resources, [], True


# ── Public API ────────────────────────────────────────────────────────────────

def parse_directory(directory: str | Path) -> ParseResult:
    """
    Recursively parse all CloudFormation / CDK-synthesized templates (*.json)
    under *directory*.

    Point it at a CDK project root or directly at its ``cdk.out`` folder.
    JSON files that are not CloudFormation templates are skipped silently.
    """
    root = Path(directory).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Directory not found: {root}")

    result = ParseResult()
    json_files = sorted(p for p in root.rglob("*.json") if "node_modules" not in p.parts)

    templates = 0
    for path in json_files:
        resources, errors, was_template = _parse_template(path)
        result.resources.extend(resources)
        result.errors.extend(errors)
        templates += was_template

    log.info(
        "Parsed %d CloudFormation resource(s) across %d template(s); %d error(s)",
        len(result.resources),
        templates,
        len(result.errors),
    )
    return result


def parse_file(path: str | Path) -> ParseResult:
    """Parse a single CloudFormation template file."""
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    resources, errors, _ = _parse_template(p)
    return ParseResult(resources=resources, errors=errors)
