"""
fedramp_auto.mapper.control_mapper
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Maps sanitized Terraform resources to satisfied NIST 800-53 Rev5 controls
using Mistral 7B running locally via Ollama.

Two-layer approach:
  1. Static lookup table — fast, deterministic mappings for well-known
     resource type / attribute combos.  No LLM call needed.
  2. LLM fallback — for resources not covered by the static table, Mistral
     is prompted with few-shot examples to infer which controls apply.

This keeps inference calls to a minimum (cheaper, faster) while still
handling novel or uncommon resource types gracefully.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

import ollama

from fedramp_auto.parser.terraform import ParsedResource

log = logging.getLogger(__name__)

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ControlMapping:
    """A single satisfied control for a given resource."""
    control_id: str       # e.g. "AC-2", "SC-28"
    control_name: str     # human-readable name
    rationale: str        # why this resource satisfies the control
    source: str           # "static" | "llm"


@dataclass
class ResourceMapping:
    """All control mappings for a single Terraform resource."""
    resource: ParsedResource
    controls: list[ControlMapping] = field(default_factory=list)

    @property
    def control_ids(self) -> list[str]:
        return [c.control_id for c in self.controls]


# ── Static lookup table ───────────────────────────────────────────────────────
# Format: resource_type -> list of (control_id, control_name, attribute_check_fn, rationale)
# attribute_check_fn receives the resource's attributes dict and returns bool.

def _has_encryption(attrs: dict) -> bool:
    return bool(attrs.get("storage_encrypted") or attrs.get("encrypted"))

def _has_versioning(attrs: dict) -> bool:
    v = attrs.get("versioning_configuration", {})
    if isinstance(v, dict):
        return str(v.get("status", "")).lower() == "enabled"
    return False

def _public_access_blocked(attrs: dict) -> bool:
    return bool(attrs.get("block_public_acls") and attrs.get("block_public_policy"))

def _key_rotation_enabled(attrs: dict) -> bool:
    return bool(attrs.get("enable_key_rotation"))

def _multi_az(attrs: dict) -> bool:
    return bool(attrs.get("multi_az"))

def _log_validation(attrs: dict) -> bool:
    return bool(attrs.get("enable_log_file_validation"))

def _multi_region(attrs: dict) -> bool:
    return bool(attrs.get("is_multi_region_trail"))

# (control_id, name, check_fn, rationale_template)
_STATIC_RULES: dict[str, list[tuple[str, str, object, str]]] = {
    "aws_s3_bucket_server_side_encryption_configuration": [
        ("SC-28", "Protection of Information at Rest",
         lambda a: True,
         "Server-side encryption ensures data at rest is protected."),
    ],
    "aws_s3_bucket_versioning": [
        ("CP-9", "Information System Backup",
         _has_versioning,
         "Versioning enabled provides object-level backup and recovery."),
        ("AU-9", "Protection of Audit Information",
         _has_versioning,
         "Versioning prevents deletion or tampering of audit log objects."),
    ],
    "aws_s3_bucket_public_access_block": [
        ("AC-3", "Access Enforcement",
         _public_access_blocked,
         "Public access block prevents unauthorized public read/write."),
        ("AC-22", "Publicly Accessible Content",
         _public_access_blocked,
         "Explicit block on public ACLs and policies limits exposure."),
        ("SC-7", "Boundary Protection",
         _public_access_blocked,
         "Restricting public access enforces a security boundary on the bucket."),
    ],
    "aws_kms_key": [
        ("SC-12", "Cryptographic Key Establishment and Management",
         lambda a: True,
         "KMS key provides managed cryptographic key lifecycle."),
        ("SC-28", "Protection of Information at Rest",
         lambda a: True,
         "KMS-managed encryption key protects data at rest."),
        ("SC-12(1)", "Cryptographic Key Establishment — Availability",
         _key_rotation_enabled,
         "Automatic key rotation reduces risk of key compromise over time."),
    ],
    "aws_db_instance": [
        ("SC-28", "Protection of Information at Rest",
         _has_encryption,
         "storage_encrypted=true encrypts the RDS volume at rest."),
        ("CP-9", "Information System Backup",
         lambda a: int(a.get("backup_retention_period", 0)) > 0,
         "Automated backups with non-zero retention period satisfy backup requirements."),
        ("SI-12", "Information Handling and Retention",
         lambda a: int(a.get("backup_retention_period", 0)) >= 35,
         "35-day retention satisfies FedRAMP audit log retention guidance."),
        ("SC-6", "Resource Availability",
         _multi_az,
         "Multi-AZ deployment provides high availability and failover."),
        ("SC-5", "Denial of Service Protection",
         _multi_az,
         "Multi-AZ protects database availability against zone failures."),
    ],
    "aws_cloudtrail": [
        ("AU-2", "Audit Events",
         lambda a: True,
         "CloudTrail records API-level audit events across the account."),
        ("AU-3", "Content of Audit Records",
         lambda a: True,
         "CloudTrail captures who, what, when, where for every API call."),
        ("AU-12", "Audit Record Generation",
         lambda a: True,
         "CloudTrail generates audit records for all supported AWS services."),
        ("AU-9", "Protection of Audit Information",
         _log_validation,
         "Log file validation detects tampering with delivered log files."),
        ("AU-6", "Audit Record Review, Analysis, and Reporting",
         lambda a: bool(a.get("include_global_service_events")),
         "Global service events provides complete audit coverage."),
        ("AU-12(1)", "Audit Record Generation — System-wide",
         _multi_region,
         "Multi-region trail ensures audit coverage in all active regions."),
    ],
    "aws_iam_role": [
        ("AC-2", "Account Management",
         lambda a: True,
         "IAM role defines a managed identity subject to account management controls."),
        ("AC-3", "Access Enforcement",
         lambda a: True,
         "IAM role policy enforces least-privilege access to AWS resources."),
        ("AC-6", "Least Privilege",
         lambda a: True,
         "Role-based access limits permissions to those required for function."),
    ],
    "aws_security_group": [
        ("SC-7", "Boundary Protection",
         lambda a: True,
         "Security group rules enforce network boundary controls."),
        ("AC-4", "Information Flow Enforcement",
         lambda a: True,
         "Inbound/outbound rules control information flow between network segments."),
    ],
    "aws_vpc": [
        ("SC-7", "Boundary Protection",
         lambda a: True,
         "VPC isolates network boundary for the system boundary."),
        ("AC-4", "Information Flow Enforcement",
         lambda a: True,
         "VPC subnets and route tables enforce information flow policies."),
    ],
    "aws_cloudwatch_log_group": [
        ("AU-4", "Audit Log Storage Capacity",
         lambda a: True,
         "CloudWatch log group provides managed audit log storage."),
        ("AU-11", "Audit Record Retention",
         lambda a: int(a.get("retention_in_days", 0)) >= 90,
         "Log retention >= 90 days satisfies FedRAMP audit retention requirements."),
    ],
    "aws_guardduty_detector": [
        ("SI-3", "Malicious Code Protection",
         lambda a: bool(a.get("enable", True)),
         "GuardDuty provides continuous threat detection for malicious activity."),
        ("SI-4", "Information System Monitoring",
         lambda a: bool(a.get("enable", True)),
         "GuardDuty monitors VPC flow logs, DNS logs, and CloudTrail for threats."),
    ],
}


def _apply_static_rules(resource: ParsedResource) -> list[ControlMapping]:
    rules = _STATIC_RULES.get(resource.resource_type, [])
    mappings = []
    for control_id, control_name, check_fn, rationale in rules:
        if check_fn(resource.attributes):
            mappings.append(ControlMapping(
                control_id=control_id,
                control_name=control_name,
                rationale=rationale,
                source="static",
            ))
    return mappings


# ── LLM prompt template ───────────────────────────────────────────────────────

_FEW_SHOT_EXAMPLES = """
Example 1:
Resource: aws_wafv2_web_acl.main
Attributes: {"default_action": {"block": {}}, "scope": "REGIONAL"}
Response:
[
  {"control_id": "SC-7", "control_name": "Boundary Protection", "rationale": "WAF acts as a boundary protection mechanism filtering malicious web traffic."},
  {"control_id": "SI-3", "control_name": "Malicious Code Protection", "rationale": "WAF rules block known malicious request patterns and SQL injection attempts."}
]

Example 2:
Resource: aws_config_configuration_recorder.main
Attributes: {"recording_group": {"all_supported": true}, "role_arn": "<REDACTED>"}
Response:
[
  {"control_id": "CM-8", "control_name": "Information System Component Inventory", "rationale": "AWS Config records configuration of all supported resource types, maintaining inventory."},
  {"control_id": "CM-6", "control_name": "Configuration Settings", "rationale": "Config recorder detects configuration drift from baseline settings."},
  {"control_id": "AU-12", "control_name": "Audit Record Generation", "rationale": "Config records configuration change history as auditable records."}
]
""".strip()


def _build_llm_prompt(resource: ParsedResource) -> str:
    attrs_json = json.dumps(resource.attributes, indent=2, default=str)
    return f"""You are a FedRAMP compliance expert. Given a Terraform resource, identify which NIST 800-53 Rev5 controls it satisfies based on its type and configuration attributes.

{_FEW_SHOT_EXAMPLES}

Now analyze this resource:
Resource: {resource.identifier}
Attributes:
{attrs_json}

Respond ONLY with a JSON array. Each item must have exactly these fields: "control_id", "control_name", "rationale".
Only include controls that are clearly satisfied by the resource configuration.
Do not include any explanation outside the JSON array."""


def _call_llm(prompt: str, model: str, base_url: str, timeout: int) -> list[ControlMapping]:
    """Call Mistral via Ollama and parse the JSON response."""
    try:
        client = ollama.Client(host=base_url)
        response = client.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1},  # low temp for consistent JSON
        )
        raw = response["message"]["content"].strip()

        # Strip markdown fences if the model wraps in ```json ... ```
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        items = json.loads(raw)
        mappings = []
        for item in items:
            if not isinstance(item, dict):
                continue
            mappings.append(ControlMapping(
                control_id=item.get("control_id", "UNKNOWN"),
                control_name=item.get("control_name", ""),
                rationale=item.get("rationale", ""),
                source="llm",
            ))
        return mappings

    except json.JSONDecodeError as exc:
        log.warning("LLM returned non-JSON for %s: %s", prompt[:80], exc)
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("LLM call failed: %s", exc)
        return []


# ── Public API ────────────────────────────────────────────────────────────────

class ControlMapper:
    """
    Maps Terraform resources to NIST 800-53 Rev5 controls.

    Usage
    -----
    mapper = ControlMapper()
    mappings = mapper.map_resources(parse_result.resources)
    for rm in mappings:
        print(rm.resource.identifier, rm.control_ids)
    """

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        timeout: int | None = None,
        llm_fallback: bool = True,
    ) -> None:
        self.model = model or os.getenv("OLLAMA_MODEL", "mistral")
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.timeout = timeout or int(os.getenv("OLLAMA_TIMEOUT", "120"))
        self.llm_fallback = llm_fallback

    def map_resource(self, resource: ParsedResource) -> ResourceMapping:
        """Map a single resource to its satisfied controls."""
        rm = ResourceMapping(resource=resource)

        # Layer 1: static rules (fast, deterministic)
        static = _apply_static_rules(resource)
        rm.controls.extend(static)

        # Layer 2: LLM fallback for unknown resource types
        if self.llm_fallback and not static:
            log.info(
                "No static rules for %s — querying LLM", resource.resource_type
            )
            prompt = _build_llm_prompt(resource)
            llm_controls = _call_llm(prompt, self.model, self.base_url, self.timeout)
            rm.controls.extend(llm_controls)

        if not rm.controls:
            log.debug("No controls mapped for %s", resource.identifier)

        return rm

    def map_resources(self, resources: list[ParsedResource]) -> list[ResourceMapping]:
        """Map a list of resources. Returns one ResourceMapping per resource."""
        results = []
        for resource in resources:
            rm = self.map_resource(resource)
            results.append(rm)
            log.info(
                "%s → %d control(s): %s",
                resource.identifier,
                len(rm.controls),
                ", ".join(rm.control_ids) or "none",
            )
        return results
