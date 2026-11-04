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
import re
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


# ── Azure ARM helpers ─────────────────────────────────────────────────────────
# ARM puts configuration under "properties"; values may be bools or strings.

def _prop(attrs: dict, *path: str) -> object:
    node: object = attrs.get("properties", {})
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node

def _is_true(value: object) -> bool:
    return value is True or str(value).lower() == "true"

def _as_int(value: object) -> int:
    return int(value) if str(value).lstrip("-").isdigit() else 0

def _tls12_plus(value: object) -> bool:
    return str(value).upper().replace("TLS", "").replace("_", ".").strip(".") in ("1.2", "1.3")

def _azure_network_locked(attrs: dict) -> bool:
    return (
        str(_prop(attrs, "publicNetworkAccess")).lower() == "disabled"
        or str(_prop(attrs, "networkAcls", "defaultAction")).lower() == "deny"
    )

def _public_blob_disabled(attrs: dict) -> bool:
    return str(_prop(attrs, "allowBlobPublicAccess")).lower() == "false"

def _diagnostic_logs_enabled(attrs: dict) -> bool:
    logs = _prop(attrs, "logs")
    return isinstance(logs, list) and any(
        isinstance(entry, dict) and _is_true(entry.get("enabled")) for entry in logs
    )

def _defender_standard(attrs: dict) -> bool:
    return str(_prop(attrs, "pricingTier")).lower() == "standard"


# ── AWS CloudFormation / CDK helpers ──────────────────────────────────────────
# CloudFormation attributes are the resource's Properties (PascalCase).  Values
# may be bools, strings ("true"), or unresolved intrinsics ({"Fn::GetAtt": ...}).

_ELB_TLS12_POLICY = re.compile(r"TLS13|TLS-1-2|FS-1-2", re.IGNORECASE)

def _cfn(attrs: dict, *path: str) -> object:
    node: object = attrs
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node

def _s3_versioned(attrs: dict) -> bool:
    return str(_cfn(attrs, "VersioningConfiguration", "Status")).lower() == "enabled"

def _s3_public_blocked(attrs: dict) -> bool:
    return _is_true(_cfn(attrs, "PublicAccessBlockConfiguration", "BlockPublicAcls")) and _is_true(
        _cfn(attrs, "PublicAccessBlockConfiguration", "BlockPublicPolicy")
    )

def _denies_insecure_transport(attrs: dict) -> bool:
    """Bucket policy contains a Deny on aws:SecureTransport=false (CDK enforceSSL)."""
    statements = _cfn(attrs, "PolicyDocument", "Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return False
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Deny":
            continue
        secure = _cfn(stmt, "Condition", "Bool", "aws:SecureTransport")
        if str(secure).lower() == "false":
            return True
    return False

def _cfn_backup_retention(attrs: dict) -> int:
    # CloudFormation defaults BackupRetentionPeriod to 1 day when omitted
    return _as_int(attrs.get("BackupRetentionPeriod", 1))

def _log_retention_ok(attrs: dict) -> bool:
    # Omitted RetentionInDays means logs never expire
    return "RetentionInDays" not in attrs or _as_int(attrs["RetentionInDays"]) >= 90

def _listener_encrypted(attrs: dict) -> bool:
    return str(attrs.get("Protocol", "")).upper() in ("HTTPS", "TLS")

def _cognito_mfa_on(attrs: dict) -> bool:
    return str(attrs.get("MfaConfiguration", "")).upper() == "ON"


# ── AWS Backup (both CloudFormation and Terraform) ────────────────────────────

def _as_list(value: object) -> list:
    if isinstance(value, list):
        return value
    return [value] if isinstance(value, dict) else []

def _cfn_backup_rules(attrs: dict) -> list:
    return [r for r in _as_list(_cfn(attrs, "BackupPlan", "BackupPlanRule")) if isinstance(r, dict)]

def _cfn_backup_retention_days(attrs: dict) -> list[int]:
    return [_as_int(_cfn(r, "Lifecycle", "DeleteAfterDays")) for r in _cfn_backup_rules(attrs)]

def _tf_backup_rules(attrs: dict) -> list:
    return [r for r in _as_list(attrs.get("rule")) if isinstance(r, dict)]

def _tf_backup_retention_days(attrs: dict) -> list[int]:
    return [
        _as_int(lc.get("delete_after"))
        for r in _tf_backup_rules(attrs)
        for lc in _as_list(r.get("lifecycle"))
        if isinstance(lc, dict)
    ]

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
         lambda a: _as_int(a.get("backup_retention_period", 0)) > 0,
         "Automated backups with non-zero retention period satisfy backup requirements."),
        ("SI-12", "Information Handling and Retention",
         lambda a: _as_int(a.get("backup_retention_period", 0)) >= 35,
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
         lambda a: _as_int(a.get("retention_in_days", 0)) >= 90,
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

    "aws_backup_plan": [
        ("CP-9", "Information System Backup",
         lambda a: bool(_tf_backup_rules(a)),
         "AWS Backup plan schedules automated backups of the selected resources."),
        ("SI-12", "Information Handling and Retention",
         lambda a: any(d >= 35 for d in _tf_backup_retention_days(a)),
         "Backup lifecycle retains recovery points for at least 35 days."),
    ],

    # ── AWS CloudFormation / CDK (exact CFN type names) ──────────────────────
    "AWS::Backup::BackupPlan": [
        ("CP-9", "Information System Backup",
         lambda a: bool(_cfn_backup_rules(a)),
         "AWS Backup plan schedules automated backups of the selected resources."),
        ("SI-12", "Information Handling and Retention",
         lambda a: any(d >= 35 for d in _cfn_backup_retention_days(a)),
         "Backup lifecycle retains recovery points for at least 35 days."),
    ],
    "AWS::S3::Bucket": [
        ("SC-28", "Protection of Information at Rest",
         lambda a: True,
         "S3 encrypts every new object at rest (SSE-S3 by default, SSE-KMS if configured)."),
        ("CP-9", "Information System Backup",
         _s3_versioned,
         "Versioning enabled provides object-level backup and recovery."),
        ("AU-9", "Protection of Audit Information",
         lambda a: _s3_versioned(a) or _is_true(a.get("ObjectLockEnabled")),
         "Versioning / Object Lock prevents deletion or tampering of stored log objects."),
        ("AC-3", "Access Enforcement",
         _s3_public_blocked,
         "Public access block prevents unauthorized public read/write."),
        ("AC-22", "Publicly Accessible Content",
         _s3_public_blocked,
         "Explicit block on public ACLs and policies limits exposure."),
        ("SC-7", "Boundary Protection",
         _s3_public_blocked,
         "Restricting public access enforces a security boundary on the bucket."),
        ("AU-12", "Audit Record Generation",
         lambda a: isinstance(a.get("LoggingConfiguration"), dict),
         "Server access logging generates audit records for bucket requests."),
    ],
    "AWS::S3::BucketPolicy": [
        ("SC-8", "Transmission Confidentiality and Integrity",
         _denies_insecure_transport,
         "Policy denies any request not made over TLS (aws:SecureTransport=false)."),
    ],
    "AWS::KMS::Key": [
        ("SC-12", "Cryptographic Key Establishment and Management",
         lambda a: True,
         "KMS key provides managed cryptographic key lifecycle."),
        ("SC-28", "Protection of Information at Rest",
         lambda a: True,
         "KMS-managed encryption key protects data at rest."),
        ("SC-12(1)", "Cryptographic Key Establishment — Availability",
         lambda a: _is_true(a.get("EnableKeyRotation")),
         "Automatic key rotation reduces risk of key compromise over time."),
    ],
    "AWS::RDS::DBInstance": [
        ("SC-28", "Protection of Information at Rest",
         lambda a: _is_true(a.get("StorageEncrypted")),
         "StorageEncrypted=true encrypts the RDS volume at rest."),
        ("CP-9", "Information System Backup",
         lambda a: _cfn_backup_retention(a) > 0,
         "Automated backups with non-zero retention period satisfy backup requirements."),
        ("SI-12", "Information Handling and Retention",
         lambda a: _cfn_backup_retention(a) >= 35,
         "35-day retention satisfies FedRAMP audit log retention guidance."),
        ("SC-6", "Resource Availability",
         lambda a: _is_true(a.get("MultiAZ")),
         "Multi-AZ deployment provides high availability and failover."),
        ("SC-5", "Denial of Service Protection",
         lambda a: _is_true(a.get("MultiAZ")),
         "Multi-AZ protects database availability against zone failures."),
    ],
    "AWS::RDS::DBCluster": [
        ("SC-28", "Protection of Information at Rest",
         lambda a: _is_true(a.get("StorageEncrypted")),
         "StorageEncrypted=true encrypts the Aurora cluster volume at rest."),
        ("CP-9", "Information System Backup",
         lambda a: _cfn_backup_retention(a) > 0,
         "Continuous automated backups with a retention window."),
        ("SI-12", "Information Handling and Retention",
         lambda a: _cfn_backup_retention(a) >= 35,
         "35-day retention satisfies FedRAMP audit log retention guidance."),
    ],
    "AWS::DynamoDB::Table": [
        ("SC-28", "Protection of Information at Rest",
         lambda a: True,
         "DynamoDB encrypts all table data at rest (AWS-owned or KMS key)."),
        ("CP-9", "Information System Backup",
         lambda a: _is_true(_cfn(a, "PointInTimeRecoverySpecification",
                                 "PointInTimeRecoveryEnabled")),
         "Point-in-time recovery provides continuous backups for 35 days."),
    ],
    "AWS::EC2::Volume": [
        ("SC-28", "Protection of Information at Rest",
         lambda a: _is_true(a.get("Encrypted")),
         "Encrypted=true encrypts the EBS volume at rest."),
    ],
    "AWS::CloudTrail::Trail": [
        ("AU-2", "Audit Events",
         lambda a: _is_true(a.get("IsLogging")),
         "CloudTrail records API-level audit events across the account."),
        ("AU-3", "Content of Audit Records",
         lambda a: _is_true(a.get("IsLogging")),
         "CloudTrail captures who, what, when, where for every API call."),
        ("AU-12", "Audit Record Generation",
         lambda a: _is_true(a.get("IsLogging")),
         "CloudTrail generates audit records for all supported AWS services."),
        ("AU-9", "Protection of Audit Information",
         lambda a: _is_true(a.get("EnableLogFileValidation")),
         "Log file validation detects tampering with delivered log files."),
        ("AU-6", "Audit Record Review, Analysis, and Reporting",
         lambda a: _is_true(a.get("IncludeGlobalServiceEvents")),
         "Global service events provides complete audit coverage."),
        ("AU-12(1)", "Audit Record Generation — System-wide",
         lambda a: _is_true(a.get("IsMultiRegionTrail")),
         "Multi-region trail ensures audit coverage in all active regions."),
    ],
    "AWS::Logs::LogGroup": [
        ("AU-4", "Audit Log Storage Capacity",
         lambda a: True,
         "CloudWatch log group provides managed audit log storage."),
        ("AU-11", "Audit Record Retention",
         _log_retention_ok,
         "Retention >= 90 days (or never-expire) satisfies FedRAMP audit retention."),
    ],
    "AWS::EC2::FlowLog": [
        ("AU-12", "Audit Record Generation",
         lambda a: True,
         "VPC flow logs record network traffic metadata for the boundary."),
        ("SI-4", "Information System Monitoring",
         lambda a: True,
         "Flow logs support monitoring for anomalous network activity."),
    ],
    "AWS::IAM::Role": [
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
    "AWS::EC2::SecurityGroup": [
        ("SC-7", "Boundary Protection",
         lambda a: True,
         "Security group rules enforce network boundary controls."),
        ("AC-4", "Information Flow Enforcement",
         lambda a: True,
         "Inbound/outbound rules control information flow between network segments."),
    ],
    "AWS::EC2::VPC": [
        ("SC-7", "Boundary Protection",
         lambda a: True,
         "VPC isolates network boundary for the system boundary."),
        ("AC-4", "Information Flow Enforcement",
         lambda a: True,
         "VPC subnets and route tables enforce information flow policies."),
    ],
    "AWS::ElasticLoadBalancingV2::Listener": [
        ("SC-8", "Transmission Confidentiality and Integrity",
         _listener_encrypted,
         "HTTPS/TLS listener encrypts client traffic in transit."),
        ("SC-8(1)", "Transmission Confidentiality — Cryptographic Protection",
         lambda a: _listener_encrypted(a)
         and bool(_ELB_TLS12_POLICY.search(str(a.get("SslPolicy", "")))),
         "SSL policy restricts clients to TLS 1.2 or higher."),
    ],
    "AWS::WAFv2::WebACL": [
        ("SC-7", "Boundary Protection",
         lambda a: True,
         "WAF acts as a boundary protection mechanism filtering web traffic."),
        ("SI-3", "Malicious Code Protection",
         lambda a: True,
         "WAF rules block known malicious request patterns and injection attempts."),
    ],
    "AWS::GuardDuty::Detector": [
        ("SI-3", "Malicious Code Protection",
         lambda a: _is_true(a.get("Enable")),
         "GuardDuty provides continuous threat detection for malicious activity."),
        ("SI-4", "Information System Monitoring",
         lambda a: _is_true(a.get("Enable")),
         "GuardDuty monitors VPC flow logs, DNS logs, and CloudTrail for threats."),
    ],
    "AWS::SecurityHub::Hub": [
        ("SI-4", "Information System Monitoring",
         lambda a: True,
         "Security Hub aggregates findings and runs continuous compliance checks."),
    ],
    "AWS::Config::ConfigurationRecorder": [
        ("CM-8", "Information System Component Inventory",
         lambda a: a.get("RecordingGroup") is None
         or _is_true(_cfn(a, "RecordingGroup", "AllSupported")),
         "AWS Config records all supported resource types, maintaining inventory."),
        ("CM-6", "Configuration Settings",
         lambda a: True,
         "Config recorder detects configuration drift from baseline settings."),
    ],
    "AWS::ECR::Repository": [
        ("RA-5", "Vulnerability Monitoring and Scanning",
         lambda a: _is_true(_cfn(a, "ImageScanningConfiguration", "ScanOnPush")),
         "Scan-on-push checks every container image for known CVEs."),
    ],
    "AWS::SecretsManager::RotationSchedule": [
        ("IA-5", "Authenticator Management",
         lambda a: True,
         "Secrets Manager rotates the credential automatically on a schedule."),
    ],
    "AWS::Cognito::UserPool": [
        ("AC-2", "Account Management",
         lambda a: True,
         "Cognito user pool centrally manages user accounts."),
        ("IA-2", "Identification and Authentication (Organizational Users)",
         _cognito_mfa_on,
         "MfaConfiguration=ON requires a second factor at every sign-in."),
        ("IA-2(1)", "Multi-factor Authentication to Privileged Accounts",
         _cognito_mfa_on,
         "MFA is mandatory for all users, including privileged ones."),
        ("IA-5", "Authenticator Management",
         lambda a: _as_int(_cfn(a, "Policies", "PasswordPolicy", "MinimumLength")) >= 12,
         "Password policy enforces a minimum length of 12 characters."),
    ],

    # ── Azure (ARM types, lowercased — ARM type names are case-insensitive) ──
    "microsoft.storage/storageaccounts": [
        ("SC-28", "Protection of Information at Rest",
         lambda a: True,
         "Azure Storage encrypts all data at rest with AES-256 by default."),
        ("SC-8", "Transmission Confidentiality and Integrity",
         lambda a: _is_true(_prop(a, "supportsHttpsTrafficOnly")),
         "supportsHttpsTrafficOnly=true rejects unencrypted HTTP requests."),
        ("SC-8(1)", "Transmission Confidentiality — Cryptographic Protection",
         lambda a: _tls12_plus(_prop(a, "minimumTlsVersion")),
         "minimumTlsVersion enforces TLS 1.2 or higher for client connections."),
        ("AC-3", "Access Enforcement",
         _public_blob_disabled,
         "allowBlobPublicAccess=false prevents anonymous access to blob data."),
        ("AC-22", "Publicly Accessible Content",
         _public_blob_disabled,
         "Disabling public blob access limits unintended public exposure."),
        ("SC-7", "Boundary Protection",
         _azure_network_locked,
         "Default-deny network ACLs / disabled public access enforce a boundary."),
    ],
    "microsoft.storage/storageaccounts/blobservices": [
        ("CP-9", "Information System Backup",
         lambda a: _is_true(_prop(a, "deleteRetentionPolicy", "enabled"))
         or _is_true(_prop(a, "isVersioningEnabled")),
         "Blob soft delete / versioning provides object-level recovery."),
        ("AU-9", "Protection of Audit Information",
         lambda a: _is_true(_prop(a, "isVersioningEnabled")),
         "Blob versioning prevents silent overwrite or deletion of stored logs."),
    ],
    "microsoft.keyvault/vaults": [
        ("SC-12", "Cryptographic Key Establishment and Management",
         lambda a: True,
         "Key Vault provides managed storage and lifecycle for keys and secrets."),
        ("AC-3", "Access Enforcement",
         lambda a: _is_true(_prop(a, "enableRbacAuthorization")),
         "Azure RBAC authorization enforces role-based access to vault contents."),
        ("SC-7", "Boundary Protection",
         _azure_network_locked,
         "Key Vault firewall restricts access to approved networks."),
        ("CP-9", "Information System Backup",
         lambda a: _is_true(_prop(a, "enablePurgeProtection")),
         "Purge protection guarantees deleted keys remain recoverable."),
    ],
    "microsoft.keyvault/vaults/keys": [
        ("SC-12", "Cryptographic Key Establishment and Management",
         lambda a: True,
         "Key Vault key is a managed cryptographic key."),
        ("SC-12(1)", "Cryptographic Key Establishment — Availability",
         lambda a: isinstance(_prop(a, "rotationPolicy"), dict),
         "Key rotation policy rotates the key automatically."),
    ],
    "microsoft.sql/servers": [
        ("IA-2", "Identification and Authentication (Organizational Users)",
         lambda a: _is_true(_prop(a, "administrators", "azureADOnlyAuthentication")),
         "Entra ID-only authentication ties every login to a managed identity."),
        ("AC-2", "Account Management",
         lambda a: _is_true(_prop(a, "administrators", "azureADOnlyAuthentication")),
         "Database accounts are managed centrally in Entra ID."),
        ("SC-8(1)", "Transmission Confidentiality — Cryptographic Protection",
         lambda a: _tls12_plus(_prop(a, "minimalTlsVersion")),
         "minimalTlsVersion enforces TLS 1.2+ for database connections."),
        ("SC-7", "Boundary Protection",
         _azure_network_locked,
         "Public network access disabled; server reachable via private endpoint only."),
    ],
    "microsoft.sql/servers/databases/transparentdataencryption": [
        ("SC-28", "Protection of Information at Rest",
         lambda a: str(_prop(a, "state")).lower() == "enabled",
         "Transparent Data Encryption encrypts the database at rest."),
    ],
    "microsoft.sql/servers/auditingsettings": [
        ("AU-2", "Audit Events",
         lambda a: str(_prop(a, "state")).lower() == "enabled",
         "SQL auditing records database events."),
        ("AU-12", "Audit Record Generation",
         lambda a: str(_prop(a, "state")).lower() == "enabled",
         "SQL auditing generates audit records for database activity."),
        ("AU-11", "Audit Record Retention",
         lambda a: str(_prop(a, "state")).lower() == "enabled"
         and (_as_int(_prop(a, "retentionDays")) == 0 or _as_int(_prop(a, "retentionDays")) >= 90),
         "Audit retention of 0 (unlimited) or >= 90 days meets FedRAMP retention."),
    ],
    "microsoft.network/networksecuritygroups": [
        ("SC-7", "Boundary Protection",
         lambda a: True,
         "NSG rules enforce network boundary controls."),
        ("AC-4", "Information Flow Enforcement",
         lambda a: True,
         "Inbound/outbound NSG rules control traffic between network segments."),
    ],
    "microsoft.network/virtualnetworks": [
        ("SC-7", "Boundary Protection",
         lambda a: True,
         "Virtual network isolates the system boundary."),
        ("AC-4", "Information Flow Enforcement",
         lambda a: True,
         "Subnets and routing enforce information flow policies."),
    ],
    "microsoft.network/azurefirewalls": [
        ("SC-7", "Boundary Protection",
         lambda a: True,
         "Azure Firewall enforces a managed network boundary."),
        ("AC-4", "Information Flow Enforcement",
         lambda a: True,
         "Firewall rules control information flow in and out of the boundary."),
        ("SI-4", "Information System Monitoring",
         lambda a: str(_prop(a, "threatIntelMode")).lower() in ("alert", "deny"),
         "Threat intelligence mode flags or blocks traffic to known-malicious hosts."),
    ],
    "microsoft.network/applicationgateways": [
        ("SC-7", "Boundary Protection",
         lambda a: True,
         "Application Gateway terminates and filters inbound web traffic."),
        ("SI-3", "Malicious Code Protection",
         lambda a: _is_true(_prop(a, "webApplicationFirewallConfiguration", "enabled"))
         or isinstance(_prop(a, "firewallPolicy"), dict),
         "WAF blocks known malicious request patterns (OWASP rule set)."),
    ],
    "microsoft.operationalinsights/workspaces": [
        ("AU-4", "Audit Log Storage Capacity",
         lambda a: True,
         "Log Analytics workspace provides managed audit log storage."),
        ("AU-11", "Audit Record Retention",
         lambda a: _as_int(_prop(a, "retentionInDays")) >= 90,
         "Workspace retention >= 90 days satisfies FedRAMP audit retention."),
    ],
    "microsoft.insights/diagnosticsettings": [
        ("AU-2", "Audit Events",
         _diagnostic_logs_enabled,
         "Diagnostic settings export resource logs for auditing."),
        ("AU-12", "Audit Record Generation",
         _diagnostic_logs_enabled,
         "Enabled log categories generate audit records for the resource."),
    ],
    "microsoft.insights/activitylogalerts": [
        ("AU-6", "Audit Record Review, Analysis, and Reporting",
         lambda a: _prop(a, "enabled") is None or _is_true(_prop(a, "enabled")),
         "Activity log alerts notify on security-relevant control-plane events."),
    ],
    "microsoft.security/pricings": [
        ("SI-3", "Malicious Code Protection",
         _defender_standard,
         "Microsoft Defender for Cloud (Standard tier) detects malware and threats."),
        ("SI-4", "Information System Monitoring",
         _defender_standard,
         "Defender for Cloud continuously monitors resources for attacks."),
        ("RA-5", "Vulnerability Monitoring and Scanning",
         lambda a: _defender_standard(a)
         and str(a.get("name", "")).lower() in ("virtualmachines", "containers", "sqlservers"),
         "Defender plan includes built-in vulnerability assessment."),
    ],
    "microsoft.managedidentity/userassignedidentities": [
        ("AC-2", "Account Management",
         lambda a: True,
         "Managed identity is a platform-managed service account."),
        ("IA-4", "Identifier Management",
         lambda a: True,
         "Managed identity provides a unique, non-reusable workload identifier."),
    ],
    "microsoft.authorization/roleassignments": [
        ("AC-2", "Account Management",
         lambda a: True,
         "Role assignment grants access to a specific managed principal."),
        ("AC-3", "Access Enforcement",
         lambda a: True,
         "Azure RBAC enforces the assigned role's permissions."),
        ("AC-6", "Least Privilege",
         lambda a: True,
         "Scoped role assignment limits permissions to what the principal needs."),
    ],
    "microsoft.web/sites": [
        ("SC-8", "Transmission Confidentiality and Integrity",
         lambda a: _is_true(_prop(a, "httpsOnly")),
         "httpsOnly=true redirects all HTTP traffic to HTTPS."),
        ("SC-8(1)", "Transmission Confidentiality — Cryptographic Protection",
         lambda a: _tls12_plus(_prop(a, "siteConfig", "minTlsVersion")),
         "minTlsVersion enforces TLS 1.2+ for the web app."),
    ],
    "microsoft.compute/virtualmachines": [
        ("SC-28", "Protection of Information at Rest",
         lambda a: _is_true(_prop(a, "securityProfile", "encryptionAtHost")),
         "Encryption at host encrypts temp disks and disk caches at rest."),
        ("SI-7", "Software, Firmware, and Information Integrity",
         lambda a: _is_true(_prop(a, "securityProfile", "uefiSettings", "secureBootEnabled")),
         "Secure Boot verifies boot-chain integrity (Trusted Launch)."),
    ],
    "microsoft.recoveryservices/vaults": [
        ("CP-9", "Information System Backup",
         lambda a: True,
         "Recovery Services vault stores managed backups."),
    ],
}


def _apply_static_rules(resource: ParsedResource) -> list[ControlMapping]:
    rules = (
        _STATIC_RULES.get(resource.resource_type)
        or _STATIC_RULES.get(resource.resource_type.lower(), [])
    )
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
""".strip()  # noqa: E501


def _build_llm_prompt(resource: ParsedResource) -> str:
    attrs_json = json.dumps(resource.attributes, indent=2, default=str)
    return f"""You are a FedRAMP compliance expert. Given an infrastructure-as-code resource (Terraform, Azure ARM, or AWS CloudFormation/CDK), identify which NIST 800-53 Rev5 controls it satisfies based on its type and configuration attributes.

{_FEW_SHOT_EXAMPLES}

Now analyze this resource:
Resource: {resource.identifier}
Attributes:
{attrs_json}

Respond ONLY with a JSON array. Each item must have exactly these fields: "control_id", "control_name", "rationale".
Only include controls that are clearly satisfied by the resource configuration.
Do not include any explanation outside the JSON array."""  # noqa: E501


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
