"""
fedramp_auto.advisor.remediation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Given a FedRAMP KSI gap, uses Mistral 7B to generate:
  1. Plain-English explanation of the risk
  2. Specific remediation action
  3. Terraform code snippet that would satisfy the control

Snippets target the cloud the scanned infrastructure runs on: ``aws``
(the ``aws`` provider) or ``azure`` (the ``azurerm`` provider).  Use
:func:`detect_cloud` to pick one from parsed resources.

Uses a static fallback library for the most common gaps so a Mistral
instance isn't strictly required to get useful output during development.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

import ollama

from fedramp_auto.gaps.detector import ControlGap

if TYPE_CHECKING:
    from fedramp_auto.parser.terraform import ParsedResource

Cloud = Literal["aws", "azure"]
SUPPORTED_CLOUDS: tuple[str, ...] = ("aws", "azure")

log = logging.getLogger(__name__)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class RemediationAdvice:
    ksi_id: str
    control_ids: list[str]
    risk_explanation: str
    remediation_action: str
    terraform_snippet: str
    source: str   # "static" | "llm" | "generic"
    cloud: str = "aws"   # "aws" | "azure" — provider the snippet targets


# ── Static remediation library ────────────────────────────────────────────────
# Covers the most commonly-missed FedRAMP controls with copy-paste Terraform.

_STATIC_REMEDIATIONS: dict[str, dict[str, str]] = {
    "KSI-SC-2": {
        "risk": (
            "Sensitive data stored without encryption is exposed if storage media "
            "is lost, stolen, or accessed without authorisation. FedRAMP SC-28 "
            "requires encryption of all data at rest using FIPS 140-2 validated modules."
        ),
        "action": (
            "Enable server-side encryption on all S3 buckets, RDS instances, and EBS "
            "volumes. Use AES-256 (SSE-S3) at minimum; prefer KMS-managed keys (SSE-KMS) "
            "for audit trail and key rotation."
        ),
        "terraform": """\
# S3 bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.app_key.arn
    }
    bucket_key_enabled = true
  }
}

# RDS encryption (must set at creation time)
resource "aws_db_instance" "example" {
  # ... other config ...
  storage_encrypted = true
  kms_key_id        = aws_kms_key.app_key.arn
}""",
    },

    "KSI-SC-1": {
        "risk": (
            "Unencrypted data in transit can be intercepted and read by an adversary "
            "performing a man-in-the-middle attack. FedRAMP SC-8 requires encryption "
            "of all data in transit using TLS 1.2 or higher."
        ),
        "action": (
            "Enforce HTTPS on all load balancers and APIs. Add an aws_lb_listener "
            "with protocol=HTTPS and a valid ACM certificate. Add an "
            "aws_api_gateway_domain_name with a security policy of TLS_1_2."
        ),
        "terraform": """\
# Force HTTPS on ALB
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.cert.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# Redirect HTTP → HTTPS
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.example.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}""",
    },

    "KSI-AU-1": {
        "risk": (
            "Without comprehensive audit logging, security incidents cannot be detected, "
            "investigated, or attributed. FedRAMP requires audit records for defined "
            "event types with content capturing who, what, when, and where."
        ),
        "action": (
            "Enable AWS CloudTrail with multi-region coverage, log file validation, "
            "and delivery to an S3 bucket with SSE-KMS encryption. Enable CloudWatch "
            "Logs integration for real-time alerting."
        ),
        "terraform": """\
resource "aws_cloudtrail" "main" {
  name                          = "fedramp-trail"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.app_key.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/fedramp"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.app_key.arn
}""",
    },

    "KSI-SC-4": {
        "risk": (
            "Without defined network boundaries, lateral movement after a breach is "
            "unrestricted. FedRAMP SC-7 requires boundary protection devices that "
            "monitor and control communications at external boundaries and key internal "
            "boundaries."
        ),
        "action": (
            "Deploy resources into a VPC with private subnets. Use security groups with "
            "explicit deny-all defaults and allow only required ports. Consider a "
            "Network ACL for subnet-level boundary enforcement."
        ),
        "terraform": """\
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "fedramp-vpc" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
}

resource "aws_security_group" "app" {
  name        = "fedramp-app-sg"
  description = "Minimal ingress — HTTPS only from ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}""",
    },

    "KSI-RA-1": {
        "risk": (
            "Unscanned systems accumulate exploitable vulnerabilities. FedRAMP RA-5 "
            "requires regular vulnerability scanning with findings tracked and "
            "remediated within defined timeframes (30 days for critical/high)."
        ),
        "action": (
            "Enable Amazon Inspector v2 for EC2 and container image scanning. "
            "Enable AWS Security Hub to aggregate findings. Configure SNS alerts "
            "for critical findings."
        ),
        "terraform": """\
resource "aws_inspector2_enabler" "main" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]
}

resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "fedramp" {
  standards_arn = "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}""",
    },

    "KSI-SI-2": {
        "risk": (
            "Without continuous monitoring, attacks can persist undetected for extended "
            "periods. FedRAMP SI-4 requires that the information system is monitored "
            "for attacks and indicators of potential attacks."
        ),
        "action": (
            "Enable Amazon GuardDuty in all regions. Configure EventBridge rules to "
            "route HIGH/CRITICAL findings to SNS for alerting."
        ),
        "terraform": """\
resource "aws_guardduty_detector" "main" {
  enable = true
  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings { ebs_volumes { enable = true } }
    }
  }
}

resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "guardduty-high-severity"
  description = "Capture GuardDuty HIGH and CRITICAL findings"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail      = { severity = [{ numeric = [">=", 7] }] }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_high.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}""",
    },

    "KSI-CP-1": {
        "risk": (
            "Without tested backups, a ransomware attack, accidental deletion, or "
            "infrastructure failure can result in irrecoverable data loss. FedRAMP CP-9 "
            "requires system and user-level data backups with tested recovery procedures."
        ),
        "action": (
            "Enable AWS Backup with a vault, a backup plan covering all critical "
            "resources, and a retention period of at least 35 days."
        ),
        "terraform": """\
resource "aws_backup_vault" "main" {
  name        = "fedramp-backup-vault"
  kms_key_arn = aws_kms_key.app_key.arn
}

resource "aws_backup_plan" "main" {
  name = "fedramp-backup-plan"
  rule {
    rule_name         = "daily-35-day-retention"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 5 ? * * *)"
    lifecycle {
      delete_after = 35
    }
    copy_action {
      destination_vault_arn = aws_backup_vault.main.arn
    }
  }
}

resource "aws_backup_selection" "all" {
  name         = "fedramp-all-resources"
  iam_role_arn = aws_iam_role.backup.arn
  plan_id      = aws_backup_plan.main.id
  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "true"
  }
}""",
    },
}


# ── Static remediation library: Azure (azurerm) ───────────────────────────────
# Same KSIs as the AWS library, expressed with the azurerm provider (v4 syntax;
# where v3 used a different attribute name it is noted inline).

_STATIC_REMEDIATIONS_AZURE: dict[str, dict[str, str]] = {
    "KSI-SC-2": {
        "risk": (
            "Sensitive data stored without encryption is exposed if storage media "
            "is lost, stolen, or accessed without authorisation. FedRAMP SC-28 "
            "requires encryption of all data at rest using FIPS 140-2 validated modules."
        ),
        "action": (
            "Azure encrypts Storage, SQL and managed disks with platform keys by default; "
            "for FedRAMP use customer-managed keys in Key Vault (purge protection on) so "
            "key use is audited and rotatable. Enable infrastructure (double) encryption "
            "on storage accounts, TDE with a Key Vault key on Azure SQL, and a disk "
            "encryption set for managed disks."
        ),
        "terraform": """\
resource "azurerm_key_vault_key" "cmk" {
  name         = "fedramp-cmk"
  key_vault_id = azurerm_key_vault.main.id   # purge_protection_enabled = true
  key_type     = "RSA-HSM"
  key_size     = 3072
  key_opts     = ["wrapKey", "unwrapKey"]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after = "P1Y"
  }
}

# Storage account: infrastructure encryption + customer-managed key
resource "azurerm_storage_account" "example" {
  # ... other config ...
  infrastructure_encryption_enabled = true

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.storage.id]
  }

  customer_managed_key {
    key_vault_key_id          = azurerm_key_vault_key.cmk.id
    user_assigned_identity_id = azurerm_user_assigned_identity.storage.id
  }
}

# Azure SQL: transparent data encryption with a Key Vault key
resource "azurerm_mssql_server_transparent_data_encryption" "example" {
  server_id        = azurerm_mssql_server.example.id
  key_vault_key_id = azurerm_key_vault_key.cmk.id
}

# Managed disks: encrypt with the same CMK via a disk encryption set
resource "azurerm_disk_encryption_set" "main" {
  name                = "fedramp-des"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  key_vault_key_id    = azurerm_key_vault_key.cmk.id

  identity {
    type = "SystemAssigned"
  }
}""",
    },

    "KSI-SC-1": {
        "risk": (
            "Unencrypted data in transit can be intercepted and read by an adversary "
            "performing a man-in-the-middle attack. FedRAMP SC-8 requires encryption "
            "of all data in transit using TLS 1.2 or higher."
        ),
        "action": (
            "Require HTTPS and a minimum of TLS 1.2 on every endpoint: storage accounts, "
            "App Service / Function apps, Azure SQL and Application Gateway listeners. "
            "Redirect HTTP to HTTPS at the gateway."
        ),
        "terraform": """\
resource "azurerm_storage_account" "example" {
  # ... other config ...
  https_traffic_only_enabled = true      # azurerm v3: enable_https_traffic_only
  min_tls_version            = "TLS1_2"
}

resource "azurerm_linux_web_app" "example" {
  # ... other config ...
  https_only = true
  site_config {
    minimum_tls_version = "1.2"
    ftps_state          = "Disabled"
  }
}

resource "azurerm_mssql_server" "example" {
  # ... other config ...
  minimum_tls_version = "1.2"
}

# Application Gateway: TLS 1.2+ policy and HTTP -> HTTPS redirect
resource "azurerm_application_gateway" "example" {
  # ... other config ...
  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101S"   # TLS 1.2 minimum
  }

  redirect_configuration {
    name                 = "http-to-https"
    redirect_type        = "Permanent"
    target_listener_name = "https-listener"
    include_path         = true
    include_query_string = true
  }
}""",
    },

    "KSI-AU-1": {
        "risk": (
            "Without comprehensive audit logging, security incidents cannot be detected, "
            "investigated, or attributed. FedRAMP requires audit records for defined "
            "event types with content capturing who, what, when, and where."
        ),
        "action": (
            "Send the subscription Activity Log and resource diagnostic logs to a "
            "central Log Analytics workspace with at least one year of retention. "
            "Add a diagnostic setting to each critical resource (Key Vault, SQL, "
            "Storage, App Service)."
        ),
        "terraform": """\
data "azurerm_subscription" "current" {}

resource "azurerm_log_analytics_workspace" "audit" {
  name                = "fedramp-audit-law"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "PerGB2018"
  retention_in_days   = 365
}

# Subscription Activity Log -> Log Analytics
resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "fedramp-activity-log"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.audit.id

  dynamic "enabled_log" {
    for_each = ["Administrative", "Security", "Policy", "Alert",
                "ServiceHealth", "Recommendation", "Autoscale", "ResourceHealth"]
    content {
      category = enabled_log.value
    }
  }
}

# Example resource-level diagnostics (repeat per critical resource)
resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name                       = "fedramp-kv-audit"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.audit.id

  enabled_log {
    category_group = "audit"
  }
  metric {
    category = "AllMetrics"
  }
}""",
    },

    "KSI-SC-4": {
        "risk": (
            "Without defined network boundaries, lateral movement after a breach is "
            "unrestricted. FedRAMP SC-7 requires boundary protection devices that "
            "monitor and control communications at external boundaries and key internal "
            "boundaries."
        ),
        "action": (
            "Place workloads in a virtual network with dedicated subnets. Attach a "
            "network security group to each subnet that allows only required ports "
            "from known sources and explicitly denies all other inbound traffic. "
            "Use private endpoints instead of public access for PaaS services."
        ),
        "terraform": """\
resource "azurerm_virtual_network" "main" {
  name                = "fedramp-vnet"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "app" {
  name                 = "app"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_security_group" "app" {
  name                = "fedramp-app-nsg"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  security_rule {
    name                       = "allow-https-from-gateway"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "10.0.0.0/24"   # Application Gateway subnet
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = azurerm_network_security_group.app.id
}""",
    },

    "KSI-RA-1": {
        "risk": (
            "Unscanned systems accumulate exploitable vulnerabilities. FedRAMP RA-5 "
            "requires regular vulnerability scanning with findings tracked and "
            "remediated within defined timeframes (30 days for critical/high)."
        ),
        "action": (
            "Enable Microsoft Defender for Cloud plans for servers (P2 includes "
            "vulnerability assessment), containers (registry image scanning) and SQL. "
            "Configure a security contact so critical findings are emailed."
        ),
        "terraform": """\
resource "azurerm_security_center_subscription_pricing" "servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
  subplan       = "P2"   # includes agentless vulnerability assessment
}

resource "azurerm_security_center_subscription_pricing" "plans" {
  for_each      = toset(["Containers", "SqlServers", "SqlServerVirtualMachines"])
  tier          = "Standard"
  resource_type = each.value
}

resource "azurerm_security_center_contact" "security_team" {
  name                = "fedramp-security"
  email               = "security@example.gov"
  alert_notifications = true
  alerts_to_admins    = true
}""",
    },

    "KSI-SI-2": {
        "risk": (
            "Without continuous monitoring, attacks can persist undetected for extended "
            "periods. FedRAMP SI-4 requires that the information system is monitored "
            "for attacks and indicators of potential attacks."
        ),
        "action": (
            "Enable Microsoft Defender for Cloud threat protection across workloads and "
            "onboard the central Log Analytics workspace to Microsoft Sentinel. Route "
            "high-severity alerts to the security team through an action group."
        ),
        "terraform": """\
resource "azurerm_security_center_subscription_pricing" "threat_protection" {
  for_each      = toset(["VirtualMachines", "StorageAccounts", "KeyVaults", "Arm", "AppServices"])
  tier          = "Standard"
  resource_type = each.value
}

# Microsoft Sentinel on the audit workspace (see KSI-AU-1)
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "main" {
  workspace_id = azurerm_log_analytics_workspace.audit.id
}

resource "azurerm_monitor_action_group" "security" {
  name                = "fedramp-security-alerts"
  resource_group_name = azurerm_resource_group.main.name
  short_name          = "secalerts"

  email_receiver {
    name          = "security-team"
    email_address = "security@example.gov"
  }
}

# Alert on Defender for Cloud high-severity security alerts
resource "azurerm_monitor_activity_log_alert" "defender_high" {
  name                = "defender-high-severity"
  resource_group_name = azurerm_resource_group.main.name
  location            = "global"
  scopes              = [data.azurerm_subscription.current.id]

  criteria {
    category = "Security"
    level    = "Critical"
  }

  action {
    action_group_id = azurerm_monitor_action_group.security.id
  }
}""",
    },

    "KSI-CP-1": {
        "risk": (
            "Without tested backups, a ransomware attack, accidental deletion, or "
            "infrastructure failure can result in irrecoverable data loss. FedRAMP CP-9 "
            "requires system and user-level data backups with tested recovery procedures."
        ),
        "action": (
            "Create a Recovery Services vault with soft delete and geo-redundant storage, "
            "a daily VM backup policy retaining at least 35 days, and protect every "
            "critical VM. Azure SQL keeps point-in-time backups; set short-term "
            "retention to 35 days."
        ),
        "terraform": """\
resource "azurerm_recovery_services_vault" "main" {
  name                = "fedramp-rsv"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Standard"
  storage_mode_type   = "GeoRedundant"
  soft_delete_enabled = true
}

resource "azurerm_backup_policy_vm" "daily" {
  name                = "daily-35-day-retention"
  resource_group_name = azurerm_resource_group.main.name
  recovery_vault_name = azurerm_recovery_services_vault.main.name

  backup {
    frequency = "Daily"
    time      = "05:00"
  }
  retention_daily {
    count = 35
  }
}

resource "azurerm_backup_protected_vm" "app" {
  resource_group_name = azurerm_resource_group.main.name
  recovery_vault_name = azurerm_recovery_services_vault.main.name
  source_vm_id        = azurerm_linux_virtual_machine.app.id
  backup_policy_id    = azurerm_backup_policy_vm.daily.id
}

resource "azurerm_mssql_database" "example" {
  # ... other config ...
  short_term_retention_policy {
    retention_days = 35
  }
}""",
    },
}

# ── LLM prompt ────────────────────────────────────────────────────────────────

_CLOUD_PROMPT_NAMES: dict[str, tuple[str, str]] = {
    # cloud: (display name, Terraform provider)
    "aws": ("AWS", "aws"),
    "azure": ("Azure", "azurerm"),
}


def _build_remediation_prompt(gap: ControlGap, cloud: str = "aws") -> str:
    cloud_name, provider = _CLOUD_PROMPT_NAMES[cloud]
    controls_str = ", ".join(gap.ksi.control_ids)
    return f"""You are a FedRAMP compliance engineer. A cloud infrastructure gap has been identified.

KSI ID      : {gap.ksi.ksi_id}
KSI Title   : {gap.ksi.title}
Controls    : {controls_str}
Description : {gap.ksi.description}
Missing controls not found in infrastructure: {", ".join(gap.missing_controls)}

Provide a remediation plan in the following JSON format exactly:
{{
  "risk_explanation": "2-3 sentence plain-English explanation of the security risk",
  "remediation_action": "Specific step-by-step action to take in {cloud_name}",
  "terraform_snippet": "Working Terraform HCL ({provider} provider) that would satisfy the control"
}}

Respond ONLY with the JSON object. No explanation outside the JSON."""


def _call_llm_for_remediation(
    gap: ControlGap, model: str, base_url: str, cloud: str = "aws"
) -> dict[str, str] | None:
    prompt = _build_remediation_prompt(gap, cloud)
    try:
        client = ollama.Client(host=base_url)
        response = client.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.2},
        )
        raw = response["message"]["content"].strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())
    except Exception as exc:  # noqa: BLE001
        log.warning("LLM remediation call failed for %s: %s", gap.ksi.ksi_id, exc)
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def detect_cloud(resources: Iterable[ParsedResource]) -> Cloud:
    """
    Pick the cloud whose remediation snippets best fit *resources*.

    Azure resources are ``azurerm_*`` Terraform types or ``Microsoft.*`` ARM
    types; AWS resources are ``aws_*`` Terraform types or ``AWS::*``
    CloudFormation/CDK types.  Whichever cloud has more resources wins; ties
    (including no resources) default to ``"aws"``.
    """
    aws = azure = 0
    for r in resources:
        rtype = r.resource_type
        if rtype.startswith(("aws_", "AWS::")):
            aws += 1
        elif rtype.startswith("azurerm_") or rtype.lower().startswith("microsoft."):
            azure += 1
    return "azure" if azure > aws else "aws"


class RemediationAdvisor:
    """
    Generates remediation advice for FedRAMP KSI gaps.

    Usage
    -----
    advisor = RemediationAdvisor(cloud="azure")   # or "aws" (default)
    advices = advisor.advise(gap_report.gaps)
    for advice in advices:
        print(advice.ksi_id)
        print(advice.terraform_snippet)
    """

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        llm_fallback: bool = True,
        cloud: Cloud = "aws",
    ) -> None:
        if cloud not in SUPPORTED_CLOUDS:
            raise ValueError(f"cloud must be one of {SUPPORTED_CLOUDS}, got {cloud!r}")
        self.cloud = cloud
        self.model = model or os.getenv("OLLAMA_MODEL", "mistral")
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.llm_fallback = llm_fallback

    def advise_gap(self, gap: ControlGap) -> RemediationAdvice:
        """Generate remediation advice for a single gap."""

        # Layer 1: static library (instant, no LLM needed)
        library = _STATIC_REMEDIATIONS_AZURE if self.cloud == "azure" else _STATIC_REMEDIATIONS
        static = library.get(gap.ksi.ksi_id)
        if static:
            return RemediationAdvice(
                ksi_id=gap.ksi.ksi_id,
                control_ids=list(gap.ksi.control_ids),
                risk_explanation=static["risk"],
                remediation_action=static["action"],
                terraform_snippet=static["terraform"],
                source="static",
                cloud=self.cloud,
            )

        # Layer 2: LLM fallback
        if self.llm_fallback:
            log.info("Querying LLM for remediation: %s", gap.ksi.ksi_id)
            result = _call_llm_for_remediation(gap, self.model, self.base_url, self.cloud)
            if result:
                return RemediationAdvice(
                    ksi_id=gap.ksi.ksi_id,
                    control_ids=list(gap.ksi.control_ids),
                    risk_explanation=result.get("risk_explanation", ""),
                    remediation_action=result.get("remediation_action", ""),
                    terraform_snippet=result.get("terraform_snippet", ""),
                    source="llm",
                    cloud=self.cloud,
                )

        # Fallback: generic advice
        return RemediationAdvice(
            ksi_id=gap.ksi.ksi_id,
            control_ids=list(gap.ksi.control_ids),
            risk_explanation=gap.ksi.description,
            remediation_action=(
                f"Implement controls {', '.join(gap.ksi.control_ids)} "
                f"to satisfy {gap.ksi.ksi_id}: {gap.ksi.title}."
            ),
            terraform_snippet="# No automated snippet available — consult FedRAMP documentation.",
            source="generic",
            cloud=self.cloud,
        )

    def advise(self, gaps: list[ControlGap]) -> list[RemediationAdvice]:
        """Generate advice for all gaps, critical/high first."""
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_gaps = sorted(gaps, key=lambda g: priority_order.get(g.ksi.severity.value, 9))
        return [self.advise_gap(gap) for gap in sorted_gaps]
