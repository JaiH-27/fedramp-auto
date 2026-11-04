"""
fedramp_auto.advisor.remediation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Given a FedRAMP KSI gap, uses Mistral 7B to generate:
  1. Plain-English explanation of the risk
  2. Specific remediation action
  3. Code snippet that would satisfy the control

Snippets target the tooling the scanned infrastructure uses: ``aws``
(Terraform, ``aws`` provider), ``azure`` (Terraform, ``azurerm`` provider)
or ``cdk`` (AWS CDK v2, TypeScript).  Use :func:`detect_cloud` to pick one
from parsed resources.

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

Cloud = Literal["aws", "azure", "cdk"]
SUPPORTED_CLOUDS: tuple[str, ...] = ("aws", "azure", "cdk")

# Language of the snippets each target produces (used for code fences)
SNIPPET_LANGUAGE: dict[str, str] = {"aws": "hcl", "azure": "hcl", "cdk": "typescript"}

_COMMENT_PREFIX: dict[str, str] = {"hcl": "#", "typescript": "//"}

log = logging.getLogger(__name__)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class RemediationAdvice:
    ksi_id: str
    control_ids: list[str]
    risk_explanation: str
    remediation_action: str
    # Historical name: holds HCL for aws/azure and TypeScript for cdk.
    # Check snippet_language rather than assuming Terraform.
    terraform_snippet: str
    source: str   # "static" | "llm" | "generic"
    cloud: str = "aws"   # "aws" | "azure" | "cdk" — what the snippet targets
    snippet_language: str = "hcl"   # "hcl" | "typescript"


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
}""",  # noqa: E501 (ARN cannot wrap)
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
    expire_after         = "P1Y"
    notify_before_expiry = "P29D"
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
  enabled_metric {
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
            "Create a geo-redundant Recovery Services vault (soft delete is on by default), "
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
  # soft delete is always on for new vaults (Azure secure-by-default)
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

# ── Static remediation library: AWS CDK (TypeScript) ──────────────────────────
# Same KSIs as the AWS library, as AWS CDK v2 (aws-cdk-lib) TypeScript.  Each
# snippet is: imports, then code for the body of a Stack constructor.  Risks
# are shared with the AWS library — only the fix differs.  Every snippet is
# type-checked and synthesized by scripts/check_cdk_snippets.py.

def _cdk(ksi_id: str, action: str, snippet: str) -> dict[str, str]:
    return {"risk": _STATIC_REMEDIATIONS[ksi_id]["risk"], "action": action, "snippet": snippet}


_STATIC_REMEDIATIONS_CDK: dict[str, dict[str, str]] = {
    "KSI-SC-2": _cdk(
        "KSI-SC-2",
        "Create a customer-managed KMS key with automatic rotation and use it for S3 "
        "(SSE-KMS with bucket keys) and RDS storage encryption. RDS encryption can "
        "only be set when the instance is created.",
        """\
import { RemovalPolicy } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as s3 from 'aws-cdk-lib/aws-s3';

// Customer-managed key with automatic yearly rotation
const appKey = new kms.Key(this, 'AppKey', {
  enableKeyRotation: true,
  removalPolicy: RemovalPolicy.RETAIN,
});

// S3: SSE-KMS with the customer-managed key
new s3.Bucket(this, 'DataBucket', {
  encryption: s3.BucketEncryption.KMS,
  encryptionKey: appKey,
  bucketKeyEnabled: true,
  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  enforceSSL: true,
});

// RDS: storage encryption (must be set at creation time)
const vpc = new ec2.Vpc(this, 'Vpc', { maxAzs: 2 });  // or reuse your existing VPC
new rds.DatabaseInstance(this, 'Database', {
  engine: rds.DatabaseInstanceEngine.postgres({ version: rds.PostgresEngineVersion.VER_16 }),
  vpc,
  storageEncrypted: true,
  storageEncryptionKey: appKey,
});""",
    ),

    "KSI-SC-1": _cdk(
        "KSI-SC-1",
        "Serve traffic through an HTTPS listener with the TLS 1.3/1.2 security policy, "
        "redirect HTTP to HTTPS, and add enforceSSL to every S3 bucket so plain-HTTP "
        "requests are denied.",
        """\
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as s3 from 'aws-cdk-lib/aws-s3';

const vpc = new ec2.Vpc(this, 'Vpc', { maxAzs: 2 });  // or reuse your existing VPC
const certificate = acm.Certificate.fromCertificateArn(
  this, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/REPLACE-ME',
);

const alb = new elbv2.ApplicationLoadBalancer(this, 'Alb', { vpc, internetFacing: true });

// HTTPS only, TLS 1.3 + 1.2 (ELBSecurityPolicy-TLS13-1-2-2021-06)
alb.addListener('Https', {
  port: 443,
  certificates: [certificate],
  sslPolicy: elbv2.SslPolicy.RECOMMENDED_TLS,
  defaultAction: elbv2.ListenerAction.fixedResponse(404),  // replace with your targets
});

// Redirect HTTP -> HTTPS
alb.addRedirect({ sourcePort: 80, targetPort: 443 });

// S3: deny any request not made over TLS 1.2+
new s3.Bucket(this, 'Bucket', { enforceSSL: true, minimumTLSVersion: 1.2 });""",
    ),

    "KSI-AU-1": _cdk(
        "KSI-AU-1",
        "Create a multi-region CloudTrail trail with log file validation, delivered to "
        "a versioned, KMS-encrypted S3 bucket and streamed to CloudWatch Logs (one-year "
        "retention) for real-time alerting.",
        """\
import { RemovalPolicy } from 'aws-cdk-lib';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';

const auditKey = new kms.Key(this, 'AuditKey', { enableKeyRotation: true });
// CloudTrail must be allowed to encrypt log files with the key
auditKey.addToResourcePolicy(new iam.PolicyStatement({
  actions: ['kms:GenerateDataKey*', 'kms:DescribeKey'],
  principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
  resources: ['*'],
}));

const auditBucket = new s3.Bucket(this, 'AuditBucket', {
  encryption: s3.BucketEncryption.KMS,
  encryptionKey: auditKey,
  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  enforceSSL: true,
  versioned: true,
  removalPolicy: RemovalPolicy.RETAIN,
});

const trail = new cloudtrail.Trail(this, 'Trail', {
  bucket: auditBucket,
  encryptionKey: auditKey,
  isMultiRegionTrail: true,
  includeGlobalServiceEvents: true,
  enableFileValidation: true,
  sendToCloudWatchLogs: true,
  cloudWatchLogsRetention: logs.RetentionDays.ONE_YEAR,
});
trail.logAllS3DataEvents();""",
    ),

    "KSI-SC-4": _cdk(
        "KSI-SC-4",
        "Deploy into a VPC with public, private and isolated subnet tiers, lock down "
        "the default security group, enable VPC flow logs, and chain least-privilege "
        "security groups so only the load balancer can reach the app tier.",
        """\
import * as ec2 from 'aws-cdk-lib/aws-ec2';

const vpc = new ec2.Vpc(this, 'Vpc', {
  ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
  maxAzs: 2,
  subnetConfiguration: [
    { name: 'public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
    { name: 'app', subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS, cidrMask: 24 },
    { name: 'data', subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 24 },
  ],
  restrictDefaultSecurityGroup: true,
  flowLogs: { all: { trafficType: ec2.FlowLogTrafficType.ALL } },
});

const albSg = new ec2.SecurityGroup(this, 'AlbSg', {
  vpc,
  description: 'Public HTTPS entry point',
  allowAllOutbound: false,
});
albSg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'HTTPS from the internet');

const appSg = new ec2.SecurityGroup(this, 'AppSg', {
  vpc,
  description: 'App tier - HTTPS from the ALB only',
  allowAllOutbound: false,
});
appSg.addIngressRule(albSg, ec2.Port.tcp(443), 'HTTPS from the ALB');
albSg.addEgressRule(appSg, ec2.Port.tcp(443), 'Forward to the app tier');""",
    ),

    "KSI-RA-1": _cdk(
        "KSI-RA-1",
        "Enable Amazon Inspector v2 for EC2, ECR and Lambda (no CloudFormation resource "
        "exists, so use an SDK custom resource), enable Security Hub with the NIST "
        "800-53 Rev. 5 standard, and turn on scan-on-push for container registries.",
        """\
import { Stack } from 'aws-cdk-lib';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as securityhub from 'aws-cdk-lib/aws-securityhub';
import * as cr from 'aws-cdk-lib/custom-resources';

// Amazon Inspector v2 has no CloudFormation resource: enable it with an SDK call
new cr.AwsCustomResource(this, 'EnableInspector', {
  onCreate: {
    service: 'Inspector2',
    action: 'enable',
    parameters: { resourceTypes: ['EC2', 'ECR', 'LAMBDA'] },
    physicalResourceId: cr.PhysicalResourceId.of('inspector2-enable'),
  },
  policy: cr.AwsCustomResourcePolicy.fromStatements([
    new iam.PolicyStatement({
      actions: ['inspector2:Enable', 'iam:CreateServiceLinkedRole'],
      resources: ['*'],
    }),
  ]),
});

// Security Hub with the NIST 800-53 Rev. 5 standard
const { partition, region } = Stack.of(this);
const hub = new securityhub.CfnHub(this, 'SecurityHub', {});
const nist = new securityhub.CfnStandard(this, 'Nist80053', {
  standardsArn: `arn:${partition}:securityhub:${region}::standards/nist-800-53/v/5.0.0`,
});
nist.addDependency(hub);

// Scan every container image on push
new ecr.Repository(this, 'AppImages', {
  imageScanOnPush: true,
  imageTagMutability: ecr.TagMutability.IMMUTABLE,
});""",
    ),

    "KSI-SI-2": _cdk(
        "KSI-SI-2",
        "Enable Amazon GuardDuty with S3, EKS audit log and EBS malware protection, and "
        "route HIGH/CRITICAL findings (severity >= 7) to an SNS topic via EventBridge.",
        """\
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as guardduty from 'aws-cdk-lib/aws-guardduty';
import * as sns from 'aws-cdk-lib/aws-sns';

new guardduty.CfnDetector(this, 'GuardDuty', {
  enable: true,
  features: [
    { name: 'S3_DATA_EVENTS', status: 'ENABLED' },
    { name: 'EKS_AUDIT_LOGS', status: 'ENABLED' },
    { name: 'EBS_MALWARE_PROTECTION', status: 'ENABLED' },
  ],
});

const securityAlerts = new sns.Topic(this, 'SecurityAlerts', { enforceSSL: true });

new events.Rule(this, 'GuardDutyHighSeverity', {
  description: 'Route HIGH and CRITICAL GuardDuty findings to the security team',
  eventPattern: {
    source: ['aws.guardduty'],
    detailType: ['GuardDuty Finding'],
    detail: { severity: events.Match.greaterThanOrEqual(7) },
  },
  targets: [new targets.SnsTopic(securityAlerts)],
});""",
    ),

    "KSI-CP-1": _cdk(
        "KSI-CP-1",
        "Create an AWS Backup vault encrypted with a customer-managed key and a daily "
        "plan retaining recovery points for 35 days, selecting every resource tagged "
        "Backup=true. For DynamoDB also enable point-in-time recovery.",
        """\
import { Duration, RemovalPolicy } from 'aws-cdk-lib';
import * as backup from 'aws-cdk-lib/aws-backup';
import * as events from 'aws-cdk-lib/aws-events';
import * as kms from 'aws-cdk-lib/aws-kms';

const backupKey = new kms.Key(this, 'BackupKey', { enableKeyRotation: true });
const vault = new backup.BackupVault(this, 'BackupVault', {
  encryptionKey: backupKey,
  removalPolicy: RemovalPolicy.RETAIN,
});

const plan = new backup.BackupPlan(this, 'BackupPlan', { backupVault: vault });
plan.addRule(new backup.BackupPlanRule({
  ruleName: 'daily-35-day-retention',
  scheduleExpression: events.Schedule.cron({ hour: '5', minute: '0' }),
  deleteAfter: Duration.days(35),
}));

// Back up every resource tagged Backup=true
plan.addSelection('Tagged', {
  resources: [backup.BackupResource.fromTag('Backup', 'true')],
});""",
    ),
}

_LIBRARIES: dict[str, dict[str, dict[str, str]]] = {
    "aws": _STATIC_REMEDIATIONS,
    "azure": _STATIC_REMEDIATIONS_AZURE,
    "cdk": _STATIC_REMEDIATIONS_CDK,
}


# ── LLM prompt ────────────────────────────────────────────────────────────────

_CLOUD_PROMPT_NAMES: dict[str, tuple[str, str]] = {
    # cloud: (display name, what the snippet must be)
    "aws": ("AWS", "Working Terraform HCL (aws provider)"),
    "azure": ("Azure", "Working Terraform HCL (azurerm provider)"),
    "cdk": (
        "AWS",
        "Working AWS CDK v2 TypeScript (aws-cdk-lib imports, then code for a Stack constructor)",
    ),
}


def _build_remediation_prompt(gap: ControlGap, cloud: str = "aws") -> str:
    cloud_name, snippet_kind = _CLOUD_PROMPT_NAMES[cloud]
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
  "snippet": "{snippet_kind} that would satisfy the control"
}}

Respond ONLY with the JSON object. No explanation outside the JSON."""  # noqa: E501


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
    Pick the snippet target that best fits *resources*.

    Azure resources are ``azurerm_*`` Terraform types or ``Microsoft.*`` ARM
    types; AWS resources are ``aws_*`` Terraform types or ``AWS::*``
    CloudFormation/CDK types.  Azure wins if it has more resources than AWS
    as a whole.  Otherwise the AWS flavour follows the IaC tool: ``"cdk"``
    when CloudFormation types outnumber Terraform ones, else ``"aws"``.
    Ties (including no resources) default to ``"aws"``.
    """
    tf_aws = cfn_aws = azure = 0
    for r in resources:
        rtype = r.resource_type
        if rtype.startswith("aws_"):
            tf_aws += 1
        elif rtype.startswith("AWS::"):
            cfn_aws += 1
        elif rtype.startswith("azurerm_") or rtype.lower().startswith("microsoft."):
            azure += 1
    if azure > tf_aws + cfn_aws:
        return "azure"
    return "cdk" if cfn_aws > tf_aws else "aws"


class RemediationAdvisor:
    """
    Generates remediation advice for FedRAMP KSI gaps.

    Usage
    -----
    advisor = RemediationAdvisor(cloud="azure")   # or "aws" (default) / "cdk"
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

        language = SNIPPET_LANGUAGE[self.cloud]

        # Layer 1: static library (instant, no LLM needed)
        static = _LIBRARIES[self.cloud].get(gap.ksi.ksi_id)
        if static:
            return RemediationAdvice(
                ksi_id=gap.ksi.ksi_id,
                control_ids=list(gap.ksi.control_ids),
                risk_explanation=static["risk"],
                remediation_action=static["action"],
                terraform_snippet=static.get("snippet") or static["terraform"],
                source="static",
                cloud=self.cloud,
                snippet_language=language,
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
                    # "snippet" is the current prompt key; accept the old one too
                    terraform_snippet=result.get("snippet") or result.get("terraform_snippet", ""),
                    source="llm",
                    cloud=self.cloud,
                    snippet_language=language,
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
            terraform_snippet=(
                f"{_COMMENT_PREFIX[language]} No automated snippet available — "
                "consult FedRAMP documentation."
            ),
            source="generic",
            cloud=self.cloud,
            snippet_language=language,
        )

    def advise(self, gaps: list[ControlGap]) -> list[RemediationAdvice]:
        """Generate advice for all gaps, critical/high first."""
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_gaps = sorted(gaps, key=lambda g: priority_order.get(g.ksi.severity.value, 9))
        return [self.advise_gap(gap) for gap in sorted_gaps]
