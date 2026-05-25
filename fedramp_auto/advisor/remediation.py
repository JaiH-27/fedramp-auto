"""
fedramp_auto.advisor.remediation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Given a FedRAMP KSI gap, uses Mistral 7B to generate:
  1. Plain-English explanation of the risk
  2. Specific remediation action
  3. Terraform code snippet that would satisfy the control

Uses a static fallback library for the most common gaps so a Mistral
instance isn't strictly required to get useful output during development.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass

import ollama

from fedramp_auto.gaps.detector import ControlGap

log = logging.getLogger(__name__)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class RemediationAdvice:
    ksi_id: str
    control_ids: list[str]
    risk_explanation: str
    remediation_action: str
    terraform_snippet: str
    source: str   # "static" | "llm"


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


# ── LLM prompt ────────────────────────────────────────────────────────────────

def _build_remediation_prompt(gap: ControlGap) -> str:
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
  "remediation_action": "Specific step-by-step action to take in AWS",
  "terraform_snippet": "Working Terraform HCL code that would satisfy the control"
}}

Respond ONLY with the JSON object. No explanation outside the JSON."""


def _call_llm_for_remediation(
    gap: ControlGap, model: str, base_url: str
) -> dict[str, str] | None:
    prompt = _build_remediation_prompt(gap)
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

class RemediationAdvisor:
    """
    Generates remediation advice for FedRAMP KSI gaps.

    Usage
    -----
    advisor = RemediationAdvisor()
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
    ) -> None:
        self.model = model or os.getenv("OLLAMA_MODEL", "mistral")
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.llm_fallback = llm_fallback

    def advise_gap(self, gap: ControlGap) -> RemediationAdvice:
        """Generate remediation advice for a single gap."""

        # Layer 1: static library (instant, no LLM needed)
        static = _STATIC_REMEDIATIONS.get(gap.ksi.ksi_id)
        if static:
            return RemediationAdvice(
                ksi_id=gap.ksi.ksi_id,
                control_ids=list(gap.ksi.control_ids),
                risk_explanation=static["risk"],
                remediation_action=static["action"],
                terraform_snippet=static["terraform"],
                source="static",
            )

        # Layer 2: LLM fallback
        if self.llm_fallback:
            log.info("Querying LLM for remediation: %s", gap.ksi.ksi_id)
            result = _call_llm_for_remediation(gap, self.model, self.base_url)
            if result:
                return RemediationAdvice(
                    ksi_id=gap.ksi.ksi_id,
                    control_ids=list(gap.ksi.control_ids),
                    risk_explanation=result.get("risk_explanation", ""),
                    remediation_action=result.get("remediation_action", ""),
                    terraform_snippet=result.get("terraform_snippet", ""),
                    source="llm",
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
        )

    def advise(self, gaps: list[ControlGap]) -> list[RemediationAdvice]:
        """Generate advice for all gaps, critical/high first."""
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_gaps = sorted(gaps, key=lambda g: priority_order.get(g.ksi.severity.value, 9))
        return [self.advise_gap(gap) for gap in sorted_gaps]
