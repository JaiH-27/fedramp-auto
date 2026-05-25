# FedRAMP-Auto scan report

**Baseline:** LOW  
**KSI coverage:** 44.8% (13/29)  
**Critical gaps:** 8  
**Total gaps:** 16

## Gaps

### KSI-AC-3 — Multi-factor authentication for privileged access
**Severity:** critical  
**Missing controls:** IA-2, IA-2(1)

### KSI-AC-4 — Session management and timeout
**Severity:** high  
**Missing controls:** AC-11, AC-12

### KSI-AC-6 — Remote access controls
**Severity:** high  
**Missing controls:** AC-17

### KSI-AU-3 — Audit log storage and retention
**Severity:** high  
**Missing controls:** AU-4, AU-11

### KSI-CM-1 — Baseline configuration and inventory
**Severity:** critical  
**Missing controls:** CM-6, CM-8

### KSI-CM-2 — Configuration change control
**Severity:** high  
**Missing controls:** CM-3

### KSI-CM-4 — Least functionality
**Severity:** medium  
**Missing controls:** CM-7

### KSI-IA-1 — Unique identification and authentication
**Severity:** critical  
**Missing controls:** IA-2, IA-4

### KSI-IA-2 — Password and authenticator management
**Severity:** high  
**Missing controls:** IA-5

### KSI-IR-1 — Incident response capability
**Severity:** critical  
**Missing controls:** IR-4, IR-5, IR-6

### KSI-RA-1 — Vulnerability scanning
**Severity:** critical  
**Missing controls:** RA-5

### KSI-SC-1 — Data in transit encryption
**Severity:** critical  
**Missing controls:** SC-8, SC-8(1)

### KSI-SC-5 — Information flow enforcement
**Severity:** high  
**Missing controls:** AC-4

### KSI-SI-1 — Malicious code protection
**Severity:** critical  
**Missing controls:** SI-3

### KSI-SI-2 — System monitoring
**Severity:** critical  
**Missing controls:** SI-4

### KSI-SI-4 — Flaw remediation
**Severity:** high  
**Missing controls:** SI-2

## Remediations

### KSI-AC-3
**Risk:** MFA is required for all privileged and remote access.

**Action:** Implement controls IA-2, IA-2(1) to satisfy KSI-AC-3: Multi-factor authentication for privileged access.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```

### KSI-CM-1
**Risk:** A documented baseline configuration and component inventory is maintained.

**Action:** Implement controls CM-6, CM-8 to satisfy KSI-CM-1: Baseline configuration and inventory.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```

### KSI-IA-1
**Risk:** All users and devices are uniquely identified and authenticated.

**Action:** Implement controls IA-2, IA-4 to satisfy KSI-IA-1: Unique identification and authentication.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```

### KSI-IR-1
**Risk:** Incidents are detected, handled, and reported per documented procedures.

**Action:** Implement controls IR-4, IR-5, IR-6 to satisfy KSI-IR-1: Incident response capability.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```

### KSI-RA-1
**Risk:** Unscanned systems accumulate exploitable vulnerabilities. FedRAMP RA-5 requires regular vulnerability scanning with findings tracked and remediated within defined timeframes (30 days for critical/high).

**Action:** Enable Amazon Inspector v2 for EC2 and container image scanning. Enable AWS Security Hub to aggregate findings. Configure SNS alerts for critical findings.

**Terraform:**
```hcl
resource "aws_inspector2_enabler" "main" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]
}

resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "fedramp" {
  standards_arn = "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}
```

### KSI-SC-1
**Risk:** Unencrypted data in transit can be intercepted and read by an adversary performing a man-in-the-middle attack. FedRAMP SC-8 requires encryption of all data in transit using TLS 1.2 or higher.

**Action:** Enforce HTTPS on all load balancers and APIs. Add an aws_lb_listener with protocol=HTTPS and a valid ACM certificate. Add an aws_api_gateway_domain_name with a security policy of TLS_1_2.

**Terraform:**
```hcl
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
}
```

### KSI-SI-1
**Risk:** Malicious code protection is deployed and updated at system entry/exit points.

**Action:** Implement controls SI-3 to satisfy KSI-SI-1: Malicious code protection.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```

### KSI-SI-2
**Risk:** Without continuous monitoring, attacks can persist undetected for extended periods. FedRAMP SI-4 requires that the information system is monitored for attacks and indicators of potential attacks.

**Action:** Enable Amazon GuardDuty in all regions. Configure EventBridge rules to route HIGH/CRITICAL findings to SNS for alerting.

**Terraform:**
```hcl
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
}
```

### KSI-AC-4
**Risk:** Inactive sessions are terminated after a defined period.

**Action:** Implement controls AC-11, AC-12 to satisfy KSI-AC-4: Session management and timeout.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```

### KSI-AC-6
**Risk:** Remote access is authorized, encrypted, and monitored.

**Action:** Implement controls AC-17 to satisfy KSI-AC-6: Remote access controls.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```

### KSI-AU-3
**Risk:** Logs are stored with sufficient capacity and retained >= 90 days.

**Action:** Implement controls AU-4, AU-11 to satisfy KSI-AU-3: Audit log storage and retention.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```

### KSI-CM-2
**Risk:** Configuration changes are controlled, reviewed, and approved.

**Action:** Implement controls CM-3 to satisfy KSI-CM-2: Configuration change control.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```

### KSI-IA-2
**Risk:** Authenticators meet complexity, rotation, and storage requirements.

**Action:** Implement controls IA-5 to satisfy KSI-IA-2: Password and authenticator management.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```

### KSI-SC-5
**Risk:** Information flows between systems are controlled and enforced.

**Action:** Implement controls AC-4 to satisfy KSI-SC-5: Information flow enforcement.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```

### KSI-SI-4
**Risk:** Security flaws are identified, reported, and corrected.

**Action:** Implement controls SI-2 to satisfy KSI-SI-4: Flaw remediation.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```

### KSI-CM-4
**Risk:** Systems are configured to provide only essential capabilities.

**Action:** Implement controls CM-7 to satisfy KSI-CM-4: Least functionality.

**Terraform:**
```hcl
# No automated snippet available — consult FedRAMP documentation.
```
