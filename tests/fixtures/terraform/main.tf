# tests/fixtures/terraform/main.tf
# Realistic AWS infrastructure — used for parser + mapper tests

resource "aws_s3_bucket" "audit_logs" {
  bucket = "my-company-audit-logs"
  tags = {
    Environment = "production"
    DataClass   = "sensitive"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket                  = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "app_role" {
  name = "fedramp-app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  # This should be REDACTED by the parser
  # (testing that secret attr names are caught)
}

resource "aws_kms_key" "app_key" {
  description             = "FedRAMP app encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false
}

resource "aws_db_instance" "app_db" {
  identifier        = "fedramp-app-db"
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  storage_encrypted = true
  # These should be REDACTED:
  password          = "s3cr3tP@ssw0rd!"
  username          = "dbadmin"
  multi_az          = true
  backup_retention_period = 35
  deletion_protection     = true
}

resource "aws_cloudtrail" "main" {
  name                          = "fedramp-trail"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
