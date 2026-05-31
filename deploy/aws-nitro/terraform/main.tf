# SHROUD relay on AWS Nitro Enclaves — Terraform module.
#
# Provisions, in one apply:
#   - S3 bucket for the encrypted config bundle + EIF artifact
#   - KMS key with an attestation-bound policy
#   - IAM role for the parent EC2 instance
#   - Security group for the relay
#   - Network Load Balancer (TLS termination optional via ACM)
#   - Launch template + Auto Scaling Group (size 1 for now)
#
# After apply:
#   1. Build the EIF locally and capture PCR0 measurement
#   2. terraform apply -var=expected_pcr0=<measurement>
#   3. Upload the EIF and the KMS-encrypted config bundle to the S3 bucket
#   4. The ASG instance's user-data fetches both at boot

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
}

provider "aws" {
  region = var.region
}

# ── Variables ────────────────────────────────────────────────────────

variable "region" {
  description = "AWS region for the relay"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC to deploy into (or leave null to use default VPC)"
  type        = string
  default     = null
}

variable "subnet_ids" {
  description = "Subnet IDs the ASG can launch into (≥ 2 for HA)"
  type        = list(string)
}

variable "instance_type" {
  description = "Nitro-enabled instance type"
  type        = string
  default     = "c6i.xlarge"
}

variable "expected_pcr0" {
  description = "Expected PCR0 measurement of the SHROUD EIF (96 hex chars)"
  type        = string
}

variable "relay_port" {
  description = "Public TCP port the relay listens on"
  type        = number
  default     = 58443
}

variable "ssh_cidr" {
  description = "Source CIDR allowed to SSH to the parent (e.g., your home IP/32)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "ssh_key_name" {
  description = "EC2 key pair for parent SSH (create one in the console first)"
  type        = string
}

variable "acm_certificate_arn" {
  description = "Optional ACM cert ARN to terminate TLS on the NLB; null = pass through"
  type        = string
  default     = null
}

# ── S3 bucket for EIF + encrypted config ─────────────────────────────

resource "aws_s3_bucket" "artifacts" {
  bucket_prefix = "shroud-artifacts-"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── KMS key with attestation-bound policy ────────────────────────────

data "aws_caller_identity" "me" {}

resource "aws_kms_key" "config" {
  description              = "SHROUD enclave config encryption key"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
  enable_key_rotation      = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Root account retains admin rights to manage the key (rotate, etc.)
        Sid       = "RootAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.me.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        # The parent role can ENCRYPT freely (we need to encrypt the config
        # before uploading) but DECRYPT requires the enclave attestation.
        Sid       = "ParentEncrypt"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.parent.arn }
        Action    = ["kms:Encrypt", "kms:GenerateDataKey"]
        Resource  = "*"
      },
      {
        # The parent role can request Decrypt, but the request MUST carry
        # a Nitro attestation document whose PCR0 matches our expected value.
        # AWS validates the attestation before releasing plaintext.
        Sid       = "EnclaveDecryptOnly"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.parent.arn }
        Action    = "kms:Decrypt"
        Resource  = "*"
        Condition = {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:ImageSha384" = var.expected_pcr0
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "config" {
  name          = "alias/shroud-relay-config"
  target_key_id = aws_kms_key.config.key_id
}

# ── IAM role for the parent instance ─────────────────────────────────

resource "aws_iam_role" "parent" {
  name = "shroud-parent-${var.region}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "parent" {
  name = "shroud-parent-policy"
  role = aws_iam_role.parent.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.artifacts.arn}/*"
      },
      {
        # KMS is also gated by the key policy condition above — granting
        # here is necessary but not sufficient (the attestation does the
        # actual gating).
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.config.arn
      },
      {
        # CloudWatch Logs are heavily IP-scrubbed in the relay; we still
        # need to be able to write to a log group for debugging the
        # parent-side services (config-server, kms-proxy).
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
        ]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.me.account_id}:log-group:/shroud/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "parent" {
  name = "shroud-parent-${var.region}"
  role = aws_iam_role.parent.name
}

# ── Security group + Network Load Balancer ───────────────────────────

resource "aws_security_group" "parent" {
  name        = "shroud-parent-${var.region}"
  description = "SHROUD relay parent instance"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Relay TCP from NLB"
    from_port       = var.relay_port
    to_port         = var.relay_port
    protocol        = "tcp"
    security_groups = [] # NLB is layer 4, so client IPs reach the SG directly
    cidr_blocks     = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH (restrict to your IP via var.ssh_cidr)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "relay" {
  name                       = "shroud-relay"
  load_balancer_type         = "network"
  internal                   = false
  subnets                    = var.subnet_ids
  enable_deletion_protection = true
  enable_cross_zone_load_balancing = true
}

resource "aws_lb_target_group" "relay" {
  name        = "shroud-relay-tg"
  port        = var.relay_port
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    enabled  = true
    port     = var.relay_port
    protocol = "TCP"
    interval = 30
  }
}

resource "aws_lb_listener" "relay" {
  load_balancer_arn = aws_lb.relay.arn
  port              = var.acm_certificate_arn == null ? var.relay_port : 443
  protocol          = var.acm_certificate_arn == null ? "TCP" : "TLS"
  certificate_arn   = var.acm_certificate_arn
  ssl_policy        = var.acm_certificate_arn == null ? null : "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.relay.arn
  }
}

# ── Launch template + Auto Scaling Group ─────────────────────────────

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_launch_template" "parent" {
  name_prefix   = "shroud-parent-"
  image_id      = data.aws_ami.al2023.id
  instance_type = var.instance_type
  key_name      = var.ssh_key_name

  iam_instance_profile { name = aws_iam_instance_profile.parent.name }

  vpc_security_group_ids = [aws_security_group.parent.id]

  enclave_options { enabled = true }

  user_data = base64encode(templatefile("${path.module}/user-data.sh.tftpl", {
    region          = var.region
    s3_bucket       = aws_s3_bucket.artifacts.bucket
    expected_pcr0   = var.expected_pcr0
    relay_port      = var.relay_port
  }))

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "shroud-relay-${var.region}" }
  }
}

resource "aws_autoscaling_group" "parent" {
  name                = "shroud-relay-asg"
  desired_capacity    = 1
  min_size            = 1
  max_size            = 2
  vpc_zone_identifier = var.subnet_ids
  target_group_arns   = [aws_lb_target_group.relay.arn]

  launch_template {
    id      = aws_launch_template.parent.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 0  # Single instance — we have to drop it to refresh
    }
  }

  tag {
    key                 = "Name"
    value               = "shroud-relay-${var.region}"
    propagate_at_launch = true
  }
}

# ── Outputs ──────────────────────────────────────────────────────────

output "relay_dns_name" {
  description = "Point client config at this DNS name"
  value       = aws_lb.relay.dns_name
}

output "s3_bucket" {
  description = "Upload shroud-enclave.eif and shroud-config.encrypted here"
  value       = aws_s3_bucket.artifacts.bucket
}

output "kms_key_arn" {
  description = "Encrypt the config bundle with this key (aws kms encrypt --key-id ...)"
  value       = aws_kms_key.config.arn
}
