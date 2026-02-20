# ─────────────────────────────────────────────────────────────
# AWS IAM Security Auditor — Terraform IaC
# Creates a least-privilege IAM role for the auditor to run with.
# Author: Ankita Dixit | github.com/master-coder1998
# ─────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "trusted_account_id" {
  description = "AWS account ID allowed to assume the auditor role"
  type        = string
}

variable "auditor_username" {
  description = "IAM user or role that will assume the auditor role"
  type        = string
  default     = "iam-auditor-ci"
}

# ── IAM Policy: Least-Privilege Read-Only Auditor ────────────

resource "aws_iam_policy" "auditor_policy" {
  name        = "IAMSecurityAuditorPolicy"
  description = "Least-privilege policy for IAM Security Auditor tool"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMReadOnly"
        Effect = "Allow"
        Action = [
          "iam:GetAccountSummary",
          "iam:GetAccountPasswordPolicy",
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:ListPolicies",
          "iam:ListMFADevices",
          "iam:ListAccessKeys",
          "iam:GetLoginProfile",
          "iam:GetPolicyVersion",
          "iam:GetPolicy",
          "iam:ListAttachedUserPolicies",
          "iam:ListUserPolicies",
          "iam:GetUserPolicy",
          "iam:GenerateCredentialReport",
          "iam:GetCredentialReport",
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Project   = "aws-iam-auditor"
    ManagedBy = "Terraform"
    Author    = "Ankita Dixit"
  }
}

# ── IAM Role: Assumed by CI/CD or Local Machine ──────────────

resource "aws_iam_role" "auditor_role" {
  name        = "IAMSecurityAuditorRole"
  description = "Role assumed by the IAM Security Auditor tool"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TrustedAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.trusted_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = {
    Project   = "aws-iam-auditor"
    ManagedBy = "Terraform"
    Author    = "Ankita Dixit"
  }
}

# ── Attach Policy to Role ─────────────────────────────────────

resource "aws_iam_role_policy_attachment" "auditor_attach" {
  role       = aws_iam_role.auditor_role.name
  policy_arn = aws_iam_policy.auditor_policy.arn
}

# ── Outputs ───────────────────────────────────────────────────

output "auditor_role_arn" {
  description = "ARN of the IAM auditor role — use this with --profile or environment variables"
  value       = aws_iam_role.auditor_role.arn
}

output "auditor_policy_arn" {
  description = "ARN of the least-privilege auditor IAM policy"
  value       = aws_iam_policy.auditor_policy.arn
}
