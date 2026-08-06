# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
# Security fixes applied: private ACL, least-privilege IAM, restricted security group
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "app_bucket" {
  bucket = "sample-app-terraform-bucket-12345"
  # CWE-284 fix: Removed public-read ACL, using private (default)
}

resource "aws_s3_bucket_acl" "app_bucket_acl" {
  bucket = aws_s3_bucket.app_bucket.id
  acl    = "private"
}

resource "aws_iam_policy" "app_policy" {
  name        = "app-least-privilege"
  description = "Least-privilege policy for application instances"

  # CWE-285 fix: Replaced wildcard actions/resources with specific permissions
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::sample-app-terraform-bucket-12345",
        "arn:aws:s3:::sample-app-terraform-bucket-12345/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/app/*"
    }
  ]
}
EOF
}

resource "aws_security_group" "open_sg" {
  name        = "app-sg"
  description = "Security group with restricted access"

  # CWE-284 fix: Restrict to HTTPS only from internal network
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
