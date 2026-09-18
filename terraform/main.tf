# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
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
  # Fixed CWE-285: Removed public-read ACL; bucket is now private by default
}

# Fixed CWE-285: Replaced wildcard (*) IAM actions and resources with least-privilege
resource "aws_iam_policy" "app_policy" {
  name        = "app-full-access"
  description = "Policy used by instances - restricted to least privilege"

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
    }
  ]
}
EOF
}

resource "aws_security_group" "open_sg" {
  name        = "open-sg"
  description = "Security group with restricted access"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    # Fixed: Restricted from 0.0.0.0/0 all-ports to HTTPS-only from private CIDR
    cidr_blocks = ["10.0.0.0/8"]
  }
}
