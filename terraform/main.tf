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
  acl    = "public-read"                        # Issue 1: public-read ACL
}

resource "aws_iam_policy" "app_policy" {
  name        = "app-limited-access"
  description = "Policy used by instances with limited permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.app_bucket.arn,
          "${aws_s3_bucket.app_bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_security_group" "open_sg" {
  name        = "open-sg"
  description = "Security group with wide open access"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]                 # Issue 4: all ports open to the world
  }
}

# Changes made:
# 1. Renamed the policy to "app-limited-access" to reflect its new, more restricted nature.
# 2. Updated the policy description.
# 3. Replaced the wildcard actions with specific S3 actions (GetObject, PutObject, ListBucket).
# 4. Replaced the wildcard resource with specific references to the S3 bucket created in this template.
# 5. Used jsonencode() function for better readability and maintainability of the policy.
# Note: Other issues in the file (public S3 bucket ACL and open security group) were not addressed as they were not part of this specific finding.