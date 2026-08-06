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
  # Fixed CWE-284: Removed public-read ACL, bucket defaults to private
}

resource "aws_iam_policy" "app_policy" {
  name        = "app-least-privilege"
  description = "Least-privilege policy for application instances"

  # Fixed CWE-285: Replaced wildcard Action/Resource with specific permissions
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
          "arn:aws:s3:::sample-app-terraform-bucket-12345",
          "arn:aws:s3:::sample-app-terraform-bucket-12345/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/app/*"
      }
    ]
  })
}

resource "aws_security_group" "open_sg" {
  name        = "app-sg"
  description = "Restricted security group for application"

  # Fixed CWE-284: Restricted from all ports/0.0.0.0/0 to HTTPS only from internal
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
