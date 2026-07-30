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
  acl    = "private"
}

resource "aws_iam_policy" "app_policy" {
  name        = "app-full-access"
  description = "Policy used by instances"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:s3:::sample-app-terraform-bucket-12345",
        "arn:aws:s3:::sample-app-terraform-bucket-12345/*",
        "arn:aws:logs:*:*:*"
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
    cidr_blocks = ["10.0.0.0/8"]
  }
}
