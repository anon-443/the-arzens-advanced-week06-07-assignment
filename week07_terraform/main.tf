terraform {
  required_version = ">= 1.5.0"
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
  # Configure an encrypted remote backend in Terraform Cloud or an S3/DynamoDB backend in production.
  # backend "s3" { bucket = "REPLACE-WITH-TFSTATE-BUCKET" key = "secure-infra/terraform.tfstate" region = "us-east-1" encrypt = true dynamodb_table = "terraform-locks" }
}
provider "aws" { region = var.aws_region }

data "aws_availability_zones" "available" { state = "available" }
resource "aws_vpc" "main" { cidr_block = var.vpc_cidr; enable_dns_support = true; enable_dns_hostnames = true; tags = { Name = "arzens-secure-vpc" } }
resource "aws_subnet" "public" { vpc_id = aws_vpc.main.id; cidr_block = var.public_subnet_cidr; availability_zone = data.aws_availability_zones.available.names[0]; map_public_ip_on_launch = false; tags = { Name = "arzens-private-subnet" } }
resource "aws_security_group" "web" { name = "arzens-web-sg"; description = "Restricted web access"; vpc_id = aws_vpc.main.id
  ingress { description = "SSH from trusted CIDR"; from_port = 22; to_port = 22; protocol = "tcp"; cidr_blocks = [var.admin_cidr] }
  ingress { description = "HTTP"; from_port = 80; to_port = 80; protocol = "tcp"; cidr_blocks = ["0.0.0.0/0"] }
  ingress { description = "HTTPS"; from_port = 443; to_port = 443; protocol = "tcp"; cidr_blocks = ["0.0.0.0/0"] }
  egress { from_port = 0; to_port = 0; protocol = "-1"; cidr_blocks = ["0.0.0.0/0"] }
  tags = { Name = "arzens-restricted-sg" }
}
resource "aws_s3_bucket" "artifacts" { bucket = var.bucket_name; force_destroy = false; tags = { Name = "arzens-encrypted-artifacts" } }
resource "aws_s3_bucket_public_access_block" "artifacts" { bucket = aws_s3_bucket.artifacts.id; block_public_acls = true; block_public_policy = true; ignore_public_acls = true; restrict_public_buckets = true }
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" { bucket = aws_s3_bucket.artifacts.id; rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
resource "aws_s3_bucket_versioning" "artifacts" { bucket = aws_s3_bucket.artifacts.id; versioning_configuration { status = "Enabled" } }
resource "aws_instance" "web" { ami = var.ami_id; instance_type = var.instance_type; subnet_id = aws_subnet.public.id; vpc_security_group_ids = [aws_security_group.web.id]; key_name = var.key_name; associate_public_ip_address = false; metadata_options { http_tokens = "required"; http_endpoint = "enabled" }; root_block_device { encrypted = true; volume_type = "gp3" }; user_data = <<-EOF
#!/bin/bash
apt-get update -y || yum update -y
EOF
  tags = { Name = "arzens-hardened-web" } }
