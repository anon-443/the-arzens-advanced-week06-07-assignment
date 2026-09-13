variable "aws_region" { type = string; default = "us-east-1" }
variable "vpc_cidr" { type = string; default = "10.20.0.0/16" }
variable "public_subnet_cidr" { type = string; default = "10.20.1.0/24" }
variable "admin_cidr" { type = string; description = "Trusted /32 or office CIDR for SSH; never use 0.0.0.0/0" }
variable "ami_id" { type = string; description = "Current hardened Ubuntu LTS AMI for the selected region" }
variable "instance_type" { type = string; default = "t3.micro" }
variable "key_name" { type = string; sensitive = true }
variable "bucket_name" { type = string; description = "Globally unique private artifact bucket name" }
