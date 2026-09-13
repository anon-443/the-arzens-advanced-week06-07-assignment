# Secure Terraform deployment

1. Install Terraform and configure AWS credentials through an approved profile or workload identity. Do not place keys in this repository.
2. Copy `terraform.tfvars.example` to `terraform.tfvars`, replace the AMI, trusted admin CIDR, key name, and globally unique bucket name, then keep the file untracked.
3. Configure a remote encrypted backend before applying. Terraform Cloud stores state remotely with encryption at rest and TLS in transit; an S3 backend should use encryption, restricted bucket access, and a DynamoDB lock table.
4. Run `terraform init`, `terraform fmt`, `terraform validate`, `terraform plan -out=tfplan`, and review the plan with a second operator.
5. Apply only after policy checks and approval: `terraform apply tfplan`.
6. Detect drift with scheduled `terraform plan -detailed-exitcode`; investigate out-of-band changes and use rollback by applying the last approved version.
