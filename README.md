# THE ARZENS Advanced Track — Week 06–07 Combined Assignment

This repository contains a complete, reproducible submission for **Threat Intelligence Automation** (Week 06) and **Infrastructure as Code Security** (Week 07). The implementation is designed to run safely in demo mode without cloud credentials; production mode is enabled through environment variables and external secret management.

## Repository map

| Task | Location | Main output |
|---|---|---|
| 1 | `docs/task1_ti_architecture.pdf` | TI enrichment architecture and data-flow diagram |
| 2 | `week06_ti/` | Multi-source Python enrichment engine |
| 3 | `week06_ioc/` | IOC lifecycle manager, blocklist export, weekly report |
| 4 | `docs/task4_iac_architecture.pdf` | Secure Terraform + Ansible architecture and module diagram |
| 5 | `week07_terraform/` | Secure AWS Terraform configuration |
| 6 | `week07_ansible/` | Idempotent hardening and compliance playbooks |

## Quick start

```bash
python3 week06_ti/ti_enricher.py --input-file week06_ti/sample_indicators.csv --format table
python3 week06_ti/ti_enricher.py --input-file week06_ti/sample_indicators.csv --format json --output /tmp/enrichment.json
python3 week06_ioc/ioc_manager.py --add-file week06_ti/sample_indicators.csv
python3 week06_ioc/ioc_manager.py --update-all
python3 week06_ioc/ioc_manager.py --expire-check
python3 week06_ioc/ioc_manager.py --export-blocklist --output week06_ioc/blocklist.txt
python3 week06_ioc/ioc_manager.py --report --output week06_ioc/weekly_report.html
```

The default behavior is **demo mode** because API keys are blank in `config.yaml`. Set `VT_API_KEY`, `ABUSEIPDB_API_KEY`, and `OTX_API_KEY` in the environment to use live providers. Never commit real credentials or `terraform.tfvars`.

## Validation

```bash
python3 -m py_compile week06_ti/ti_enricher.py week06_ioc/ioc_manager.py
terraform -chdir=week07_terraform fmt -check   # if Terraform is installed
ansible-playbook -i week07_ansible/hosts.ini week07_ansible/site.yml --syntax-check  # if Ansible is installed
```

## Safety notes

The Terraform example uses an externalized AMI, SSH CIDR, and bucket name. Review the plan before applying it in a real AWS account. The sample Ansible inventory points to localhost and is intentionally non-invasive unless the operator changes it to a real host.

## References

- [MISP Project](https://www.misp-project.org/)
- [HashiCorp Terraform recommended practices](https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices)
- [HashiCorp Terraform security model](https://developer.hashicorp.com/terraform/cloud-docs/architectural-details/security-model)
