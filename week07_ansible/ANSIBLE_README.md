# Ansible hardening and compliance

Review `hosts.ini` before execution. The checked-in inventory targets localhost for safe syntax and demonstration runs. For a real server, use SSH keys, a dedicated least-privilege operator, and an approved maintenance window.

```bash
ansible-playbook -i hosts.ini site.yml --syntax-check
ansible-playbook -i hosts.ini site.yml --check --diff
ansible-playbook -i hosts.ini site.yml
ansible-playbook -i hosts.ini security.yml --check --diff
```

The roles are idempotent. Package installation uses `state: present`, configuration uses managed templates/lines, and services use `enabled: true` with explicit state. Compliance tasks write a simple report to `/var/log/arzens-compliance-report.txt`.
