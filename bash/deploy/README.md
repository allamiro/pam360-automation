# PAM360 Sync Service Deployment

Ansible playbook to deploy the PAM360 sync bash script as a systemd service with timer on RHEL/CentOS/Fedora/Debian/Ubuntu systems.

## Overview

This playbook:

1. Installs dependencies (jq, curl)
2. Deploys the `pam360_sync.sh` script to `/usr/local/sbin/pam360-sync`
3. Creates a secure environment file at `/etc/pam360-sync.env`
4. Sets up a systemd oneshot service
5. Configures a systemd timer for scheduled execution

## Quick Start

```bash
cd bash/deploy

# Edit inventory with target hosts
vi inventory

# Edit site.yml with your PAM360 credentials
vi site.yml

# Run the playbook
ansible-playbook -i inventory site.yml -kK
```

## Configuration

Edit `site.yml` to configure:

```yaml
vars:
  # Required - PAM360 credentials
  pam_url: "https://your-pam360-server:8282"
  pam_token: "YOUR-API-TOKEN"
  
  # Target users to rotate
  target_users:
    - root
    - admin
  
  # PAM360 settings
  resource_group_name: "Linux Servers"
  share_user_id: "1"
  
  # Schedule (systemd calendar format)
  sync_schedule: "daily"           # or "*-*-* 02:00:00" for 2 AM
  sync_random_delay: "30m"         # randomize to avoid thundering herd
```

## Schedule Examples

| Schedule | Description |
|----------|-------------|
| `daily` | Once per day |
| `weekly` | Once per week |
| `*-*-* 02:00:00` | Daily at 2:00 AM |
| `*-*-01 03:00:00` | 1st of each month at 3 AM |
| `Mon *-*-* 04:00:00` | Every Monday at 4 AM |

## Manual Operations

After deployment, you can:

```bash
# Run sync manually
sudo systemctl start pam360-sync.service

# Check service status
sudo systemctl status pam360-sync.service

# View logs
sudo journalctl -u pam360-sync.service -n 100

# Check timer status
systemctl list-timers pam360-sync.timer

# Disable scheduled runs
sudo systemctl disable pam360-sync.timer

# Re-enable scheduled runs
sudo systemctl enable --now pam360-sync.timer
```

## File Locations

| File | Purpose |
|------|---------|
| `/usr/local/sbin/pam360-sync` | Main script |
| `/etc/pam360-sync.env` | Credentials (mode 0600) |
| `/etc/systemd/system/pam360-sync.service` | Service unit |
| `/etc/systemd/system/pam360-sync.timer` | Timer unit |

## Security Features

- **No hardcoded tokens**: Script requires `PAM_TOKEN` from environment
- **Protected env file**: Mode 0600, owned by root
- **Systemd hardening**: ProtectSystem, PrivateTmp, NoNewPrivileges enabled
- **Timeout protection**: 300s timeout prevents hung processes

## STIG Compliance

This setup supports password rotation requirements for:

- **RHEL-07-010200**: Passwords must be changed at least every 60 days
- **RHEL-08-020200**: Passwords must be changed when a user requests a password change

Configure `sync_schedule` according to your password policy (e.g., `*-*-1,15 02:00:00` for twice monthly).

## Troubleshooting

```bash
# Check if timer is active
systemctl is-active pam360-sync.timer

# Check next scheduled run
systemctl list-timers --all | grep pam360

# View full service logs
sudo journalctl -u pam360-sync.service --no-pager

# Test script manually
sudo /usr/local/sbin/pam360-sync

# Verify environment file
sudo cat /etc/pam360-sync.env
```
