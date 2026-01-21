# PAM360 RHEL Ansible Automation Toolkit

Automated password rotation and synchronization for Linux/RHEL systems with [ManageEngine PAM360](https://www.manageengine.com/privileged-access-management/).

## Quick Start

```bash
# Clone the repository
git clone https://github.com/allamiro/pam360-automation.git

# Navigate to the project
cd pam360-automation

# For Ansible playbook
cd ansible

# For Bash script
cd bash

# For Python script
cd python
```

## Overview

This toolkit automates the rotation of local Linux user passwords and synchronizes them with PAM360 Privileged Access Management. It ensures passwords are securely managed, rotated on schedule, and stored in PAM360 for centralized credential management.

## Features

- **Automatic Password Generation** - Generates strong passwords compliant with PAM360 Strong policy
- **PAM360 Synchronization** - Creates/updates accounts in PAM360 via REST API
- **Linux Password Rotation** - Updates local user passwords on target hosts
- **Resource Management** - Automatically creates resources in PAM360 if they don't exist
- **Access Sharing** - Shares resources and accounts with designated PAM360 users
- **Resource Group Association** - Associates resources with PAM360 resource groups
- **Idempotent Operations** - Safe to run multiple times without side effects
- **Comprehensive Reporting** - Detailed summary with account details from PAM360

## Requirements

- Ansible 2.9+
- Python 3.6+
- Network access to PAM360 server (HTTPS)
- PAM360 API token with appropriate permissions
- SSH access to target Linux hosts

## Project Structure

```text
pam360-automation/
├── LICENSE
├── README.md
├── ansible/
│   ├── inventory              # Target hosts
│   ├── site.yml               # Main playbook
│   └── roles/
│       └── pam360_sync/
│           ├── defaults/
│           │   └── main.yml   # Default variables
│           └── tasks/
│               ├── main.yml           # Main task flow
│               ├── process_user.yml   # Per-user processing
│               └── update_passwords.yml # Linux password update
├── bash/
│   └── pam360_sync.sh         # Standalone bash script
└── python/
    └── pam360_sync.py         # Python script (stdlib only)
```

## Configuration

Edit `ansible/roles/pam360_sync/defaults/main.yml`:

```yaml
# PAM360 Server Configuration
pam_url: "https://your-pam360-server:8282"
pam_token: "YOUR-API-TOKEN-HERE"
pam_validate_certs: false

# Target Users to Rotate
pam_target_users:
  - root
  - admin

# Sharing Configuration
pam_share_user_id: "1"           # PAM360 user ID to share with
pam_resource_group_name: "Linux Servers"
```

## Usage

### Ansible Playbook

```bash
cd ansible
ansible-playbook -i inventory site.yml -kK
```

### Bash Script

```bash
# Navigate to bash directory
cd bash

# Make executable (first time only)
chmod +x pam360_sync.sh

# Edit configuration variables in the script
vim pam360_sync.sh

# Run the script
./pam360_sync.sh
```

**Configuration variables to edit in `pam360_sync.sh`:**

- `PAM_URL` - PAM360 server URL
- `PAM_TOKEN` - API authentication token
- `TARGET_USERS` - Array of users to rotate
- `RESOURCE_GROUP` - PAM360 resource group name
- `SHARE_USER_ID` - PAM360 user ID to share with

### Python Script

```bash
# Navigate to python directory
cd python

# Edit configuration variables in the script
vim pam360_sync.py

# Run the script (requires Python 3.6+)
python3 pam360_sync.py

# Or make executable and run directly
chmod +x pam360_sync.py
./pam360_sync.py
```

**Configuration variables to edit in `pam360_sync.py`:**

- `PAM_URL` - PAM360 server URL
- `PAM_TOKEN` - API authentication token
- `TARGET_USERS` - List of users to rotate
- `RESOURCE_GROUP_NAME` - PAM360 resource group name
- `SHARE_USER_ID` - PAM360 user ID to share with

**Note:** The Python script uses only standard library modules (no pip install required).
## Sample Output

```text
============================================
PAM360 SYNC SUMMARY - hostname
============================================
Resource ID: 4
Resource Group: Linux Servers (ID: 304)

LOCAL STATUS:
  root: PAM360=UPDATED, Linux=ROTATED
  admin: PAM360=UPDATED, Linux=ROTATED

PAM360 ACCOUNTS (confirmed from API):
  - root (ID: 5, Policy: Strong)
  - admin (ID: 6, Policy: Strong)

ACCOUNT DETAILS:
  root:
    Last Modified: Jan 9, 2026 05:16 AM
    Last Accessed: Jan 7, 2026 01:17 PM
============================================
```

## Password Policy

Generated passwords comply with PAM360 **Strong** policy:

- 14 characters total
- Starts with an alphabet character
- Contains at least 1 special character (`.!@#$%`)
- Contains uppercase and lowercase letters
- Contains numbers

## PAM360 Sharing Strategy

A practical sharing strategy in PAM360 is to treat sharing as **authorization to use a credential**, not as a distribution mechanism, and to enforce **least privilege + group-based access + fast revocation**.

### Recommended Approach

**1. Prefer User Groups / Resource Groups over per-user sharing**

Model access as: `Team (user group) → Environment/Scope (resource group)`

Use the bulk share resource groups endpoints (API 9.9 / 9.10) as your default, and reserve per-resource/per-account sharing for exceptions. This aligns with PAM360's operational model where sharing is typically done at resource or resource-group level for many systems.

**2. Use least privilege on accessType**

| Access Type | Use Case |
|-------------|----------|
| `view` | Auditors/visibility use-cases (read-only) |
| `modify` | Operators who must use the password and may need to update metadata, but shouldn't re-share widely |
| `fullaccess` | Credential owners / PAM admins only - implies complete management and the ability to re-share |

### This Toolkit's Default

This toolkit uses:
- **`fullaccess`** for resource-level sharing (API 9.1)
- **`modify`** for account-level sharing (API 9.5)

Adjust the `ACCESSTYPE` values in the playbook based on your organization's security requirements.

## Security Considerations

- Store API tokens securely (use Ansible Vault for production)
- Use `no_log: true` for tasks handling passwords
- Validate SSL certificates in production (`pam_validate_certs: true`)
- Restrict API token permissions to minimum required

## License

MIT

## References

- [ManageEngine PAM360](https://www.manageengine.com/privileged-access-management/)
- [PAM360 REST API Documentation](https://www.manageengine.com/privileged-access-management/help/restapi.html)
