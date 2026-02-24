#!/usr/bin/env python3
"""
PAM360 password sync + local Linux password rotation
Stdlib only (urllib/json/ssl/subprocess/etc.). No classes.
"""

import os
import sys
import json
import ssl
import csv
import time
import pwd
import secrets
import string
import datetime
import subprocess
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# =========================
# CONFIG (edit as needed)
# =========================
PAM_URL = os.environ.get("PAM_URL", "https://10.0.0.14:8282")
PAM_TOKEN = os.environ.get("PAM_TOKEN", "44F011D4-9D03-4FFB-BB20-C1EA81A471D9")

PAM_VALIDATE_CERTS = False

PAM_TARGET_USERS = ["root", "admin", "jdoe", "trump"]

PAM_RESOURCE_GROUP_NAME = "Linux Servers"

# Share with individual users (preferred in your role for API 9.1, 9.5)
PAM_SHARE_USER_NAMES = ["admin"]

# Share with user groups (API 9.3, 9.7, 9.10, 9.9)
PAM_SHARE_GROUP_NAMES = ["LINUX ADMINS"]

# Optional KeePass CSV export
PAM_CREATE_PASSWORD_FILE = False

# Local account handling (create if missing)
PAM_CREATE_LOCAL_ACCOUNTS = True

# Where to write password_records (mimics playbook_dir/password_records)
PASSWORD_RECORDS_DIR = os.path.join(os.getcwd(), "password_records")


# =========================
# Helpers
# =========================
def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def run_cmd(cmd: List[str], check: bool = True, capture: bool = True) -> Tuple[int, str, str]:
    p = subprocess.run(
        cmd,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed ({p.returncode}): {' '.join(cmd)}\n{p.stderr or ''}")
    return p.returncode, (p.stdout or ""), (p.stderr or "")


def get_system_hostname_ip() -> Tuple[str, str]:
    _, h_out, _ = run_cmd(["hostname"], check=True)
    hostname = h_out.strip() or "unknown-host"

    # hostname -I may fail; follow your playbook fallback
    ip = "127.0.0.1"
    try:
        rc, ip_out, _ = run_cmd(["hostname", "-I"], check=False)
        if rc == 0:
            parts = ip_out.strip().split()
            if parts:
                ip = parts[0]
    except Exception:
        pass
    return hostname, ip


def ssl_context(validate_certs: bool) -> ssl.SSLContext:
    if validate_certs:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def pam_request(
    method: str,
    path: str,
    token: str,
    validate_certs: bool,
    query: Optional[Dict[str, str]] = None,
    input_data_obj: Optional[Dict[str, Any]] = None,
    accept_status: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """
    Implements Ansible 'uri' behavior:
      - GET with query params
      - POST/PUT with body: INPUT_DATA=<json> (as in your playbook)
    """
    if accept_status is None:
        accept_status = [200, 201]

    base = PAM_URL.rstrip("/")
    url = f"{base}{path}"

    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"

    headers = {"AUTHTOKEN": token}
    data_bytes = None

    if input_data_obj is not None:
        # Your playbook sends: body: 'INPUT_DATA={"operation":{...}}'
        # We'll send application/x-www-form-urlencoded to match that style.
        payload = {"INPUT_DATA": json.dumps(input_data_obj, separators=(",", ":"))}
        data_bytes = urllib.parse.urlencode(payload).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(url=url, method=method.upper(), headers=headers, data=data_bytes)
    ctx = ssl_context(validate_certs)

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            status = resp.getcode()
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as he:
        status = he.code
        body = he.read().decode("utf-8", errors="replace")
    except Exception as ex:
        raise RuntimeError(f"HTTP request failed: {method} {url}: {ex}") from ex

    if status not in accept_status:
        # Still try to parse JSON for error details (like Ansible status_code list behavior)
        try:
            parsed = json.loads(body) if body else {}
        except Exception:
            parsed = {"raw": body}
        raise RuntimeError(f"PAM HTTP {status} for {method} {url}\n{json.dumps(parsed, indent=2)}")

    if not body:
        return {}

    try:
        return json.loads(body)
    except Exception:
        return {"raw": body}


def pam_status_ok(resp: Dict[str, Any]) -> bool:
    try:
        return resp["operation"]["result"]["status"] == "Success"
    except Exception:
        return False


def pam_message(resp: Dict[str, Any]) -> str:
    try:
        return str(resp["operation"]["result"].get("message", ""))
    except Exception:
        return ""


def generate_password() -> str:
    # Mirrors your pattern:
    # 1 letter + 10 alnum + 1 symbol (.,!@#$) + 2 digits
    letters = string.ascii_letters
    alnum = string.ascii_letters + string.digits
    symbols = ".,!@#$"
    digits = string.digits

    return (
        secrets.choice(letters)
        + "".join(secrets.choice(alnum) for _ in range(10))
        + secrets.choice(symbols)
        + "".join(secrets.choice(digits) for _ in range(2))
    )


def resolve_share_users(usernames: List[str]) -> List[Dict[str, str]]:
    resolved = []
    for name in usernames:
        resp = pam_request(
            "GET",
            "/restapi/json/v1/user/getUserId",
            PAM_TOKEN,
            PAM_VALIDATE_CERTS,
            query={"USERNAME": name},
        )
        user_id = None
        try:
            user_id = resp["operation"]["Details"]["USERID"]
        except Exception:
            user_id = None

        eprint(f"[share-user] {name} status={resp.get('operation', {}).get('result', {}).get('status','N/A')} "
               f"user_id={user_id if user_id else 'NOT FOUND'} msg={pam_message(resp)}")

        if pam_status_ok(resp) and user_id:
            resolved.append({"name": name, "id": str(user_id)})
    return resolved


def resolve_share_groups(group_names: List[str]) -> List[Dict[str, str]]:
    resolved = []
    for gname in group_names:
        resp = pam_request(
            "GET",
            "/restapi/json/v1/user/getUserGroupId",
            PAM_TOKEN,
            PAM_VALIDATE_CERTS,
            query={"USERGROUPNAME": gname},
        )
        group_id = None
        try:
            group_id = resp["operation"]["Details"]["USERGROUPID"]
        except Exception:
            group_id = None

        eprint(f"[share-group] {gname} status={resp.get('operation', {}).get('result', {}).get('status','N/A')} "
               f"group_id={group_id if group_id else 'NOT FOUND'} msg={pam_message(resp)}")

        if pam_status_ok(resp) and group_id:
            resolved.append({"name": gname, "id": str(group_id)})
    return resolved


def find_resource_id_by_hostname(hostname: str) -> str:
    resp = pam_request(
        "GET",
        "/restapi/json/v1/resources",
        PAM_TOKEN,
        PAM_VALIDATE_CERTS,
    )
    details = resp.get("operation", {}).get("Details", []) or []
    for item in details:
        try:
            if item.get("RESOURCE NAME") == hostname:
                return str(item.get("RESOURCE ID", ""))
        except Exception:
            continue
    return ""


def create_resource(hostname: str, ip: str, first_user: str, first_pass: str, resource_group_name: str) -> None:
    input_data = {
        "operation": {
            "Details": {
                "RESOURCENAME": hostname,
                "ACCOUNTNAME": first_user,
                "RESOURCETYPE": "Linux",
                "PASSWORD": first_pass,
                "DNSNAME": ip,
                "RESOURCEPASSWORDPOLICY": "Strong",
                "ACCOUNTPASSWORDPOLICY": "Strong",
                "RESOURCEGROUPNAME": resource_group_name,
            }
        }
    }
    resp = pam_request(
        "POST",
        "/restapi/json/v1/resources",
        PAM_TOKEN,
        PAM_VALIDATE_CERTS,
        input_data_obj=input_data,
        accept_status=[200, 201, 400, 401, 403, 404, 500],
    )
    eprint(f"[resource-create] {pam_message(resp) or json.dumps(resp)[:200]}")


def fetch_resource_id_by_resourcename(hostname: str) -> str:
    resp = pam_request(
        "GET",
        f"/restapi/json/v1/resources/resourcename/{urllib.parse.quote(hostname)}",
        PAM_TOKEN,
        PAM_VALIDATE_CERTS,
    )
    try:
        return str(resp["operation"]["Details"]["RESOURCEID"])
    except Exception:
        return ""


def get_accounts(resource_id: str) -> List[Dict[str, Any]]:
    resp = pam_request(
        "GET",
        f"/restapi/json/v1/resources/{resource_id}/accounts",
        PAM_TOKEN,
        PAM_VALIDATE_CERTS,
    )
    return resp.get("operation", {}).get("Details", {}).get("ACCOUNT LIST", []) or []


def account_id_by_name(accounts: List[Dict[str, Any]], username: str) -> str:
    for a in accounts:
        if a.get("ACCOUNT NAME") == username:
            return str(a.get("ACCOUNT ID", ""))
    return ""


def update_account_password(resource_id: str, account_id: str, newpass: str) -> Dict[str, Any]:
    input_data = {"operation": {"Details": {"NEWPASSWORD": newpass, "RESETTYPE": "LOCAL", "REASON": "Rotated via Python"}}}
    return pam_request(
        "PUT",
        f"/restapi/json/v1/resources/{resource_id}/accounts/{account_id}/password",
        PAM_TOKEN,
        PAM_VALIDATE_CERTS,
        input_data_obj=input_data,
        accept_status=[200, 201, 400, 401, 403, 404, 500],
    )


def create_account(resource_id: str, username: str, passwd: str) -> Dict[str, Any]:
    input_data = {
        "operation": {
            "Details": {
                "ACCOUNTLIST": [
                    {"ACCOUNTNAME": username, "PASSWORD": passwd, "ACCOUNTPASSWORDPOLICY": "Strong"}
                ]
            }
        }
    }
    return pam_request(
        "POST",
        f"/restapi/json/v1/resources/{resource_id}/accounts",
        PAM_TOKEN,
        PAM_VALIDATE_CERTS,
        input_data_obj=input_data,
        accept_status=[200, 201, 400, 401, 403, 404, 500],
    )


def share_resource_with_users(resource_id: str, share_users: List[Dict[str, str]]) -> None:
    for u in share_users:
        input_data = {"operation": {"Details": {"ACCESSTYPE": "fullaccess", "USERID": u["id"]}}}
        resp = pam_request(
            "PUT",
            f"/restapi/json/v1/resources/{resource_id}/share",
            PAM_TOKEN,
            PAM_VALIDATE_CERTS,
            input_data_obj=input_data,
            accept_status=[200, 201, 400, 401, 403, 404, 500],
        )
        eprint(f"[share-resource-user] {u['name']} -> {pam_message(resp) or resp.get('operation', {}).get('result', {}).get('status','')}")


def share_resource_with_groups(resource_id: str, share_groups: List[Dict[str, str]]) -> None:
    for g in share_groups:
        input_data = {"operation": {"Details": {"ACCESSTYPE": "fullaccess", "USERGROUPID": g["id"]}}}
        resp = pam_request(
            "PUT",
            f"/restapi/json/v1/resources/{resource_id}/share",
            PAM_TOKEN,
            PAM_VALIDATE_CERTS,
            input_data_obj=input_data,
            accept_status=[200, 201, 400, 401, 403, 404, 500],
        )
        eprint(f"[share-resource-group] {g['name']} -> {pam_message(resp) or resp.get('operation', {}).get('result', {}).get('status','')}")


def share_accounts_with_users(resource_id: str, accounts: List[Dict[str, Any]], share_users: List[Dict[str, str]]) -> None:
    for acc in accounts:
        acc_id = str(acc.get("ACCOUNT ID", ""))
        acc_name = str(acc.get("ACCOUNT NAME", ""))
        if not acc_id:
            continue
        for u in share_users:
            input_data = {"operation": {"Details": {"ACCESSTYPE": "modify", "USERID": u["id"]}}}
            resp = pam_request(
                "PUT",
                f"/restapi/json/v1/resources/{resource_id}/accounts/{acc_id}/share",
                PAM_TOKEN,
                PAM_VALIDATE_CERTS,
                input_data_obj=input_data,
                accept_status=[200, 201, 400, 401, 403, 404, 500],
            )
            eprint(f"[share-account-user] {acc_name} -> {u['name']} : {pam_message(resp) or resp.get('operation', {}).get('result', {}).get('status','')}")


def share_accounts_with_groups(resource_id: str, accounts: List[Dict[str, Any]], share_groups: List[Dict[str, str]]) -> None:
    for acc in accounts:
        acc_id = str(acc.get("ACCOUNT ID", ""))
        acc_name = str(acc.get("ACCOUNT NAME", ""))
        if not acc_id:
            continue
        for g in share_groups:
            input_data = {"operation": {"Details": {"ACCESSTYPE": "modify", "USERGROUPID": g["id"]}}}
            resp = pam_request(
                "PUT",
                f"/restapi/json/v1/resources/{resource_id}/accounts/{acc_id}/share",
                PAM_TOKEN,
                PAM_VALIDATE_CERTS,
                input_data_obj=input_data,
                accept_status=[200, 201, 400, 401, 403, 404, 500],
            )
            eprint(f"[share-account-group] {acc_name} -> {g['name']} : {pam_message(resp) or resp.get('operation', {}).get('result', {}).get('status','')}")


def get_resource_groups() -> List[Dict[str, Any]]:
    resp = pam_request(
        "GET",
        "/restapi/json/v1/resourcegroup",
        PAM_TOKEN,
        PAM_VALIDATE_CERTS,
    )
    return resp.get("operation", {}).get("Details", []) or []


def find_resource_group_id(groups: List[Dict[str, Any]], group_name: str) -> str:
    for g in groups:
        if g.get("resourceGroupName") == group_name:
            return str(g.get("resourceGroupId", ""))
    return ""


def get_associated_groups(resource_id: str) -> List[Dict[str, Any]]:
    resp = pam_request(
        "GET",
        f"/restapi/json/v1/resources/{resource_id}/associatedGroups",
        PAM_TOKEN,
        PAM_VALIDATE_CERTS,
    )
    return resp.get("operation", {}).get("Details", {}).get("ASSOCIATED GROUPS", []) or []


def associate_resource_to_group(resource_id: str, group_id: str) -> None:
    input_data = {"operation": {"Details": {"RESOURCEIDS": [int(resource_id)]}}}
    resp = pam_request(
        "POST",
        f"/restapi/json/v1/resourcegroup/{group_id}/associateResources",
        PAM_TOKEN,
        PAM_VALIDATE_CERTS,
        input_data_obj=input_data,
        accept_status=[200, 201, 400, 401, 403, 404, 500],
    )
    eprint(f"[associate-resource-group] {pam_message(resp) or resp.get('operation', {}).get('result', {}).get('status','')}")


def share_resource_group_with_groups(resource_group_id: str, share_groups: List[Dict[str, str]]) -> None:
    for g in share_groups:
        input_data = {
            "operation": {
                "Details": {
                    "resourceGroupIds": [resource_group_id],
                    "userGroupIds": [g["id"]],
                    "accessType": "fullaccess",
                }
            }
        }
        resp = pam_request(
            "PUT",
            "/restapi/json/v1/resourcegroup/share",
            PAM_TOKEN,
            PAM_VALIDATE_CERTS,
            input_data_obj=input_data,
            accept_status=[200, 201, 400, 401, 403, 404, 500],
        )
        eprint(f"[share-resourcegroup-group] {g['name']} -> {pam_message(resp) or resp.get('operation', {}).get('result', {}).get('status','')}")


def share_resource_group_with_users(resource_group_id: str, share_users: List[Dict[str, str]]) -> None:
    for u in share_users:
        input_data = {
            "operation": {
                "Details": {
                    "resourceGroupIds": [resource_group_id],
                    "userIds": [u["id"]],
                    "accessType": "fullaccess",
                }
            }
        }
        resp = pam_request(
            "PUT",
            "/restapi/json/v1/resourcegroup/share",
            PAM_TOKEN,
            PAM_VALIDATE_CERTS,
            input_data_obj=input_data,
            accept_status=[200, 201, 400, 401, 403, 404, 500],
        )
        eprint(f"[share-resourcegroup-user] {u['name']} -> {pam_message(resp) or resp.get('operation', {}).get('result', {}).get('status','')}")


def ensure_local_user_and_rotate(username: str, newpass: str, create_if_missing: bool) -> Tuple[bool, bool, bool]:
    """
    Returns tuple: (rotated_linux, created_local, skipped_missing_local)
    Matches your update_passwords.yml logic.
    """
    user_exists = True
    try:
        pwd.getpwnam(username)
    except KeyError:
        user_exists = False

    created_local = False
    skipped = False

    if not user_exists:
        if create_if_missing:
            # useradd -m -s /bin/bash <user>
            run_cmd(["useradd", "-m", "-s", "/bin/bash", username], check=True)
            created_local = True
        else:
            skipped = True
            return (False, False, True)

    # Rotate password using chpasswd (hashing handled by system)
    # echo "user:pass" | chpasswd
    p = subprocess.run(
        ["chpasswd"],
        input=f"{username}:{newpass}\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if p.returncode != 0:
        raise RuntimeError(f"Failed to set password for {username}: {p.stderr}")

    return (True, created_local, False)


def write_keepass_csv(
    group_name: str,
    hostname: str,
    ip: str,
    resource_id: str,
    user_pass_map: Dict[str, str],
) -> str:
    ts_basic = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    os.makedirs(PASSWORD_RECORDS_DIR, mode=0o700, exist_ok=True)
    csv_path = os.path.join(PASSWORD_RECORDS_DIR, f"passwords_{ts_basic}.csv")

    # Header + rows (KeePass import-friendly)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Group", "Title", "Username", "Password", "URL", "Notes"])
        now_iso = datetime.datetime.now().isoformat(timespec="seconds")
        for user, pw in user_pass_map.items():
            title = f"{hostname} - {user}"
            url = f"ssh://{ip}"
            notes = f"Rotated: {now_iso} | Resource ID: {resource_id}"
            w.writerow([group_name, title, user, pw, url, notes])

    return csv_path


def get_account_details(resource_id: str, account_id: str) -> Dict[str, Any]:
    return pam_request(
        "GET",
        f"/restapi/json/v1/resources/{resource_id}/accounts/{account_id}",
        PAM_TOKEN,
        PAM_VALIDATE_CERTS,
    )


# =========================
# Main flow (mirrors role)
# =========================
def main() -> int:
    if os.geteuid() != 0:
        eprint("This script must run as root (local password rotation + useradd/chpasswd).")
        return 2

    user_status: Dict[str, Dict[str, bool]] = {}

    hostname, ip = get_system_hostname_ip()
    print(f"System: {hostname} ({ip})")

    # 1) Resolve share IDs
    share_users = resolve_share_users(PAM_SHARE_USER_NAMES or [])
    share_groups = resolve_share_groups(PAM_SHARE_GROUP_NAMES or [])

    # 2) Generate passwords
    user_pass_map: Dict[str, str] = {u: generate_password() for u in PAM_TARGET_USERS}

    # 3) Resource existence
    resource_id = find_resource_id_by_hostname(hostname)
    resource_was_created = False

    if resource_id:
        print(f"Resource exists: {hostname} -> ID {resource_id}")
        accounts = get_accounts(resource_id)

        # 3A) Update/create accounts (process_user.yml)
        for user, pw in user_pass_map.items():
            acc_id = account_id_by_name(accounts, user)
            if acc_id:
                resp = update_account_password(resource_id, acc_id, pw)
                ok = pam_status_ok(resp)
                user_status.setdefault(user, {})
                user_status[user]["updated_pam"] = ok
                user_status[user]["api_failed"] = not ok
                print(f"Updated PAM account '{user}': {resp.get('operation', {}).get('result', {}).get('status','')} - {pam_message(resp)}")
            else:
                resp = create_account(resource_id, user, pw)
                ok = pam_status_ok(resp)
                user_status.setdefault(user, {})
                user_status[user]["created_in_pam"] = ok
                user_status[user]["api_failed"] = not ok
                print(f"Created PAM account '{user}': {resp.get('operation', {}).get('result', {}).get('status','')} - {pam_message(resp)}")

        # refresh accounts for sharing
        accounts = get_accounts(resource_id)

    else:
        print(f"Resource NOT FOUND for hostname '{hostname}' -> creating.")
        first_user = PAM_TARGET_USERS[0]
        first_pass = user_pass_map[first_user]
        remaining_users = PAM_TARGET_USERS[1:]

        # 4) Create resource with first account (API 1.2)
        create_resource(hostname, ip, first_user, first_pass, PAM_RESOURCE_GROUP_NAME)

        # 4b) Fetch new resource id (API 1.3 style / resourcename endpoint)
        resource_id = fetch_resource_id_by_resourcename(hostname)
        if not resource_id:
            raise RuntimeError("Resource creation appeared to succeed but RESOURCEID could not be fetched.")
        resource_was_created = True
        print(f"New Resource ID: {resource_id}")

        # 5) Create remaining accounts (API 2.4)
        for user in remaining_users:
            resp = create_account(resource_id, user, user_pass_map[user])
            ok = pam_status_ok(resp)
            user_status.setdefault(user, {})
            user_status[user]["created_in_pam"] = ok
            user_status[user]["api_failed"] = not ok
            print(f"Created remaining PAM account '{user}': {resp.get('operation', {}).get('result', {}).get('status','')} - {pam_message(resp)}")

        accounts = get_accounts(resource_id)

    # 5) Share resource + accounts (users + groups)
    if resource_id and share_users:
        share_resource_with_users(resource_id, share_users)
    if resource_id and share_groups:
        share_resource_with_groups(resource_id, share_groups)

    if resource_id and share_users:
        share_accounts_with_users(resource_id, accounts, share_users)
    if resource_id and share_groups:
        share_accounts_with_groups(resource_id, accounts, share_groups)

    # 6) Associate resource to resource group
    pam_resource_group_id = ""
    groups = get_resource_groups()
    pam_resource_group_id = find_resource_group_id(groups, PAM_RESOURCE_GROUP_NAME)
    print(f"Resource Group '{PAM_RESOURCE_GROUP_NAME}' ID: {pam_resource_group_id or 'NOT FOUND'}")

    already_in_group = False
    if resource_id and pam_resource_group_id:
        assoc = get_associated_groups(resource_id)
        assoc_ids = [str(x.get("GROUP ID", "")) for x in assoc]
        already_in_group = pam_resource_group_id in assoc_ids
        print(f"Resource already in '{PAM_RESOURCE_GROUP_NAME}': {already_in_group}")

        if not already_in_group:
            associate_resource_to_group(resource_id, pam_resource_group_id)

    # 6b/6c) Share resource group to groups/users
    if pam_resource_group_id and share_groups:
        share_resource_group_with_groups(pam_resource_group_id, share_groups)
    if pam_resource_group_id and share_users:
        share_resource_group_with_users(pam_resource_group_id, share_users)

    # 7) Rotate local Linux passwords
    for user, pw in user_pass_map.items():
        try:
            rotated, created_local, skipped = ensure_local_user_and_rotate(user, pw, PAM_CREATE_LOCAL_ACCOUNTS)
            user_status.setdefault(user, {})
            if created_local:
                user_status[user]["created_local"] = True
            if rotated:
                user_status[user]["rotated_linux"] = True
            if skipped:
                user_status[user]["skipped_missing_local"] = True
        except Exception as ex:
            user_status.setdefault(user, {})
            user_status[user]["rotated_linux"] = False
            eprint(f"[linux-rotate] {user}: FAILED: {ex}")

    # 8) Optional KeePass CSV
    csv_path = ""
    if PAM_CREATE_PASSWORD_FILE:
        csv_path = write_keepass_csv(PAM_RESOURCE_GROUP_NAME, hostname, ip, resource_id, user_pass_map)
        print(f"Password record saved to: {csv_path}")
    else:
        print("Password file creation skipped (PAM_CREATE_PASSWORD_FILE: false)")

    # 9) Fetch final accounts + details
    final_accounts = get_accounts(resource_id) if resource_id else []
    account_details: List[Tuple[str, Dict[str, Any]]] = []
    for acc in final_accounts:
        acc_name = str(acc.get("ACCOUNT NAME", ""))
        acc_id = str(acc.get("ACCOUNT ID", ""))
        if not acc_id:
            continue
        detail = get_account_details(resource_id, acc_id)
        account_details.append((acc_name, detail))

    # 10) Summary (mirrors your debug block)
    print("\n" + "=" * 44)
    print(f"PAM360 SYNC SUMMARY - {hostname}")
    print("=" * 44)
    print(f"Resource ID: {resource_id}")
    print(f"Resource Group: {PAM_RESOURCE_GROUP_NAME} (ID: {pam_resource_group_id or 'N/A'})")
    print("\nLOCAL STATUS:")
    for user in PAM_TARGET_USERS:
        st = user_status.get(user, {})
        pam_state = (
            "CREATED" if st.get("created_in_pam") else
            ("UPDATED" if st.get("updated_pam") else
             ("FAILED" if st.get("api_failed") else "NO CHANGE"))
        )
        linux_state = (
            "ROTATED" if st.get("rotated_linux") else
            ("SKIPPED" if st.get("skipped_missing_local") else "NO CHANGE")
        )
        print(f"  {user}: PAM360={pam_state}, Linux={linux_state}")

    print("\nPAM360 ACCOUNTS (confirmed from API):")
    for acc in final_accounts:
        print(f"  - {acc.get('ACCOUNT NAME')} (ID: {acc.get('ACCOUNT ID')}, Policy: {acc.get('ACCOUNT PASSWORD POLICY')})")

    print("\nACCOUNT DETAILS:")
    for name, detail in account_details:
        try:
            d = detail["operation"]["Details"]
            lm = d.get("LAST MODIFIED TIME", "N/A")
            la = d.get("LAST ACCESSED TIME", "N/A")
        except Exception:
            lm, la = "N/A", "N/A"
        print(f"  {name}:")
        print(f"    Last Modified: {lm}")
        print(f"    Last Accessed: {la}")

    print("=" * 44 + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        eprint("Interrupted.")
        sys.exit(130)
    except Exception as exc:
        eprint(f"ERROR: {exc}")
        sys.exit(1)
