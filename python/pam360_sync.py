#!/usr/bin/env python3
"""
PAM360 Password Sync Script
Rotates local passwords and syncs with PAM360
Uses only Python built-in modules (no pip install required)
"""

import json
import os
import platform
import random
import socket
import ssl
import string
import subprocess
import sys
import urllib.parse
import urllib.request

# =======================================================
# 1. Configuration
# =======================================================
PAM_TOKEN = os.environ.get("PAM_TOKEN", "44F011D4-9D03-4FFB-BB20-C1EA81A471D9")
PAM_URL = os.environ.get("PAM_URL", "https://10.0.0.14:8282")
TARGET_USERS = ["root", "admin"]
RESOURCE_GROUP_NAME = "Linux Servers"
SHARE_USER_ID = "1"

# Colors for output
class Colors:
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    RED = "\033[0;31m"
    NC = "\033[0m"

def log_info(msg):
    print(f"{Colors.GREEN}[INFO]{Colors.NC} {msg}")

def log_warn(msg):
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}")

def log_error(msg):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")

# =======================================================
# Helper Functions
# =======================================================
def get_hostname():
    """Get system hostname"""
    return socket.gethostname()

def get_ip_address():
    """Get primary IP address (Mac and Linux compatible)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def generate_password(length=14):
    """Generate random password"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def api_request(method, endpoint, data=None):
    """Make API request to PAM360"""
    url = f"{PAM_URL}{endpoint}"
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    headers = {
        "AUTHTOKEN": PAM_TOKEN,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    body = None
    if data:
        body = urllib.parse.urlencode({"INPUT_DATA": json.dumps(data)}).encode()
    
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except:
            return {"operation": {"result": {"status": "Failed", "message": str(e)}}}
    except Exception as e:
        return {"operation": {"result": {"status": "Failed", "message": str(e)}}}

def change_local_password(user, password):
    """Change local password (Linux only)"""
    if platform.system() == "Darwin":
        return False
    
    try:
        proc = subprocess.Popen(
            ["chpasswd"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        proc.communicate(input=f"{user}:{password}\n".encode())
        return proc.returncode == 0
    except Exception as e:
        log_error(f"Failed to change password for {user}: {e}")
        return False

# =======================================================
# Main Logic
# =======================================================
def main():
    system_name = get_hostname()
    ip_address = get_ip_address()
    user_passwords = {}
    
    log_info(f"System: {system_name} ({ip_address})")
    log_info(f"Platform: {platform.system()}")
    
    # =======================================================
    # 2. Generate Passwords
    # =======================================================
    log_info("Generating passwords for target users...")
    for user in TARGET_USERS:
        user_passwords[user] = generate_password()
        log_info(f"Generated password for {user}")
    
    # =======================================================
    # 3. Check Resource Existence (API 1.1)
    # =======================================================
    log_info(f"Checking if resource '{system_name}' exists in PAM360...")
    
    result = api_request("GET", "/restapi/json/v1/resources")
    resources = result.get("operation", {}).get("Details", [])
    
    resource_id = None
    for r in resources:
        if r.get("RESOURCE NAME") == system_name:
            resource_id = r.get("RESOURCE ID")
            break
    
    # =======================================================
    # 4. Logic Branch A: Resource Exists
    # =======================================================
    if resource_id:
        log_info(f"Resource found (ID: {resource_id}). Processing accounts...")
        
        result = api_request("GET", f"/restapi/json/v1/resources/{resource_id}/accounts")
        accounts = result.get("operation", {}).get("Details", {}).get("ACCOUNT LIST", [])
        
        for user in TARGET_USERS:
            password = user_passwords[user]
            
            account_id = None
            for acc in accounts:
                if acc.get("ACCOUNT NAME") == user:
                    account_id = acc.get("ACCOUNT ID")
                    break
            
            if account_id:
                log_info(f"Updating password for account '{user}' (ID: {account_id})...")
                
                data = {
                    "operation": {
                        "Details": {
                            "NEWPASSWORD": password,
                            "RESETTYPE": "LOCAL",
                            "REASON": "Rotated via Python Script"
                        }
                    }
                }
                result = api_request("PUT", f"/restapi/json/v1/resources/{resource_id}/accounts/{account_id}/password", data)
                status = result.get("operation", {}).get("result", {}).get("status", "Unknown")
                
                if status == "Success":
                    log_info(f"Password updated for '{user}'")
                else:
                    log_warn(f"Update result: {status}")
            else:
                log_info(f"Account '{user}' not found. Creating...")
                
                data = {
                    "operation": {
                        "Details": {
                            "ACCOUNTLIST": [{
                                "ACCOUNTNAME": user,
                                "PASSWORD": password,
                                "ACCOUNTPASSWORDPOLICY": "Strong"
                            }]
                        }
                    }
                }
                result = api_request("POST", f"/restapi/json/v1/resources/{resource_id}/accounts", data)
                status = result.get("operation", {}).get("result", {}).get("status", "Unknown")
                
                if status == "Success":
                    log_info(f"Account '{user}' created")
                else:
                    log_warn(f"Create result: {status}")
    
    # =======================================================
    # 5. Logic Branch B: Resource Does Not Exist
    # =======================================================
    else:
        log_info(f"Resource '{system_name}' not found. Creating...")
        
        first_user = TARGET_USERS[0]
        first_pass = user_passwords[first_user]
        
        data = {
            "operation": {
                "Details": {
                    "RESOURCENAME": system_name,
                    "ACCOUNTNAME": first_user,
                    "RESOURCETYPE": "Linux",
                    "PASSWORD": first_pass,
                    "DNSNAME": ip_address,
                    "RESOURCEPASSWORDPOLICY": "Strong",
                    "ACCOUNTPASSWORDPOLICY": "Strong",
                    "RESOURCEGROUPNAME": RESOURCE_GROUP_NAME
                }
            }
        }
        result = api_request("POST", "/restapi/json/v1/resources", data)
        message = result.get("operation", {}).get("result", {}).get("message", "Unknown")
        log_info(f"Resource creation: {message}")
        
        result = api_request("GET", f"/restapi/json/v1/resources/resourcename/{system_name}")
        resource_id = result.get("operation", {}).get("Details", {}).get("RESOURCEID")
        
        if not resource_id:
            log_error("Failed to get resource ID")
            sys.exit(1)
        
        log_info(f"New Resource ID: {resource_id}")
        
        for user in TARGET_USERS[1:]:
            password = user_passwords[user]
            log_info(f"Adding account '{user}'...")
            
            data = {
                "operation": {
                    "Details": {
                        "ACCOUNTLIST": [{
                            "ACCOUNTNAME": user,
                            "PASSWORD": password,
                            "ACCOUNTPASSWORDPOLICY": "Strong"
                        }]
                    }
                }
            }
            result = api_request("POST", f"/restapi/json/v1/resources/{resource_id}/accounts", data)
            status = result.get("operation", {}).get("result", {}).get("status", "Unknown")
            
            if status == "Success":
                log_info(f"Account '{user}' created")
            else:
                log_warn(f"Create result: {status}")
    
    # =======================================================
    # 6. Share Resource (API 9.1)
    # =======================================================
    if resource_id:
        log_info(f"Sharing resource {resource_id} with user ID {SHARE_USER_ID}...")
        
        data = {
            "operation": {
                "Details": {
                    "ACCESSTYPE": "fullaccess",
                    "USERID": SHARE_USER_ID
                }
            }
        }
        result = api_request("PUT", f"/restapi/json/v1/resources/{resource_id}/share", data)
        message = result.get("operation", {}).get("result", {}).get("message", "Unknown")
        log_info(f"Share result: {message}")
    
    # =======================================================
    # 7. Update Local Passwords (AFTER PAM360 sync)
    # =======================================================
    if platform.system() == "Darwin":
        log_warn("Running on Mac - skipping local password changes (PAM360 sync only)")
    else:
        log_info("Updating local passwords...")
        for user in TARGET_USERS:
            if change_local_password(user, user_passwords[user]):
                log_info(f"Changed local password for '{user}'")
            else:
                log_warn(f"Could not change local password for '{user}'")
    
    log_info("Script execution complete.")

if __name__ == "__main__":
    main()
