#!/bin/bash
set -euo pipefail

# =======================================================
# PAM360 Password Sync Script
# Rotates local passwords and syncs with PAM360
# Designed to run as systemd oneshot service
# =======================================================

# =======================================================
# 1. Configuration (from environment or defaults)
# =======================================================
# Required - fail if not set
: "${PAM_TOKEN:?PAM_TOKEN is required - set in /etc/pam360-sync.env}"
: "${PAM_URL:?PAM_URL is required - set in /etc/pam360-sync.env}"

# Optional with defaults
RESOURCE_GROUP_NAME="${RESOURCE_GROUP_NAME:-Linux Servers}"
SHARE_USER_ID="${SHARE_USER_ID:-1}"

# Target users - from env or default
if [[ -n "${TARGET_USERS:-}" ]]; then
    IFS=' ' read -ra TARGET_USERS_ARRAY <<< "$TARGET_USERS"
else
    TARGET_USERS_ARRAY=('root' 'admin')
fi

# Get system details - use FQDN for uniqueness
SYSTEM_NAME=$(hostname -f 2>/dev/null || hostname)
# Get primary IP address
IP_ADDRESS=$(ip -4 route get 1 2>/dev/null | awk '{print $7; exit}' || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

# Password storage
declare -A USER_PASSWORDS

# Colors for output (disabled if not interactive)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

log_info() { echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }

# =======================================================
# 2. Dependency Check
# =======================================================
log_info "Checking dependencies..."

for cmd in jq curl chpasswd; do
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Required command '$cmd' not found. Install it first."
        exit 1
    fi
done

log_info "All dependencies available."

# =======================================================
# 3. Generate Passwords (BEFORE any changes)
# =======================================================
log_info "Generating passwords for target users..."

for user in "${TARGET_USERS_ARRAY[@]}"; do
    # Generate password meeting PAM360 Strong policy:
    # - 14 chars, starts with letter, includes special char and digits
    first_char=$(tr -dc 'a-zA-Z' < /dev/urandom | fold -w 1 | head -n 1)
    middle=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 10 | head -n 1)
    special=$(echo '.,!@#$%' | fold -w 1 | shuf | head -n 1)
    digits=$(tr -dc '0-9' < /dev/urandom | fold -w 2 | head -n 1)
    password="${first_char}${middle}${special}${digits}"
    USER_PASSWORDS[$user]=$password
    log_info "Generated password for $user"
done

# =======================================================
# 4. PAM360 API Functions
# =======================================================
pam_api() {
    local method=$1
    local endpoint=$2
    local data=${3:-}
    
    local curl_args=(
        -s -k
        -X "$method"
        -H "AUTHTOKEN: $PAM_TOKEN"
        --max-time 30
    )
    
    if [[ -n "$data" ]]; then
        curl_args+=(-H "Content-Type: text/json" --data-urlencode "INPUT_DATA=$data")
    fi
    
    local response
    response=$(curl "${curl_args[@]}" "${PAM_URL}/restapi/json/v1/${endpoint}")
    
    # Check for valid JSON response
    if ! echo "$response" | jq -e . >/dev/null 2>&1; then
        log_error "Invalid JSON response from PAM360"
        return 1
    fi
    
    echo "$response"
}

check_api_response() {
    local response=$1
    local operation=${2:-"operation"}
    
    local status
    status=$(echo "$response" | jq -r '.operation.result.status // "Unknown"')
    
    if [[ "$status" != "Success" ]]; then
        local message
        message=$(echo "$response" | jq -r '.operation.result.message // "No message"')
        log_error "$operation failed: $message"
        return 1
    fi
    return 0
}

# =======================================================
# 5. Check/Create Resource in PAM360
# =======================================================
log_info "Checking if resource '$SYSTEM_NAME' exists in PAM360..."

# Use direct resource lookup by name
RESOURCE_RESPONSE=$(pam_api GET "resources/resourcename/$SYSTEM_NAME" || echo '{}')
RESOURCE_ID=$(echo "$RESOURCE_RESPONSE" | jq -r '.operation.Details."RESOURCE ID" // empty')

if [[ -z "$RESOURCE_ID" ]]; then
    log_info "Resource not found, creating new resource..."
    
    # Get first user for resource creation
    FIRST_USER="${TARGET_USERS_ARRAY[0]}"
    FIRST_PASS="${USER_PASSWORDS[$FIRST_USER]}"
    
    CREATE_DATA=$(cat <<EOF
{
  "operation": {
    "Details": {
      "RESOURCENAME": "$SYSTEM_NAME",
      "RESOURCETYPE": "Linux",
      "RESOURCEURL": "$IP_ADDRESS",
      "RESOURCEGROUPNAME": "$RESOURCE_GROUP_NAME",
      "ACCOUNTLIST": [{
        "ACCOUNTNAME": "$FIRST_USER",
        "PASSWORD": "$FIRST_PASS",
        "ACCOUNTPASSWORDPOLICY": "Strong"
      }]
    }
  }
}
EOF
)
    
    CREATE_RESPONSE=$(pam_api POST "resources" "$CREATE_DATA")
    
    if check_api_response "$CREATE_RESPONSE" "Resource creation"; then
        log_info "Resource created successfully"
        # Fetch the new resource ID
        RESOURCE_RESPONSE=$(pam_api GET "resources/resourcename/$SYSTEM_NAME")
        RESOURCE_ID=$(echo "$RESOURCE_RESPONSE" | jq -r '.operation.Details."RESOURCE ID"')
        RESOURCE_CREATED=true
    else
        log_error "Failed to create resource in PAM360"
        exit 1
    fi
else
    log_info "Resource found with ID: $RESOURCE_ID"
    RESOURCE_CREATED=false
fi

# =======================================================
# 6. Update/Create Accounts in PAM360
# =======================================================
log_info "Syncing accounts to PAM360..."

# Get existing accounts
ACCOUNTS_RESPONSE=$(pam_api GET "resources/$RESOURCE_ID/accounts")
EXISTING_ACCOUNTS=$(echo "$ACCOUNTS_RESPONSE" | jq -r '.operation.Details."ACCOUNT LIST"[]."ACCOUNT NAME" // empty' 2>/dev/null || echo "")

for user in "${TARGET_USERS_ARRAY[@]}"; do
    password="${USER_PASSWORDS[$user]}"
    
    # Skip first user if resource was just created
    if [[ "$RESOURCE_CREATED" == "true" && "$user" == "${TARGET_USERS_ARRAY[0]}" ]]; then
        log_info "Skipping $user (already created with resource)"
        continue
    fi
    
    if echo "$EXISTING_ACCOUNTS" | grep -qx "$user"; then
        # Update existing account
        log_info "Updating password for $user in PAM360..."
        
        # Get account ID
        ACCOUNT_ID=$(echo "$ACCOUNTS_RESPONSE" | jq -r ".operation.Details.\"ACCOUNT LIST\"[] | select(.\"ACCOUNT NAME\"==\"$user\") | .\"ACCOUNT ID\"")
        
        UPDATE_DATA=$(cat <<EOF
{
  "operation": {
    "Details": {
      "NEWPASSWORD": "$password",
      "RESETTYPE": "LOCAL"
    }
  }
}
EOF
)
        
        UPDATE_RESPONSE=$(pam_api PUT "resources/$RESOURCE_ID/accounts/$ACCOUNT_ID/password" "$UPDATE_DATA")
        
        if check_api_response "$UPDATE_RESPONSE" "Password update for $user"; then
            log_info "PAM360 password updated for $user"
        else
            log_warn "Failed to update PAM360 password for $user"
        fi
    else
        # Create new account
        log_info "Creating account for $user in PAM360..."
        
        CREATE_ACC_DATA=$(cat <<EOF
{
  "operation": {
    "Details": {
      "ACCOUNTLIST": [{
        "ACCOUNTNAME": "$user",
        "PASSWORD": "$password",
        "ACCOUNTPASSWORDPOLICY": "Strong"
      }]
    }
  }
}
EOF
)
        
        CREATE_ACC_RESPONSE=$(pam_api POST "resources/$RESOURCE_ID/accounts" "$CREATE_ACC_DATA")
        
        if check_api_response "$CREATE_ACC_RESPONSE" "Account creation for $user"; then
            log_info "Account created for $user in PAM360"
        else
            log_warn "Failed to create account for $user in PAM360"
        fi
    fi
done

# =======================================================
# 7. Share Resource (if configured)
# =======================================================
if [[ -n "$SHARE_USER_ID" ]]; then
    log_info "Sharing resource with user ID: $SHARE_USER_ID..."
    
    SHARE_DATA='{"operation":{"Details":{"ACCESSTYPE":"fullaccess","USERID":"'"$SHARE_USER_ID"'"}}}'
    SHARE_RESPONSE=$(pam_api PUT "resources/$RESOURCE_ID/share" "$SHARE_DATA")
    
    if check_api_response "$SHARE_RESPONSE" "Resource sharing"; then
        log_info "Resource shared successfully"
    else
        log_warn "Failed to share resource"
    fi
fi

# =======================================================
# 8. Update Local Linux Passwords
# =======================================================
log_info "Updating local Linux passwords..."

LOCAL_FAILURES=0
for user in "${TARGET_USERS_ARRAY[@]}"; do
    password="${USER_PASSWORDS[$user]}"
    
    # Check if user exists locally
    if id "$user" &>/dev/null; then
        if echo "$user:$password" | chpasswd 2>/dev/null; then
            log_info "Local password updated for $user"
        else
            log_error "Failed to update local password for $user"
            ((LOCAL_FAILURES++))
        fi
    else
        log_warn "User $user does not exist locally, skipping"
    fi
done

# =======================================================
# 9. Summary
# =======================================================
echo ""
log_info "============================================"
log_info "PAM360 SYNC COMPLETE - $SYSTEM_NAME"
log_info "============================================"
log_info "Resource ID: $RESOURCE_ID"
log_info "Users processed: ${TARGET_USERS_ARRAY[*]}"
log_info "Local failures: $LOCAL_FAILURES"
log_info "============================================"

if [[ $LOCAL_FAILURES -gt 0 ]]; then
    exit 1
fi

exit 0
