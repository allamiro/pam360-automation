
#!/bin/bash
set -euo pipefail

# =======================================================
# PAM360 Password Sync Script
# Rotates local passwords and syncs with PAM360
# =======================================================

# =======================================================
# 1. Configuration
# =======================================================
PAM_TOKEN="${PAM_TOKEN:-44F011D4-9D03-4FFB-BB20-C1EA81A471D9}"
PAM_URL="${PAM_URL:-https://10.0.0.14:8282}"
TARGET_USERS=('root' 'admin')
RESOURCE_GROUP_NAME="Linux Servers"
SHARE_USER_ID="1"  # User ID (numeric) to share with

# Get system details
SYSTEM_NAME=$(hostname)
# Get IP address (Mac compatible)
if [[ "$OSTYPE" == "darwin"* ]]; then
    IP_ADDRESS=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "127.0.0.1")
else
    IP_ADDRESS=$(hostname -I 2>/dev/null | awk '{print $1}' || ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
fi

# Password storage
declare -A USER_PASSWORDS

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# =======================================================
# 2. Generate Passwords (BEFORE any changes)
# =======================================================
log_info "Generating passwords for target users..."

for user in "${TARGET_USERS[@]}"; do
    password=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 14 | head -n 1)
    USER_PASSWORDS[$user]=$password
    log_info "Generated password for $user"
done

# =======================================================
# 3. Check Resource Existence (API 1.1)
# =======================================================
log_info "Checking if resource '$SYSTEM_NAME' exists in PAM360..."

ALL_RESOURCES=$(curl -s -k -H "AUTHTOKEN:$PAM_TOKEN" "$PAM_URL/restapi/json/v1/resources")
RSRCID=$(echo "$ALL_RESOURCES" | jq -r --arg name "$SYSTEM_NAME" '.operation.Details[] | select(."RESOURCE NAME" == $name) | ."RESOURCE ID"' 2>/dev/null || echo "")

# =======================================================
# 4. Logic Branch A: Resource Exists
# =======================================================
if [ -n "$RSRCID" ] && [ "$RSRCID" != "null" ]; then
    log_info "Resource found (ID: $RSRCID). Processing accounts..."

    # API 2.1: Get existing accounts
    EXISTING_ACCOUNTS=$(curl -s -k -H "AUTHTOKEN:$PAM_TOKEN" "$PAM_URL/restapi/json/v1/resources/$RSRCID/accounts")

    for user in "${TARGET_USERS[@]}"; do
        CURRENT_PASSWORD="${USER_PASSWORDS[$user]}"
        ACCOUNT_ID=$(echo "$EXISTING_ACCOUNTS" | jq -r --arg user "$user" '.operation.Details["ACCOUNT LIST"][] | select(."ACCOUNT NAME" == $user) | ."ACCOUNT ID"' 2>/dev/null || echo "")

        if [ -n "$ACCOUNT_ID" ] && [ "$ACCOUNT_ID" != "null" ]; then
            # API 3.2: Update existing account password
            log_info "Updating password for account '$user' (ID: $ACCOUNT_ID)..."
            
            RESULT=$(curl -s -k -X PUT -H "AUTHTOKEN:$PAM_TOKEN" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                "$PAM_URL/restapi/json/v1/resources/$RSRCID/accounts/$ACCOUNT_ID/password" \
                --data-urlencode "INPUT_DATA={\"operation\":{\"Details\":{\"NEWPASSWORD\":\"$CURRENT_PASSWORD\",\"RESETTYPE\":\"LOCAL\",\"REASON\":\"Rotated via Script\"}}}")
            
            STATUS=$(echo "$RESULT" | jq -r '.operation.result.status' 2>/dev/null || echo "Unknown")
            [ "$STATUS" == "Success" ] && log_info "Password updated for '$user'" || log_warn "Update result: $STATUS"
        else
            # API 2.4: Create new account
            log_info "Account '$user' not found. Creating..."
            
            RESULT=$(curl -s -k -X POST -H "AUTHTOKEN:$PAM_TOKEN" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                "$PAM_URL/restapi/json/v1/resources/$RSRCID/accounts" \
                --data-urlencode "INPUT_DATA={\"operation\":{\"Details\":{\"ACCOUNTLIST\":[{\"ACCOUNTNAME\":\"$user\",\"PASSWORD\":\"$CURRENT_PASSWORD\",\"ACCOUNTPASSWORDPOLICY\":\"Strong\"}]}}}")
            
            STATUS=$(echo "$RESULT" | jq -r '.operation.result.status' 2>/dev/null || echo "Unknown")
            [ "$STATUS" == "Success" ] && log_info "Account '$user' created" || log_warn "Create result: $STATUS"
        fi
    done

# =======================================================
# 5. Logic Branch B: Resource Does Not Exist
# =======================================================
else
    log_info "Resource '$SYSTEM_NAME' not found. Creating..."

    FIRST_USER="${TARGET_USERS[0]}"
    FIRST_PASS="${USER_PASSWORDS[$FIRST_USER]}"

    # API 1.2: Create new resource with first account
    # NOTE: Use DNSNAME for IP address, not RESOURCEURL
    RESULT=$(curl -s -k -X POST -H "AUTHTOKEN:$PAM_TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        "$PAM_URL/restapi/json/v1/resources" \
        --data-urlencode "INPUT_DATA={\"operation\":{\"Details\":{\"RESOURCENAME\":\"$SYSTEM_NAME\",\"ACCOUNTNAME\":\"$FIRST_USER\",\"RESOURCETYPE\":\"Linux\",\"PASSWORD\":\"$FIRST_PASS\",\"DNSNAME\":\"$IP_ADDRESS\",\"RESOURCEPASSWORDPOLICY\":\"Strong\",\"ACCOUNTPASSWORDPOLICY\":\"Strong\",\"RESOURCEGROUPNAME\":\"$RESOURCE_GROUP_NAME\"}}}")
    
    MESSAGE=$(echo "$RESULT" | jq -r '.operation.result.message' 2>/dev/null || echo "Unknown")
    log_info "Resource creation: $MESSAGE"

    # API 1.3: Get new resource ID
    RSRCID_JSON=$(curl -s -k -H "AUTHTOKEN:$PAM_TOKEN" "$PAM_URL/restapi/json/v1/resources/resourcename/$SYSTEM_NAME")
    RSRCID=$(echo "$RSRCID_JSON" | jq -r '.operation.Details.RESOURCEID' 2>/dev/null || echo "")
    
    if [ -z "$RSRCID" ] || [ "$RSRCID" == "null" ]; then
        log_error "Failed to get resource ID"
        exit 1
    fi
    
    log_info "New Resource ID: $RSRCID"

    # API 2.4: Create remaining accounts
    for i in "${!TARGET_USERS[@]}"; do
        if [ $i -gt 0 ]; then
            user="${TARGET_USERS[$i]}"
            pass="${USER_PASSWORDS[$user]}"
            
            log_info "Adding account '$user'..."
            
            RESULT=$(curl -s -k -X POST -H "AUTHTOKEN:$PAM_TOKEN" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                "$PAM_URL/restapi/json/v1/resources/$RSRCID/accounts" \
                --data-urlencode "INPUT_DATA={\"operation\":{\"Details\":{\"ACCOUNTLIST\":[{\"ACCOUNTNAME\":\"$user\",\"PASSWORD\":\"$pass\",\"ACCOUNTPASSWORDPOLICY\":\"Strong\"}]}}}")
            
            STATUS=$(echo "$RESULT" | jq -r '.operation.result.status' 2>/dev/null || echo "Unknown")
            [ "$STATUS" == "Success" ] && log_info "Account '$user' created" || log_warn "Create result: $STATUS"
        fi
    done
fi

# =======================================================
# 6. Share Resource (API 9.1)
# =======================================================
if [ -n "$RSRCID" ] && [ "$RSRCID" != "null" ]; then
    log_info "Sharing resource $RSRCID with user ID $SHARE_USER_ID..."

    RESULT=$(curl -s -k -X PUT -H "AUTHTOKEN:$PAM_TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        "$PAM_URL/restapi/json/v1/resources/$RSRCID/share" \
        --data-urlencode "INPUT_DATA={\"operation\":{\"Details\":{\"ACCESSTYPE\":\"fullaccess\",\"USERID\":\"$SHARE_USER_ID\"}}}")
    
    MESSAGE=$(echo "$RESULT" | jq -r '.operation.result.message' 2>/dev/null || echo "Unknown")
    log_info "Share result: $MESSAGE"
fi

# =======================================================
# 7. Update Local Passwords (AFTER PAM360 sync)
# =======================================================
if [[ "$OSTYPE" == "darwin"* ]]; then
    log_warn "Running on Mac - skipping local password changes (PAM360 sync only)"
else
    log_info "Updating local passwords..."
    for user in "${TARGET_USERS[@]}"; do
        if id "$user" &>/dev/null; then
            echo "$user:${USER_PASSWORDS[$user]}" | chpasswd
            log_info "Changed local password for '$user'"
        else
            log_warn "User '$user' does not exist locally, skipping"
        fi
    done
fi

log_info "Script execution complete."