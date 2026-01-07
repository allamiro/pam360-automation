
#!/bin/bash

# =======================================================
# 1. Initialize Constants
# =======================================================
PAM_TOKEN="6892524E-0EE0-44F7-959F-5E2AE7EB6529"
PAM_URL="https://10.0.0.14:8282" 
# Users to manage on this system
TARGET_USERS=('root' 'user') 
# The PAM360 Resource Group to assign new resources to
RESOURCE_GROUP_NAME="Linux Servers" 
# The User ID to grant full access to (Step 7)
SHARE_USER_ID="allamiro" 

# Get system details
SYSTEM_NAME=$(hostname)
IP_ADDRESS=$(hostname -I | awk '{print $1}')

# Dictionary to hold the new passwords so we can send them to the API later
declare -A USER_PASSWORDS

# =======================================================
# 2. Local Password Rotation
# =======================================================
# Loop through the target users, change their local password, and save it
for user in "${TARGET_USERS[@]}"; do
    # Generate a random 14 char password
    password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 14 | head -n 1)
    
    # Save to array for API steps later
    USER_PASSWORDS[$user]=$password

    # Change password locally on the Linux system
    # 'chpasswd' is safer for scripting than 'passwd --stdin'
    echo "$user:$password" | chpasswd
    echo "Changed local password for $user"
done

# =======================================================
# 3. Get Resource ID for this Hostname
# =======================================================
# API 1.1: Get Resources
# We filter the output to see if this specific hostname already exists in PAM360
# NOTE: We use --data-urlencode for INPUT_DATA to handle JSON special characters automatically

echo "Checking if Resource $SYSTEM_NAME exists in PAM360..."

ALL_RESOURCES=$(curl -s -k -X GET -H "AUTHTOKEN: $PAM_TOKEN" "$PAM_URL/restapi/json/v1/resources")
RSRCID=$(echo "$ALL_RESOURCES" | jq -r '.operation.Details[] | select(."RESOURCE NAME" == "'$SYSTEM_NAME'") | ."RESOURCE ID"')

# =======================================================
# 4. Logic Flow: Exists vs Not Exists
# =======================================================

if [ -n "$RSRCID" ] && [ "$RSRCID" != "null" ]; then
    # ---------------------------------------------------
    # 5. Resource Exists: Update or Create Accounts
    # ---------------------------------------------------
    echo "Resource found (ID: $RSRCID). Checking accounts..."

    # API 2.1: Get Accounts for this Resource
    EXISTING_ACCOUNTS=$(curl -s -k -X GET -H "AUTHTOKEN: $PAM_TOKEN" "$PAM_URL/restapi/json/v1/resources/$RSRCID/accounts")

    for user in "${TARGET_USERS[@]}"; do
        # Retrieve the password we generated in Step 2
        CURRENT_PASSWORD="${USER_PASSWORDS[$user]}"

        # Check if account exists in the JSON response
        ACCOUNT_ID=$(echo "$EXISTING_ACCOUNTS" | jq -r '.operation.Details["ACCOUNT LIST"][] | select(."ACCOUNT NAME" == "'$user'") | ."ACCOUNT ID"')

        if [ -n "$ACCOUNT_ID" ] && [ "$ACCOUNT_ID" != "null" ]; then
            # 5b. Account Exists -> Update Password
            # API 3.2: Change Password
            # RESETTYPE is LOCAL because we already changed it on the server in Step 2
            echo "Updating password for existing account $user (ID: $ACCOUNT_ID)..."
            
            update_json='{"operation":{"Details":{"NEWPASSWORD":"'$CURRENT_PASSWORD'","RESETTYPE":"LOCAL","REASON":"Rotated via Script"}}}'
            
            curl -s -k -X PUT -H "AUTHTOKEN: $PAM_TOKEN" \
                 "$PAM_URL/restapi/json/v1/resources/$RSRCID/accounts/$ACCOUNT_ID/password" \
                 --data-urlencode "INPUT_DATA=$update_json"

        else
            # 5c. Account Missing -> Create Account
            # API 2.4: Create Accounts under Specific Resource
            echo "Account $user not found. Creating..."
            
            create_account_json='{"operation":{"Details":{"ACCOUNTLIST":[{"ACCOUNTNAME":"'$user'","PASSWORD":"'$CURRENT_PASSWORD'","ACCOUNTPASSWORDPOLICY":"Strong"}]}}}'
            
            curl -s -k -X POST -H "AUTHTOKEN: $PAM_TOKEN" \
                 "$PAM_URL/restapi/json/v1/resources/$RSRCID/accounts" \
                 --data-urlencode "INPUT_DATA=$create_account_json"
        fi
    done

else
    # ---------------------------------------------------
    # 6. Resource Does Not Exist: Create Resource & Accounts
    # ---------------------------------------------------
    echo "Resource $SYSTEM_NAME not found. Creating new resource..."

    # We use the first user in our list to create the initial resource
    FIRST_USER="${TARGET_USERS[0]}"
    FIRST_PASS="${USER_PASSWORDS[$FIRST_USER]}"

    # API 1.2: Create New Resource
    # Added RESOURCEGROUPNAME to automatically assign it to the group (Requirement 3)
    resource_json='{"operation":{"Details":{"RESOURCENAME":"'$SYSTEM_NAME'","ACCOUNTNAME":"'$FIRST_USER'","RESOURCETYPE":"Linux","PASSWORD":"'$FIRST_PASS'","RESOURCEURL":"'$IP_ADDRESS'","RESOURCEPASSWORDPOLICY":"Strong","ACCOUNTPASSWORDPOLICY":"Strong","RESOURCEGROUPNAME":"'$RESOURCE_GROUP_NAME'"}}}'

    curl -s -k -X POST -H "AUTHTOKEN: $PAM_TOKEN" \
         "$PAM_URL/restapi/json/v1/resources" \
         --data-urlencode "INPUT_DATA=$resource_json"

    # Fetch the new ID by name (API 1.3) because Create response structure varies
    RSRCID_JSON=$(curl -s -k -X GET -H "AUTHTOKEN: $PAM_TOKEN" "$PAM_URL/restapi/json/v1/resources/resourcename/$SYSTEM_NAME")
    RSRCID=$(echo "$RSRCID_JSON" | jq -r '.operation.Details."RESOURCEID"')
    
    echo "New Resource ID is: $RSRCID"

    # 6b. Create the REST of the accounts (skipping the first one we just used)
    # Loop starting from index 1
    for i in "${!TARGET_USERS[@]}"; do
        if [ $i -gt 0 ]; then
            user="${TARGET_USERS[$i]}"
            pass="${USER_PASSWORDS[$user]}"
            
            echo "Adding additional account $user..."
            
            # API 2.4: Create Accounts
            add_acct_json='{"operation":{"Details":{"ACCOUNTLIST":[{"ACCOUNTNAME":"'$user'","PASSWORD":"'$pass'","ACCOUNTPASSWORDPOLICY":"Strong"}]}}}'

            curl -s -k -X POST -H "AUTHTOKEN: $PAM_TOKEN" \
                 "$PAM_URL/restapi/json/v1/resources/$RSRCID/accounts" \
                 --data-urlencode "INPUT_DATA=$add_acct_json"
        fi
    done
fi

# =======================================================
# 7. Update Permissions (Sharing)
# =======================================================
# API 9.1: Share Resource
if [ -n "$RSRCID" ] && [ "$RSRCID" != "null" ]; then
    echo "Sharing Resource $RSRCID with User $SHARE_USER_ID..."

    share_json='{"operation":{"Details":{"ACCESSTYPE":"fullaccess","USERID":"'$SHARE_USER_ID'"}}}'

    curl -s -k -X PUT -H "AUTHTOKEN: $PAM_TOKEN" \
         "$PAM_URL/restapi/json/v1/resources/$RSRCID/share" \
         --data-urlencode "INPUT_DATA=$share_json"
fi

echo "Script execution complete."