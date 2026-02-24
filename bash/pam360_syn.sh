#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# CONFIG (edit or provide via env vars)
# ==========================================================
PAM_URL="${PAM_URL:-https://10.0.0.14:8282}"
PAM_TOKEN="${PAM_TOKEN:-44F011D4-9D03-4FFB-BB20-C1EA81A471D9}"
PAM_VALIDATE_CERTS="${PAM_VALIDATE_CERTS:-false}"

PAM_RESOURCE_GROUP_NAME="${PAM_RESOURCE_GROUP_NAME:-Linux Servers}"

# Target users for rotation
PAM_TARGET_USERS=("root" "admin" "jdoe" "trump")

# Share resource/accounts with these PAM users (resolved by username -> USERID)
PAM_SHARE_USER_NAMES=("admin")

# Share resource/accounts/resource-group with these PAM user groups (resolved by name -> USERGROUPID)
PAM_SHARE_GROUP_NAMES=("LINUX ADMINS")

# Optional KeePass CSV export
PAM_CREATE_PASSWORD_FILE="${PAM_CREATE_PASSWORD_FILE:-false}"
PASSWORD_RECORDS_DIR="${PASSWORD_RECORDS_DIR:-$PWD/password_records}"

# Local account options
PAM_CREATE_LOCAL_ACCOUNTS="${PAM_CREATE_LOCAL_ACCOUNTS:-true}"

# ==========================================================
# GUARDS
# ==========================================================
if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: run as root (needed for useradd/chpasswd)." >&2
  exit 2
fi

CURL_TLS=()
if [[ "${PAM_VALIDATE_CERTS}" != "true" ]]; then
  CURL_TLS=(-k)
fi

# ==========================================================
# JSON parsing helpers (PURE BASH)
#   - These are regex-based and assume typical PAM360 JSON formatting.
# ==========================================================
json_get_first_string() {
  # Extract first occurrence of "KEY":"value"
  # Usage: json_get_first_string "$json" "USERID"
  local json="$1" key="$2"
  echo "$json" | tr -d '\n' | sed -nE "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\1/p" | head -n1
}

json_get_first_number() {
  # Extract first occurrence of "KEY":123
  # Usage: json_get_first_number "$json" "RESOURCEID"
  local json="$1" key="$2"
  echo "$json" | tr -d '\n' | sed -nE "s/.*\"${key}\"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p" | head -n1
}

json_get_status() {
  # operation.result.status
  local json="$1"
  # matches "status":"Success" anywhere
  json_get_first_string "$json" "status"
}

json_get_message() {
  local json="$1"
  json_get_first_string "$json" "message"
}

urlencode() {
  # pure bash urlencode for spaces + a few common chars (good enough for group names)
  # Note: full RFC3986 encoding is long; PAM360 group names mainly need space->%20.
  local s="$1"
  s="${s// /%20}"
  s="${s//+/%2B}"
  s="${s//\&/%26}"
  s="${s//\?/%3F}"
  s="${s//\=/%3D}"
  echo "$s"
}

# ==========================================================
# HTTP helpers (curl-only)
# ==========================================================
pam_get() {
  local path="$1"
  curl -sS "${CURL_TLS[@]}" \
    -H "AUTHTOKEN: ${PAM_TOKEN}" \
    "${PAM_URL%/}${path}"
}

pam_post_inputdata() {
  # body: INPUT_DATA=<json>
  local path="$1" input_json="$2"
  curl -sS "${CURL_TLS[@]}" \
    -H "AUTHTOKEN: ${PAM_TOKEN}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "INPUT_DATA=${input_json}" \
    "${PAM_URL%/}${path}"
}

pam_put_inputdata() {
  local path="$1" input_json="$2"
  curl -sS "${CURL_TLS[@]}" \
    -X PUT \
    -H "AUTHTOKEN: ${PAM_TOKEN}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "INPUT_DATA=${input_json}" \
    "${PAM_URL%/}${path}"
}

# ==========================================================
# Password generator (pure bash using /dev/urandom)
# Matches your pattern:
# 1 letter + 10 alnum + 1 symbol (.,!@#$) + 2 digits
# ==========================================================
rand_from_set() {
  local set="$1" n="$2"
  # shellcheck disable=SC2005
  echo "$(LC_ALL=C tr -dc "$set" < /dev/urandom | head -c "$n")"
}

gen_password() {
  local letters='A-Za-z'
  local alnum='A-Za-z0-9'
  local symbols='.,!@#$'
  local digits='0-9'
  printf "%s%s%s%s" \
    "$(rand_from_set "$letters" 1)" \
    "$(rand_from_set "$alnum" 10)" \
    "$(rand_from_set "$symbols" 1)" \
    "$(rand_from_set "$digits" 2)"
}

# ==========================================================
# System info (matches playbook behavior)
# ==========================================================
SYSTEM_HOSTNAME="$(hostname | tr -d '\n')"
SYSTEM_IP="127.0.0.1"
IP_OUT="$(hostname -I 2>/dev/null || true)"
if [[ -n "${IP_OUT}" ]]; then
  SYSTEM_IP="$(echo "$IP_OUT" | awk '{print $1}')"
  [[ -z "${SYSTEM_IP}" ]] && SYSTEM_IP="127.0.0.1"
fi
echo "System: ${SYSTEM_HOSTNAME} (${SYSTEM_IP})"

# ==========================================================
# State tracking like user_status
# ==========================================================
declare -A USER_PASS
declare -A ST_CREATED_PAM ST_UPDATED_PAM ST_API_FAILED
declare -A ST_ROTATED_LINUX ST_SKIPPED_LOCAL ST_CREATED_LOCAL

# ==========================================================
# 1) Resolve share users -> USERID (API 4.5)
# ==========================================================
declare -A SHARE_USER_ID_BY_NAME
for uname in "${PAM_SHARE_USER_NAMES[@]}"; do
  resp="$(pam_get "/restapi/json/v1/user/getUserId?USERNAME=${uname}")"
  status="$(json_get_status "$resp")"
  msg="$(json_get_message "$resp")"
  uid="$(json_get_first_string "$resp" "USERID")"
  [[ -z "$uid" ]] && uid="$(json_get_first_number "$resp" "USERID")"

  echo "[share-user] ${uname} status=${status:-N/A} user_id=${uid:-NOT FOUND} msg=${msg:-}"

  if [[ "$status" == "Success" && -n "$uid" ]]; then
    SHARE_USER_ID_BY_NAME["$uname"]="$uid"
  fi
done

# ==========================================================
# 1b) Resolve share groups -> USERGROUPID (API 5.1)
# ==========================================================
declare -A SHARE_GROUP_ID_BY_NAME
for gname in "${PAM_SHARE_GROUP_NAMES[@]}"; do
  enc="$(urlencode "$gname")"
  resp="$(pam_get "/restapi/json/v1/user/getUserGroupId?USERGROUPNAME=${enc}")"
  status="$(json_get_status "$resp")"
  msg="$(json_get_message "$resp")"
  gid="$(json_get_first_string "$resp" "USERGROUPID")"
  [[ -z "$gid" ]] && gid="$(json_get_first_number "$resp" "USERGROUPID")"

  echo "[share-group] ${gname} status=${status:-N/A} group_id=${gid:-NOT FOUND} msg=${msg:-}"

  if [[ "$status" == "Success" && -n "$gid" ]]; then
    SHARE_GROUP_ID_BY_NAME["$gname"]="$gid"
  fi
done

# ==========================================================
# 2) Generate passwords for target users
# ==========================================================
for u in "${PAM_TARGET_USERS[@]}"; do
  USER_PASS["$u"]="$(gen_password)"
done

# ==========================================================
# 3) Find Resource ID by hostname (API 1.1 via /resources list)
#   NOTE: Pure bash parsing: find the object containing "RESOURCE NAME":"<hostname>"
# ==========================================================
all_resources="$(pam_get "/restapi/json/v1/resources")"
# compress to one line for regex ops
all_resources_1l="$(echo "$all_resources" | tr -d '\n')"

PAM_RESOURCE_ID=""

# Split crudely by occurrences of "RESOURCE NAME" blocks
# We look for the substring that contains the hostname and then extract the nearest "RESOURCE ID".
# This is heuristic but works with common PAM360 JSON layouts.
candidate_block="$(echo "$all_resources_1l" | sed -nE "s/.*(\{[^{}]*\"RESOURCE NAME\"[[:space:]]*:[[:space:]]*\"${SYSTEM_HOSTNAME}\"[^{}]*\}).*/\1/p")"
if [[ -n "$candidate_block" ]]; then
  PAM_RESOURCE_ID="$(echo "$candidate_block" | sed -nE 's/.*"RESOURCE ID"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' | head -n1)"
fi

RESOURCE_WAS_CREATED="false"

if [[ -n "${PAM_RESOURCE_ID}" ]]; then
  echo "Resource exists: ${SYSTEM_HOSTNAME} -> ID ${PAM_RESOURCE_ID}"
else
  echo "Resource NOT FOUND for hostname '${SYSTEM_HOSTNAME}' -> creating."

  FIRST_USER="${PAM_TARGET_USERS[0]}"
  FIRST_PASS="${USER_PASS[$FIRST_USER]}"

  input_json='{"operation":{"Details":{'
  input_json+='"RESOURCENAME":"'"${SYSTEM_HOSTNAME}"'",'
  input_json+='"ACCOUNTNAME":"'"${FIRST_USER}"'",'
  input_json+='"RESOURCETYPE":"Linux",'
  input_json+='"PASSWORD":"'"${FIRST_PASS}"'",'
  input_json+='"DNSNAME":"'"${SYSTEM_IP}"'",'
  input_json+='"RESOURCEPASSWORDPOLICY":"Strong",'
  input_json+='"ACCOUNTPASSWORDPOLICY":"Strong",'
  input_json+='"RESOURCEGROUPNAME":"'"${PAM_RESOURCE_GROUP_NAME}"'"'
  input_json+='}}}'

  resp="$(pam_post_inputdata "/restapi/json/v1/resources" "$input_json")"
  echo "[resource-create] $(json_get_message "$resp")"

  # Fetch new RESOURCEID (API 1.3)
  new_res="$(pam_get "/restapi/json/v1/resources/resourcename/${SYSTEM_HOSTNAME}")"
  PAM_RESOURCE_ID="$(json_get_first_string "$new_res" "RESOURCEID")"
  [[ -z "$PAM_RESOURCE_ID" ]] && PAM_RESOURCE_ID="$(json_get_first_number "$new_res" "RESOURCEID")"

  if [[ -z "${PAM_RESOURCE_ID}" ]]; then
    echo "ERROR: created resource but could not fetch RESOURCEID." >&2
    exit 1
  fi

  RESOURCE_WAS_CREATED="true"
  echo "New Resource ID: ${PAM_RESOURCE_ID}"

  # Create remaining accounts (API 2.4)
  for ((i=1; i<${#PAM_TARGET_USERS[@]}; i++)); do
    u="${PAM_TARGET_USERS[$i]}"
    pw="${USER_PASS[$u]}"

    input_json='{"operation":{"Details":{"ACCOUNTLIST":[{"ACCOUNTNAME":"'"${u}"'","PASSWORD":"'"${pw}"'","ACCOUNTPASSWORDPOLICY":"Strong"}]}}}'
    resp="$(pam_post_inputdata "/restapi/json/v1/resources/${PAM_RESOURCE_ID}/accounts" "$input_json")"

    status="$(json_get_status "$resp")"
    msg="$(json_get_message "$resp")"
    echo "Created account '${u}' in PAM360: ${status:-} - ${msg:-}"

    if [[ "$status" == "Success" ]]; then
      ST_CREATED_PAM["$u"]="true"
    else
      ST_API_FAILED["$u"]="true"
    fi
  done
fi

# ==========================================================
# If resource existed: update/create each account (process_user.yml logic)
# ==========================================================
if [[ "${RESOURCE_WAS_CREATED}" != "true" ]]; then
  existing_accounts="$(pam_get "/restapi/json/v1/resources/${PAM_RESOURCE_ID}/accounts")"
  existing_accounts_1l="$(echo "$existing_accounts" | tr -d '\n')"

  for u in "${PAM_TARGET_USERS[@]}"; do
    pw="${USER_PASS[$u]}"

    # Try to find matching account block containing "ACCOUNT NAME":"<user>"
    acc_block="$(echo "$existing_accounts_1l" | sed -nE "s/.*(\{[^{}]*\"ACCOUNT NAME\"[[:space:]]*:[[:space:]]*\"${u}\"[^{}]*\}).*/\1/p")"
    acc_id=""
    if [[ -n "$acc_block" ]]; then
      acc_id="$(echo "$acc_block" | sed -nE 's/.*"ACCOUNT ID"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' | head -n1)"
    fi

    if [[ -n "$acc_id" ]]; then
      # Update password (API 3.2)
      input_json='{"operation":{"Details":{"NEWPASSWORD":"'"${pw}"'","RESETTYPE":"LOCAL","REASON":"Rotated via Bash"}}}'
      resp="$(pam_put_inputdata "/restapi/json/v1/resources/${PAM_RESOURCE_ID}/accounts/${acc_id}/password" "$input_json")"
      status="$(json_get_status "$resp")"
      msg="$(json_get_message "$resp")"
      echo "Updated password for '${u}' in PAM360: ${status:-} - ${msg:-}"

      if [[ "$status" == "Success" ]]; then
        ST_UPDATED_PAM["$u"]="true"
      else
        ST_API_FAILED["$u"]="true"
      fi
    else
      # Create account (API 2.4)
      input_json='{"operation":{"Details":{"ACCOUNTLIST":[{"ACCOUNTNAME":"'"${u}"'","PASSWORD":"'"${pw}"'","ACCOUNTPASSWORDPOLICY":"Strong"}]}}}'
      resp="$(pam_post_inputdata "/restapi/json/v1/resources/${PAM_RESOURCE_ID}/accounts" "$input_json")"
      status="$(json_get_status "$resp")"
      msg="$(json_get_message "$resp")"
      echo "Created account '${u}' in PAM360: ${status:-} - ${msg:-}"

      if [[ "$status" == "Success" ]]; then
        ST_CREATED_PAM["$u"]="true"
      else
        ST_API_FAILED["$u"]="true"
      fi
    fi
  done
fi

# Refresh accounts for sharing
accounts_for_sharing="$(pam_get "/restapi/json/v1/resources/${PAM_RESOURCE_ID}/accounts")"
accounts_for_sharing_1l="$(echo "$accounts_for_sharing" | tr -d '\n')"

# ==========================================================
# 5) Share Resource with Users (API 9.1)
# ==========================================================
for uname in "${!SHARE_USER_ID_BY_NAME[@]}"; do
  uid="${SHARE_USER_ID_BY_NAME[$uname]}"
  input_json='{"operation":{"Details":{"ACCESSTYPE":"fullaccess","USERID":"'"${uid}"'"}}}'
  resp="$(pam_put_inputdata "/restapi/json/v1/resources/${PAM_RESOURCE_ID}/share" "$input_json")"
  echo "Shared resource with user '${uname}': $(json_get_message "$resp")"
done

# ==========================================================
# 5c) Share Resource with User Groups (API 9.3)
# ==========================================================
for gname in "${!SHARE_GROUP_ID_BY_NAME[@]}"; do
  gid="${SHARE_GROUP_ID_BY_NAME[$gname]}"
  input_json='{"operation":{"Details":{"ACCESSTYPE":"fullaccess","USERGROUPID":"'"${gid}"'"}}}'
  resp="$(pam_put_inputdata "/restapi/json/v1/resources/${PAM_RESOURCE_ID}/share" "$input_json")"
  echo "Shared resource with group '${gname}': $(json_get_message "$resp")"
done

# ==========================================================
# 5b/5d) Share Accounts with Users (API 9.5) and Groups (API 9.7)
#   Pure bash heuristic:
#     - Iterate over account IDs present in the accounts list
#     - For each ID, also try to extract its ACCOUNT NAME nearby
# ==========================================================
# Extract all ACCOUNT IDs (numbers) from the JSON (may include duplicates; we unique them)
mapfile -t ACCOUNT_IDS < <(echo "$accounts_for_sharing_1l" | grep -oE '"ACCOUNT ID"[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | sort -u)

for acc_id in "${ACCOUNT_IDS[@]}"; do
  # Find a block containing this ACCOUNT ID and pull ACCOUNT NAME from it
  block="$(echo "$accounts_for_sharing_1l" | sed -nE "s/.*(\{[^{}]*\"ACCOUNT ID\"[[:space:]]*:[[:space:]]*${acc_id}[^{}]*\}).*/\1/p")"
  acc_name="$(echo "$block" | sed -nE 's/.*"ACCOUNT NAME"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"
  [[ -z "$acc_name" ]] && acc_name="(id:${acc_id})"

  # Share with users
  for uname in "${!SHARE_USER_ID_BY_NAME[@]}"; do
    uid="${SHARE_USER_ID_BY_NAME[$uname]}"
    input_json='{"operation":{"Details":{"ACCESSTYPE":"modify","USERID":"'"${uid}"'"}}}'
    resp="$(pam_put_inputdata "/restapi/json/v1/resources/${PAM_RESOURCE_ID}/accounts/${acc_id}/share" "$input_json")"
    echo "Shared account '${acc_name}' with user '${uname}': $(json_get_message "$resp")"
  done

  # Share with groups
  for gname in "${!SHARE_GROUP_ID_BY_NAME[@]}"; do
    gid="${SHARE_GROUP_ID_BY_NAME[$gname]}"
    input_json='{"operation":{"Details":{"ACCESSTYPE":"modify","USERGROUPID":"'"${gid}"'"}}}'
    resp="$(pam_put_inputdata "/restapi/json/v1/resources/${PAM_RESOURCE_ID}/accounts/${acc_id}/share" "$input_json")"
    echo "Shared account '${acc_name}' with group '${gname}': $(json_get_message "$resp")"
  done
done

# ==========================================================
# 6) Associate Resource to Resource Group (API 6.2)
# ==========================================================
all_groups="$(pam_get "/restapi/json/v1/resourcegroup")"
all_groups_1l="$(echo "$all_groups" | tr -d '\n')"

# Find resourceGroupId for resourceGroupName
rg_block="$(echo "$all_groups_1l" | sed -nE "s/.*(\{[^{}]*\"resourceGroupName\"[[:space:]]*:[[:space:]]*\"${PAM_RESOURCE_GROUP_NAME}\"[^{}]*\}).*/\1/p")"
PAM_RESOURCE_GROUP_ID="$(echo "$rg_block" | sed -nE 's/.*"resourceGroupId"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' | head -n1)"

echo "Resource Group '${PAM_RESOURCE_GROUP_NAME}' ID: ${PAM_RESOURCE_GROUP_ID:-NOT FOUND}"

ALREADY_IN_GROUP="false"
if [[ -n "${PAM_RESOURCE_GROUP_ID:-}" ]]; then
  associated="$(pam_get "/restapi/json/v1/resources/${PAM_RESOURCE_ID}/associatedGroups")"
  if echo "$associated" | tr -d '\n' | grep -q "\"GROUP ID\"[[:space:]]*:[[:space:]]*${PAM_RESOURCE_GROUP_ID}"; then
    ALREADY_IN_GROUP="true"
  fi
  echo "Resource already in '${PAM_RESOURCE_GROUP_NAME}': ${ALREADY_IN_GROUP}"

  if [[ "${ALREADY_IN_GROUP}" != "true" ]]; then
    input_json='{"operation":{"Details":{"RESOURCEIDS":['"${PAM_RESOURCE_ID}"']}}}'
    resp="$(pam_post_inputdata "/restapi/json/v1/resourcegroup/${PAM_RESOURCE_GROUP_ID}/associateResources" "$input_json")"
    echo "Association result: $(json_get_message "$resp")"
  fi
fi

# ==========================================================
# 6b) Share Resource Group with User Groups (API 9.10)
# ==========================================================
if [[ -n "${PAM_RESOURCE_GROUP_ID:-}" ]]; then
  for gname in "${!SHARE_GROUP_ID_BY_NAME[@]}"; do
    gid="${SHARE_GROUP_ID_BY_NAME[$gname]}"
    input_json='{"operation":{"Details":{"resourceGroupIds":["'"${PAM_RESOURCE_GROUP_ID}"'"],"userGroupIds":["'"${gid}"'"],"accessType":"fullaccess"}}}'
    resp="$(pam_put_inputdata "/restapi/json/v1/resourcegroup/share" "$input_json")"
    echo "Shared resource group '${PAM_RESOURCE_GROUP_NAME}' with group '${gname}': $(json_get_message "$resp")"
  done
fi

# ==========================================================
# 6c) Share Resource Group with Users (API 9.9)
# ==========================================================
if [[ -n "${PAM_RESOURCE_GROUP_ID:-}" ]]; then
  for uname in "${!SHARE_USER_ID_BY_NAME[@]}"; do
    uid="${SHARE_USER_ID_BY_NAME[$uname]}"
    input_json='{"operation":{"Details":{"resourceGroupIds":["'"${PAM_RESOURCE_GROUP_ID}"'"],"userIds":["'"${uid}"'"],"accessType":"fullaccess"}}}'
    resp="$(pam_put_inputdata "/restapi/json/v1/resourcegroup/share" "$input_json")"
    echo "Shared resource group '${PAM_RESOURCE_GROUP_NAME}' with user '${uname}': $(json_get_message "$resp")"
  done
fi

# ==========================================================
# 7) Update local Linux passwords (update_passwords.yml logic)
# ==========================================================
for u in "${PAM_TARGET_USERS[@]}"; do
  pw="${USER_PASS[$u]}"

  if id -u "$u" >/dev/null 2>&1; then
    echo "${u}:${pw}" | chpasswd
    ST_ROTATED_LINUX["$u"]="true"
  else
    if [[ "${PAM_CREATE_LOCAL_ACCOUNTS}" == "true" ]]; then
      useradd -m -s /bin/bash "$u"
      ST_CREATED_LOCAL["$u"]="true"
      echo "${u}:${pw}" | chpasswd
      ST_ROTATED_LINUX["$u"]="true"
    else
      ST_SKIPPED_LOCAL["$u"]="true"
    fi
  fi
done

# ==========================================================
# 8) Optional KeePass CSV
# ==========================================================
CSV_PATH=""
if [[ "${PAM_CREATE_PASSWORD_FILE}" == "true" ]]; then
  TS="$(date +%Y%m%dT%H%M%S)"
  mkdir -p -m 700 "${PASSWORD_RECORDS_DIR}"
  CSV_PATH="${PASSWORD_RECORDS_DIR}/passwords_${TS}.csv"

  umask 077
  {
    echo '"Group","Title","Username","Password","URL","Notes"'
    NOW_ISO="$(date -Iseconds)"
    for u in "${PAM_TARGET_USERS[@]}"; do
      pw="${USER_PASS[$u]}"
      echo "\"${PAM_RESOURCE_GROUP_NAME}\",\"${SYSTEM_HOSTNAME} - ${u}\",\"${u}\",\"${pw}\",\"ssh://${SYSTEM_IP}\",\"Rotated: ${NOW_ISO} | Resource ID: ${PAM_RESOURCE_ID}\""
    done
  } > "${CSV_PATH}"

  echo "Password record saved to: ${CSV_PATH}"
else
  echo "Password file creation skipped (PAM_CREATE_PASSWORD_FILE: false)"
fi

# ==========================================================
# 9) Final account list + details (API 2.1 & 2.2)
# ==========================================================
final_accounts="$(pam_get "/restapi/json/v1/resources/${PAM_RESOURCE_ID}/accounts")"
final_accounts_1l="$(echo "$final_accounts" | tr -d '\n')"

# ==========================================================
# 10) Summary (matches your summary structure)
# ==========================================================
echo
echo "============================================"
echo "PAM360 SYNC SUMMARY - ${SYSTEM_HOSTNAME}"
echo "============================================"
echo "Resource ID: ${PAM_RESOURCE_ID}"
echo "Resource Group: ${PAM_RESOURCE_GROUP_NAME} (ID: ${PAM_RESOURCE_GROUP_ID:-N/A})"
echo
echo "LOCAL STATUS:"
for u in "${PAM_TARGET_USERS[@]}"; do
  pam_state="NO CHANGE"
  [[ "${ST_CREATED_PAM[$u]:-false}" == "true" ]] && pam_state="CREATED"
  [[ "${ST_UPDATED_PAM[$u]:-false}" == "true" ]] && pam_state="UPDATED"
  [[ "${ST_API_FAILED[$u]:-false}" == "true" ]] && pam_state="FAILED"

  linux_state="NO CHANGE"
  [[ "${ST_ROTATED_LINUX[$u]:-false}" == "true" ]] && linux_state="ROTATED"
  [[ "${ST_SKIPPED_LOCAL[$u]:-false}" == "true" ]] && linux_state="SKIPPED"

  echo "  ${u}: PAM360=${pam_state}, Linux=${linux_state}"
done

echo
echo "PAM360 ACCOUNTS (from API 2.1):"
# Attempt to print ACCOUNT NAME + ACCOUNT ID + POLICY using regex extraction
# We extract simple pairs from one-line JSON (heuristic)
echo "$final_accounts_1l" | grep -oE '\{[^{}]*"ACCOUNT NAME"[[:space:]]*:[[:space:]]*"[^"]+"[^{}]*\}' | while read -r blk; do
  name="$(echo "$blk" | sed -nE 's/.*"ACCOUNT NAME"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p')"
  aid="$(echo "$blk" | sed -nE 's/.*"ACCOUNT ID"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p')"
  pol="$(echo "$blk" | sed -nE 's/.*"ACCOUNT PASSWORD POLICY"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p')"
  [[ -n "$name" ]] && echo "  - ${name} (ID: ${aid:-?}, Policy: ${pol:-?})"
done

echo
echo "ACCOUNT DETAILS (API 2.2):"
for acc_id in "${ACCOUNT_IDS[@]}"; do
  detail="$(pam_get "/restapi/json/v1/resources/${PAM_RESOURCE_ID}/accounts/${acc_id}")"
  detail_1l="$(echo "$detail" | tr -d '\n')"
  lm="$(echo "$detail_1l" | sed -nE 's/.*"LAST MODIFIED TIME"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"
  la="$(echo "$detail_1l" | sed -nE 's/.*"LAST ACCESSED TIME"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"

  # Attempt to find the account name from earlier block
  block="$(echo "$final_accounts_1l" | sed -nE "s/.*(\{[^{}]*\"ACCOUNT ID\"[[:space:]]*:[[:space:]]*${acc_id}[^{}]*\}).*/\1/p")"
  acc_name="$(echo "$block" | sed -nE 's/.*"ACCOUNT NAME"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"
  [[ -z "$acc_name" ]] && acc_name="(id:${acc_id})"

  echo "  ${acc_name}:"
  echo "    Last Modified: ${lm:-N/A}"
  echo "    Last Accessed: ${la:-N/A}"
done

echo "============================================"
