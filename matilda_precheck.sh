#!/usr/bin/env bash
# Matilda Precheck Script (enhanced)
# - Inline URL list (no external file)
# - Graceful "SKIP" when external server files are missing/empty
# - Styled output with icons/colors
# - End-of-run indented summary
# - Safer checks for CPU, Memory, Disk, Commands, Ports, and URLs

set -uo pipefail

#############################################
# Styling & Icons
#############################################
BOLD="\e[1m"
DIM="\e[2m"
RESET="\e[0m"

FG_RED="\e[31m"
FG_GREEN="\e[32m"
FG_YELLOW="\e[33m"
FG_BLUE="\e[34m"
FG_CYAN="\e[36m"
FG_MAGENTA="\e[35m"
FG_WHITE="\e[97m"

BG_RED="\e[41m"
BG_GREEN="\e[42m"
BG_YELLOW="\e[43m"
BG_BLUE="\e[44m"
BG_MAGENTA="\e[45m"
BG_CYAN="\e[46m"
BG_WHITE="\e[47m"

ICON_OK="✅"
ICON_WARN="⚠️"
ICON_FAIL="❌"
ICON_SKIP="⏭️"

# Section header helper
section() {
  local title="$1"
  echo -e "${BOLD}${FG_CYAN}\n=== ${title} ===${RESET}"
}

# Result loggers
SUCCESS_LOG=()
WARN_LOG=()
FAIL_LOG=()
SKIP_LOG=()

log_ok()   { echo -e "${FG_GREEN}${ICON_OK} $*${RESET}"; SUCCESS_LOG+=("$*"); }
log_warn() { echo -e "${FG_YELLOW}${ICON_WARN} $*${RESET}"; WARN_LOG+=("$*"); }
log_fail() { echo -e "${FG_RED}${ICON_FAIL} $*${RESET}"; FAIL_LOG+=("$*"); }
log_skip() { echo -e "${FG_BLUE}${ICON_SKIP} $*${RESET}"; SKIP_LOG+=("$*"); }

#############################################
# Config
#############################################
CONNECTION_TIMEOUT="${CONNECTION_TIMEOUT:-5}"
URL_CONNECTION_TIMEOUT="${URL_CONNECTION_TIMEOUT:-10}"
URL_RETRIES="${URL_RETRIES:-2}"

REQUIRED_CPU=4
REQUIRED_MEMORY_GB=12

# Disk requirements (GiB)
REQUIRED_ROOT_GIB=10
REQUIRED_VAR_GIB=10
REQUIRED_MATILDA_GIB=20

MATILDA_BASE="${MATILDA_BASE:-/matilda}"
PWD_DIR="${PWD}"

# Inline URL list
URLS=(
  "https://auth.docker.io/"
  "https://dl.fedoraproject.org/"
  "https://download.docker.com/"
  "https://dev.azure.com/"
  "https://hub.docker.com/"
  "https://production.cloudflare.docker.com/"
  "https://registry-1.docker.io/"
)

# External server definition files (optional)
WINDOWS_LIST="${WINDOWS_LIST:-${PWD_DIR}/windows_servers}"
LINUX_LIST="${LINUX_LIST:-${PWD_DIR}/linux_servers}"
DISCOVERY_LIST="${DISCOVERY_LIST:-${PWD_DIR}/discover_server}"
MONGO_LIST="${MONGO_LIST:-${PWD_DIR}/mongo_servers}"
MSSQL_LIST="${MSSQL_LIST:-${PWD_DIR}/mssql_servers}"
MYSQL_LIST="${MYSQL_LIST:-${PWD_DIR}/mysql_servers}"
ORACLE_LIST="${ORACLE_LIST:-${PWD_DIR}/oracle_servers}"

#############################################
# Helpers
#############################################
# Curl helper: returns body only if HTTP 200, else empty
curl_body_200() {
  # usage: curl_body_200 <curl-args...>
  local body http
  body=$(curl -sS "$@" -w '\n%{http_code}' 2>/dev/null)
  http="${body##*$'\n'}"
  body="${body%$'\n'*}"
  [[ "$http" == "200" ]] && { echo "$body"; return 0; } || return 1
}

get_primary_ip() {
  local ip
  ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  [[ -z "$ip" ]] && ip=$(ip -4 -o addr 2>/dev/null | awk '$2!="lo"{split($4,a,"/"); print a[1]; exit}')
  echo "$ip"
}

# Validate IPv4 (simple regex; avoids HTML/garbage)
is_valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  # Ensure each octet <= 255
  IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

# Return first valid IPv4 from a list of commands
first_valid_ip() {
  local out
  while (( "$#" )); do
    # eval is safe here as we control the candidates below
    out=$(eval "$1" 2>/dev/null | tr -d '\r' | head -n1 | tr -d ' ')
    if is_valid_ipv4 "$out"; then
      echo "$out"
      return 0
    fi
    shift
  done
  return 1
}

# Usage: get_public_ip "<primary_ip>"
# - Tries AWS/Azure/GCP metadata
# - Falls back to external service
# - If still empty and a primary_ip was provided, uses that (non-cloud)
# - If still empty, returns "--"
get_public_ip() {
  local primary_ip="${1:-}"
  local ip=""

  # AWS
  ip=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/public-ipv4 || true)

  # Azure
  if [[ -z "$ip" ]]; then
    ip=$(curl -s --max-time 2 -H Metadata:true \
      "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text" || true)
  fi

  # GCP
  if [[ -z "$ip" ]]; then
    ip=$(curl -s --max-time 2 -H "Metadata-Flavor: Google" \
      "http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" || true)
  fi

  # External fallback
  if [[ -z "$ip" ]]; then
    ip=$(curl -s --max-time 3 https://ifconfig.me || true)
  fi

  # Non-cloud (or blocked) fallback to primary IP
  if [[ -z "$ip" && -n "$primary_ip" ]]; then
    ip="$primary_ip"
  fi

  [[ -z "$ip" ]] && ip="--"
  echo "$ip"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Count available lines (returns 0 for missing/empty)
count_lines() {
  local f="$1"
  [[ -s "$f" ]] && wc -l < "$f" || echo 0
}

# Generic TCP port check
check_port() {
  local host="$1" port="$2" label="$3"
  if nc -w "$CONNECTION_TIMEOUT" -z "$host" "$port" >/dev/null 2>&1; then
    log_ok "$label: $host:$port reachable"
    return 0
  else
    log_fail "$label: $host:$port NOT reachable"
    return 1
  fi
}

#############################################
# Checks
#############################################
section "Command Availability"
cmd_validation() {
  local missing=0
  for CMD in curl git nc awk df cut sed grep; do
    if have_cmd "$CMD"; then
      log_ok "Command '$CMD' found at $(command -v "$CMD")"
    else
      log_fail "Command '$CMD' is missing"
      ((missing++))
    fi
  done
  return $missing
}
cmd_validation || true

section "System Requirements (CPU/Memory)"
system_check() {
  # CPU
  local cpu
  cpu="$( (LC_ALL=C lscpu 2>/dev/null | awk -F: '/^CPU\\(s\\)/{gsub(/ /,"",$2); print $2}') || true )"
  [[ -z "$cpu" ]] && cpu="$(nproc 2>/dev/null || echo 0)"
  if [[ -z "$cpu" || "$cpu" -lt "$REQUIRED_CPU" ]]; then
    log_fail "CPU check failed: need >= ${REQUIRED_CPU} vCPUs, found ${cpu:-0}"
  else
    log_ok "CPU check passed: ${cpu} vCPUs"
  fi

  # Memory
  local mem_kb mem_gb
  mem_kb="$(awk '/MemTotal:/{print $2}' /proc/meminfo)"
  mem_gb=$(( mem_kb / 1024 / 1024 ))
  if (( mem_gb < REQUIRED_MEMORY_GB )); then
    log_fail "Memory check failed: need >= ${REQUIRED_MEMORY_GB} GiB, found ${mem_gb} GiB"
  else
    log_ok "Memory check passed: ${mem_gb} GiB"
  fi
}
system_check

section "Filesystem Requirements"
fs_check() {
  # Ensure base dir exists for measurement
  if [[ ! -d "$MATILDA_BASE" ]]; then
    mkdir -p "$MATILDA_BASE" || true
    log_warn "Created ${MATILDA_BASE} (not a dedicated mount)"
  fi

  # helper to get GiB free for a path
  local free_root_gib free_var_gib free_matilda_gib
  free_root_gib="$(df -k /      | awk 'NR==2{printf "%.0f", $4/1024/1024}')"
  free_var_gib="$(df -k /var    | awk 'NR==2{printf "%.0f", $4/1024/1024}')"
  free_matilda_gib="$(df -k "$MATILDA_BASE" | awk 'NR==2{printf "%.0f", $4/1024/1024}')"

  (( free_root_gib   >= REQUIRED_ROOT_GIB   )) && log_ok   "/ free >= ${REQUIRED_ROOT_GIB} GiB (have ${free_root_gib} GiB)" \
                                                  || log_fail "/ free <  ${REQUIRED_ROOT_GIB} GiB (have ${free_root_gib} GiB)"
  (( free_var_gib    >= REQUIRED_VAR_GIB    )) && log_ok   "/var free >= ${REQUIRED_VAR_GIB} GiB (have ${free_var_gib} GiB)" \
                                                  || log_fail "/var free <  ${REQUIRED_VAR_GIB} GiB (have ${free_var_gib} GiB)"
  (( free_matilda_gib>= REQUIRED_MATILDA_GIB)) && log_ok   "${MATILDA_BASE} free >= ${REQUIRED_MATILDA_GIB} GiB (have ${free_matilda_gib} GiB)" \
                                                  || log_fail "${MATILDA_BASE} free <  ${REQUIRED_MATILDA_GIB} GiB (have ${free_matilda_gib} GiB)"
}
fs_check

section "URL Connectivity (inline list)"
urls_validation() {
  local failures=0
  local failed_file="/tmp/failed_urls.$RANDOM"
  : > "$failed_file"
  for url in "${URLS[@]}"; do
    if curl -sSIL --retry "$URL_RETRIES" --retry-delay 1 --max-time "$URL_CONNECTION_TIMEOUT" "$url" >/dev/null 2>&1; then
      log_ok "URL OK: $url"
    else
      log_fail "URL FAIL: $url"
      echo "$url" >> "$failed_file"
      ((failures++))
    fi
  done
  if (( failures > 0 )); then
    echo -e "${FG_RED}${BOLD}The following URLs failed:${RESET}"
    sed 's/^/  - /' "$failed_file" || true
  fi
}
urls_validation

section "Network Connectivity to Known Ports"
# File-driven checks with graceful SKIP
list_check() {
  local file="$1" label="$2" port="$3"
  local n
  n=$(count_lines "$file")
  if (( n == 0 )); then
    log_skip "$label: no entries found (file missing or empty) – check skipped"
    return 0
  fi
  local failures=0 total=0
  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    ((total++))
    check_port "$host" "$port" "$label" || ((failures++))
  done < "$file"
  if (( failures == 0 )); then
    log_ok "$label: $total host(s) passed"
  else
    log_fail "$label: $failures/$total host(s) failed"
  fi
}

# Windows WinRM
list_check "$WINDOWS_LIST"  "Windows WinRM (5985)" 5985
list_check "$WINDOWS_LIST"  "Windows WinRM TLS (5986)" 5986
# Linux SSH
list_check "$LINUX_LIST"    "Linux SSH (22)" 22
# Discovery over 443
list_check "$DISCOVERY_LIST" "Discovery (443)" 443
# Databases
list_check "$MONGO_LIST"    "MongoDB (27017)" 27017
list_check "$MSSQL_LIST"    "MSSQL (1433)" 1433
list_check "$MYSQL_LIST"    "MySQL (3306)" 3306
list_check "$ORACLE_LIST"   "Oracle (1521)" 1521

#############################################
# System Information (for Summary)
#############################################
gather_system_info() {
  HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
  OS_NAME_VAL=$(awk -F= '/^NAME=/{print $2}' /etc/os-release 2>/dev/null | tr -d '"' | sed 's/^ *//;s/ *$//')
  OS_VER_VAL=$(awk -F= '/^VERSION=/{print $2}' /etc/os-release 2>/dev/null | tr -d '"' | sed 's/^ *//;s/ *$//')
  KERNEL_VAL=$(uname -r 2>/dev/null || echo "unknown")
  CPU_COUNT_VAL=$(nproc 2>/dev/null || echo 0)
  MEM_TOTAL_GIB_VAL=$(awk '/MemTotal:/{printf "%.0f", $2/1024/1024}' /proc/meminfo 2>/dev/null)
  IP_ADDR_VAL=$(hostname -I 2>/dev/null | awk '{print $1}')
  [[ -z "$IP_ADDR_VAL" ]] && IP_ADDR_VAL=$(ip -4 -o addr 2>/dev/null | awk '$2!="lo"{split($4,a,"/"); print a[1]; exit}')
  [[ -z "$IP_ADDR_VAL" ]] && IP_ADDR_VAL="unknown"

  ROOT_FREE_VAL=$(df -h /       2>/dev/null | awk 'NR==2 {print $4}')
  VAR_FREE_VAL=$(df -h /var     2>/dev/null | awk 'NR==2 {print $4}')
  MATILDA_FREE_VAL=$(df -h '"$MATILDA_BASE"' 2>/dev/null | awk 'NR==2 {print $4}')
  [[ -z "$MATILDA_FREE_VAL" ]] && MATILDA_FREE_VAL="N/A"

  # Render a simple ASCII table
  local w1=18 w2=48
  local sep="+------------------+------------------------------------------------+\n"
  printf "${BOLD}${FG_WHITE}System Information:${RESET}\n"
  printf "%b" "$sep"
  printf "| %-*s | %-*s |\n" $w1 "Field" $w2 "Value"
  printf "%b" "$sep"
  printf "| %-*s | %-*s |\n" $w1 "Hostname"      $w2 "$HOSTNAME_VAL"
  printf "| %-*s | %-*s |\n" $w1 "OS"            $w2 "$OS_NAME_VAL $OS_VER_VAL"
  printf "| %-*s | %-*s |\n" $w1 "Kernel"        $w2 "$KERNEL_VAL"
  printf "| %-*s | %-*s |\n" $w1 "CPU Count"     $w2 "$CPU_COUNT_VAL"
  printf "| %-*s | %-*s |\n" $w1 "Memory (GiB)"  $w2 "$MEM_TOTAL_GIB_VAL"
  printf "| %-*s | %-*s |\n" $w1 "Primary IP"    $w2 "$IP_ADDR_VAL"
  printf "| %-*s | %-*s |\n" $w1 "Disk Free /"   $w2 "${ROOT_FREE_VAL:-unknown}"
  printf "| %-*s | %-*s |\n" $w1 "Disk Free /var" $w2 "${VAR_FREE_VAL:-unknown}"
  printf "| %-*s | %-*s |\n" $w1 "Disk Free ${MATILDA_BASE}" $w2 "${MATILDA_FREE_VAL}"
  printf "%b\n" "$sep"
}

#############################################
# Summary
#############################################
section "Summary"
print_summary() {
  gather_system_info
  echo
echo -e "${BOLD}${FG_WHITE}Run Summary:${RESET}"
  echo -e "${DIM}(${#SUCCESS_LOG[@]} OK, ${#WARN_LOG[@]} WARN, ${#FAIL_LOG[@]} FAIL, ${#SKIP_LOG[@]} SKIP)${RESET}\n"

  if ((${#FAIL_LOG[@]})); then
    echo -e "${FG_RED}${BOLD}Failures:${RESET}"
    for s in "${FAIL_LOG[@]}"; do echo -e "  ${FG_RED}- $s${RESET}"; done
    echo
  fi

  if ((${#WARN_LOG[@]})); then
    echo -e "${FG_YELLOW}${BOLD}Warnings:${RESET}"
    for s in "${WARN_LOG[@]}"; do echo -e "  ${FG_YELLOW}- $s${RESET}"; done
    echo
  fi

  if ((${#SKIP_LOG[@]})); then
    echo -e "${FG_BLUE}${BOLD}Skipped Checks:${RESET}"
    for s in "${SKIP_LOG[@]}"; do echo -e "  ${FG_BLUE}- $s${RESET}"; done
    echo
  fi

  if ((${#SUCCESS_LOG[@]})); then
    echo -e "${FG_GREEN}${BOLD}Successes:${RESET}"
    for s in "${SUCCESS_LOG[@]}"; do echo -e "  ${FG_GREEN}- $s${RESET}"; done
    echo
  fi

  # Exit code: 0 if no failures; 1 otherwise
  if ((${#FAIL_LOG[@]})); then
    echo -e "${BG_RED}${FG_WHITE}${BOLD} OVERALL: FAIL ${RESET}"
    return 1
  else
    echo -e "${BG_GREEN}${FG_WHITE}${BOLD} OVERALL: PASS ${RESET}"
    return 0
  fi
}
print_summary