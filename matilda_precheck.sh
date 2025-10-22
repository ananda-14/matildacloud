#
# matilda_installer.sh — System pre-installation validator and installer
#

set -o pipefail

#-----------------------------
# Configuration
#-----------------------------
BASE_URL="${BASE_URL:-http://localhost:8000}"
LICENSE_TOKEN=""
AUTO_CONFIRM=0
RUN_IN_BACKGROUND=0
STATUS_FILE="/var/tmp/matilda_install_status.txt"
PID_FILE="/var/tmp/matilda_install.pid"

#-----------------------------
# Logging Setup
#-----------------------------
LOGFILE="/var/log/matilda_installer.log"
if ! touch "$LOGFILE" 2>/dev/null; then
  LOGFILE="./matilda_installer.log"
fi
touch "$LOGFILE" 2>/dev/null || { echo "Cannot write log file"; exit 2; }

log() {
  printf "%s [%s] %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$1" "$2" >>"$LOGFILE"
  printf "%s [%s] %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$1" "$2"
}
log_info()  { log INFO "$*"; }
log_warn()  { log WARN "$*"; }
log_error() { log ERROR "$*"; }


if [ -t 1 ]; then
  RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BOLD="\033[1m"; RESET="\033[0m"
else
  RED=""; GREEN=""; YELLOW=""; BOLD=""; RESET=""
fi

#-----------------------------
# Utility
#-----------------------------
is_rhel_family() {
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    case "$ID $ID_LIKE" in
      *rhel*|*centos*|*rocky*|*almalinux*|*fedora*) return 0 ;;
    esac
  fi
  return 1
}
get_val_or_na() { [ -n "$1" ] && echo "$1" || echo "n/a"; }

#-----------------------------
# Command Line Argument Parsing
#-----------------------------
parse_arguments() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -y)
        AUTO_CONFIRM=1
        shift
        ;;
      -b|--background)
        RUN_IN_BACKGROUND=1
        shift
        ;;
      status|--status)
        show_status
        exit 0
        ;;
      *)
        LICENSE_TOKEN="$1"
        shift
        ;;
    esac
  done
}

#-----------------------------
# Status Management Functions
#-----------------------------
update_status() {
  local step=$1
  local status=$2
  local message=$3
  local timestamp=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

  cat > "$STATUS_FILE" <<EOF
{
  "timestamp": "$timestamp",
  "step": "$step",
  "status": "$status",
  "message": "$message",
  "pid": "$$"
}
EOF
}

show_status() {
  if [ ! -f "$STATUS_FILE" ]; then
    echo -e "${YELLOW}No installation in progress or status not found.${RESET}"
    return 1
  fi

  echo -e "\n${BOLD}=== Matilda Installation Status ===${RESET}\n"

  if [ -f "$PID_FILE" ]; then
    local pid=$(cat "$PID_FILE" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      echo -e "${GREEN}Installation Process: RUNNING (PID: $pid)${RESET}"
    else
      echo -e "${YELLOW}Installation Process: COMPLETED or STOPPED${RESET}"
    fi
  fi

  if command -v jq >/dev/null 2>&1; then
    # Use jq for pretty printing if available
    jq -r '"Timestamp: " + .timestamp, "Step: " + .step, "Status: " + .status, "Message: " + .message' "$STATUS_FILE"
  else
    # Fallback to basic parsing
    cat "$STATUS_FILE"
  fi

  echo -e "\n${BOLD}Log file: $LOGFILE${RESET}"
  echo -e "\nTo view live logs, run:"
  echo -e "  ${YELLOW}tail -f $LOGFILE${RESET}\n"
}

cleanup_status_files() {
  rm -f "$PID_FILE" 2>/dev/null
}

#-----------------------------
# API Call Functions
#-----------------------------
validate_license() {
  local token=$1
  local ip_address=$2

  log_info "Validating license with token: ${token:0:10}... and IP: $ip_address"

  local payload=$(cat <<EOF
{
  "token": "$token",
  "ip_address": "$ip_address"
}
EOF
)

  local response=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}/api/v1/licenses/validate")

  if [ $? -ne 0 ]; then
    log_error "Failed to connect to license validation API"
    return 1
  fi

  echo "$response"
}

build_package() {
  local ip_address=$1
  local license_key=$2
  local os_type=$3

  log_info "Requesting package build for OS: $os_type, IP: $ip_address"

  local payload=$(cat <<EOF
{
  "ip_address": "$ip_address",
  "license_key": "$license_key",
  "os_type": "$os_type"
}
EOF
)

  local response=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}/api/v1/packages/build")

  if [ $? -ne 0 ]; then
    log_error "Failed to connect to package build API"
    return 1
  fi

  echo "$response"
}

get_dockerhub_credentials() {
  local license_key=$1
  local ip_address=$2

  log_info "Fetching DockerHub credentials for IP: $ip_address"

  local payload=$(cat <<EOF
{
  "license_key": "$license_key",
  "ip_address": "$ip_address"
}
EOF
)

  local response=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}/api/v1/dockerhub/credentials")

  if [ $? -ne 0 ]; then
    log_error "Failed to connect to DockerHub credentials API"
    return 1
  fi

  echo "$response"
}

send_installation_status() {
  local customer_name=$1
  local installation_status=$2
  local installation_health=$3
  local installation_message=$4
  local installation_version=$5

  log_info "Sending installation status: $installation_status"

  local payload=$(cat <<EOF
{
  "customer_name": "$customer_name",
  "installation_status": "$installation_status",
  "installation_health": "$installation_health",
  "installation_message": "$installation_message",
  "installation_version": "$installation_version"
}
EOF
)

  local response=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}/api/v1/installation/status")

  if [ $? -ne 0 ]; then
    log_error "Failed to send installation status"
    return 1
  fi

  log_info "Installation status sent successfully"
  echo "$response"
}

detect_os_type() {
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
      debian|ubuntu|linuxmint)
        echo "debian"
        ;;
      rhel|centos|rocky|almalinux|fedora)
        echo "rhel"
        ;;
      *)
        echo "unknown"
        ;;
    esac
  else
    echo "unknown"
  fi
}

#-----------------------------
# 1. System Info
#-----------------------------
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
OS=$(awk -F= '/^PRETTY_NAME/{gsub(/"/,"");print $2}' /etc/os-release 2>/dev/null)
KERNEL=$(uname -r)
ARCH=$(uname -m)
CPU_COUNT=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
MEM_GIB=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
PRIMARY_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}')
[ -z "$PRIMARY_IP" ] && PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')

log_info "System Info: $HOSTNAME, $OS, $KERNEL, $ARCH, $CPU_COUNT CPUs, $MEM_GIB GiB, $PRIMARY_IP"

#---------------------------------------------
# 2. Verify required commands existence & versions
#---------------------------------------------
REQUIRED_CMDS="openssl git curl nc"
MISSING=()

for cmd in $REQUIRED_CMDS; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_warn "Missing: $cmd"
    if is_rhel_family; then
      if command -v sudo >/dev/null 2>&1; then
        pkg=$cmd
        [ "$cmd" = "nc" ] && pkg="nmap-ncat"
        log_info "Attempting to install $pkg (RHEL family)"
        if ! sudo yum -y install "$pkg" >>"$LOGFILE" 2>&1 && ! sudo dnf -y install "$pkg" >>"$LOGFILE" 2>&1; then
          log_error "Failed to install $pkg"
          MISSING+=("$cmd")
        fi
      else
        log_error "sudo not available; cannot install $cmd"
        MISSING+=("$cmd")
      fi
    else
      if command -v sudo >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
        log_info "Attempting to install $cmd via apt-get"
        if ! sudo apt-get update -y >>"$LOGFILE" 2>&1 || ! sudo apt-get install -y "$cmd" >>"$LOGFILE" 2>&1; then
          log_error "Failed to install $cmd via apt-get"
          MISSING+=("$cmd")
        fi
      else
        log_warn "Please install $cmd manually."
        MISSING+=("$cmd")
      fi
    fi
  else
    case "$cmd" in
      openssl)
        ver=$(openssl version 2>/dev/null | head -n1)
        ;;
      git)
        ver=$(git --version 2>/dev/null | head -n1)
        ;;
      curl)
        ver=$(curl --version 2>/dev/null | head -n1)
        ;;
      nc)
        ver=$(nc -h 2>&1 | head -n1 | grep -Eo "v[0-9\.]+" || echo "nc (version info unavailable)")
        ;;
      *)
        ver=$($cmd --version 2>/dev/null | head -n1 || echo "$cmd version unknown")
        ;;
    esac

    ver=$(echo "$ver" | tr -d '\r')
    log_info "$cmd found: $ver"
  fi
done

#-----------------------------
# 3. AVX support
#-----------------------------
AVX_OK=0
if grep -qi 'avx' /proc/cpuinfo 2>/dev/null; then
  AVX_OK=1; log_info "AVX supported"
else
  log_error "AVX not supported"
fi

#-----------------------------
# 4. /var mount noexec
#-----------------------------
VAR_NOEXEC=0
VAR_IS_SEPARATE=0
if grep -q " /var " /proc/mounts; then
  VAR_IS_SEPARATE=1
  opts=$(awk '$2=="/var"{print $4}' /proc/mounts)
  echo "$opts" | grep -qw noexec && VAR_NOEXEC=1
  VAR_AVAIL=$(df -h /var | awk 'NR==2 {print $4}')
else
  opts=$(awk '$2=="/"{print $4}' /proc/mounts)
  echo "$opts" | grep -qw noexec && VAR_NOEXEC=1
  VAR_AVAIL=""
fi
[ "$VAR_NOEXEC" -eq 1 ] && log_error "/var mounted with noexec"

#-----------------------------
# 5. URL Connectivity
#-----------------------------
URLS=("https://auth.docker.io" "https://hub.docker.com" "https://production.cloudflare.docker.com/" "https://registry-1.docker.io/" "https://dl.fedoraproject.org/")
URL_FAIL=()
for u in "${URLS[@]}"; do
  code=$(curl -k -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$u")
  if [[ "$code" =~ ^2|3|4 ]]; then
    log_info "Reachable: $u (HTTP $code)"
  else
    log_error "Cannot reach $u (code: $code)"
    URL_FAIL+=("$u")
  fi
done

#-----------------------------
# 6. CPU & Memory Minimums (Portable, no bc)
#-----------------------------
CPU_MIN=12
MEM_MIN=23.5  # in GiB
CPU_FAIL=0; MEM_FAIL=0

MEM_GIB=$(awk '/MemTotal/ {printf "%.1f", $2/1024/1024}' /proc/meminfo)
CPU_COUNT=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)

if [ "$CPU_COUNT" -lt "$CPU_MIN" ]; then
  CPU_FAIL=1
  log_error "CPU count ($CPU_COUNT) < required $CPU_MIN"
else
  log_info "CPU count sufficient ($CPU_COUNT >= $CPU_MIN)"
fi

if awk -v a="$MEM_GIB" -v b="$MEM_MIN" 'BEGIN {exit (a < b)}'; then
  log_info "Memory sufficient (${MEM_GIB} GiB >= ${MEM_MIN} GiB)"
else
  MEM_FAIL=1
  log_error "Memory ${MEM_GIB} GiB < required ${MEM_MIN} GiB"
fi

#-----------------------------
# 7. Storage checks (Enhanced)
#-----------------------------
required_gb=200      # Minimum total storage required
required_percent=50  # Minimum free percentage
STORAGE_OK=0
MATILDA_EXISTS=0
MATILDA_AVAIL="n/a"
FREE_MOUNT="/"
FREE_SPACE_HUMAN="n/a"
ROOT_AVAIL=$(df -h / | awk 'NR==2 {print $4}')

check_fs_space() {
  local mount=$1
  local total_kb free_kb used_pct total_gb free_gb free_percent
  read total_kb free_kb used_pct <<<"$(df -Pk "$mount" | awk 'NR==2 {print $2, $4, $5}' | tr -d '%')"
  total_gb=$(awk -v kb="$total_kb" 'BEGIN {printf "%.1f", kb/1024/1024}')
  free_gb=$(awk -v kb="$free_kb" 'BEGIN {printf "%.1f", kb/1024/1024}')
  free_percent=$(awk -v t="$total_kb" -v f="$free_kb" 'BEGIN {printf "%.1f", (f/t)*100}')
  log_info "Mount $mount -> Total: ${total_gb}GiB, Free: ${free_gb}GiB (${free_percent}%)"

  if (( $(awk -v p="$free_percent" -v r="$required_percent" 'BEGIN {print (p>=r)}') )) && \
     (( $(awk -v t="$total_gb" -v r="$required_gb" 'BEGIN {print (t>=r)}') )); then
    STORAGE_OK=1
    FREE_MOUNT="$mount"
    FREE_SPACE_HUMAN="${free_gb}GiB (${free_percent}%)"
    log_info "$mount meets requirements (${free_percent}% free, ${free_gb}GiB available)"
  fi
}

if mountpoint -q /matilda 2>/dev/null; then
  MATILDA_EXISTS=1
  check_fs_space /matilda
  if [ "$STORAGE_OK" -eq 1 ]; then
    MATILDA_AVAIL="$FREE_SPACE_HUMAN"
  else
    MATILDA_AVAIL=$(df -h /matilda | awk 'NR==2{print $4}')
    log_error "/matilda insufficient space (${MATILDA_AVAIL})"
  fi
fi

if [ "$STORAGE_OK" -eq 0 ]; then
  while read -r mp fstype; do
    case "$fstype" in
      tmpfs|devtmpfs|squashfs|overlay|loop*) continue ;;
    esac
    check_fs_space "$mp"
    [ "$STORAGE_OK" -eq 1 ] && break
  done < <(df -Pk | awk 'NR>1 {print $6, $2}')
fi

if [ "$STORAGE_OK" -eq 0 ]; then
  check_fs_space /
  if [ "$STORAGE_OK" -eq 0 ]; then
    log_error "No filesystem meets space criteria (>=${required_percent}% free and >=${required_gb}GiB total)."
  fi
fi

#-----------------------------
# 8. Selinux checks
#-----------------------------
if is_rhel_family; then
  if command -v getenforce >/dev/null 2>&1; then
    SELINUX_STATUS=$(getenforce 2>/dev/null)
    log_info "SELinux status: $SELINUX_STATUS"
    if [ "$SELINUX_STATUS" = "Enforcing" ]; then
      log_warn "SELinux is Enforcing; ensure proper policies are in place."
    fi
  else
    log_warn "getenforce command not found; cannot check SELinux status."
  fi
fi

#-----------------------------------------------
# Detect Cloud Environment & Public/Private IPs
#-----------------------------------------------
PRIMARY_IP=""
PUBLIC_IP=""
CLOUD_ENV=""

check_metadata() { curl -s --connect-timeout 1 -m 1 "$1" >/dev/null 2>&1; }

if check_metadata http://169.254.169.254/latest/meta-data/; then
  CLOUD_ENV="AWS"
elif check_metadata "http://169.254.169.254/metadata/instance?api-version=2021-02-01"; then
  CLOUD_ENV="AZURE"
elif check_metadata "http://metadata.google.internal/computeMetadata/v1/"; then
  CLOUD_ENV="GCP"
elif check_metadata "http://169.254.169.254/opc/v1/instance/"; then
  CLOUD_ENV="OCI"
else
  CLOUD_ENV="ON_PREM"
fi

log_info "Environment detected: $CLOUD_ENV"

case "$CLOUD_ENV" in
  AWS)
    PUBLIC_IP=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)
    ;;
  AZURE)
    PUBLIC_IP=$(curl -s -H "Metadata:true" --connect-timeout 2 \
      "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text" 2>/dev/null)
    ;;
  GCP)
    PUBLIC_IP=$(curl -s -H "Metadata-Flavor: Google" --connect-timeout 2 \
      "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" 2>/dev/null)
    ;;
  OCI)
    PUBLIC_IP=$(curl -s --connect-timeout 2 http://169.254.169.254/opc/v1/instance/ \
      | grep -oP '"publicIp":"\K[0-9.]+' 2>/dev/null)
    ;;
esac

if ! echo "$PUBLIC_IP" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
  log_warn "Public IP lookup failed or unauthorized; falling back to private IP."
  PUBLIC_IP=""
fi

if [ -z "$PUBLIC_IP" ]; then
  PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || ip route get 1 | awk '{print $7; exit}')
else
  PRIMARY_IP="$PUBLIC_IP"
fi

log_info "Primary IP determined: $PRIMARY_IP"


#-----------------------------
# Results aggregation
#-----------------------------
BLOCKING=()
SUGGEST_FIXES=()

[ "${#MISSING[@]}" -gt 0 ] && BLOCKING+=("Missing:${MISSING[*]}") && \
  SUGGEST_FIXES+=("Install missing commands: ${MISSING[*]}")

[ "$AVX_OK" -eq 0 ] && BLOCKING+=("AVX not supported") && \
  SUGGEST_FIXES+=("Use hardware with AVX instruction support.")

[ "$VAR_NOEXEC" -eq 1 ] && BLOCKING+=("/var noexec") && \
  SUGGEST_FIXES+=("Remove 'noexec' from /var mount options.")

[ "${#URL_FAIL[@]}" -gt 0 ] && BLOCKING+=("URL fail:${URL_FAIL[*]}") && \
  SUGGEST_FIXES+=("Check proxy or connectivity for: ${URL_FAIL[*]}")

[ "$CPU_FAIL" -eq 1 ] && BLOCKING+=("Low CPU") && \
  SUGGEST_FIXES+=("Increase CPUs to at least ${CPU_MIN} logical cores.")

[ "$MEM_FAIL" -eq 1 ] && BLOCKING+=("Low Memory") && \
  SUGGEST_FIXES+=("Add RAM to reach ${MEM_MIN} GiB total.")

[ "$STORAGE_OK" -eq 0 ] && BLOCKING+=("Storage insufficient") && \
  SUGGEST_FIXES+=("Provide >=${required_gb} GiB free on /matilda or another filesystem.")

#-----------------------------
# Summary Table
#-----------------------------
#----------------------------------------------
# Final Summary Table (Enhanced Capacity Format)
#----------------------------------------------
table_line="+----------------------+------------------------------------------------+"
printf "\nSystem Information:\n"
echo "$table_line"
printf "| %-20s | %-46s |\n" "Field" "Value"
echo "$table_line"

# Core system info
printf "| %-20s | %-46s |\n" "FQDN" "$HOSTNAME"
printf "| %-20s | %-46s |\n" "OS" "$OS"
printf "| %-20s | %-46s |\n" "Kernel" "$KERNEL"
printf "| %-20s | %-46s |\n" "CPU Count" "$CPU_COUNT"
printf "| %-20s | %-46s |\n" "Memory (GiB)" "$MEM_GIB"
printf "| %-20s | %-46s |\n" "Primary IP" "$(get_val_or_na "$PRIMARY_IP")"

get_fs_info() {
  local mount=$1
  if mountpoint -q "$mount" 2>/dev/null; then
    df -h "$mount" | awk 'NR==2 {printf "%s total, %s available (%s used)", $2, $4, $5}'
  else
    echo "n/a"
  fi
}

printf "| %-20s | %-46s |\n" "Filesystem /" "$(get_fs_info /)"

if [ "${VAR_IS_SEPARATE:-0}" -eq 1 ]; then
  printf "| %-20s | %-46s |\n" "Filesystem /var" "$(get_fs_info /var)"
fi

if [ "$MATILDA_EXISTS" -eq 1 ]; then
  printf "| %-20s | %-46s |\n" "Filesystem /matilda" "$(get_fs_info /matilda)"
elif [ "$FREE_MOUNT" != "/" ]; then
  printf "| %-20s | %-46s |\n" "Filesystem ${FREE_MOUNT}" "$(get_fs_info "$FREE_MOUNT")"
fi

# SELinux (RHEL-based)
if is_rhel_family; then
  SELINUX_STATUS=$(getenforce 2>/dev/null || echo "Unknown")
  printf "| %-20s | %-46s |\n" "SELinux Status" "$SELINUX_STATUS"
fi

echo "$table_line"

#-----------------------------
# Precheck Function
#-----------------------------
run_precheck() {
  log_info "========================================"
  log_info "Starting System Prechecks"
  log_info "========================================"

  # All the precheck logic above is already executed
  # Just need to evaluate the results here

  if [ "${#BLOCKING[@]}" -eq 0 ]; then
    echo -e "\n${GREEN}${BOLD}OVERALL PRECHECK STATUS: SUCCESS${RESET}"
    log_info "Precheck SUCCESS"
    return 0
  else
    reason=$(printf "%s; " "${BLOCKING[@]}" | sed 's/; $//')
    echo -e "\n${RED}${BOLD}OVERALL PRECHECK STATUS: FAILURE${RESET} - ${YELLOW}${reason}${RESET}\n"
    log_error "Precheck FAILURE: $reason"
    echo -e "${BOLD}${YELLOW}Suggested Fixes:${RESET}"
    for fix in "${SUGGEST_FIXES[@]}"; do
      echo -e "  - ${YELLOW}${fix}${RESET}"
    done
    echo
    return 1
  fi
}

#-----------------------------
# Installation Function
#-----------------------------
run_installation() {
  local token=$1
  local ip_address=$2

  log_info "========================================"
  log_info "Starting Matilda Installation"
  log_info "========================================"

  update_status "INIT" "IN_PROGRESS" "Installation started"

  # Step 1: Validate License
  log_info "Step 1/6: Validating license..."
  update_status "1/6 - License Validation" "IN_PROGRESS" "Validating license token"
  local validation_response=$(validate_license "$token" "$ip_address")

  if [ -z "$validation_response" ]; then
    log_error "License validation failed - no response received"
    update_status "1/6 - License Validation" "FAILED" "License validation API returned no response"
    send_installation_status "unknown" "FAILED" "UNHEALTHY" "License validation API returned no response" "unknown"
    cleanup_status_files
    return 1
  fi

  local validation_status=$(echo "$validation_response" | grep -o '"status"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
  local validation_message=$(echo "$validation_response" | grep -o '"message"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
  local customer_name=$(echo "$validation_response" | grep -o '"customer_name"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)

  log_info "License validation status: $validation_status"
  log_info "License validation message: $validation_message"

  if [ "$validation_status" != "SUCCESS" ]; then
    log_error "License validation failed: $validation_message"
    echo -e "\n${RED}${BOLD}Installation aborted: $validation_message${RESET}\n"
    update_status "1/6 - License Validation" "FAILED" "$validation_message"
    send_installation_status "${customer_name:-unknown}" "FAILED" "UNHEALTHY" "License validation failed: $validation_message" "unknown"
    cleanup_status_files
    return 1
  fi

  echo -e "${GREEN}License validated successfully${RESET}"
  update_status "1/6 - License Validation" "COMPLETED" "License validated successfully"

  # Step 2: Detect OS type
  log_info "Step 2/6: Detecting OS type..."
  update_status "2/6 - OS Detection" "IN_PROGRESS" "Detecting operating system type"
  local os_type=$(detect_os_type)
  log_info "Detected OS type: $os_type"

  if [ "$os_type" = "unknown" ]; then
    log_error "Unable to detect OS type"
    update_status "2/6 - OS Detection" "FAILED" "Unable to detect OS type"
    send_installation_status "$customer_name" "FAILED" "UNHEALTHY" "Unable to detect OS type" "unknown"
    cleanup_status_files
    return 1
  fi

  update_status "2/6 - OS Detection" "COMPLETED" "Detected OS type: $os_type"

  # Step 3: Build Package
  log_info "Step 3/6: Requesting package build..."
  update_status "3/6 - Package Build" "IN_PROGRESS" "Requesting package build from API"
  local build_response=$(build_package "$ip_address" "$token" "$os_type")

  if [ -z "$build_response" ]; then
    log_error "Package build failed - no response received"
    update_status "3/6 - Package Build" "FAILED" "Package build API returned no response"
    send_installation_status "$customer_name" "FAILED" "UNHEALTHY" "Package build API returned no response" "unknown"
    cleanup_status_files
    return 1
  fi

  local package_url=$(echo "$build_response" | grep -o '"download_url"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)

  if [ -z "$package_url" ]; then
    log_error "Package build failed - no download_url in response"
    log_error "Build response: $build_response"
    update_status "3/6 - Package Build" "FAILED" "Package build returned no download URL"
    send_installation_status "$customer_name" "FAILED" "UNHEALTHY" "Package build returned no download URL" "unknown"
    cleanup_status_files
    return 1
  fi

  log_info "Package download_url received: $package_url"
  echo -e "${GREEN}Package build completed${RESET}"
  update_status "3/6 - Package Build" "COMPLETED" "Package build successful, download URL received"

  # Step 4: Download and Install Package
  log_info "Step 4/6: Downloading and installing package..."
  update_status "4/6 - Package Installation" "IN_PROGRESS" "Downloading package from URL"
  local package_name="matilda-installer-package"
  local package_file=""

  if [ "$os_type" = "debian" ]; then
    package_file="/tmp/${package_name}.deb"
    log_info "Downloading Debian package to $package_file"

    if ! curl -L -o "$package_file" "$package_url"; then
      log_error "Failed to download package from $package_url"
      update_status "4/6 - Package Installation" "FAILED" "Failed to download package"
      send_installation_status "$customer_name" "FAILED" "UNHEALTHY" "Failed to download package" "unknown"
      cleanup_status_files
      return 1
    fi

    log_info "Installing Debian package..."
    update_status "4/6 - Package Installation" "IN_PROGRESS" "Installing Debian package"
    if ! sudo dpkg -i "$package_file" 2>&1 | tee -a "$LOGFILE"; then
      log_error "Package installation failed"
      update_status "4/6 - Package Installation" "FAILED" "dpkg installation failed"
      send_installation_status "$customer_name" "FAILED" "UNHEALTHY" "dpkg installation failed" "unknown"
      cleanup_status_files
      return 1
    fi
  else
    package_file="/tmp/${package_name}.rpm"
    log_info "Downloading RPM package to $package_file"

    if ! curl -L -o "$package_file" "$package_url"; then
      log_error "Failed to download package from $package_url"
      update_status "4/6 - Package Installation" "FAILED" "Failed to download package"
      send_installation_status "$customer_name" "FAILED" "UNHEALTHY" "Failed to download package" "unknown"
      cleanup_status_files
      return 1
    fi

    log_info "Installing RPM package..."
    update_status "4/6 - Package Installation" "IN_PROGRESS" "Installing RPM package"
    if ! sudo rpm -i "$package_file" 2>&1 | tee -a "$LOGFILE"; then
      log_error "Package installation failed"
      update_status "4/6 - Package Installation" "FAILED" "rpm installation failed"
      send_installation_status "$customer_name" "FAILED" "UNHEALTHY" "rpm installation failed" "unknown"
      cleanup_status_files
      return 1
    fi
  fi

  echo -e "${GREEN}Package installed successfully${RESET}"
  update_status "4/6 - Package Installation" "COMPLETED" "Package installed successfully"

  # Step 5: Get DockerHub Credentials
  log_info "Step 5/6: Fetching secrets..."
  update_status "5/6 - Fetch Credentials" "IN_PROGRESS" "Fetching DockerHub credentials"
  local dockerhub_response=$(get_dockerhub_credentials "$token" "$ip_address")

  if [ -z "$dockerhub_response" ]; then
    log_error "Failed to fetch secrets"
    update_status "5/6 - Fetch Credentials" "FAILED" "Failed to fetch secrets"
    send_installation_status "$customer_name" "FAILED" "UNHEALTHY" "Failed to fetch secrets" "unknown"
    cleanup_status_files
    return 1
  fi

  local dockerhub_username=$(echo "$dockerhub_response" | grep -o '"dockerhub_username"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
  local dockerhub_password=$(echo "$dockerhub_response" | grep -o '"dockerhub_password"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)

  if [ -z "$dockerhub_username" ] || [ -z "$dockerhub_password" ]; then
    log_error "DockerHub credentials incomplete"
    update_status "5/6 - Fetch Credentials" "FAILED" "Secrets incomplete"
    send_installation_status "$customer_name" "FAILED" "UNHEALTHY" "Secrets incomplete" "unknown"
    cleanup_status_files
    return 1
  fi

  log_info "DockerHub credentials received successfully"
  echo -e "${GREEN}DockerHub credentials fetched${RESET}"
  update_status "5/6 - Fetch Credentials" "COMPLETED" "DockerHub credentials fetched successfully"

  # Step 6: Run matilda-installer
  log_info "Step 6/6: Running matilda-installer..."
  update_status "6/6 - Run Installer" "IN_PROGRESS" "Running matilda-installer with Docker credentials"
  echo -e "${YELLOW}Running matilda-installer with Secrets...${RESET}"

  if ! sudo matilda-installer \
    --docker-username "$dockerhub_username" \
    --docker-password "$dockerhub_password" \
    -y 2>&1 | tee -a "$LOGFILE"; then
    log_error "matilda-installer failed"
    update_status "6/6 - Run Installer" "FAILED" "matilda-installer execution failed"
    send_installation_status "$customer_name" "FAILED" "UNHEALTHY" "matilda-installer execution failed" "unknown"
    cleanup_status_files
    return 1
  fi

  echo -e "${GREEN}Matilda installation completed successfully${RESET}"
  update_status "6/6 - Run Installer" "COMPLETED" "matilda-installer completed successfully"

  # Get installation version (try to detect from installed package)
  local installation_version="1.0.0"
  if command -v matilda-installer >/dev/null 2>&1; then
    installation_version=$(matilda-installer --version 2>/dev/null || echo "1.0.0")
  fi

  # Step 7: Send Installation Status
  log_info "Sending installation success status..."
  update_status "COMPLETED" "SUCCESS" "Installation completed successfully - Version: $installation_version"
  send_installation_status "$customer_name" "SUCCESS" "HEALTHY" "Installation completed successfully" "$installation_version"

  echo -e "\n${GREEN}${BOLD}========================================"
  echo -e "INSTALLATION COMPLETED SUCCESSFULLY"
  echo -e "========================================${RESET}\n"

  cleanup_status_files
  return 0
}

#-----------------------------
# Main Execution Flow
#-----------------------------
main() {
  # Parse command line arguments
  parse_arguments "$@"

  log_info "========================================"
  log_info "Matilda Installer Script Started"
  log_info "Base URL: $BASE_URL"
  log_info "========================================"

  # Run prechecks (this executes all the precheck code above)
  if ! run_precheck; then
    log_error "Prechecks failed. Please fix the issues and try again."
    exit 1
  fi

  # If no license token provided, exit after prechecks
  if [ -z "$LICENSE_TOKEN" ]; then
    log_info "No license token provided. Precheck completed. Use '$0 <token>' to proceed with installation."
    echo -e "\n${YELLOW}To proceed with installation, run:${RESET}"
    echo -e "  $0 <license-token>"
    echo -e "  $0 <license-token> -y              ${YELLOW}(to auto-confirm)${RESET}"
    echo -e "  $0 <license-token> -y -b           ${YELLOW}(to run in background)${RESET}"
    echo -e "  $0 status                          ${YELLOW}(to check installation status)${RESET}\n"
    exit 0
  fi

  # License token provided, ask for confirmation unless -y flag is set
  if [ "$AUTO_CONFIRM" -eq 0 ] && [ "$RUN_IN_BACKGROUND" -eq 0 ]; then
    echo -e "\n${YELLOW}${BOLD}Prechecks passed. Ready to proceed with installation.${RESET}"
    echo -e "${YELLOW}License Token: ${LICENSE_TOKEN:0:10}...${RESET}"
    echo -e "${YELLOW}Primary IP: $PRIMARY_IP${RESET}"
    read -p "Do you want to proceed with installation? (yes/no): " confirm

    case "$confirm" in
      yes|YES|y|Y)
        log_info "User confirmed installation"
        ;;
      *)
        log_info "Installation cancelled by user"
        echo -e "${YELLOW}Installation cancelled.${RESET}"
        exit 0
        ;;
    esac
  else
    log_info "Auto-confirm enabled, proceeding with installation"
    echo -e "${YELLOW}Auto-confirm enabled. Proceeding with installation...${RESET}"
  fi

  # Check if running in background mode
  if [ "$RUN_IN_BACKGROUND" -eq 1 ]; then
    log_info "Starting installation in background mode"
    echo -e "\n${GREEN}${BOLD}Starting installation in background...${RESET}"

    # Store PID and run in background
    nohup bash -c "
      echo \$\$ > '$PID_FILE'
      $(declare -f run_installation)
      $(declare -f validate_license)
      $(declare -f build_package)
      $(declare -f get_dockerhub_credentials)
      $(declare -f send_installation_status)
      $(declare -f detect_os_type)
      $(declare -f update_status)
      $(declare -f cleanup_status_files)
      $(declare -f log)
      $(declare -f log_info)
      $(declare -f log_error)

      BASE_URL='$BASE_URL'
      LOGFILE='$LOGFILE'
      STATUS_FILE='$STATUS_FILE'
      PID_FILE='$PID_FILE'
      GREEN='$GREEN'
      RED='$RED'
      YELLOW='$YELLOW'
      BOLD='$BOLD'
      RESET='$RESET'

      run_installation '$LICENSE_TOKEN' '$PRIMARY_IP'
    " >> "$LOGFILE" 2>&1 &

    local bg_pid=$!
    echo "$bg_pid" > "$PID_FILE"

    echo -e "${GREEN}Installation started in background (PID: $bg_pid)${RESET}"
    echo -e "${YELLOW}Log file: $LOGFILE${RESET}"
    echo -e "${YELLOW}Status file: $STATUS_FILE${RESET}\n"
    echo -e "To monitor progress, run:"
    echo -e "  ${GREEN}$0 status${RESET}           - View current status"
    echo -e "  ${GREEN}tail -f $LOGFILE${RESET}    - View live logs\n"

    exit 0
  else
    # Run installation in foreground
    if ! run_installation "$LICENSE_TOKEN" "$PRIMARY_IP"; then
      log_error "Installation failed"
      exit 1
    fi
  fi

  exit 0
}

# Execute main function
main "$@"

