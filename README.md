# Matilda Installer Script

A comprehensive system pre-check and installation script for deploying Matilda with support for background execution, live status tracking, and automated installation workflows.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Status Tracking](#status-tracking)
- [Troubleshooting](#troubleshooting)
- [API Endpoints](#api-endpoints)
- [Files and Locations](#files-and-locations)

## Overview

The Matilda Installer Script (`matilda_precheck.sh`) performs comprehensive system validation checks and automates the complete installation process of Matilda. It validates system requirements, manages license verification, handles package installation, and configures Docker credentials.

## Features

### System Pre-checks
- ✅ CPU, Memory, and Storage validation
- ✅ AVX instruction set support verification
- ✅ Network connectivity checks (Docker registries, package repositories)
- ✅ Operating system detection (Debian/RHEL families)
- ✅ SELinux status validation
- ✅ Cloud environment detection (AWS, Azure, GCP, OCI, On-Prem)
- ✅ Required command availability (openssl, git, curl, nc)

### Installation Capabilities
- 🚀 Automated license validation
- 🚀 Dynamic package building and installation
- 🚀 DockerHub credential management
- 🚀 Background execution support
- 🚀 Live installation status tracking
- 🚀 Session disconnect resilience
- 🚀 Comprehensive logging

### Execution Modes
- **Precheck Only**: Validate system without installation
- **Interactive Installation**: Prompt user for confirmation
- **Automated Installation**: Skip confirmation with `-y` flag
- **Background Installation**: Run installation as background process with `-b` flag

## Prerequisites

### System Requirements
- **CPU**: Minimum 12 logical cores
- **Memory**: Minimum 23.5 GiB RAM
- **Storage**: Minimum 200 GiB total with 50% free space
- **Architecture**: x86_64 with AVX support
- **OS**: Debian-based (Ubuntu, Debian) or RHEL-based (CentOS, Rocky, AlmaLinux, RHEL)

### Required Commands
- `openssl`
- `git`
- `curl`
- `nc` (netcat)
- `sudo` (for package installation)

### Network Connectivity
The following URLs must be accessible:
- https://auth.docker.io
- https://hub.docker.com
- https://production.cloudflare.docker.com/
- https://registry-1.docker.io/
- https://dl.fedoraproject.org/

## Installation

### Option 1: Using Source Script (Readable)

1. Download the script:
```bash
curl -O https://your-domain.com/matilda_precheck.sh
chmod +x matilda_precheck.sh
```

2. Verify the script is executable:
```bash
ls -l matilda_precheck.sh
```

### Option 2: Using Binary/Encrypted Version (Non-Readable)

For production environments where you want to protect the source code, you can create a non-readable binary or encrypted version:

#### Method A: Compiled Binary (Most Secure)

1. Install and run the compilation script:
```bash
# Download compilation script
curl -O https://your-domain.com/build_binary.sh
chmod +x build_binary.sh

# Compile to binary (requires shc)
./build_binary.sh

# This creates: matilda_installer (binary executable)
```

The compiled binary:
- Cannot be read or decompiled to source code
- Executes directly without exposing script content
- Requires `shc` (Shell Script Compiler) to be installed
- Architecture-specific (compile on target system)

#### Method B: Encrypted Self-Extracting (More Portable)

1. Create encrypted version:
```bash
# Download encryption script
curl -O https://your-domain.com/build_encrypted.sh
chmod +x build_encrypted.sh

# Create encrypted installer
./build_encrypted.sh

# This creates: matilda_installer_encrypted (obfuscated executable)
```

The encrypted version:
- Source code is compressed and base64 encoded
- Extracts to temporary directory at runtime
- Works on any Linux system with bash, gzip, base64
- More portable than compiled binary
- Less secure than shc binary but harder to read than plain script

## Usage

### Basic Usage

#### 1. Run Pre-checks Only
```bash
./matilda_precheck.sh
```
**Output**: System validation report with pass/fail status and suggested fixes.

#### 2. Interactive Installation
```bash
./matilda_precheck.sh <license-token>
```
**Flow**:
1. Runs system pre-checks
2. Prompts for user confirmation
3. Proceeds with installation if confirmed

#### 3. Automated Installation (No Prompts)
```bash
./matilda_precheck.sh <license-token> -y
```
**Flow**:
1. Runs system pre-checks
2. Automatically proceeds with installation
3. Runs in foreground (terminal must stay connected)

#### 4. Background Installation
```bash
./matilda_precheck.sh <license-token> -y -b
```
**Flow**:
1. Runs system pre-checks
2. Starts installation in background
3. Returns immediately with PID
4. Installation continues even if terminal disconnects

### Advanced Usage

#### Check Installation Status
```bash
./matilda_precheck.sh status
# or
./matilda_precheck.sh --status
```

#### View Live Logs
```bash
tail -f /var/log/matilda_installer.log
```

#### Custom Base URL
```bash
BASE_URL=https://api.production.com ./matilda_precheck.sh <license-token> -y -b
```

### Command-Line Flags

| Flag | Description |
|------|-------------|
| `-y` | Auto-confirm installation without prompting |
| `-b` or `--background` | Run installation in background |
| `status` or `--status` | Check current installation status |

### Usage Examples

```bash
# Example 1: Quick pre-check
./matilda_precheck.sh

# Example 2: Standard installation with confirmation
./matilda_precheck.sh abc123xyz456token

# Example 3: Automated installation
./matilda_precheck.sh abc123xyz456token -y

# Example 4: Background installation (recommended for remote sessions)
./matilda_precheck.sh abc123xyz456token -y -b

# Example 5: Check status of background installation
./matilda_precheck.sh status

# Example 6: Production environment with custom API
BASE_URL=https://api.matilda.prod.com ./matilda_precheck.sh <token> -y -b
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_URL` | `http://localhost:8000` | API base URL for license validation and package builds |

### Configuration Files

**Status File**: `/var/tmp/matilda_install_status.txt`
- JSON format
- Contains current step, status, message, timestamp, and PID

**PID File**: `/var/tmp/matilda_install.pid`
- Contains background process ID
- Used to track running installations

**Log File**: `/var/log/matilda_installer.log`
- Comprehensive installation logs
- Falls back to `./matilda_installer.log` if `/var/log` is not writable

## Status Tracking

### Installation Steps

The installation process is divided into 6 tracked steps:

| Step | Description | Duration |
|------|-------------|----------|
| 1/6 | License Validation | ~5 seconds |
| 2/6 | OS Detection | ~1 second |
| 3/6 | Package Build | ~30-60 seconds |
| 4/6 | Package Installation | ~30-120 seconds |
| 5/6 | Fetch Docker Credentials | ~5 seconds |
| 6/6 | Run Matilda Installer | ~5-15 minutes |

### Status Values

- `IN_PROGRESS`: Step is currently executing
- `COMPLETED`: Step finished successfully
- `FAILED`: Step encountered an error

### Viewing Status

When you run `./matilda_precheck.sh status`, you'll see:

```
=== Matilda Installation Status ===

Installation Process: RUNNING (PID: 12345)
Timestamp: 2025-10-21T18:45:32Z
Step: 4/6 - Package Installation
Status: IN_PROGRESS
Message: Installing Debian package

Log file: /var/log/matilda_installer.log

To view live logs, run:
  tail -f /var/log/matilda_installer.log
```

## Troubleshooting

### Pre-check Failures

#### Low CPU Count
```
Error: CPU count (8) < required 12
Fix: Increase CPUs to at least 12 logical cores
```

#### Insufficient Memory
```
Error: Memory 16.0 GiB < required 23.5 GiB
Fix: Add RAM to reach 23.5 GiB total
```

#### Missing AVX Support
```
Error: AVX not supported
Fix: Use hardware with AVX instruction support
```

#### URL Connectivity Issues
```
Error: Cannot reach https://hub.docker.com
Fix: Check proxy or connectivity settings
```

#### Storage Insufficient
```
Error: Storage insufficient
Fix: Provide >=200 GiB free on /matilda or another filesystem
```

### Installation Failures

#### License Validation Failed
```
Error: License validation failed: Invalid token
Solution: Verify your license token is correct and not expired
```

#### Package Download Failed
```
Error: Failed to download package
Solution: Check network connectivity and firewall rules
```

#### Docker Credentials Invalid
```
Error: Matilda Credentials are invalid
Solution: Contact Matilda support team to verify DockerHub credentials
```

### Common Issues

#### Installation Stuck
```bash
# Check if process is still running
./matilda_precheck.sh status

# View live logs
tail -f /var/log/matilda_installer.log

# Check process
ps aux | grep matilda
```

#### Background Process Not Found
```bash
# Check PID file
cat /var/tmp/matilda_install.pid

# Check if process exists
kill -0 $(cat /var/tmp/matilda_install.pid)
```

#### Permission Denied
```bash
# Ensure script is executable
chmod +x matilda_precheck.sh

# Ensure sudo access for package installation
sudo -v
```

## API Endpoints

The script interacts with the following API endpoints:

### 1. License Validation
**Endpoint**: `POST /api/v1/licenses/validate`

**Request**:
```json
{
  "token": "string",
  "ip_address": "string"
}
```

**Response**:
```json
{
  "status": "SUCCESS",
  "message": "string",
  "customer_name": "string"
}
```

### 2. Package Build
**Endpoint**: `POST /api/v1/packages/build`

**Request**:
```json
{
  "ip_address": "string",
  "license_key": "string",
  "os_type": "debian"
}
```

**Response**:
```json
{
  "download_url": "https://..."
}
```

### 3. DockerHub Credentials
**Endpoint**: `POST /api/v1/dockerhub/credentials`

**Request**:
```json
{
  "license_key": "string",
  "ip_address": "string"
}
```

**Response**:
```json
{
  "status": "string",
  "message": "string",
  "customer_name": "string",
  "dockerhub_username": "string",
  "dockerhub_password": "string",
  "registry_url": "string"
}
```

### 4. Installation Status Report
**Endpoint**: `POST /api/v1/installation/status`

**Request**:
```json
{
  "customer_name": "string",
  "installation_status": "SUCCESS",
  "installation_health": "HEALTHY",
  "installation_message": "string",
  "installation_version": "string"
}
```

## Creating Non-Readable Executables

For production deployments where you want to protect the source code from being read or modified, you can create non-readable executable versions.

### Comparison of Methods

| Feature | Source Script | Compiled Binary | Encrypted Self-Extracting |
|---------|--------------|-----------------|---------------------------|
| **Readable** | Yes | No | No (obfuscated) |
| **Modifiable** | Yes | No | No |
| **Portability** | High | Low (arch-specific) | High |
| **Security** | Low | High | Medium |
| **Requirements** | bash | shc compiler | bash, gzip, base64 |
| **Size** | Small | Medium | Larger |
| **Speed** | Fast | Fast | Slightly slower (extraction) |

### Method 1: Compiled Binary (Recommended for Production)

**Advantages:**
- True binary executable
- Impossible to read or reverse engineer source code
- Best security protection
- Same execution speed as source script

**Disadvantages:**
- Architecture-specific (must compile on target platform)
- Requires `shc` to be installed
- Cannot easily distribute across different architectures

**How to Create:**
```bash
# Run the compilation script
./build_binary.sh

# Output: matilda_installer (binary executable)
```

**What it does:**
1. Checks for `shc` (Shell Script Compiler) and installs if needed
2. Compiles `matilda_precheck.sh` to native binary
3. Creates `matilda_installer` executable
4. Sets proper permissions
5. Verifies the binary works

**Manual Compilation:**
```bash
# Install shc
sudo apt-get install shc  # Debian/Ubuntu
sudo yum install shc      # RHEL/CentOS

# Compile
shc -f matilda_precheck.sh -o matilda_installer -r -U

# Make executable
chmod +x matilda_installer
```

### Method 2: Encrypted Self-Extracting

**Advantages:**
- Works on any Linux system
- Portable across architectures
- No special tools required for execution
- Source code obfuscated

**Disadvantages:**
- Slightly larger file size
- Small extraction overhead at runtime
- Less secure than compiled binary (can be decoded if someone knows the method)

**How to Create:**
```bash
# Run the encryption script
./build_encrypted.sh

# Output: matilda_installer_encrypted (self-extracting executable)
```

**What it does:**
1. Compresses source script with gzip
2. Encodes compressed data with base64
3. Wraps in self-extracting shell wrapper
4. Creates standalone executable
5. Cleans up at runtime automatically

**How it Works:**
- Script is gzipped and base64 encoded
- Wrapper extracts to temporary directory at execution time
- Executes extracted script with all provided arguments
- Automatically cleans up temporary files on exit

### Using Non-Readable Executables

Once created, use them exactly like the original script:

```bash
# Using compiled binary
./matilda_installer                    # Prechecks only
./matilda_installer <token>            # Interactive install
./matilda_installer <token> -y         # Auto-confirm install
./matilda_installer <token> -y -b      # Background install
./matilda_installer status             # Check status

# Using encrypted version
./matilda_installer_encrypted <token> -y -b
```

### Distribution Recommendations

**For Single Architecture (e.g., all Ubuntu 20.04 x86_64):**
- Use **compiled binary** (Method 1)
- Maximum security, no readable source code

**For Multiple Architectures/Distributions:**
- Use **encrypted self-extracting** (Method 2)
- Works everywhere, good obfuscation

**For Development/Testing:**
- Use **source script**
- Easy to modify and debug

### Security Notes

⚠️ **Important Security Considerations:**

1. **Compiled Binary**: Cannot be easily reverse-engineered, but determined attackers with binary analysis tools might extract some information
2. **Encrypted Version**: Can be decoded if attacker knows it's base64+gzip, but requires effort
3. **Neither method** protects against runtime analysis (memory dumps, strace, etc.)
4. **Best Practice**: Use binaries to prevent casual inspection and unauthorized modifications
5. **Credentials**: Neither method exposes credentials since they're fetched at runtime from APIs

## Files and Locations

### Script Files
- **Main Script**: `matilda_precheck.sh` (source, readable)
- **Binary Builder**: `build_binary.sh`
- **Encrypted Builder**: `build_encrypted.sh`
- **Compiled Binary**: `matilda_installer` (generated, non-readable)
- **Encrypted Installer**: `matilda_installer_encrypted` (generated, obfuscated)
- **README**: `README.md`

### Runtime Files
- **Log File**: `/var/log/matilda_installer.log` (or `./matilda_installer.log`)
- **Status File**: `/var/tmp/matilda_install_status.txt`
- **PID File**: `/var/tmp/matilda_install.pid`

### Temporary Files
- **Downloaded Packages**: `/tmp/matilda-installer-package.deb` or `/tmp/matilda-installer-package.rpm`

### Installation Directories
- **Matilda Mount**: `/matilda` (optional, checked during pre-validation)

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Pre-check failure or installation error |
| 2 | Cannot write log file |

## Security Considerations

- **Credentials**: DockerHub credentials are never logged or printed to console
- **License Tokens**: Only first 10 characters displayed in logs
- **API Communication**: All API calls use HTTPS in production
- **Sudo Access**: Required for package installation only

## Support

For issues or questions:
1. Check the log file: `/var/log/matilda_installer.log`
2. Review the status: `./matilda_precheck.sh status`
3. Contact Matilda support with:
   - Log file contents
   - System information (OS, CPU, Memory)
   - Error messages

## License

Copyright © 2025 Matilda. All rights reserved.

---

**Version**: 1.0.0
**Last Updated**: October 2025
**Maintained By**: Matilda Team
