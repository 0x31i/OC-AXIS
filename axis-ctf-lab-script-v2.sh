#!/bin/bash
# AXIS Camera Vulnerable IoT Lab Configuration Script v2.0
# Lord of the Rings CTF Flag System for IoT Penetration Testing Training
# Target: AXIS M1065-LW Network Camera at 192.168.1.132
# WARNING: FOR ISOLATED LAB ENVIRONMENT ONLY - NEVER USE IN PRODUCTION
# This script intentionally creates security vulnerabilities for educational purposes

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
CAMERA_IP="192.168.1.132"
CAMERA_MODEL="AXIS M1065-LW"
LAB_PASSWORD="AxisRoot@2024!"
FLAG_COUNTER=1
declare -a FLAG_LIST
HOSTNAME=$(hostname)

# Lord of the Rings characters for deterministic flags
LOTR_CHARACTERS=(
    "FRODO" "GANDALF" "ARAGORN" "LEGOLAS" "GIMLI"
    "BOROMIR" "SAMWISE" "MERRY" "PIPPIN" "GALADRIEL"
    "ELROND" "ARWEN" "EOWYN" "FARAMIR" "THEODEN"
    "EOMER" "TREEBEARD" "SARUMAN" "GOLLUM" "BILBO"
    "SAURON" "BALROG" "SHELOB" "NAZGUL" "WORMTONGUE"
    "DENETHOR" "GRIMA" "RADAGAST" "THRANDUIL" "BARD"
)

echo -e "${RED}==========================================${NC}"
echo -e "${RED}VULNERABLE IoT CAMERA CONFIGURATION v2.0${NC}"
echo -e "${RED}AXIS CAMERA CTF LAB - LOTR FLAGS${NC}"
echo -e "${RED}FOR EDUCATIONAL PURPOSES ONLY${NC}"
echo -e "${RED}NEVER USE IN PRODUCTION ENVIRONMENTS${NC}"
echo -e "${RED}==========================================${NC}"
echo ""
read -p "Type 'VULNERABLE' to confirm this is for an isolated lab: " confirm
if [ "$confirm" != "VULNERABLE" ]; then
    echo "Confirmation failed. Exiting."
    exit 1
fi

# Function to generate deterministic flag
generate_flag() {
    local location="$1"
    local description="$2"
    local points="$3"
    local difficulty="$4"
    local owasp_mapping="$5"
    
    # Use deterministic selection based on counter
    local char_index=$((FLAG_COUNTER % ${#LOTR_CHARACTERS[@]}))
    local character="${LOTR_CHARACTERS[$char_index]}"
    
    # Generate deterministic 8-digit number using hash
    local seed="AXIS${FLAG_COUNTER}${CAMERA_IP}${HOSTNAME}"
    local hash_value=$(echo -n "$seed" | md5sum | cut -c1-8)
    local digits=$(printf "%08d" $((0x$hash_value % 100000000)))
    
    local flag="FLAG{${character}${digits}}"
    
    # Add to tracking list
    FLAG_LIST+=("${FLAG_COUNTER}|${flag}|${location}|${description}|${points}|${difficulty}|${owasp_mapping}")
    
    FLAG_COUNTER=$((FLAG_COUNTER + 1))
    echo "$flag"
}

# Function to log actions
log_action() {
    echo -e "${GREEN}[✓]${NC} $1"
}

# Function to log errors
log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Function to log warnings
log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# ==========================================
# OWASP IoT-01: Weak, Guessable, or Hardcoded Passwords
# ==========================================
configure_weak_passwords() {
    echo -e "\n${CYAN}Configuring OWASP IoT-01: Weak Passwords...${NC}"
    
    # Create user with predictable password
    local flag1=$(generate_flag "User Account" "User 'user' with simple password" 10 "Easy" "IoT-01")
    
    # Add users with slightly more complex passwords
    adduser -D -s /bin/sh user 2>/dev/null || true
    echo "user:password12345" | chpasswd 2>/dev/null || true
    echo "# Flag: $flag1" >> /home/user/.profile
    
    adduser -D -s /bin/sh testuser 2>/dev/null || true
    echo "testuser:TestAccount2024!" | chpasswd 2>/dev/null || true
    
    adduser -D -s /bin/sh camera-admin 2>/dev/null || true
    echo "camera-admin:CamAdmin#2024" | chpasswd 2>/dev/null || true
    
    adduser -D -s /bin/sh iot-device 2>/dev/null || true
    echo "iot-device:IoT_Device$2025" | chpasswd 2>/dev/null || true
    
    adduser -D -s /bin/sh service-account 2>/dev/null || true
    echo "service-account:Svc@Account2024" | chpasswd 2>/dev/null || true
    
    # Create hardcoded credentials file
    local flag2=$(generate_flag "Hardcoded Credentials" "Default credentials in config file" 10 "Easy" "IoT-01")
    mkdir -p /var/camera-config
    cat > /var/camera-config/credentials.txt << EOF
# Default Camera Credentials
username=admin
password=AdminPass@123
api_key=AXIS-DEFAULT-KEY-2024
backup_user=operator
backup_pass=Operator#2024
flag=$flag2
EOF
    chmod 644 /var/camera-config/credentials.txt
    
    log_action "Weak passwords configured (2 flags)"
}

# ==========================================
# OWASP IoT-02: Insecure Network Services - RTSP Buffer Overflow
# ==========================================
configure_rtsp_buffer_overflow() {
    echo -e "\n${CYAN}Configuring OWASP IoT-02: RTSP Buffer Overflow Vulnerability...${NC}"
    
    # Create vulnerable RTSP service handler with buffer overflow
    local flag3=$(generate_flag "RTSP Buffer Overflow" "Stack-based buffer overflow in RTSP handler" 40 "Hard" "IoT-02")
    
    mkdir -p /usr/local/bin/rtsp_handler
    
    # Create vulnerable RTSP handler script
    cat > /usr/local/bin/rtsp_handler/rtsp_vuln.c << 'EOF'
// Vulnerable RTSP Handler - Buffer Overflow Example
// DO NOT USE IN PRODUCTION - EDUCATIONAL ONLY
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 256

void process_rtsp_request(char *request) {
    char buffer[BUFFER_SIZE];  // Fixed size buffer
    
    // VULNERABLE: No bounds checking on strcpy
    strcpy(buffer, request);   // Buffer overflow here!
    
    printf("Processing RTSP request: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        process_rtsp_request(argv[1]);
    }
    return 0;
}
EOF
    
    # Create exploit documentation
    cat > /usr/local/bin/rtsp_handler/exploit_notes.txt << EOF
RTSP Buffer Overflow Vulnerability
===================================
Vulnerability: Stack-based buffer overflow
Location: RTSP request handler
Buffer Size: 256 bytes
Overflow Offset: 260 bytes

Exploitation Steps:
1. Connect to RTSP service on port 554
2. Send DESCRIBE request with oversized URI
3. Overflow occurs at byte 260
4. Control EIP at offset 264
5. ROP chain possible due to no DEP

Example Payload:
DESCRIBE rtsp://$CAMERA_IP/[A*260][EIP][SHELLCODE] RTSP/1.0

Flag: $flag3

Additional Info:
- No stack canaries present
- ASLR disabled on embedded system
- Return address overwrite possible
EOF
    
    # Create simulated crash dump
    local flag4=$(generate_flag "RTSP Crash Dump" "Memory dump from RTSP crash" 35 "Hard" "IoT-02")
    mkdir -p /var/crash
    cat > /var/crash/rtsp_crash.dump << EOF
RTSP Service Crash Dump
========================
Time: $(date)
Signal: SIGSEGV (Segmentation fault)
Process: rtsp_handler (PID: 1337)

Registers:
EIP: 0x41414141 (AAAA - controlled)
ESP: 0xbffff4c0
EBP: 0x42424242 (BBBB - controlled)

Stack Trace:
0xbffff4c0: 0x43434343 0x44444444 0x45454545
0xbffff4cc: 0x90909090 0x90909090 0x31c03190
0xbffff4d8: 0xdb31c931 0x68b0d231 0x6873732f

Memory at crash:
00000000: 4445 5343 5249 4245 2072 7473 703a 2f2f  DESCRIBE rtsp://
00000010: 3139 322e 3136 382e 312e 3133 322f 4141  192.168.1.132/AA
00000020: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
[... truncated ...]

Exploitable: YES
Flag: $flag4
EOF
    chmod 644 /var/crash/rtsp_crash.dump
    
    # Create RTSP fuzzing results
    local flag5=$(generate_flag "RTSP Fuzzer Results" "Fuzzing discovered multiple crashes" 30 "Hard" "IoT-02")
    cat > /var/crash/fuzzer_results.txt << EOF
RTSP Fuzzer Results
===================
Target: RTSP Service on port 554
Fuzzer: Custom RTSP Protocol Fuzzer
Duration: 2 hours
Crashes Found: 17

Interesting Crashes:
--------------------
1. DESCRIBE overflow at 260 bytes - EXPLOITABLE
2. SETUP integer overflow in Content-Length - EXPLOITABLE  
3. PLAY format string in User-Agent - EXPLOITABLE
4. OPTIONS null pointer dereference - DOS only
5. TEARDOWN use-after-free condition - EXPLOITABLE

Most Reliable Exploit:
DESCRIBE buffer overflow provides consistent EIP control
No modern protections (DEP/ASLR/Canaries) present

Flag: $flag5
EOF
    
    log_action "RTSP buffer overflow vulnerability configured (3 flags)"
}

# ==========================================
# OWASP IoT-02: Insecure Network Services - Additional Services
# ==========================================
configure_insecure_network_services() {
    echo -e "\n${CYAN}Configuring OWASP IoT-02: Additional Network Services...${NC}"
    
    # Enable vulnerable FTP (keeping this as it's different from telnet)
    local flag6=$(generate_flag "FTP Service" "Anonymous FTP access enabled" 15 "Easy" "IoT-02")
    
    # Simple FTP server using busybox
    mkdir -p /var/ftp
    echo "$flag6" > /var/ftp/flag.txt
    /usr/sbin/tcpsvd -vE 0.0.0.0 21 ftpd -w / &
    
    # Create vulnerable NTP service
    local flag7=$(generate_flag "NTP Service" "NTP amplification vulnerability" 25 "Medium" "IoT-02")
    mkdir -p /etc/ntp
    cat > /etc/ntp/ntp.conf << EOF
# Vulnerable NTP Configuration
# Mode 7 queries enabled (CVE-2013-5211)
enable mode7
enable monitor
restrict default nomodify notrap nopeer noquery
restrict 127.0.0.1
# Monlist enabled - allows amplification attacks
# Flag: $flag7
EOF
    
    # Create UPnP vulnerability
    local flag8=$(generate_flag "UPnP Service" "Exposed UPnP service" 25 "Medium" "IoT-02")
    mkdir -p /var/upnp
    cat > /var/upnp/device.xml << EOF
<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<device>
<deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
<friendlyName>AXIS Camera</friendlyName>
<manufacturer>AXIS Communications</manufacturer>
<modelName>M1065-LW</modelName>
<serialNumber>ACCC8E123456</serialNumber>
<UDN>uuid:12345678-1234-1234-1234-$flag8</UDN>
<serviceList>
  <service>
    <serviceType>urn:schemas-upnp-org:service:AVTransport:1</serviceType>
    <serviceId>urn:upnp-org:serviceId:AVTransport</serviceId>
    <controlURL>/upnp/control/AVTransport</controlURL>
    <eventSubURL>/upnp/event/AVTransport</eventSubURL>
    <SCPDURL>/upnp/scpd/AVTransport.xml</SCPDURL>
  </service>
</serviceList>
</device>
</root>
EOF
    
    log_action "Additional insecure network services configured (3 flags)"
}

# ==========================================
# OWASP IoT-03: Insecure Ecosystem Interfaces
# ==========================================
configure_insecure_interfaces() {
    echo -e "\n${CYAN}Configuring OWASP IoT-03: Insecure Ecosystem Interfaces...${NC}"
    
    # Create vulnerable web interface
    local flag9=$(generate_flag "Web Interface" "Hidden flag in HTML comment" 10 "Easy" "IoT-03")
    
    mkdir -p /var/www/html
    cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head><title>AXIS Camera Interface</title></head>
<body>
<h1>AXIS M1065-LW Camera</h1>
<!-- Admin Panel: /admin.php -->
<!-- Debug Mode: enabled -->
<!-- API Endpoint: /axis-cgi/param.cgi -->
<!-- $flag9 -->
<form action="/login" method="GET">
Username: <input type="text" name="user"><br>
Password: <input type="password" name="pass"><br>
<input type="submit" value="Login">
</form>
</body>
</html>
EOF
    
    # Create hidden admin panel
    local flag10=$(generate_flag "Admin Panel" "Unprotected admin interface" 20 "Medium" "IoT-03")
    cat > /var/www/html/admin.php << EOF
<?php
// Vulnerable admin panel
// Flag: $flag10
// Default login: admin/AdminPass@123
// SQL Injection possible: admin' OR '1'='1
?>
<h1>Camera Administration</h1>
<a href="/stream">Live Stream</a>
<a href="/config">Configuration</a>
<a href="/logs">System Logs</a>
EOF
    
    # VAPIX API vulnerability
    local flag11=$(generate_flag "VAPIX API" "Exposed VAPIX API endpoint" 25 "Medium" "IoT-03")
    mkdir -p /var/www/axis-cgi
    cat > /var/www/axis-cgi/param.cgi << EOF
#!/bin/sh
# Vulnerable VAPIX parameter handler
# Command injection: param.cgi?action=set&Network.NTP.Server=\$(whoami)
# Flag: $flag11
echo "Content-Type: text/plain"
echo ""
echo "VAPIX API v1.0"
EOF
    chmod 755 /var/www/axis-cgi/param.cgi
    
    # Create GraphQL endpoint with introspection enabled
    local flag12=$(generate_flag "GraphQL API" "GraphQL introspection enabled" 30 "Hard" "IoT-03")
    mkdir -p /var/www/graphql
    cat > /var/www/graphql/schema.json << EOF
{
  "__schema": {
    "types": [
      {
        "name": "Camera",
        "fields": [
          {"name": "id", "type": "ID"},
          {"name": "stream_url", "type": "String"},
          {"name": "admin_token", "type": "String", "value": "$flag12"},
          {"name": "firmware_version", "type": "String"}
        ]
      }
    ]
  }
}
EOF
    
    log_action "Insecure interfaces configured (4 flags)"
}

# ==========================================
# OWASP IoT-04: Lack of Secure Update Mechanism
# ==========================================
configure_insecure_update() {
    echo -e "\n${CYAN}Configuring OWASP IoT-04: Insecure Update Mechanism...${NC}"
    
    # Create fake firmware update directory
    local flag13=$(generate_flag "Firmware Update" "Insecure firmware update mechanism" 30 "Hard" "IoT-04")
    
    mkdir -p /var/firmware
    cat > /var/firmware/update.sh << EOF
#!/bin/sh
# Insecure firmware update script
# No signature verification!
# Accepts unsigned firmware from any source
# Flag: $flag13

if [ -f /tmp/firmware.bin ]; then
    echo "Installing firmware without verification..."
    # Vulnerable: No cryptographic verification
    dd if=/tmp/firmware.bin of=/dev/mtd0
fi
EOF
    chmod 755 /var/firmware/update.sh
    
    # Create update config with HTTP URL
    local flag14=$(generate_flag "Update Config" "Firmware updates over HTTP" 25 "Medium" "IoT-04")
    cat > /etc/update.conf << EOF
UPDATE_SERVER=http://update.axis.com
CHECK_SIGNATURE=false
AUTO_UPDATE=true
ROLLBACK_ENABLED=false
UPDATE_INTERVAL=86400
BETA_CHANNEL=true
UPDATE_FLAG=$flag14
EOF
    
    log_action "Insecure update mechanism configured (2 flags)"
}

# ==========================================
# OWASP IoT-05: Use of Insecure or Outdated Components
# ==========================================
configure_outdated_components() {
    echo -e "\n${CYAN}Configuring OWASP IoT-05: Outdated Components...${NC}"
    
    # Create fake vulnerable library versions
    local flag15=$(generate_flag "OpenSSL Version" "Outdated OpenSSL library" 20 "Medium" "IoT-05")
    
    cat > /etc/versions.txt << EOF
System Component Versions:
==========================
OpenSSL 1.0.1e (CVE-2014-0160 Heartbleed vulnerable)
BusyBox v1.20.0 (Multiple CVEs)
Linux Kernel 3.10.0 (Dirty COW vulnerable)
libcurl 7.40.0 (CVE-2014-3613)
bash 4.3.0 (Shellshock vulnerable)
glibc 2.24 (CVE-2016-3706)
Flag: $flag15
EOF
    
    # Shellshock vulnerability simulation
    local flag16=$(generate_flag "Shellshock" "Bash Shellshock vulnerability present" 35 "Hard" "IoT-05")
    mkdir -p /cgi-bin
    cat > /cgi-bin/status.sh << EOF
#!/bin/bash
# Vulnerable to Shellshock (CVE-2014-6271)
# Test: curl -H "User-Agent: () { :; }; echo; /bin/cat /etc/passwd" http://$CAMERA_IP/cgi-bin/status.sh
# Flag: $flag16
echo "Content-Type: text/plain"
echo ""
echo "Camera Status: OK"
uptime
EOF
    chmod 755 /cgi-bin/status.sh
    
    log_action "Outdated components configured (2 flags)"
}

# ==========================================
# OWASP IoT-06: Insufficient Privacy Protection
# ==========================================
configure_privacy_issues() {
    echo -e "\n${CYAN}Configuring OWASP IoT-06: Privacy Issues...${NC}"
    
    # Create user data leak
    local flag17=$(generate_flag "User Data" "Exposed user information" 15 "Easy" "IoT-06")
    
    mkdir -p /var/logs
    cat > /var/logs/users.log << EOF
2024-01-01 10:00:00 User: John Smith, IP: 192.168.1.100, Action: Login
2024-01-01 10:05:00 User: Admin, Password: AdminPass@123, Status: Success
2024-01-01 10:10:00 Flag: $flag17
2024-01-01 10:15:00 User: Jane Doe, Email: jane@example.com, Phone: 555-1234
2024-01-01 10:20:00 User: Bob Wilson, Location: 40.7128,-74.0060 (New York)
2024-01-01 10:25:00 Face detected: PersonID_4823, Confidence: 98.5%
EOF
    chmod 644 /var/logs/users.log
    
    # Motion detection logs with privacy data
    local flag18=$(generate_flag "Motion Logs" "Motion detection logs with timestamps" 20 "Medium" "IoT-06")
    cat > /var/logs/motion.log << EOF
Motion Detection Log - Private Areas Included
==============================================
2024-01-01 22:30:00 Living Room - 2 persons detected
2024-01-01 23:45:00 Master Bedroom - Motion detected
2024-01-02 03:15:00 Bathroom - Motion detected
2024-01-02 07:30:00 Child's Room - Wake up detected
Alert sent to: user@example.com, admin@company.com
SMS sent to: +1-555-0123
Flag: $flag18
Home Layout Mapped: 4 bedrooms, 3 bathrooms, 2 floors
EOF
    
    log_action "Privacy protection issues configured (2 flags)"
}

# ==========================================
# OWASP IoT-07: Insecure Data Transfer and Storage
# ==========================================
configure_insecure_data() {
    echo -e "\n${CYAN}Configuring OWASP IoT-07: Insecure Data Transfer...${NC}"
    
    # Unencrypted stream configuration
    local flag19=$(generate_flag "Stream Config" "Unencrypted RTSP stream" 20 "Medium" "IoT-07")
    
    mkdir -p /etc/stream
    cat > /etc/stream/rtsp.conf << EOF
# RTSP Configuration - INSECURE
ENCRYPTION=none
AUTH=none
PORT=554
URL=rtsp://$CAMERA_IP/live/stream1
MULTICAST=enabled
TRANSPORT=UDP
AUDIO_CODEC=PCMU
VIDEO_CODEC=H264
FLAG=$flag19
EOF
    
    # Clear text API keys
    local flag20=$(generate_flag "API Keys" "API keys stored in plaintext" 25 "Medium" "IoT-07")
    cat > /etc/api_keys.txt << EOF
Production API Keys - PLAINTEXT STORAGE
========================================
ONVIF_API_KEY=ONVIF-KEY-PLAINTEXT-2024-PROD
VAPIX_API_KEY=VAPIX-KEY-PLAINTEXT-2024-PROD
MQTT_API_KEY=MQTT-KEY-PLAINTEXT-2024-PROD
AWS_ACCESS_KEY=AKIA1234567890ABCDEF
AWS_SECRET_KEY=abcdef1234567890ABCDEF1234567890
GOOGLE_API_KEY=AIzaSyD-1234567890abcdefghijklmn
FLAG=$flag20
EOF
    chmod 644 /etc/api_keys.txt
    
    # Unencrypted backup with sensitive data
    local flag21=$(generate_flag "Backup File" "Unencrypted configuration backup" 30 "Hard" "IoT-07")
    mkdir -p /var/backups
    cat > /var/backups/sensitive_data.sql << EOF
-- Camera Database Dump
-- Contains user credentials and settings
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(100),
    email VARCHAR(100)
);

INSERT INTO users VALUES (1, 'admin', 'AdminPass@123', 'admin@axis.com');
INSERT INTO users VALUES (2, 'operator', 'Operator#2024', 'operator@axis.com');
INSERT INTO users VALUES (3, 'viewer', 'Viewer$2024', 'viewer@axis.com');

-- Flag: $flag21

CREATE TABLE wifi_networks (
    ssid VARCHAR(32),
    password VARCHAR(63)
);

INSERT INTO wifi_networks VALUES ('OfficeWiFi', 'SecurePassword123');
INSERT INTO wifi_networks VALUES ('GuestNetwork', 'Welcome2024!');
EOF
    
    log_action "Insecure data transfer configured (3 flags)"
}

# ==========================================
# OWASP IoT-08: Lack of Device Management
# ==========================================
configure_device_management() {
    echo -e "\n${CYAN}Configuring OWASP IoT-08: Device Management Issues...${NC}"
    
    # No password complexity requirements
    local flag22=$(generate_flag "Password Policy" "No password complexity enforcement" 15 "Easy" "IoT-08")
    cat > /etc/password_policy.conf << EOF
MIN_LENGTH=1
COMPLEXITY=disabled
UPPERCASE=optional
LOWERCASE=optional
NUMBERS=optional
SPECIAL_CHARS=optional
EXPIRATION=never
HISTORY=0
LOCKOUT_ATTEMPTS=unlimited
FLAG=$flag22
EOF
    
    # No session management
    local flag23=$(generate_flag "Session Management" "No session timeout configured" 25 "Medium" "IoT-08")
    mkdir -p /var/sessions
    cat > /var/sessions/config << EOF
SESSION_TIMEOUT=0
CONCURRENT_SESSIONS=unlimited
SESSION_ID_LENGTH=8
SESSION_ID_PREDICTABLE=true
COOKIE_SECURE_FLAG=false
COOKIE_HTTPONLY=false
# Active sessions never expire
# Session ID format: SESS0001, SESS0002, etc.
# Flag: $flag23
EOF
    
    log_action "Device management issues configured (2 flags)"
}

# ==========================================
# OWASP IoT-09: Insecure Default Settings
# ==========================================
configure_insecure_defaults() {
    echo -e "\n${CYAN}Configuring OWASP IoT-09: Insecure Default Settings...${NC}"
    
    # Default settings file
    local flag24=$(generate_flag "Default Settings" "Insecure default configuration" 10 "Easy" "IoT-09")
    
    cat > /etc/camera_defaults.conf << EOF
# Camera Default Settings - INSECURE BY DEFAULT
ENABLE_FTP=yes
ENABLE_UPNP=yes
ENABLE_ONVIF=yes
ENABLE_RTSP_AUTH=no
DEFAULT_USER=admin
DEFAULT_PASS=AdminPass@123
WPS_ENABLED=yes
P2P_ENABLED=yes
CLOUD_UPLOAD=yes
TELEMETRY=enabled
DEBUG_MODE=yes
FACTORY_RESET_CODE=12345
FLAG=$flag24
EOF
    
    # Debug mode enabled by default
    local flag25=$(generate_flag "Debug Mode" "Debug mode enabled by default" 15 "Easy" "IoT-09")
    cat > /etc/debug.conf << EOF
DEBUG_MODE=enabled
VERBOSE_LOGGING=yes
STACK_TRACES=yes
CORE_DUMPS=yes
DEBUG_PORT=9999
REMOTE_DEBUG=enabled
MEMORY_DUMPS=enabled
FLAG=$flag25
EOF
    
    # World-writable directories
    chmod 777 /tmp 2>/dev/null || true
    chmod 777 /var/tmp 2>/dev/null || true
    
    log_action "Insecure default settings configured (2 flags)"
}

# ==========================================
# OWASP IoT-10: Lack of Physical Hardening
# ==========================================
configure_physical_hardening() {
    echo -e "\n${CYAN}Configuring OWASP IoT-10: Physical Hardening Issues...${NC}"
    
    # UART/Serial console hints
    local flag26=$(generate_flag "UART Access" "UART console accessible" 30 "Hard" "IoT-10")
    mkdir -p /dev/serial
    cat > /dev/serial/console.txt << EOF
UART Console Configuration
==========================
Board: AXIS M1065-LW Rev 2.1
UART Pins: J4 Header (Near SD Card)
Pin 1: GND (Square pad)
Pin 2: TX (3.3V)
Pin 3: RX (3.3V)
Pin 4: VCC (3.3V - Do not connect)

Serial Settings:
Baud Rate: 115200
Data Bits: 8
Stop Bits: 1
Parity: None
Flow Control: None

Boot Interrupt Key: ESC (Hold during power on)
U-Boot Password: axis2024
Root Shell: No Authentication Required

Memory Map Exposed:
0x00000000-0x07FFFFFF: RAM
0x10000000-0x1FFFFFFF: Flash
0x20000000-0x2FFFFFFF: Peripherals

Flag: $flag26
EOF
    
    # JTAG debug interface
    local flag27=$(generate_flag "JTAG Interface" "JTAG debugging enabled" 35 "Hard" "IoT-10")
    mkdir -p /sys/jtag
    cat > /sys/jtag/config << EOF
JTAG Configuration
==================
Status: ENABLED
Interface: ARM JTAG 20-pin
Location: J12 Header (Under heatsink)
TCK: Pin 9
TMS: Pin 7  
TDI: Pin 5
TDO: Pin 13
TRST: Pin 3
GND: Pin 4,6,8,10

Debugger Support:
- OpenOCD compatible
- J-Link compatible
- Bus Pirate compatible

Accessible Operations:
- Memory read/write
- Flash programming
- Bootloader bypass
- Crypto key extraction

Flag: $flag27
EOF
    
    # Exposed test points
    local flag28=$(generate_flag "Test Points" "Factory test points exposed" 30 "Hard" "IoT-10")
    cat > /etc/hardware_test.conf << EOF
Factory Test Points - PCB Rev 2.1
==================================
TEST_MODE=enabled
FACTORY_ACCESS=yes

Test Points:
TP1: Boot Mode Select (Pull low for recovery)
TP2: Flash Write Enable
TP3: Debug UART2 TX
TP4: Debug UART2 RX
TP5: I2C SDA (EEPROM access)
TP6: I2C SCL (EEPROM access)
TP7: SPI MISO (Flash dump)
TP8: SPI MOSI (Flash write)
TP9: Reset (Pull low to reset)
TP10: Bootloader bypass

Hidden Service Mode:
Hold TP1 + TP9 during boot for service menu
Service Code: 31337

FLAG=$flag28
EOF
    
    log_action "Physical hardening issues configured (3 flags)"
}

# ==========================================
# Additional IoT-Specific Vulnerabilities
# ==========================================
configure_additional_vulns() {
    echo -e "\n${CYAN}Configuring Additional IoT Vulnerabilities...${NC}"
    
    # MQTT misconfiguration
    local flag29=$(generate_flag "MQTT Config" "Insecure MQTT broker settings" 25 "Medium" "IoT-02")
    mkdir -p /etc/mqtt
    cat > /etc/mqtt/broker.conf << EOF
BROKER_HOST=mqtt.local
BROKER_PORT=1883
USE_TLS=false
USERNAME=camera
PASSWORD=MqttCam2024!
ANONYMOUS_ACCESS=true
TOPIC=/axis/camera/telemetry
WILDCARD_SUBS=true
SYS_TOPIC_EXPOSED=true
FLAG=$flag29
EOF
    
    # ONVIF misconfiguration
    local flag30=$(generate_flag "ONVIF Service" "ONVIF discovery enabled" 20 "Medium" "IoT-03")
    mkdir -p /etc/onvif
    cat > /etc/onvif/discovery.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
<Header/>
<Body>
<ProbeMatch>
<EndpointReference>
<Address>http://$CAMERA_IP/onvif/device_service</Address>
</EndpointReference>
<Types>NetworkVideoTransmitter</Types>
<Scopes>
  onvif://www.onvif.org/location/country/usa
  onvif://www.onvif.org/hardware/M1065-LW
  onvif://www.onvif.org/name/AXIS-ACCC8E123456
</Scopes>
<MetadataVersion>1</MetadataVersion>
<!-- Discovery Flag: $flag30 -->
</ProbeMatch>
</Body>
</Envelope>
EOF
    
    # Memory leak in stream handler
    local flag31=$(generate_flag "Memory Leak" "Memory leak in video handler" 35 "Hard" "IoT-05")
    mkdir -p /proc/camera
    cat > /proc/camera/memleak << EOF
Memory Leak Analysis
====================
Leak detected in: video_stream_handler()
Leak size: 4KB per connection
Leak rate: Continuous
Exploitable: Yes (Information disclosure)

Leaked memory contains:
- Previous frame buffers
- User session tokens  
- Decrypted passwords
- Configuration data
- Flag: $flag31

Trigger: Open multiple RTSP streams
Effect: Memory exhaustion in ~2 hours
EOF
    
    # Command injection vector
    local flag32=$(generate_flag "Command Injection" "OS command injection in API" 35 "Hard" "IoT-03")
    mkdir -p /cgi-bin
    cat > /cgi-bin/exec.cgi << EOF
#!/bin/sh
# Vulnerable CGI script - Command Injection
# Test: /cgi-bin/exec.cgi?cmd=\$(whoami)
# Flag: $flag32
echo "Content-Type: text/plain"
echo ""
echo "System Information:"
eval "echo \$QUERY_STRING"
EOF
    chmod 755 /cgi-bin/exec.cgi
    
    log_action "Additional IoT vulnerabilities configured (4 flags)"
}

# ==========================================
# Create SSH Keys with Weak Permissions
# ==========================================
configure_ssh_vulnerabilities() {
    echo -e "\n${CYAN}Configuring SSH Vulnerabilities...${NC}"
    
    local flag33=$(generate_flag "SSH Key" "Private SSH key with weak permissions" 20 "Medium" "IoT-01")
    
    mkdir -p /root/.ssh
    ssh-keygen -t rsa -b 1024 -f /root/.ssh/id_rsa -N "" -C "$flag33" 2>/dev/null || true
    chmod 644 /root/.ssh/id_rsa  # Intentionally weak permissions
    
    # Authorized keys with flag
    local flag34=$(generate_flag "Auth Keys" "Exposed authorized_keys file" 15 "Easy" "IoT-09")
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDummy admin@axis # $flag34" >> /root/.ssh/authorized_keys
    chmod 644 /root/.ssh/authorized_keys
    
    log_action "SSH vulnerabilities configured (2 flags)"
}

# ==========================================
# Create Flag Report
# ==========================================
create_flag_report() {
    echo -e "\n${CYAN}Generating Flag Report...${NC}"
    
    cat > /var/lib/ctf-flags.txt << EOF
====================================================
AXIS Camera CTF Lab v2.0 - Flag Report
====================================================
Generated: $(date)
Camera Model: $CAMERA_MODEL
IP Address: $CAMERA_IP
Total Flags: $((FLAG_COUNTER - 1))

FLAG LIST:
----------
EOF
    
    # Count by difficulty
    local easy_count=0
    local medium_count=0
    local hard_count=0
    
    for flag_entry in "${FLAG_LIST[@]}"; do
        echo "$flag_entry" >> /var/lib/ctf-flags.txt
        
        # Count by difficulty
        if [[ $flag_entry == *"Easy"* ]]; then
            easy_count=$((easy_count + 1))
        elif [[ $flag_entry == *"Medium"* ]]; then
            medium_count=$((medium_count + 1))
        elif [[ $flag_entry == *"Hard"* ]]; then
            hard_count=$((hard_count + 1))
        fi
    done
    
    cat >> /var/lib/ctf-flags.txt << EOF

STATISTICS:
-----------
Easy Flags: $easy_count
Medium Flags: $medium_count  
Hard Flags: $hard_count
Total: $((FLAG_COUNTER - 1))

OWASP IoT Top 10 Coverage:
--------------------------
IoT-01: Weak Passwords ✓
IoT-02: Insecure Network Services ✓
IoT-03: Insecure Ecosystem Interfaces ✓
IoT-04: Lack of Secure Update ✓
IoT-05: Outdated Components ✓
IoT-06: Insufficient Privacy ✓
IoT-07: Insecure Data Transfer ✓
IoT-08: Lack of Device Management ✓
IoT-09: Insecure Default Settings ✓
IoT-10: Lack of Physical Hardening ✓

Special Vulnerability: RTSP Buffer Overflow (Hard)
====================================================
EOF
    
    chmod 600 /var/lib/ctf-flags.txt
    
    echo -e "${GREEN}Flag report saved to /var/lib/ctf-flags.txt${NC}"
    echo -e "${GREEN}Easy Flags: $easy_count${NC}"
    echo -e "${YELLOW}Medium Flags: $medium_count${NC}"
    echo -e "${RED}Hard Flags: $hard_count${NC}"
}

# ==========================================
# Create Persistence Script
# ==========================================
create_persistence() {
    echo -e "\n${CYAN}Creating Persistence Mechanisms...${NC}"
    
    # Create maintenance script
    cat > /usr/local/bin/maintain_ctf.sh << 'MAINTAIN_EOF'
#!/bin/sh
# CTF Lab Maintenance Script v2.0
# Ensures vulnerabilities persist

# Ensure FTP is running (telnet removed)
pgrep ftpd > /dev/null || /usr/sbin/tcpsvd -vE 0.0.0.0 21 ftpd -w / &

# Ensure weak permissions remain
chmod 777 /tmp 2>/dev/null
chmod 644 /etc/passwd 2>/dev/null
chmod 644 /var/camera-config/credentials.txt 2>/dev/null
chmod 755 /cgi-bin/*.cgi 2>/dev/null

# Log maintenance
echo "[$(date)] CTF maintenance completed" >> /var/log/ctf-maintain.log
MAINTAIN_EOF
    
    chmod +x /usr/local/bin/maintain_ctf.sh
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "*/10 * * * * /usr/local/bin/maintain_ctf.sh") | crontab -
    
    log_action "Persistence mechanisms created"
}

# ==========================================
# Main Execution
# ==========================================

echo -e "\n${BLUE}Starting AXIS Camera CTF Lab Configuration v2.0...${NC}\n"

# Run all configuration functions
configure_weak_passwords
configure_rtsp_buffer_overflow
configure_insecure_network_services
configure_insecure_interfaces
configure_insecure_update
configure_outdated_components
configure_privacy_issues
configure_insecure_data
configure_device_management
configure_insecure_defaults
configure_physical_hardening
configure_additional_vulns
configure_ssh_vulnerabilities

# Create persistence
create_persistence

# Generate final report
create_flag_report

echo -e "\n${GREEN}==========================================${NC}"
echo -e "${GREEN}CTF Lab Configuration Complete!${NC}"
echo -e "${GREEN}==========================================${NC}"
echo -e "\n${YELLOW}Camera Model:${NC} $CAMERA_MODEL"
echo -e "${YELLOW}IP Address:${NC} $CAMERA_IP"
echo -e "${YELLOW}Total Flags Deployed:${NC} $((FLAG_COUNTER - 1))"
echo -e "\n${YELLOW}Services Enabled:${NC}"
echo -e "  - FTP (Port 21)"
echo -e "  - HTTP (Port 80)"
echo -e "  - RTSP (Port 554) - ${RED}WITH BUFFER OVERFLOW${NC}"
echo -e "  - SSH (Port 22)"
echo -e "  - ONVIF (Port 80)"
echo -e "  - NTP (Port 123)"
echo -e "  - UPnP (Port 1900)"
echo -e "\n${YELLOW}User Credentials:${NC}"
echo -e "  - user:password12345"
echo -e "  - testuser:TestAccount2024!"
echo -e "  - camera-admin:CamAdmin#2024"
echo -e "  - iot-device:IoT_Device\$2025"
echo -e "  - service-account:Svc@Account2024"
echo -e "  - root:${LAB_PASSWORD}"
echo -e "\n${RED}SPECIAL VULNERABILITY:${NC}"
echo -e "  ${RED}RTSP Buffer Overflow at offset 260 bytes${NC}"
echo -e "  ${RED}Exploitable for remote code execution${NC}"
echo -e "  ${RED}See /var/crash/ for exploitation details${NC}"
echo -e "\n${RED}WARNING: This camera is now EXTREMELY VULNERABLE!${NC}"
echo -e "${RED}Only use in isolated lab environments!${NC}"
echo -e "\n${CYAN}Flag report location: /var/lib/ctf-flags.txt${NC}"
echo -e "${CYAN}Maintenance script: /usr/local/bin/maintain_ctf.sh${NC}"
echo -e "\n${GREEN}Happy Hunting!${NC}\n"