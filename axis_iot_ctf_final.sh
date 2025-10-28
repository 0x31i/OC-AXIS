#!/bin/sh
# AXIS Camera IoT CTF Configuration Script v4
# Ultra-minimal BusyBox compatible (no cksum, no base64, no seq)
# POSIX-compliant shell script
# Maps to OWASP IoT Top 10 with LOTR-themed flags

# WARNING: FOR ISOLATED LAB ENVIRONMENT ONLY
# This script creates intentional vulnerabilities for education

echo "==========================================="
echo "AXIS CAMERA IoT CTF SETUP v4.0"
echo "OWASP IoT Top 10 Training Environment"
echo "Ultra-Minimal BusyBox Edition"
echo "FOR EDUCATIONAL PURPOSES ONLY"
echo "==========================================="
echo ""
echo "Type 'VULNERABLE' to confirm this is for an isolated lab:"
read confirm
if [ "$confirm" != "VULNERABLE" ]; then
    echo "Exiting - confirmation not received"
    exit 1
fi

# Initialize flag tracking
FLAG_COUNT=0
HOSTNAME=$(hostname 2>/dev/null || echo "axis-camera")

# LOTR character names for flags
LOTR_NAMES="FRODO GANDALF ARAGORN LEGOLAS GIMLI BOROMIR SAMWISE MERRY PIPPIN ELROND GALADRIEL BILBO THORIN SAURON SARUMAN GOLLUM FARAMIR EOWYN ARWEN THEODEN TREEBEARD RADAGAST GLORFINDEL ELENDIL ISILDUR"

# Function to generate deterministic flag without cksum or seq
generate_flag() {
    position=$1
    difficulty=$2
    location=$3
    
    # Select LOTR name based on position
    name_index=$(( position % 25 + 1 ))
    lotr_name=$(echo $LOTR_NAMES | cut -d' ' -f$name_index)
    
    # Generate deterministic 8-digit number using simple math
    # No seq needed - just use position and hostname length
    seed="${position}${HOSTNAME}"
    seed_len=$(echo "$seed" | wc -c | tr -d ' ')
    
    # Simple hash calculation without loops
    hash_val=$(( position * 31415926 + seed_len * 27182818 ))
    hash_val=$(( hash_val % 100000000 ))
    
    # Ensure 8 digits
    digits=$(printf "%08d" $hash_val)
    
    flag="FLAG{${lotr_name}${digits}}"
    FLAG_COUNT=$(( FLAG_COUNT + 1 ))
    
    # Log flag for documentation
    echo "[$difficulty] Flag #${FLAG_COUNT}: $flag - Location: $location" >> /tmp/ctf_flags.log
    
    echo "$flag"
}

# Function to create directory if it doesn't exist
ensure_dir() {
    dir=$1
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir" 2>/dev/null || true
    fi
}

# Function to encode without base64 (simple ROT13-like)
simple_encode() {
    echo "$1" | tr 'A-Za-z0-9' 'N-ZA-Mn-za-m5-90-4'
}

echo "[*] Starting IoT vulnerability configuration..."

# ===========================================================================
# OWASP IoT-01: Weak, Guessable, or Hardcoded Passwords
# ===========================================================================

echo "[+] Configuring IoT-01: Weak Password vulnerabilities..."

# Create necessary directories first
ensure_dir "/tmp"
ensure_dir "/etc/axis"
ensure_dir "/var/config"

# EASY FLAG 1: Default credentials in plaintext config
flag1=$(generate_flag 1 "EASY" "VAPIX config file")
cat > /tmp/vapix.conf << EOF
# VAPIX API Configuration
api_version=1.4
admin_user=root
admin_password=pass
camera_id=$flag1
EOF
cp /tmp/vapix.conf /etc/axis/vapix.conf 2>/dev/null || true
chmod 644 /tmp/vapix.conf

# MEDIUM FLAG 1: Encoded credentials
flag2=$(generate_flag 2 "MEDIUM" "Encoded ONVIF credentials")
encoded_creds=$(simple_encode "onvif:camera123:$flag2")
cat > /tmp/onvif_auth << EOF
# ONVIF Authentication (ROT13 encoded)
auth_data=$encoded_creds
EOF
cp /tmp/onvif_auth /var/config/onvif_auth 2>/dev/null || true
chmod 644 /tmp/onvif_auth

# HARD FLAG 1: Weak password hint
flag3=$(generate_flag 3 "HARD" "Service account password hint")
cat > /tmp/shadow_hint.txt << EOF
# Service account password hint
# Password is: service_$flag3
# Hash: \$1\$xyz\$YzQs3WTG7PnJ3YzKqQ8xN/
EOF
chmod 644 /tmp/shadow_hint.txt

# ===========================================================================
# OWASP IoT-02: Insecure Network Services (SSH)
# ===========================================================================

echo "[+] Configuring IoT-02: Insecure Network Services (SSH)..."

ensure_dir "/etc/ssh"
ensure_dir "/root/.ssh"

# EASY FLAG 2: SSH banner disclosure
flag4=$(generate_flag 4 "EASY" "SSH banner disclosure")
cat > /tmp/sshd_banner << EOF
*************************************************
* AXIS Camera SSH Service                      *
* Firmware: 10.5.0                              *
* Device ID: $flag4                            *
*************************************************
EOF
cp /tmp/sshd_banner /etc/ssh/sshd_banner 2>/dev/null || true
chmod 644 /tmp/sshd_banner

# MEDIUM FLAG 2: SSH authorized_keys with flag
flag5=$(generate_flag 5 "MEDIUM" "SSH authorized_keys comment")
cat > /tmp/authorized_keys << EOF
# Backup key for admin access - $flag5
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfake admin@axis
EOF
cp /tmp/authorized_keys /root/.ssh/authorized_keys 2>/dev/null || true
chmod 600 /tmp/authorized_keys

# Configure SSH if available
if [ -x /usr/sbin/sshd ]; then
    cat > /etc/ssh/sshd_config << EOF
Port 22
Banner /etc/ssh/sshd_banner
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
StrictModes no
EOF
    /usr/sbin/sshd -f /etc/ssh/sshd_config 2>/dev/null
    echo "    OpenSSH started on port 22"
elif [ -x /usr/sbin/dropbear ]; then
    dropbear -F -E -w -g -p 22 2>/dev/null &
    echo "    Dropbear SSH started on port 22"
fi

# MEDIUM FLAG 3: RTSP stream configuration
flag6=$(generate_flag 6 "MEDIUM" "RTSP stream metadata")
ensure_dir "/var/rtsp"
cat > /tmp/stream1.sdp << EOF
v=0
o=- 0 0 IN IP4 127.0.0.1
s=AXIS Media Stream
i=$flag6
c=IN IP4 0.0.0.0
m=video 0 RTP/AVP 96
EOF
cp /tmp/stream1.sdp /var/rtsp/stream1.sdp 2>/dev/null || true
chmod 644 /tmp/stream1.sdp

# ===========================================================================
# OWASP IoT-03: Insecure Ecosystem Interfaces (Web, API, Cloud)
# ===========================================================================

echo "[+] Configuring IoT-03: Insecure Web/API Interfaces..."

ensure_dir "/var/www"
ensure_dir "/var/www/cgi-bin"
ensure_dir "/var/www/axis-cgi"

# EASY FLAG 3: Information disclosure in HTML
flag7=$(generate_flag 7 "EASY" "HTML source comment")
cat > /tmp/index.html << EOF
<html>
<head><title>AXIS Camera</title></head>
<body>
<h1>Camera Web Interface</h1>
<!-- Debug: $flag7 -->
<a href="/cgi-bin/admin.cgi">Admin Panel</a>
</body>
</html>
EOF
cp /tmp/index.html /var/www/index.html 2>/dev/null || true
chmod 644 /tmp/index.html

# MEDIUM FLAG 4: Command injection in CGI
flag8=$(generate_flag 8 "MEDIUM" "Command injection via param.cgi")
cat > /tmp/param.cgi << CGISCRIPT
#!/bin/sh
echo "Content-type: text/plain"
echo ""
PARAM=\$(echo "\$QUERY_STRING" | sed 's/.*action=//' | sed 's/[;&|]//g')
if [ "\$PARAM" = "getflag" ]; then
    echo "$flag8"
else
    eval "echo Executing: \$PARAM"
fi
CGISCRIPT
cp /tmp/param.cgi /var/www/axis-cgi/param.cgi 2>/dev/null || cp /tmp/param.cgi /var/www/param.cgi 2>/dev/null || true
chmod 755 /tmp/param.cgi

# HARD FLAG 2: Blind command injection
flag9=$(generate_flag 9 "HARD" "Blind injection in pwdgrp.cgi")
cat > /tmp/pwdgrp.cgi << CGISCRIPT
#!/bin/sh
echo "Content-type: text/plain"
echo ""
echo "Processing..."
USER=\$(echo "\$QUERY_STRING" | sed 's/.*user=//' | cut -d'&' -f1)
echo "$flag9" > /tmp/.flag_\$USER 2>/dev/null
eval "id \$USER" > /dev/null 2>&1
echo "Done"
CGISCRIPT
cp /tmp/pwdgrp.cgi /var/www/axis-cgi/pwdgrp.cgi 2>/dev/null || cp /tmp/pwdgrp.cgi /var/www/pwdgrp.cgi 2>/dev/null || true
chmod 755 /tmp/pwdgrp.cgi

# MEDIUM FLAG 5: Path traversal
flag10=$(generate_flag 10 "MEDIUM" "Path traversal in download.cgi")
echo "$flag10" > /tmp/system.conf
cp /tmp/system.conf /var/config/system.conf 2>/dev/null || true

cat > /tmp/download.cgi << CGISCRIPT
#!/bin/sh
echo "Content-type: text/plain"
echo ""
FILE=\$(echo "\$QUERY_STRING" | sed 's/.*file=//' | sed 's/\.\.\///g')
if [ -f "/var/www/files/\$FILE" ]; then
    cat "/var/www/files/\$FILE"
else
    cat "\$FILE" 2>/dev/null || echo "File not found"
fi
CGISCRIPT
cp /tmp/download.cgi /var/www/cgi-bin/download.cgi 2>/dev/null || cp /tmp/download.cgi /var/www/download.cgi 2>/dev/null || true
chmod 755 /tmp/download.cgi

# ===========================================================================
# OWASP IoT-04: Lack of Secure Update Mechanism
# ===========================================================================

echo "[+] Configuring IoT-04: Insecure Update Mechanism..."

# MEDIUM FLAG 6: Unsigned firmware update
flag11=$(generate_flag 11 "MEDIUM" "Firmware update manifest")
cat > /tmp/firmware_update.sh << EOFSCRIPT
#!/bin/sh
echo "Checking firmware: $flag11"
FW_URL=\$1
if [ -n "\$FW_URL" ]; then
    wget "\$FW_URL" -O /tmp/firmware.bin 2>/dev/null || echo "Download failed"
    echo "Firmware downloaded (NOT VERIFIED)"
fi
EOFSCRIPT
chmod 755 /tmp/firmware_update.sh

# HARD FLAG 3: Hardcoded update server
flag12=$(generate_flag 12 "HARD" "Hardcoded update server")
cat > /tmp/check_updates << EOFSCRIPT
#!/bin/sh
UPDATE_SERVER="updates.axis-cam.local"
echo "Connecting to update server..."
echo "Server fingerprint: $flag12"
EOFSCRIPT
chmod 755 /tmp/check_updates

# ===========================================================================
# OWASP IoT-05: Use of Insecure or Outdated Components
# ===========================================================================

echo "[+] Configuring IoT-05: Outdated Components..."

# MEDIUM FLAG 7: Old vulnerable service
flag13=$(generate_flag 13 "MEDIUM" "Legacy service version")
cat > /tmp/legacy_daemon << EOFSCRIPT
#!/bin/sh
echo "Legacy Daemon v1.0 (CVE-2017-9765 vulnerable)"
echo "Service ID: $flag13"
EOFSCRIPT
chmod 755 /tmp/legacy_daemon

# ===========================================================================
# OWASP IoT-06: Insufficient Privacy Protection
# ===========================================================================

echo "[+] Configuring IoT-06: Privacy Issues..."

# EASY FLAG 4: Unencrypted stream URLs
flag14=$(generate_flag 14 "EASY" "Exposed stream URL")
cat > /tmp/streams.txt << EOF
# Camera Stream URLs
rtsp://admin:admin@192.168.1.100:554/stream1
rtsp://root:pass@192.168.1.100:554/stream2?token=$flag14
EOF
chmod 644 /tmp/streams.txt

# ===========================================================================
# OWASP IoT-07: Insecure Data Transfer and Storage
# ===========================================================================

echo "[+] Configuring IoT-07: Insecure Data Storage..."

# MEDIUM FLAG 8: Plaintext API keys
flag15=$(generate_flag 15 "MEDIUM" "API key in config")
cat > /tmp/api.conf << EOF
# Cloud API Configuration
api_endpoint=https://api.axis-cloud.com
api_key=sk_live_$flag15
EOF
chmod 644 /tmp/api.conf

# HARD FLAG 4: Weakly encoded credential
flag16=$(generate_flag 16 "HARD" "Encoded credential")
encoded_flag=$(simple_encode "$flag16")
echo "$encoded_flag" > /tmp/encrypted_pass
chmod 644 /tmp/encrypted_pass

# ===========================================================================
# OWASP IoT-08: Lack of Device Management
# ===========================================================================

echo "[+] Configuring IoT-08: Device Management Issues..."

# MEDIUM FLAG 9: Debug interface enabled
flag17=$(generate_flag 17 "MEDIUM" "Debug interface")
cat > /tmp/debug_enabled << EOF
DEBUG_MODE=1
DEBUG_PORT=9999
DEBUG_TOKEN=$flag17
EOF
chmod 644 /tmp/debug_enabled

# HARD FLAG 5: Hidden maintenance backdoor
flag18=$(generate_flag 18 "HARD" "SSH maintenance backdoor")
ensure_dir "/var/.hidden"
cat > /tmp/backdoor_key << EOF
ssh-rsa AAAAB3NzaC1yc2E maintenance@axis
# Backdoor access code: $flag18
EOF
cp /tmp/backdoor_key /var/.hidden/backdoor_key 2>/dev/null || true
chmod 600 /tmp/backdoor_key

# ===========================================================================
# OWASP IoT-09: Insecure Default Settings
# ===========================================================================

echo "[+] Configuring IoT-09: Insecure Defaults..."

# EASY FLAG 5: Default SNMP community
flag19=$(generate_flag 19 "EASY" "SNMP community string")
cat > /tmp/snmpd.conf << EOF
rocommunity public
rwcommunity private
sysdescr AXIS Camera $flag19
EOF
chmod 644 /tmp/snmpd.conf

# MEDIUM FLAG 10: UPnP info disclosure
flag20=$(generate_flag 20 "MEDIUM" "UPnP device description")
cat > /tmp/device.xml << EOF
<?xml version="1.0"?>
<device>
    <serialNumber>ACCC8E$flag20</serialNumber>
    <UDN>uuid:$flag20</UDN>
</device>
EOF
chmod 644 /tmp/device.xml

# ===========================================================================
# OWASP IoT-10: Lack of Physical Hardening
# ===========================================================================

echo "[+] Configuring IoT-10: Physical Access vulnerabilities..."

# HARD FLAG 6: UART console
flag21=$(generate_flag 21 "HARD" "U-Boot environment")
cat > /tmp/uboot.env << EOF
bootdelay=3
baudrate=115200
unlock_code=$flag21
EOF
chmod 644 /tmp/uboot.env

# HARD FLAG 7: JTAG debug
flag22=$(generate_flag 22 "HARD" "JTAG boundary scan")
cat > /tmp/jtag_idcode << EOF
IDCODE: 0x4BA00477
DEBUG_KEY: $flag22
EOF
chmod 644 /tmp/jtag_idcode

# ===========================================================================
# Additional Vulnerabilities
# ===========================================================================

echo "[+] Creating additional exploitation scenarios..."

# HARD FLAG 8: SSRF via webhook
flag23=$(generate_flag 23 "HARD" "SSRF via webhook")
cat > /tmp/webhook.cgi << CGISCRIPT
#!/bin/sh
echo "Content-type: text/plain"
echo ""
URL=\$(echo "\$QUERY_STRING" | sed 's/.*url=//' | cut -d'&' -f1)
if echo "\$URL" | grep -q "127.0.0.1:22"; then
    echo "Internal SSH service flag: $flag23"
else
    wget -q -O - "\$URL" 2>/dev/null | head -n 10 || echo "Failed"
fi
CGISCRIPT
chmod 755 /tmp/webhook.cgi

# MEDIUM FLAG 11: SSH config leak
flag24=$(generate_flag 24 "MEDIUM" "SSH config disclosure")
ensure_dir "/var/www/backup"
cat > /tmp/ssh_config_backup.txt << EOF
# SSH Configuration Backup
# Flag: $flag24
PasswordAuthentication yes
EOF
cp /tmp/ssh_config_backup.txt /var/www/backup/ssh_config_backup.txt 2>/dev/null || true
chmod 644 /tmp/ssh_config_backup.txt

# ===========================================================================
# Create httpd configuration and start services
# ===========================================================================

echo "[+] Starting vulnerable services..."

# Configure httpd
cat > /tmp/httpd.conf << 'EOF'
A:*
.cgi:/bin/sh
D:*
/cgi-bin:admin:admin
EOF

# Start httpd if available
if [ -x /usr/sbin/httpd ]; then
    httpd -f -p 80 -h /var/www -c /tmp/httpd.conf &
    echo "    HTTP server started on port 80"
elif [ -x /usr/bin/httpd ]; then
    httpd -f -p 80 -h /var/www -c /tmp/httpd.conf &
    echo "    HTTP server started on port 80"
elif [ -x /bin/httpd ]; then
    httpd -f -p 80 -h /var/www -c /tmp/httpd.conf &
    echo "    HTTP server started on port 80"
else
    echo "    HTTP server not found - check /tmp for CGI scripts"
fi

# Create privilege escalation vectors
echo "[+] Creating privilege escalation vectors..."

# MEDIUM FLAG 12: SUID binary
if [ -f /bin/busybox ]; then
    cp /bin/busybox /tmp/busybox_suid
    chmod 4755 /tmp/busybox_suid
    flag25=$(generate_flag 25 "MEDIUM" "SUID busybox privesc")
    echo "$flag25" > /tmp/suid_flag
    chmod 644 /tmp/suid_flag
fi

# MEDIUM FLAG 13: World-writable script
flag26=$(generate_flag 26 "MEDIUM" "Script hijacking")
cat > /tmp/backup.sh << EOFSCRIPT
#!/bin/sh
echo "Running backup..."
echo "Backup ID: $flag26"
EOFSCRIPT
chmod 777 /tmp/backup.sh

# HARD FLAG 9: Race condition
flag27=$(generate_flag 27 "HARD" "Race condition")
cat > /tmp/race.sh << EOFSCRIPT
#!/bin/sh
# Race condition vulnerability
echo "$flag27" > /tmp/race_flag
sleep 1
rm /tmp/race_flag 2>/dev/null
EOFSCRIPT
chmod 755 /tmp/race.sh

# ===========================================================================
# Documentation and Summary
# ===========================================================================

echo ""
echo "[*] Setup complete! CTF Flags created:"
echo "==========================================="
echo ""
echo "Flag Summary (27 flags total):"
echo "  Easy flags (5): Check /tmp/*conf, /tmp/streams.txt"
echo "  Medium flags (13): Check /tmp/*auth, /tmp/*.cgi"
echo "  Hard flags (9): Check /tmp/encrypted*, hidden files"
echo ""
echo "Primary flag locations:"
echo "  /tmp/ - ALL flag files are here"
echo "  /var/www/ - Web files (if directory exists)"
echo "  /var/.hidden/ - Hidden backdoor (if writable)"
echo ""
echo "Quick flag check:"
echo "  grep FLAG /tmp/* 2>/dev/null"
echo ""
echo "OWASP IoT Top 10 Coverage:"
echo "  IoT-01: Weak Passwords - /tmp/vapix.conf, /tmp/shadow_hint.txt"
echo "  IoT-02: Insecure Services - /tmp/sshd_banner, /tmp/authorized_keys"
echo "  IoT-03: Insecure Interfaces - /tmp/*.cgi scripts"
echo "  IoT-04: Insecure Updates - /tmp/firmware_update.sh"
echo "  IoT-05: Outdated Components - /tmp/legacy_daemon"
echo "  IoT-06: Privacy Issues - /tmp/streams.txt"
echo "  IoT-07: Insecure Storage - /tmp/api.conf, /tmp/encrypted_pass"
echo "  IoT-08: Device Management - /tmp/debug_enabled, /tmp/backdoor_key"
echo "  IoT-09: Insecure Defaults - /tmp/snmpd.conf, /tmp/device.xml"
echo "  IoT-10: Physical Hardening - /tmp/uboot.env, /tmp/jtag_idcode"
echo ""
echo "Attack vectors to test:"
echo "  1. Check ALL files in /tmp directory"
echo "  2. Test CGI endpoints (if web server running)"
echo "  3. Look for encoded data (ROT13-like)"
echo "  4. Check SUID binary: /tmp/busybox_suid"
echo "  5. Test writable script: /tmp/backup.sh"
echo "  6. Try race condition: /tmp/race.sh"
echo "  7. Decode: tr 'N-ZA-Mn-za-m5-90-4' 'A-Za-z0-9' < /tmp/encrypted_pass"
echo ""
echo "Services Status:"
ps | grep -E "httpd|sshd|dropbear" | grep -v grep || echo "  No services detected running"
echo ""
echo "Flag list saved to: /tmp/ctf_flags.log"
echo ""
echo "WARNING: This system is now INTENTIONALLY VULNERABLE!"
echo "Only use in isolated, controlled environments!"
echo "==========================================="
