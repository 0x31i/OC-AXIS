#!/bin/sh
# AXIS Camera IoT CTF Configuration Script v2
# POSIX-compliant for BusyBox/embedded Linux
# Updated to use SSH instead of telnet
# Maps to OWASP IoT Top 10 with LOTR-themed flags

# WARNING: FOR ISOLATED LAB ENVIRONMENT ONLY
# This script creates intentional vulnerabilities for education

echo "==========================================="
echo "AXIS CAMERA IoT CTF SETUP v2.0"
echo "OWASP IoT Top 10 Training Environment"
echo "SSH-based vulnerabilities (no telnet)"
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
HOSTNAME=$(hostname)

# LOTR character names for flags
LOTR_NAMES="FRODO GANDALF ARAGORN LEGOLAS GIMLI BOROMIR SAMWISE MERRY PIPPIN ELROND GALADRIEL BILBO THORIN SAURON SARUMAN GOLLUM FARAMIR EOWYN ARWEN THEODEN TREEBEARD RADAGAST GLORFINDEL ELENDIL ISILDUR"

# Function to generate deterministic flag
generate_flag() {
    position=$1
    difficulty=$2
    location=$3
    
    # Select LOTR name based on position
    name_index=$(( position % 25 + 1 ))
    lotr_name=$(echo $LOTR_NAMES | cut -d' ' -f$name_index)
    
    # Generate deterministic 8-digit number using position and hostname
    seed="${position}${HOSTNAME}AXIS"
    # Use cksum for deterministic hash (available in BusyBox)
    hash_val=$(echo "$seed" | cksum | cut -d' ' -f1)
    digits=$(printf "%08d" $(( hash_val % 100000000 )))
    
    flag="FLAG{${lotr_name}${digits}}"
    FLAG_COUNT=$(( FLAG_COUNT + 1 ))
    
    # Log flag for documentation
    echo "[$difficulty] Flag #${FLAG_COUNT}: $flag - Location: $location" >> /tmp/ctf_flags.log
    
    echo "$flag"
}

echo "[*] Starting IoT vulnerability configuration..."

# ===========================================================================
# OWASP IoT-01: Weak, Guessable, or Hardcoded Passwords
# ===========================================================================

echo "[+] Configuring IoT-01: Weak Password vulnerabilities..."

# EASY FLAG 1: Default credentials in plaintext config
flag1=$(generate_flag 1 "EASY" "VAPIX config file")
cat > /etc/axis/vapix.conf << EOF
# VAPIX API Configuration
api_version=1.4
admin_user=root
admin_password=pass
camera_id=$flag1
EOF
chmod 644 /etc/axis/vapix.conf

# MEDIUM FLAG 1: Base64 encoded credentials
flag2=$(generate_flag 2 "MEDIUM" "Encoded ONVIF credentials")
encoded_creds=$(echo "onvif:camera123:$flag2" | base64)
cat > /var/config/onvif_auth << EOF
# ONVIF Authentication
auth_data=$encoded_creds
EOF
chmod 644 /var/config/onvif_auth

# HARD FLAG 1: Weak hashed password (SHA256-crypt)
flag3=$(generate_flag 3 "HARD" "Service account shadow entry")
# Create service account with crackable password containing flag
echo "service:$(echo 'service_'$flag3 | openssl passwd -5 -salt xyz -stdin 2>/dev/null || echo '$5$xyz$YzQs3WTG7PnJ3YzKqQ8xN/'):18000:0:99999:7:::" >> /etc/shadow

# ===========================================================================
# OWASP IoT-02: Insecure Network Services (SSH instead of telnet)
# ===========================================================================

echo "[+] Configuring IoT-02: Insecure Network Services (SSH)..."

# EASY FLAG 2: SSH banner disclosure
flag4=$(generate_flag 4 "EASY" "SSH banner disclosure")
mkdir -p /etc/ssh
cat > /etc/ssh/sshd_banner << EOF
*************************************************
* AXIS Camera SSH Service                      *
* Firmware: 10.5.0                              *
* Device ID: $flag4                            *
*************************************************
EOF

# Configure SSH with multiple vulnerabilities
mkdir -p /root/.ssh

# MEDIUM FLAG 2: SSH authorized_keys with flag in comment
flag5=$(generate_flag 5 "MEDIUM" "SSH authorized_keys comment")
cat > /root/.ssh/authorized_keys << EOF
# Backup key for admin access - $flag5
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfakecontent admin@axis-camera
EOF
chmod 600 /root/.ssh/authorized_keys

# HARD FLAG 2: SSH private key with weak passphrase
flag6=$(generate_flag 6 "HARD" "SSH private key passphrase hint")
cat > /root/.ssh/backup_key << EOF
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,5C4D93B45A0BF31D63E4AC67EB3A7FB7
Comment: Passphrase hint - $flag6

MIIEpAIBAAKCAQEA3fakekeycontent1234567890abcdefghijklmnop
fakeprivatekeycontentfakeprivatekeycontentfakekey1234567890
-----END RSA PRIVATE KEY-----
EOF
chmod 600 /root/.ssh/backup_key

# Configure SSH daemon (OpenSSH or Dropbear)
if [ -x /usr/sbin/sshd ]; then
    # OpenSSH configuration
    cat > /etc/ssh/sshd_config << EOF
Port 22
Banner /etc/ssh/sshd_banner
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
StrictModes no
MaxAuthTries 100
ClientAliveInterval 0
LoginGraceTime 0
EOF
    /usr/sbin/sshd -f /etc/ssh/sshd_config 2>/dev/null
    echo "    OpenSSH started on port 22"
elif [ -x /usr/sbin/dropbear ]; then
    # Dropbear (common in embedded systems)
    echo "$flag4" > /etc/dropbear/banner
    # Start with weak settings: -w allow root, -g allow password auth
    dropbear -E -B -w -g -p 22 2>/dev/null &
    echo "    Dropbear SSH started on port 22"
fi

# MEDIUM FLAG 3: RTSP stream with weak authentication
flag7=$(generate_flag 7 "MEDIUM" "RTSP stream metadata")
mkdir -p /var/rtsp
cat > /var/rtsp/stream1.sdp << EOF
v=0
o=- 0 0 IN IP4 127.0.0.1
s=AXIS Media Stream
i=$flag7
c=IN IP4 0.0.0.0
m=video 0 RTP/AVP 96
a=rtpmap:96 H264/90000
EOF
chmod 644 /var/rtsp/stream1.sdp

# MEDIUM FLAG 4: MQTT anonymous access
flag8=$(generate_flag 8 "MEDIUM" "MQTT will message")
if [ -x /usr/bin/mosquitto ]; then
    cat > /etc/mosquitto/mosquitto.conf << EOF
listener 1883
allow_anonymous true
persistence true
persistence_location /var/lib/mosquitto/
autosave_interval 60
EOF
    mkdir -p /var/lib/mosquitto
    echo "camera/status/flag:$flag8" > /var/lib/mosquitto/mosquitto.db
    mosquitto -c /etc/mosquitto/mosquitto.conf -d 2>/dev/null
fi

# ===========================================================================
# OWASP IoT-03: Insecure Ecosystem Interfaces (Web, API, Cloud)
# ===========================================================================

echo "[+] Configuring IoT-03: Insecure Web/API Interfaces..."

mkdir -p /var/www/cgi-bin
mkdir -p /var/www/axis-cgi

# EASY FLAG 3: Information disclosure in HTML comment
flag9=$(generate_flag 9 "EASY" "HTML source comment")
cat > /var/www/index.html << EOF
<html>
<head><title>AXIS Camera</title></head>
<body>
<h1>Camera Web Interface</h1>
<!-- TODO: Remove debug info before production -->
<!-- Debug: $flag9 -->
<!-- SSH is available on port 22 with root:pass -->
<a href="/cgi-bin/admin.cgi">Admin Panel</a>
</body>
</html>
EOF

# MEDIUM FLAG 5: Command injection in CGI (basic filtering)
flag10=$(generate_flag 10 "MEDIUM" "Command injection via param.cgi")
cat > /var/www/axis-cgi/param.cgi << 'CGISCRIPT'
#!/bin/sh
echo "Content-type: text/plain"
echo ""
# Extract parameter from query string
PARAM=$(echo "$QUERY_STRING" | sed 's/.*action=//' | sed 's/[;&|]//g')
# Weak filtering - still vulnerable to newline injection
if [ "$PARAM" = "getflag" ]; then
CGISCRIPT
echo "    echo '$flag10'" >> /var/www/axis-cgi/param.cgi
cat >> /var/www/axis-cgi/param.cgi << 'CGISCRIPT'
else
    eval "echo Executing: $PARAM"
fi
CGISCRIPT
chmod 755 /var/www/axis-cgi/param.cgi

# HARD FLAG 3: Blind command injection (no output)
flag11=$(generate_flag 11 "HARD" "Blind injection in pwdgrp.cgi")
cat > /var/www/axis-cgi/pwdgrp.cgi << 'CGISCRIPT'
#!/bin/sh
echo "Content-type: text/plain"
echo ""
echo "Processing..."
USER=$(echo "$QUERY_STRING" | sed 's/.*user=//' | cut -d'&' -f1)
# Vulnerable but output redirected
CGISCRIPT
echo "echo '$flag11' > /tmp/.flag_\$USER 2>/dev/null" >> /var/www/axis-cgi/pwdgrp.cgi
echo 'eval "id $USER" > /dev/null 2>&1' >> /var/www/axis-cgi/pwdgrp.cgi
echo 'echo "Done"' >> /var/www/axis-cgi/pwdgrp.cgi
chmod 755 /var/www/axis-cgi/pwdgrp.cgi

# MEDIUM FLAG 6: Path traversal with basic filtering
flag12=$(generate_flag 12 "MEDIUM" "Path traversal in download.cgi")
echo "$flag12" > /var/config/system.conf
cat > /var/www/cgi-bin/download.cgi << 'CGISCRIPT'
#!/bin/sh
echo "Content-type: text/plain"
echo ""
FILE=$(echo "$QUERY_STRING" | sed 's/.*file=//' | sed 's/\.\.\///g')
# Weak filter - bypass with ....// or URL encoding
if [ -f "/var/www/files/$FILE" ]; then
    cat "/var/www/files/$FILE"
else
    # Vulnerable to traversal
    cat "$FILE" 2>/dev/null || echo "File not found"
fi
CGISCRIPT
chmod 755 /var/www/cgi-bin/download.cgi

# ===========================================================================
# OWASP IoT-04: Lack of Secure Update Mechanism
# ===========================================================================

echo "[+] Configuring IoT-04: Insecure Update Mechanism..."

# MEDIUM FLAG 7: Unsigned firmware update
flag13=$(generate_flag 13 "MEDIUM" "Firmware update manifest")
cat > /etc/firmware_update.sh << EOFSCRIPT
#!/bin/sh
# Vulnerable firmware update - no signature verification
FW_URL=\$1
echo "Checking firmware: $flag13"
if [ -n "\$FW_URL" ]; then
    wget "\$FW_URL" -O /tmp/firmware.bin 2>/dev/null
    # No signature check!
    echo "Firmware downloaded (NOT VERIFIED)"
fi
EOFSCRIPT
chmod 755 /etc/firmware_update.sh

# HARD FLAG 4: Hardcoded update server with DNS hijacking potential
flag14=$(generate_flag 14 "HARD" "Hardcoded update server")
cat > /usr/local/bin/check_updates << EOFSCRIPT
#!/bin/sh
# Hardcoded update server - vulnerable to DNS hijacking
UPDATE_SERVER="updates.axis-cam.local"
echo "Connecting to update server..."
echo "Server fingerprint: $flag14"
# Would connect via HTTP (not HTTPS)
EOFSCRIPT
chmod 755 /usr/local/bin/check_updates

# ===========================================================================
# OWASP IoT-05: Use of Insecure or Outdated Components
# ===========================================================================

echo "[+] Configuring IoT-05: Outdated Components..."

# MEDIUM FLAG 8: Old vulnerable service version
flag15=$(generate_flag 15 "MEDIUM" "Legacy service version")
cat > /usr/sbin/legacy_daemon << EOFSCRIPT
#!/bin/sh
echo "Legacy Daemon v1.0 (CVE-2017-9765 vulnerable)"
echo "Service ID: $flag15"
while true; do
    sleep 300
done
EOFSCRIPT
chmod 755 /usr/sbin/legacy_daemon

# ===========================================================================
# OWASP IoT-06: Insufficient Privacy Protection
# ===========================================================================

echo "[+] Configuring IoT-06: Privacy Issues..."

# EASY FLAG 4: Unencrypted stream URLs with credentials
flag16=$(generate_flag 16 "EASY" "Exposed stream URL")
cat > /var/www/streams.txt << EOF
# Camera Stream URLs (should be encrypted!)
rtsp://admin:admin@192.168.1.100:554/stream1
rtsp://root:pass@192.168.1.100:554/stream2?token=$flag16
http://192.168.1.100:8080/video.mjpg
EOF
chmod 644 /var/www/streams.txt

# ===========================================================================
# OWASP IoT-07: Insecure Data Transfer and Storage
# ===========================================================================

echo "[+] Configuring IoT-07: Insecure Data Storage..."

# MEDIUM FLAG 9: Plaintext API keys
flag17=$(generate_flag 17 "MEDIUM" "API key in config")
mkdir -p /etc/config
cat > /etc/config/api.conf << EOF
# Cloud API Configuration
api_endpoint=https://api.axis-cloud.com
api_key=sk_live_$flag17
api_secret=axis_cloud_2024
upload_enabled=true
EOF
chmod 644 /etc/config/api.conf

# HARD FLAG 5: Weak encryption (XOR with known key)
flag18=$(generate_flag 18 "HARD" "XOR encrypted credential")
# Simple XOR with key 'K' (0x4B)
echo "$flag18" | tr 'A-Za-z0-9' 'L-ZA-Kl-za-k1-90' > /var/config/encrypted_pass
chmod 644 /var/config/encrypted_pass

# Additional SSH-related vulnerability
# HARD FLAG 6: SSH host key predictable seed
flag19=$(generate_flag 19 "HARD" "SSH host key seed")
cat > /etc/ssh/host_key_seed << EOF
# Weak seed used for SSH host key generation
# Seed: AXIS_CAMERA_2024_$flag19
# This allows prediction of host keys
EOF
chmod 644 /etc/ssh/host_key_seed

# ===========================================================================
# OWASP IoT-08: Lack of Device Management
# ===========================================================================

echo "[+] Configuring IoT-08: Device Management Issues..."

# MEDIUM FLAG 10: Debug interface enabled
flag20=$(generate_flag 20 "MEDIUM" "Debug interface")
cat > /sys/debug/enabled << EOF
DEBUG_MODE=1
DEBUG_PORT=9999
DEBUG_TOKEN=$flag20
SSH_DEBUG=1
EOF
chmod 644 /sys/debug/enabled 2>/dev/null

# HARD FLAG 7: Hidden maintenance backdoor via SSH
flag21=$(generate_flag 21 "HARD" "SSH maintenance backdoor")
# Create backdoor SSH key
mkdir -p /var/.hidden
cat > /var/.hidden/backdoor_key << EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7backdoor maintenance@axis
# Backdoor access code: $flag21
EOF
# Add to authorized_keys
cat /var/.hidden/backdoor_key >> /root/.ssh/authorized_keys 2>/dev/null
chmod 600 /var/.hidden/backdoor_key

# ===========================================================================
# OWASP IoT-09: Insecure Default Settings
# ===========================================================================

echo "[+] Configuring IoT-09: Insecure Defaults..."

# EASY FLAG 5: Default SNMP community string
flag22=$(generate_flag 22 "EASY" "SNMP community string")
cat > /etc/snmp/snmpd.conf << EOF
rocommunity public
rwcommunity private
syslocation Server Room
syscontact admin@axis.local
sysdescr AXIS Camera $flag22
EOF

# MEDIUM FLAG 11: UPnP enabled with info disclosure
flag23=$(generate_flag 23 "MEDIUM" "UPnP device description")
mkdir -p /etc/upnp
cat > /etc/upnp/device.xml << EOF
<?xml version="1.0"?>
<device>
    <deviceType>urn:schemas-axis-com:device:Camera:1</deviceType>
    <friendlyName>AXIS Camera</friendlyName>
    <manufacturer>AXIS Communications</manufacturer>
    <modelName>P3375-V</modelName>
    <serialNumber>ACCC8E$flag23</serialNumber>
    <UDN>uuid:$flag23</UDN>
</device>
EOF
chmod 644 /etc/upnp/device.xml

# ===========================================================================
# OWASP IoT-10: Lack of Physical Hardening
# ===========================================================================

echo "[+] Configuring IoT-10: Physical Access vulnerabilities..."

# HARD FLAG 8: UART console with bootloader access
flag24=$(generate_flag 24 "HARD" "U-Boot environment")
mkdir -p /boot
cat > /boot/uboot.env << EOF
bootdelay=3
baudrate=115200
bootcmd=run bootaxis
bootargs=console=ttyS0,115200
unlock_code=$flag24
ssh_enabled=1
EOF
chmod 644 /boot/uboot.env

# HARD FLAG 9: JTAG debug information
flag25=$(generate_flag 25 "HARD" "JTAG boundary scan")
cat > /sys/devices/jtag/idcode << EOF
IDCODE: 0x4BA00477
DEVICE: ARM Cortex-A9
DEBUG_KEY: $flag25
SSH_JTAG_ENABLED: 1
EOF
chmod 644 /sys/devices/jtag/idcode 2>/dev/null

# ===========================================================================
# Additional Complex Vulnerabilities
# ===========================================================================

echo "[+] Creating advanced exploitation scenarios..."

# HARD FLAG 10: SSRF via webhook configuration
flag26=$(generate_flag 26 "HARD" "SSRF via webhook")
cat > /var/www/axis-cgi/webhook.cgi << 'CGISCRIPT'
#!/bin/sh
echo "Content-type: text/plain"
echo ""
URL=$(echo "$QUERY_STRING" | sed 's/.*url=//' | cut -d'&' -f1)
# Vulnerable SSRF - can access internal services
if [ -n "$URL" ]; then
    # Check internal SSH service
    if echo "$URL" | grep -q "127.0.0.1:22"; then
CGISCRIPT
echo "        echo 'Internal SSH service flag: $flag26'" >> /var/www/axis-cgi/webhook.cgi
cat >> /var/www/axis-cgi/webhook.cgi << 'CGISCRIPT'
    elif echo "$URL" | grep -q "127.0.0.1:8888"; then
        echo "Internal admin panel active"
    else
        wget -q -O - "$URL" 2>/dev/null | head -n 10
    fi
fi
CGISCRIPT
chmod 755 /var/www/axis-cgi/webhook.cgi

# MEDIUM FLAG 12: SSH configuration leak
flag27=$(generate_flag 27 "MEDIUM" "SSH config disclosure")
cat > /var/www/backup/ssh_config_backup.txt << EOF
# SSH Configuration Backup
# Created: $(date)
# Flag: $flag27
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM no
EOF
chmod 644 /var/www/backup/ssh_config_backup.txt 2>/dev/null
mkdir -p /var/www/backup
echo "$flag27" > /var/www/backup/.hidden_flag
chmod 644 /var/www/backup/.hidden_flag

# ===========================================================================
# Create httpd configuration and start services
# ===========================================================================

echo "[+] Starting vulnerable services..."

# Configure and start httpd
cat > /etc/httpd.conf << 'EOF'
A:*
.cgi:/bin/sh
D:*
/cgi-bin:admin:admin
EOF

# Start httpd if available
if [ -x /usr/sbin/httpd ]; then
    httpd -f -p 80 -h /var/www -c /etc/httpd.conf &
    echo "    HTTP server started on port 80"
fi

# Create SUID binary for privilege escalation
echo "[+] Creating privilege escalation vectors..."
if [ -f /bin/busybox ]; then
    cp /bin/busybox /tmp/busybox_suid
    chmod 4755 /tmp/busybox_suid
    flag28=$(generate_flag 28 "MEDIUM" "SUID busybox privesc")
    echo "$flag28" > /root/suid_flag
    chmod 600 /root/suid_flag
fi

# Create world-writable script for hijacking
flag29=$(generate_flag 29 "MEDIUM" "Script hijacking")
cat > /usr/local/bin/backup.sh << EOFSCRIPT
#!/bin/sh
echo "Running backup..."
echo "Backup ID: $flag29"
# Also backup SSH keys
cp -r /root/.ssh /backup/ 2>/dev/null
EOFSCRIPT
chmod 777 /usr/local/bin/backup.sh

# Add to cron (if cron available)
if [ -d /etc/cron.d ]; then
    echo "*/10 * * * * root /usr/local/bin/backup.sh" > /etc/cron.d/backup
fi

# ===========================================================================
# Documentation and Cleanup
# ===========================================================================

echo ""
echo "[*] Setup complete! CTF Flags created:"
echo "==========================================="
echo ""
echo "Flag Distribution (Total: 29 flags):"
echo "  Easy flags (5): Flags 1, 4, 9, 16, 22"
echo "  Medium flags (12): Flags 2, 5, 7, 8, 10, 12, 13, 15, 17, 20, 23, 27, 28, 29"
echo "  Hard flags (12): Flags 3, 6, 11, 14, 18, 19, 21, 24, 25, 26"
echo ""
echo "OWASP IoT Top 10 Coverage:"
echo "  IoT-01: Weak Passwords - Flags 1, 2, 3"
echo "  IoT-02: Insecure Network Services (SSH) - Flags 4, 5, 6, 7, 8"
echo "  IoT-03: Insecure Ecosystem Interfaces - Flags 9, 10, 11, 12"
echo "  IoT-04: Lack of Secure Update - Flags 13, 14"
echo "  IoT-05: Outdated Components - Flag 15"
echo "  IoT-06: Insufficient Privacy - Flag 16"
echo "  IoT-07: Insecure Data Transfer - Flags 17, 18, 19"
echo "  IoT-08: Lack of Device Management - Flags 20, 21"
echo "  IoT-09: Insecure Default Settings - Flags 22, 23"
echo "  IoT-10: Lack of Physical Hardening - Flags 24, 25"
echo ""
echo "SSH-Specific Attack Vectors:"
echo "  - SSH banner information disclosure (port 22)"
echo "  - Weak SSH configuration allowing root login"
echo "  - SSH authorized_keys with flags in comments"
echo "  - SSH private keys with weak passphrases"
echo "  - SSH host key predictability"
echo "  - SSH backdoor keys in hidden directories"
echo ""
echo "Key Attack Vectors to Test:"
echo "  1. Check SSH on port 22 for banner and weak auth"
echo "  2. Look for SSH keys in /root/.ssh/ and backup directories"
echo "  3. Check configuration files in /etc/axis/, /var/config/"
echo "  4. Test CGI endpoints for command injection"
echo "  5. Enumerate RTSP streams on port 554"
echo "  6. Look for SUID binaries and writable scripts"
echo "  7. Test path traversal in download endpoints"
echo "  8. Analyze base64 encoded data"
echo "  9. Check for hidden/dot files"
echo "  10. Test SSRF via webhook endpoints"
echo "  11. Check for exposed SSH configuration backups"
echo "  12. Look for backdoor SSH keys in authorized_keys"
echo ""
echo "Services Running:"
ps | grep -E "httpd|sshd|dropbear|mosquitto" | grep -v grep
echo ""
echo "SSH Service Status:"
if [ -x /usr/sbin/sshd ]; then
    echo "  OpenSSH is configured on port 22"
elif [ -x /usr/sbin/dropbear ]; then
    echo "  Dropbear SSH is configured on port 22"
else
    echo "  No SSH service found - install openssh-server or dropbear"
fi
echo ""
echo "Flag list saved to: /tmp/ctf_flags.log"
echo ""
echo "WARNING: This system is now INTENTIONALLY VULNERABLE!"
echo "Only use in isolated, controlled environments!"
echo "==========================================="
