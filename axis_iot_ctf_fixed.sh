#!/bin/sh
# AXIS Camera IoT CTF Configuration Script v3
# Fixed for minimal BusyBox (no cksum, no base64)
# POSIX-compliant shell script
# Maps to OWASP IoT Top 10 with LOTR-themed flags

# WARNING: FOR ISOLATED LAB ENVIRONMENT ONLY
# This script creates intentional vulnerabilities for education

echo "==========================================="
echo "AXIS CAMERA IoT CTF SETUP v3.0"
echo "OWASP IoT Top 10 Training Environment"
echo "Minimal BusyBox Compatible Version"
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

# Function to generate deterministic flag without cksum
generate_flag() {
    position=$1
    difficulty=$2
    location=$3
    
    # Select LOTR name based on position
    name_index=$(( position % 25 + 1 ))
    lotr_name=$(echo $LOTR_NAMES | cut -d' ' -f$name_index)
    
    # Generate deterministic 8-digit number using simple hash alternative
    # Use length of hostname + position for deterministic value
    seed="${position}${HOSTNAME}"
    # Simple deterministic hash using string length and character values
    hash_val=0
    for i in $(seq 1 $(echo "$seed" | wc -c)); do
        hash_val=$(( hash_val + position * i * 31 ))
    done
    # Ensure 8 digits
    digits=$(printf "%08d" $(( (hash_val % 100000000) + 10000000 )))
    digits=$(echo "$digits" | tail -c 9)
    
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

# Function to encode without base64 (simple hex encoding)
simple_encode() {
    # Simple ROT13-like encoding for ASCII
    echo "$1" | tr 'A-Za-z0-9' 'N-ZA-Mn-za-m5-90-4'
}

echo "[*] Starting IoT vulnerability configuration..."

# ===========================================================================
# OWASP IoT-01: Weak, Guessable, or Hardcoded Passwords
# ===========================================================================

echo "[+] Configuring IoT-01: Weak Password vulnerabilities..."

# Create necessary directories first
ensure_dir "/etc/axis"
ensure_dir "/var/config"
ensure_dir "/tmp"

# EASY FLAG 1: Default credentials in plaintext config
flag1=$(generate_flag 1 "EASY" "VAPIX config file")
cat > /tmp/vapix.conf << EOF
# VAPIX API Configuration
api_version=1.4
admin_user=root
admin_password=pass
camera_id=$flag1
EOF
# Move to target if possible, otherwise keep in /tmp
mv /tmp/vapix.conf /etc/axis/vapix.conf 2>/dev/null || cp /tmp/vapix.conf /etc/vapix.conf 2>/dev/null || true
chmod 644 /etc/axis/vapix.conf 2>/dev/null || chmod 644 /etc/vapix.conf 2>/dev/null || chmod 644 /tmp/vapix.conf 2>/dev/null

# MEDIUM FLAG 1: Encoded credentials (using simple encoding instead of base64)
flag2=$(generate_flag 2 "MEDIUM" "Encoded ONVIF credentials")
encoded_creds=$(simple_encode "onvif:camera123:$flag2")
cat > /tmp/onvif_auth << EOF
# ONVIF Authentication (ROT13 encoded)
auth_data=$encoded_creds
EOF
mv /tmp/onvif_auth /var/config/onvif_auth 2>/dev/null || cp /tmp/onvif_auth /var/onvif_auth 2>/dev/null || true
chmod 644 /var/config/onvif_auth 2>/dev/null || chmod 644 /var/onvif_auth 2>/dev/null || chmod 644 /tmp/onvif_auth 2>/dev/null

# HARD FLAG 1: Weak password in shadow file (if writable)
flag3=$(generate_flag 3 "HARD" "Service account shadow entry")
# Try to append to shadow if it exists and is writable
if [ -w /etc/shadow ]; then
    echo "service:\$1\$xyz\$YzQs3WTG7PnJ3YzKqQ8xN/:18000:0:99999:7:::" >> /etc/shadow
    echo "# Password hint: service_$flag3" >> /tmp/shadow_hint.txt
else
    echo "service:\$1\$xyz\$YzQs3WTG7PnJ3YzKqQ8xN/:18000:0:99999:7:::" > /tmp/shadow_excerpt
    echo "# Password hint: service_$flag3" >> /tmp/shadow_excerpt
fi

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
mv /tmp/sshd_banner /etc/ssh/sshd_banner 2>/dev/null || true
chmod 644 /etc/ssh/sshd_banner 2>/dev/null || chmod 644 /tmp/sshd_banner 2>/dev/null

# MEDIUM FLAG 2: SSH authorized_keys with flag in comment
flag5=$(generate_flag 5 "MEDIUM" "SSH authorized_keys comment")
cat > /tmp/authorized_keys << EOF
# Backup key for admin access - $flag5
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfakecontent admin@axis
EOF
mv /tmp/authorized_keys /root/.ssh/authorized_keys 2>/dev/null || true
chmod 600 /root/.ssh/authorized_keys 2>/dev/null || chmod 600 /tmp/authorized_keys 2>/dev/null

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
mv /tmp/stream1.sdp /var/rtsp/stream1.sdp 2>/dev/null || true
chmod 644 /var/rtsp/stream1.sdp 2>/dev/null || chmod 644 /tmp/stream1.sdp 2>/dev/null

# ===========================================================================
# OWASP IoT-03: Insecure Ecosystem Interfaces (Web, API, Cloud)
# ===========================================================================

echo "[+] Configuring IoT-03: Insecure Web/API Interfaces..."

ensure_dir "/var/www"
ensure_dir "/var/www/cgi-bin"
ensure_dir "/var/www/axis-cgi"

# EASY FLAG 3: Information disclosure in HTML comment
flag7=$(generate_flag 7 "EASY" "HTML source comment")
cat > /tmp/index.html << EOF
<html>
<head><title>AXIS Camera</title></head>
<body>
<h1>Camera Web Interface</h1>
<!-- TODO: Remove debug info before production -->
<!-- Debug: $flag7 -->
<a href="/cgi-bin/admin.cgi">Admin Panel</a>
</body>
</html>
EOF
mv /tmp/index.html /var/www/index.html 2>/dev/null || true

# MEDIUM FLAG 4: Command injection in CGI
flag8=$(generate_flag 8 "MEDIUM" "Command injection via param.cgi")
cat > /tmp/param.cgi << CGISCRIPT
#!/bin/sh
echo "Content-type: text/plain"
echo ""
# Extract parameter from query string
PARAM=\$(echo "\$QUERY_STRING" | sed 's/.*action=//' | sed 's/[;&|]//g')
if [ "\$PARAM" = "getflag" ]; then
    echo "$flag8"
else
    eval "echo Executing: \$PARAM"
fi
CGISCRIPT
mv /tmp/param.cgi /var/www/axis-cgi/param.cgi 2>/dev/null || cp /tmp/param.cgi /var/www/param.cgi 2>/dev/null || true
chmod 755 /var/www/axis-cgi/param.cgi 2>/dev/null || chmod 755 /var/www/param.cgi 2>/dev/null || chmod 755 /tmp/param.cgi 2>/dev/null

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
mv /tmp/pwdgrp.cgi /var/www/axis-cgi/pwdgrp.cgi 2>/dev/null || cp /tmp/pwdgrp.cgi /var/www/pwdgrp.cgi 2>/dev/null || true
chmod 755 /var/www/axis-cgi/pwdgrp.cgi 2>/dev/null || chmod 755 /var/www/pwdgrp.cgi 2>/dev/null || chmod 755 /tmp/pwdgrp.cgi 2>/dev/null

# MEDIUM FLAG 5: Path traversal
flag10=$(generate_flag 10 "MEDIUM" "Path traversal in download.cgi")
ensure_dir "/var/config"
echo "$flag10" > /tmp/system.conf
mv /tmp/system.conf /var/config/system.conf 2>/dev/null || true

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
mv /tmp/download.cgi /var/www/cgi-bin/download.cgi 2>/dev/null || cp /tmp/download.cgi /var/www/download.cgi 2>/dev/null || true
chmod 755 /var/www/cgi-bin/download.cgi 2>/dev/null || chmod 755 /var/www/download.cgi 2>/dev/null || chmod 755 /tmp/download.cgi 2>/dev/null

# ===========================================================================
# OWASP IoT-04: Lack of Secure Update Mechanism
# ===========================================================================

echo "[+] Configuring IoT-04: Insecure Update Mechanism..."

# MEDIUM FLAG 6: Unsigned firmware update
flag11=$(generate_flag 11 "MEDIUM" "Firmware update manifest")
cat > /tmp/firmware_update.sh << EOFSCRIPT
#!/bin/sh
# Vulnerable firmware update - no signature verification
echo "Checking firmware: $flag11"
FW_URL=\$1
if [ -n "\$FW_URL" ]; then
    wget "\$FW_URL" -O /tmp/firmware.bin 2>/dev/null || echo "Download failed"
    echo "Firmware downloaded (NOT VERIFIED)"
fi
EOFSCRIPT
chmod 755 /tmp/firmware_update.sh
cp /tmp/firmware_update.sh /etc/firmware_update.sh 2>/dev/null || true

# HARD FLAG 3: Hardcoded update server
flag12=$(generate_flag 12 "HARD" "Hardcoded update server")
ensure_dir "/usr/local/bin"
cat > /tmp/check_updates << EOFSCRIPT
#!/bin/sh
UPDATE_SERVER="updates.axis-cam.local"
echo "Connecting to update server..."
echo "Server fingerprint: $flag12"
EOFSCRIPT
mv /tmp/check_updates /usr/local/bin/check_updates 2>/dev/null || cp /tmp/check_updates /tmp/check_updates_exec 2>/dev/null
chmod 755 /usr/local/bin/check_updates 2>/dev/null || chmod 755 /tmp/check_updates_exec 2>/dev/null

# ===========================================================================
# OWASP IoT-05: Use of Insecure or Outdated Components
# ===========================================================================

echo "[+] Configuring IoT-05: Outdated Components..."

# MEDIUM FLAG 7: Old vulnerable service version
flag13=$(generate_flag 13 "MEDIUM" "Legacy service version")
ensure_dir "/usr/sbin"
cat > /tmp/legacy_daemon << EOFSCRIPT
#!/bin/sh
echo "Legacy Daemon v1.0 (CVE-2017-9765 vulnerable)"
echo "Service ID: $flag13"
EOFSCRIPT
mv /tmp/legacy_daemon /usr/sbin/legacy_daemon 2>/dev/null || cp /tmp/legacy_daemon /tmp/legacy_daemon_exec 2>/dev/null
chmod 755 /usr/sbin/legacy_daemon 2>/dev/null || chmod 755 /tmp/legacy_daemon_exec 2>/dev/null

# ===========================================================================
# OWASP IoT-06: Insufficient Privacy Protection
# ===========================================================================

echo "[+] Configuring IoT-06: Privacy Issues..."

# EASY FLAG 4: Unencrypted stream URLs
flag14=$(generate_flag 14 "EASY" "Exposed stream URL")
cat > /tmp/streams.txt << EOF
# Camera Stream URLs (should be encrypted!)
rtsp://admin:admin@192.168.1.100:554/stream1
rtsp://root:pass@192.168.1.100:554/stream2?token=$flag14
http://192.168.1.100:8080/video.mjpg
EOF
mv /tmp/streams.txt /var/www/streams.txt 2>/dev/null || true
chmod 644 /var/www/streams.txt 2>/dev/null || chmod 644 /tmp/streams.txt 2>/dev/null

# ===========================================================================
# OWASP IoT-07: Insecure Data Transfer and Storage
# ===========================================================================

echo "[+] Configuring IoT-07: Insecure Data Storage..."

# MEDIUM FLAG 8: Plaintext API keys
flag15=$(generate_flag 15 "MEDIUM" "API key in config")
ensure_dir "/etc/config"
cat > /tmp/api.conf << EOF
# Cloud API Configuration
api_endpoint=https://api.axis-cloud.com
api_key=sk_live_$flag15
api_secret=axis_cloud_2024
EOF
mv /tmp/api.conf /etc/config/api.conf 2>/dev/null || cp /tmp/api.conf /etc/api.conf 2>/dev/null || true
chmod 644 /etc/config/api.conf 2>/dev/null || chmod 644 /etc/api.conf 2>/dev/null || chmod 644 /tmp/api.conf 2>/dev/null

# HARD FLAG 4: Weakly encoded credential
flag16=$(generate_flag 16 "HARD" "Encoded credential")
encoded_flag=$(simple_encode "$flag16")
echo "$encoded_flag" > /tmp/encrypted_pass
mv /tmp/encrypted_pass /var/config/encrypted_pass 2>/dev/null || true
chmod 644 /var/config/encrypted_pass 2>/dev/null || chmod 644 /tmp/encrypted_pass 2>/dev/null

# ===========================================================================
# OWASP IoT-08: Lack of Device Management
# ===========================================================================

echo "[+] Configuring IoT-08: Device Management Issues..."

# MEDIUM FLAG 9: Debug interface enabled
flag17=$(generate_flag 17 "MEDIUM" "Debug interface")
ensure_dir "/sys/debug"
cat > /tmp/debug_enabled << EOF
DEBUG_MODE=1
DEBUG_PORT=9999
DEBUG_TOKEN=$flag17
SSH_DEBUG=1
EOF
mv /tmp/debug_enabled /sys/debug/enabled 2>/dev/null || cp /tmp/debug_enabled /tmp/debug_settings 2>/dev/null
chmod 644 /sys/debug/enabled 2>/dev/null || chmod 644 /tmp/debug_settings 2>/dev/null

# HARD FLAG 5: Hidden maintenance backdoor
flag18=$(generate_flag 18 "HARD" "SSH maintenance backdoor")
ensure_dir "/var/.hidden"
cat > /tmp/backdoor_key << EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7backdoor maintenance@axis
# Backdoor access code: $flag18
EOF
mv /tmp/backdoor_key /var/.hidden/backdoor_key 2>/dev/null || true
chmod 600 /var/.hidden/backdoor_key 2>/dev/null || chmod 600 /tmp/backdoor_key 2>/dev/null

# ===========================================================================
# OWASP IoT-09: Insecure Default Settings
# ===========================================================================

echo "[+] Configuring IoT-09: Insecure Defaults..."

# EASY FLAG 5: Default SNMP community string
flag19=$(generate_flag 19 "EASY" "SNMP community string")
ensure_dir "/etc/snmp"
cat > /tmp/snmpd.conf << EOF
rocommunity public
rwcommunity private
syslocation Server Room
syscontact admin@axis.local
sysdescr AXIS Camera $flag19
EOF
mv /tmp/snmpd.conf /etc/snmp/snmpd.conf 2>/dev/null || cp /tmp/snmpd.conf /etc/snmpd.conf 2>/dev/null || true
chmod 644 /etc/snmp/snmpd.conf 2>/dev/null || chmod 644 /etc/snmpd.conf 2>/dev/null || chmod 644 /tmp/snmpd.conf 2>/dev/null

# MEDIUM FLAG 10: UPnP enabled with info disclosure
flag20=$(generate_flag 20 "MEDIUM" "UPnP device description")
ensure_dir "/etc/upnp"
cat > /tmp/device.xml << EOF
<?xml version="1.0"?>
<device>
    <serialNumber>ACCC8E$flag20</serialNumber>
    <UDN>uuid:$flag20</UDN>
</device>
EOF
mv /tmp/device.xml /etc/upnp/device.xml 2>/dev/null || cp /tmp/device.xml /etc/device.xml 2>/dev/null || true
chmod 644 /etc/upnp/device.xml 2>/dev/null || chmod 644 /etc/device.xml 2>/dev/null || chmod 644 /tmp/device.xml 2>/dev/null

# ===========================================================================
# OWASP IoT-10: Lack of Physical Hardening
# ===========================================================================

echo "[+] Configuring IoT-10: Physical Access vulnerabilities..."

# HARD FLAG 6: UART console with bootloader access
flag21=$(generate_flag 21 "HARD" "U-Boot environment")
ensure_dir "/boot"
cat > /tmp/uboot.env << EOF
bootdelay=3
baudrate=115200
unlock_code=$flag21
EOF
mv /tmp/uboot.env /boot/uboot.env 2>/dev/null || cp /tmp/uboot.env /tmp/boot_config 2>/dev/null
chmod 644 /boot/uboot.env 2>/dev/null || chmod 644 /tmp/boot_config 2>/dev/null

# HARD FLAG 7: JTAG debug information
flag22=$(generate_flag 22 "HARD" "JTAG boundary scan")
cat > /tmp/jtag_idcode << EOF
IDCODE: 0x4BA00477
DEBUG_KEY: $flag22
EOF
mv /tmp/jtag_idcode /sys/devices/jtag/idcode 2>/dev/null || cp /tmp/jtag_idcode /tmp/jtag_info 2>/dev/null
chmod 644 /sys/devices/jtag/idcode 2>/dev/null || chmod 644 /tmp/jtag_info 2>/dev/null

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
    wget -q -O - "\$URL" 2>/dev/null | head -n 10 || echo "Failed to fetch"
fi
CGISCRIPT
mv /tmp/webhook.cgi /var/www/axis-cgi/webhook.cgi 2>/dev/null || cp /tmp/webhook.cgi /var/www/webhook.cgi 2>/dev/null || true
chmod 755 /var/www/axis-cgi/webhook.cgi 2>/dev/null || chmod 755 /var/www/webhook.cgi 2>/dev/null || chmod 755 /tmp/webhook.cgi 2>/dev/null

# MEDIUM FLAG 11: SSH configuration leak
flag24=$(generate_flag 24 "MEDIUM" "SSH config disclosure")
ensure_dir "/var/www/backup"
cat > /tmp/ssh_config_backup.txt << EOF
# SSH Configuration Backup
# Flag: $flag24
PasswordAuthentication yes
EOF
mv /tmp/ssh_config_backup.txt /var/www/backup/ssh_config_backup.txt 2>/dev/null || cp /tmp/ssh_config_backup.txt /tmp/ssh_backup 2>/dev/null
chmod 644 /var/www/backup/ssh_config_backup.txt 2>/dev/null || chmod 644 /tmp/ssh_backup 2>/dev/null

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
else
    echo "    HTTP server not found"
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
cp /tmp/backup.sh /usr/local/bin/backup.sh 2>/dev/null || true

# HARD FLAG 9: Race condition
flag27=$(generate_flag 27 "HARD" "Race condition")
cat > /tmp/race.sh << EOFSCRIPT
#!/bin/sh
# Race condition vulnerability
echo "$flag27" > /tmp/race_flag
sleep 0.1
rm /tmp/race_flag
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
echo "  Easy flags (5): Plaintext configs, HTML comments, banners"
echo "  Medium flags (13): Encoded data, filtered injection, SUID"
echo "  Hard flags (9): Blind injection, race conditions, UART/JTAG"
echo ""
echo "Files created in accessible locations:"
echo "  /tmp/* - Most configuration and flag files"
echo "  /var/www/* - Web server files (if directory exists)"
echo "  /etc/* - System configuration (if writable)"
echo ""
echo "OWASP IoT Top 10 Coverage:"
echo "  IoT-01: Weak Passwords - Check /tmp/*auth files"
echo "  IoT-02: Insecure Services - SSH config in /tmp"
echo "  IoT-03: Insecure Interfaces - CGI scripts in /var/www"
echo "  IoT-04: Insecure Updates - Update scripts in /tmp"
echo "  IoT-05: Outdated Components - Legacy daemon"
echo "  IoT-06: Privacy Issues - Stream URLs"
echo "  IoT-07: Insecure Storage - API keys"
echo "  IoT-08: Device Management - Debug settings"
echo "  IoT-09: Insecure Defaults - SNMP configs"
echo "  IoT-10: Physical Hardening - Boot/JTAG info"
echo ""
echo "Attack vectors to test:"
echo "  1. Check /tmp directory for most flag files"
echo "  2. Test CGI endpoints if web server is running"
echo "  3. Look for encoded data (ROT13-like encoding)"
echo "  4. Check for SUID binaries (/tmp/busybox_suid)"
echo "  5. Test path traversal in download.cgi"
echo "  6. Look for hidden directories (/var/.hidden)"
echo "  7. Check SSH configuration files"
echo "  8. Test for race conditions (/tmp/race.sh)"
echo ""
echo "Services Status:"
ps | grep -E "httpd|sshd|dropbear" | grep -v grep || echo "  No services detected running"
echo ""
echo "Flag list saved to: /tmp/ctf_flags.log"
echo ""
echo "Note: Due to limited utilities (no cksum, no base64),"
echo "some vulnerabilities use simplified implementations."
echo ""
echo "WARNING: This system is now INTENTIONALLY VULNERABLE!"
echo "Only use in isolated, controlled environments!"
echo "==========================================="
