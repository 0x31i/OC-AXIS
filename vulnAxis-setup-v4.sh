#!/bin/sh
# IoT Camera CTF Setup Script v4.0 - Maximum Distribution Edition
# POSIX-compliant for BusyBox ash
# Flags distributed across ALL writable directories for realistic challenge

echo "[*] Starting Axis Camera CTF setup - Maximum Distribution v4.0"
echo "[*] $(date)"

# ============================================================================
# CREATE REALISTIC AXIS CAMERA DIRECTORY STRUCTURE
# Using ALL available writable locations
# ============================================================================
echo "[+] Creating comprehensive Axis camera directory structure..."

# Core Axis directories in /var
mkdir -p /var/lib/axis/conf
mkdir -p /var/lib/axis/licenses
mkdir -p /var/lib/axis/certificates
mkdir -p /var/cache/axis/vapix
mkdir -p /var/cache/axis/thumbnails
mkdir -p /var/opt/axis/applications
mkdir -p /var/opt/axis/overlays
mkdir -p /var/run/axis/services
mkdir -p /var/www/local/axis-cgi
mkdir -p /var/www/local/admin
mkdir -p /var/spool/cron/crontabs
mkdir -p /var/backups/config
mkdir -p /var/backups/firmware
mkdir -p /var/db/axis
mkdir -p /var/log/axis/services
mkdir -p /var/log/axis/vapix
mkdir -p /var/log/axis/.archived

# Persistent storage directories (/var/lib/persistent)
mkdir -p /var/lib/persistent/system/configs
mkdir -p /var/lib/persistent/system/licenses
mkdir -p /var/lib/persistent/network/certificates
mkdir -p /var/lib/persistent/applications/custom
mkdir -p /var/lib/persistent/security/keys
mkdir -p /var/lib/persistent/firmware/backups

# Recording cache directories (/var/cache/recorder)
mkdir -p /var/cache/recorder/streams/primary
mkdir -p /var/cache/recorder/streams/secondary
mkdir -p /var/cache/recorder/thumbnails
mkdir -p /var/cache/recorder/analytics/motion
mkdir -p /var/cache/recorder/analytics/metadata
mkdir -p /var/cache/recorder/.temp

# Flash storage directories (/mnt/flash)
mkdir -p /mnt/flash/boot/uboot
mkdir -p /mnt/flash/boot/kernel
mkdir -p /mnt/flash/firmware/images
mkdir -p /mnt/flash/firmware/signatures
mkdir -p /mnt/flash/config/factory
mkdir -p /mnt/flash/config/user
mkdir -p /mnt/flash/config/.backup

# Shared memory directories (/dev/shm)
mkdir -p /dev/shm/axis/runtime
mkdir -p /dev/shm/axis/ipc
mkdir -p /dev/shm/axis/streams

# Runtime directories (/run)
mkdir -p /run/axis/services
mkdir -p /run/axis/network
mkdir -p /run/axis/camera
mkdir -p /run/axis/locks

# Custom local applications (/usr/local)
mkdir -p /usr/local/axis/bin
mkdir -p /usr/local/axis/lib
mkdir -p /usr/local/axis/etc
mkdir -p /usr/local/axis/share/scripts

# cgroup directories (/sys/fs/cgroup)
mkdir -p /sys/fs/cgroup/axis/camera.service
mkdir -p /sys/fs/cgroup/axis/network.service

echo "  [✓] Comprehensive directory structure created across all writable locations"

# ============================================================================
# EASY FLAGS (5 flags) - Discoverable with basic enumeration
# ============================================================================

echo ""
echo "[+] Distributing EASY FLAGS across writable directories..."

# Flag #1: Default VAPIX Configuration (/var/lib/axis/conf/)
echo "[+] Flag #1: VAPIX Configuration..."
cat > /var/lib/axis/conf/vapix.conf << 'EOF'
# AXIS VAPIX API Configuration v3.0
# Generated: 2024-01-01 12:00:00

[Network]
api_version=3.0
protocol=http,https
port=80,443

[Authentication]
method=digest
realm=AXIS_ACCC8E

[Device]
model=M1025
firmware=10.5.0
serial=ACCC8E-FLAG{FRODO27189846}
build_date=2024-01-01

[Features]
motion_detection=enabled
audio=disabled
ptz=disabled
EOF
chmod 644 /var/lib/axis/conf/vapix.conf

# Flag #4: SSH Banner in syslog (/var/log/)
echo "[+] Flag #4: System Log Entry..."
cat > /var/log/messages << 'EOF'
Jan  1 12:00:01 axis-camera syslogd: syslogd started: BusyBox v1.31.1
Jan  1 12:00:05 axis-camera kernel: Linux version 4.9.0-axis1 (build@axis.com)
Jan  1 12:00:10 axis-camera sshd[234]: Server listening on 0.0.0.0 port 22
Jan  1 12:00:11 axis-camera sshd[234]: Device-ID: FLAG{GIMLI42137246}
Jan  1 12:00:15 axis-camera network: eth0: link up
Jan  1 12:00:20 axis-camera vapix: VAPIX API started on port 80
Jan  1 12:00:25 axis-camera camera: Video encoder initialized
Jan  1 12:00:30 axis-camera rtsp: RTSP server started on port 554
EOF
chmod 644 /var/log/messages

# Flag #7: HTML Comment in web interface (/var/www/)
echo "[+] Flag #7: Web Interface HTML..."
mkdir -p /var/www/local/admin
cat > /var/www/local/admin/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>AXIS Camera Station</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .status { color: green; }
    </style>
</head>
<body>
    <h1>AXIS Network Camera - Management Interface</h1>
    <div class="status">System Status: Online</div>
    
    <!-- Development Note: Remove before production deployment -->
    <!-- Build version: 10.5.0-dev -->
    <!-- Debug token: FLAG{MERRY36385024} -->
    <!-- Contact: dev-team@axis.com for issues -->
    
    <p>Welcome to the camera management interface.</p>
    <ul>
        <li><a href="/axis-cgi/param.cgi">Parameters</a></li>
        <li><a href="/axis-cgi/admin/systemlog.cgi">System Log</a></li>
        <li><a href="/axis-cgi/mjpg/video.cgi">Live View</a></li>
    </ul>
</body>
</html>
EOF
chmod 644 /var/www/local/admin/index.html
ln -sf /var/www/local/admin/index.html /var/www/index.html 2>/dev/null

# Flag #14: Recording Stream Configuration (/var/cache/recorder/)
echo "[+] Flag #14: Recording Stream Configuration..."
cat > /var/cache/recorder/streams/primary/stream_config.conf << 'EOF'
# Primary Stream Recording Configuration
# Auto-generated by recorder service

[Stream_Settings]
name=MainRecordingStream
resolution=1920x1080
framerate=30
codec=h264
bitrate=4096

[Recording]
enabled=true
path=/var/cache/recorder/storage
retention_days=30
continuous=true

[Authentication]
stream_user=recorder
stream_pass=rec0rd3r
auth_token=FLAG{SARUMAN83479324}

[Analytics]
motion_detection=enabled
object_tracking=enabled
EOF
chmod 644 /var/cache/recorder/streams/primary/stream_config.conf

# Flag #19: Factory Configuration (/mnt/flash/config/factory/)
echo "[+] Flag #19: Factory Configuration..."
cat > /mnt/flash/config/factory/device_info.txt << 'EOF'
# AXIS Device Factory Configuration
# DO NOT MODIFY - Factory sealed settings

[Manufacturing]
serial_number=ACCC8E-M1025-2024
manufacture_date=2024-01-01
manufacturing_site=Sweden_Lund
batch_number=20240101-A

[Quality_Assurance]
test_passed=true
test_date=2024-01-01
test_engineer=qa-team@axis.com
qa_code=FLAG{THEODEN40558954}

[Hardware]
model=M1025
revision=1.0
sensor=Sony_IMX334
processor=ARTPEC-7
EOF
chmod 644 /mnt/flash/config/factory/device_info.txt

# ============================================================================
# MEDIUM FLAGS (13 flags) - Require enumeration + exploitation
# ============================================================================

echo ""
echo "[+] Distributing MEDIUM FLAGS across writable directories..."

# Flag #2: Persistent License File (/var/lib/persistent/)
echo "[+] Flag #2: Persistent License..."
cat > /var/lib/persistent/system/licenses/vapix_pro.lic << 'EOF'
# AXIS VAPIX Professional License
# License Type: Enterprise
# Issued: 2024-01-01

[License_Info]
product=VAPIX_Professional
version=3.0
license_type=perpetual
issued_date=2024-01-01
expiry_date=perpetual

[Activation]
# Activation code (ROT13): SYNT{NENTBEA79305394}
activation_key=VF6K8M2P9HXLQC3R7BNVW4YT
hardware_id=ACCC8E-M1025
status=active

[Features]
api_access=unlimited
analytics=enabled
cloud_integration=enabled
multi_streaming=enabled
EOF
chmod 640 /var/lib/persistent/system/licenses/vapix_pro.lic

# Flag #5: Persistent SSH Keys (/var/lib/persistent/security/)
echo "[+] Flag #5: Persistent SSH Keys..."
cat > /var/lib/persistent/security/keys/authorized_keys << 'EOF'
# AXIS Camera - Persistent Authorized SSH Keys
# Management access keys for remote support

# Production admin key - expires 2025-12-31
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDGpxKjhkL... admin@axis-prod

# Support team backup access - FLAG{BOROMIR73553172}
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCxR8vhNmP... support@axis-backup

# Monitoring service key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDR4vGhTqW... monitor@axis-service
EOF
chmod 600 /var/lib/persistent/security/keys/authorized_keys

# Flag #6: Recording Analytics Metadata (/var/cache/recorder/analytics/)
echo "[+] Flag #6: Analytics Metadata..."
cat > /var/cache/recorder/analytics/metadata/stream_analysis.json << 'EOF'
{
  "stream_info": {
    "stream_id": "primary_001",
    "start_time": "2024-01-01T12:00:00Z",
    "duration_seconds": 3600,
    "format": "h264"
  },
  "analytics": {
    "motion_events": 47,
    "object_detections": 123,
    "people_count": 15,
    "vehicle_count": 8
  },
  "metadata": {
    "description": "Primary stream analytics data",
    "processing_flag": "FLAG{SAMWISE04969098}",
    "version": "2.0"
  },
  "quality_metrics": {
    "average_bitrate": 4096,
    "dropped_frames": 0,
    "encoding_quality": "high"
  }
}
EOF
chmod 644 /var/cache/recorder/analytics/metadata/stream_analysis.json

# Flag #8: Command Injection in param.cgi (/var/www/)
echo "[+] Flag #8: Vulnerable Parameter CGI..."
cat > /var/www/local/axis-cgi/param.cgi << 'CGISCRIPT'
#!/bin/sh
echo "Content-type: text/plain"
echo ""

# Parse action from query string
ACTION=$(echo "$QUERY_STRING" | sed 's/.*action=\([^&]*\).*/\1/' | sed 's/%20/ /g')

case "$ACTION" in
    list)
        echo "root.Brand=AXIS"
        echo "root.ProdNbr=M1025"
        echo "root.ProdType=Network Camera"
        echo "root.Version=10.5.0"
        ;;
    listdefinitions)
        echo "root.Brand (string)"
        echo "root.ProdNbr (string)"
        echo "root.ProdType (string)"
        echo "root.Version (string)"
        ;;
    get)
        PARAM=$(echo "$QUERY_STRING" | sed 's/.*group=\([^&]*\).*/\1/')
        # Vulnerable to command injection via parameter
        eval "echo \"$PARAM.Value=configured\""
        # FLAG{PIPPIN54784931} can be extracted via injection
        ;;
    *)
        echo "Error: Unknown action"
        echo "Supported actions: list, listdefinitions, get"
        ;;
esac
CGISCRIPT
chmod 755 /var/www/local/axis-cgi/param.cgi

# Flag #9: Firmware Signature (/mnt/flash/firmware/)
echo "[+] Flag #9: Firmware Signature..."
cat > /mnt/flash/firmware/signatures/firmware_10.5.0.sig << 'EOF'
# AXIS Firmware Digital Signature
# Firmware Version: 10.5.0
# Build Date: 2024-01-01

[Signature_Info]
algorithm=RSA-SHA256
key_size=4096
signature_format=PKCS1_v1_5

[Verification]
public_key_id=AXIS-ROOT-CA-2024
signature_hash=8f14e45fceea167a5a36dedd4bea2543
verification_url=https://www.axis.com/firmware/verify

[Build_Info]
build_id=20240101_105000
builder=firmware-build@axis.com
build_flag=FLAG{GANDALF19774520}
integrity_check=passed

[Signature_Data]
-----BEGIN SIGNATURE-----
MIIGRgYJKoZIhvcNAQcCoIIGNzCCBjMCAQExDTALBglghkgBZQMEAgEwCwYJKoZI
hvcNAQcBoIIDQTCCAz0wggIloAMCAQICCQDXwnq8...
-----END SIGNATURE-----
EOF
chmod 644 /mnt/flash/firmware/signatures/firmware_10.5.0.sig

# Flag #10: Path Traversal via download.cgi (/var/www/)
echo "[+] Flag #10: Vulnerable Download CGI..."
cat > /var/www/local/axis-cgi/download.cgi << 'CGISCRIPT'
#!/bin/sh
echo "Content-type: application/octet-stream"

# Parse filename from query string - VULNERABLE to path traversal
FILE=$(echo "$QUERY_STRING" | sed 's/.*file=\([^&]*\).*/\1/' | sed 's/%2F/\//g' | sed 's/%2E/./g')

echo "Content-Disposition: attachment; filename=$(basename $FILE)"
echo ""

# Insecure file access - allows path traversal
if [ -f "$FILE" ]; then
    cat "$FILE"
else
    echo "Error: File not found"
    # Hidden flag in error path: FLAG{LEGOLAS81553308}
fi
CGISCRIPT
chmod 755 /var/www/local/axis-cgi/download.cgi

# Flag #11: Runtime Service Configuration (/run/axis/)
echo "[+] Flag #11: Runtime Service Config..."
cat > /run/axis/services/camera_service.conf << 'EOF'
# Camera Service Runtime Configuration
# PID: 1234
# Started: 2024-01-01 12:00:00

[Service]
name=camera-encoder
status=running
pid=1234
uptime=86400

[Runtime_Credentials]
service_user=camera_svc
service_token=c4m3r4_t0k3n_2024
internal_api_key=FLAG{TREEBEARD58447193}

[Resources]
memory_limit=512M
cpu_limit=2.0
priority=high
EOF
chmod 640 /run/axis/services/camera_service.conf

# Flag #12: Custom Application Script (/usr/local/axis/)
echo "[+] Flag #12: Custom Application..."
cat > /usr/local/axis/share/scripts/backup_service.sh << 'SCRIPT'
#!/bin/sh
# AXIS Custom Backup Service
# Installed: 2024-01-01

BACKUP_DIR=/var/backups/config
LOG_FILE=/var/log/axis/backup.log

# Configuration backup function
backup_configs() {
    echo "[$(date)] Starting configuration backup..." >> $LOG_FILE
    
    # API key for backup service
    API_KEY="FLAG{CELEBORN26694785}"
    
    tar -czf $BACKUP_DIR/config_$(date +%Y%m%d).tar.gz \
        /var/lib/axis/conf \
        /var/lib/persistent/system/configs
    
    echo "[$(date)] Backup completed successfully" >> $LOG_FILE
}

backup_configs
SCRIPT
chmod 755 /usr/local/axis/share/scripts/backup_service.sh

# Flag #13: Cgroup Service Limits (/sys/fs/cgroup/)
echo "[+] Flag #13: CGroup Service Configuration..."
cat > /sys/fs/cgroup/axis/camera.service/cgroup.procs << 'EOF'
1234
1235
1236
EOF

cat > /sys/fs/cgroup/axis/camera.service/service.conf << 'EOF'
# Camera Service Control Group Configuration
# Controls resource limits for camera processes

[Limits]
memory_limit=512M
cpu_quota=200000
cpu_period=100000

[Monitoring]
enable_stats=true
stats_interval=60

[Security]
isolation_enabled=true
namespace=camera_ns
security_token=FLAG{GALADRIEL47829561}
EOF
chmod 644 /sys/fs/cgroup/axis/camera.service/service.conf

# Flag #15: UPnP Discovery (/run/axis/network/)
echo "[+] Flag #15: UPnP Service..."
cat > /run/axis/network/upnp_description.xml << 'EOF'
<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
    <specVersion>
        <major>1</major>
        <minor>0</minor>
    </specVersion>
    <device>
        <deviceType>urn:schemas-upnp-org:device:NetworkCamera:1</deviceType>
        <friendlyName>AXIS M1025 Network Camera</friendlyName>
        <manufacturer>AXIS Communications</manufacturer>
        <manufacturerURL>http://www.axis.com</manufacturerURL>
        <modelDescription>AXIS M1025 Network Camera</modelDescription>
        <modelName>M1025</modelName>
        <modelNumber>M1025</modelNumber>
        <serialNumber>ACCC8E</serialNumber>
        <UDN>uuid:axis-m1025-FLAG{HALDIR92336184}-accc8e</UDN>
        <serviceList>
            <service>
                <serviceType>urn:axis-com:service:BasicService:1</serviceType>
                <serviceId>urn:axis-com:serviceId:BasicService</serviceId>
                <SCPDURL>/upnp/BasicService.xml</SCPDURL>
                <controlURL>/upnp/control/BasicService</controlURL>
                <eventSubURL>/upnp/event/BasicService</eventSubURL>
            </service>
        </serviceList>
    </device>
</root>
EOF
chmod 644 /run/axis/network/upnp_description.xml

# Flag #16: Persistent Network Certificates (/var/lib/persistent/)
echo "[+] Flag #16: Persistent Certificates..."
cat > /var/lib/persistent/network/certificates/server_cert.pem << 'EOF'
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAK8yB7v3qZ9RMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMTIwMDAwWhcNMjUwMTAxMTIwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# Certificate issued for: AXIS-M1025-ACCC8E
# Subject: CN=axis-camera.local
# Issuer: CN=AXIS-Root-CA
# Serial: FLAG{ELROND34719845}
# Valid: 2024-01-01 to 2025-01-01
CgKCAQEAwqM5Bk9zqvC8xW6E...
-----END CERTIFICATE-----
EOF
chmod 644 /var/lib/persistent/network/certificates/server_cert.pem

# Flag #17: SUID Binary in /usr/local
echo "[+] Flag #17: Custom SUID Binary..."
cat > /usr/local/axis/bin/camera_admin << 'SCRIPT'
#!/bin/sh
# Camera Administration Utility
# SUID binary for privileged operations

if [ "$1" = "--version" ]; then
    echo "AXIS Camera Admin v1.0"
    echo "Build: 2024-01-01"
    echo "Flag: FLAG{FARAMIR68821477}"
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Must run as root"
    exit 1
fi

echo "Camera administration utility"
echo "Use --version for build info"
SCRIPT
chmod 4755 /usr/local/axis/bin/camera_admin

# ============================================================================
# HARD FLAGS (9 flags) - Advanced techniques required
# ============================================================================

echo ""
echo "[+] Distributing HARD FLAGS across writable directories..."

# Flag #18: Shared Memory IPC (/dev/shm/)
echo "[+] Flag #18: Shared Memory IPC..."
cat > /dev/shm/axis/ipc/camera_control.shm << 'EOF'
# Shared Memory Control Structure
# Used for inter-process communication

[Camera_Control]
command_queue=active
status_ready=true
pid=1234

[IPC_Auth]
shared_secret=0x4a8f2e1c9d3b7a5f
auth_required=true
# Hidden in memory: FLAG{GOLLUM73854692}

[Buffer_Info]
buffer_size=1048576
buffer_count=4
EOF
chmod 600 /dev/shm/axis/ipc/camera_control.shm

# Flag #19: Firmware Backup (/var/lib/persistent/firmware/)
echo "[+] Flag #19: Persistent Firmware Backup..."
dd if=/dev/zero of=/var/lib/persistent/firmware/backups/bootloader.img bs=1024 count=64 2>/dev/null
echo "AXIS-BOOTLOADER-v2.0-FLAG{SMEAGOL95772184}" >> /var/lib/persistent/firmware/backups/bootloader.img
chmod 644 /var/lib/persistent/firmware/backups/bootloader.img

# Flag #20: Hidden Config Backup (/mnt/flash/config/.backup/)
echo "[+] Flag #20: Flash Config Backup..."
cat > /mnt/flash/config/.backup/.shadow_config << 'EOF'
# Shadow Configuration - Development Only
# DO NOT DEPLOY TO PRODUCTION

[Hidden_Settings]
debug_mode=enabled
backdoor_enabled=false
test_account=disabled

[Development_Credentials]
dev_user=axis_dev
dev_pass=d3v_p@ss_2024
maintenance_token=FLAG{WORMTONGUE19485736}

[Build_Info]
build_type=debug
build_machine=dev-build-01.axis.internal
EOF
chmod 600 /mnt/flash/config/.backup/.shadow_config

# Flag #21: Boot Environment (/mnt/flash/boot/uboot/)
echo "[+] Flag #21: U-Boot Environment..."
cat > /mnt/flash/boot/uboot/uboot.env << 'EOF'
# U-Boot Environment Variables
# Extracted from: /dev/mtd0
# Extraction Date: 2024-01-01

bootdelay=3
baudrate=115200
ethaddr=00:40:8c:cc:8e:ff
ipaddr=192.168.1.100
serverip=192.168.1.1
netmask=255.255.255.0

# Boot security
secure_boot=disabled
unlock_code=FLAG{RADAGAST03390806}

# Boot command
bootcmd=nand read 0x1000000 0x100000 0x400000; bootm 0x1000000
bootargs=console=ttyS0,115200 root=/dev/mmcblk0p2 rw rootwait

# Device identification
product_name=AXIS M1025
hardware_version=1.0
EOF
chmod 644 /mnt/flash/boot/uboot/uboot.env

# Flag #22: Hardware Debug (/var/lib/axis/conf/)
echo "[+] Flag #22: Hardware Debug Interface..."
cat > /var/lib/axis/conf/hardware_debug.conf << 'EOF'
# Hardware Debug Interface Configuration
# AXIS M1025 - ARTPEC-7 SoC

[JTAG_Interface]
enabled=false
port=virtual_jtag0
speed=10MHz

[Debug_Information]
chain_id=0x4BA00477
manufacturer=ARM Ltd (0x23B)
part_number=Cortex-A9 (0xBA00)
version=r3p0

[Security]
debug_locked=false
jtag_password=disabled
debug_authentication_key=FLAG{GLORFINDEL34806732}

[Supported_Operations]
boundary_scan=supported
system_trace=supported
debug_halt=supported
memory_access=full
EOF
chmod 640 /var/lib/axis/conf/hardware_debug.conf

# Flag #23: SSRF via Webhook (/var/www/)
echo "[+] Flag #23: Webhook Integration CGI..."
cat > /var/www/local/axis-cgi/webhook.cgi << 'CGISCRIPT'
#!/bin/sh
echo "Content-type: application/json"
echo ""

# Parse webhook URL from query string
WEBHOOK_URL=$(echo "$QUERY_STRING" | sed 's/.*url=\([^&]*\).*/\1/' | sed 's/%3A/:/g' | sed 's/%2F/\//g')

echo "{"
echo '  "status": "processing",'
echo '  "webhook_url": "'$WEBHOOK_URL'",'

# Vulnerable SSRF - makes internal requests
if echo "$WEBHOOK_URL" | grep -q "127.0.0.1:22"; then
    echo '  "response": "SSH Service Active",'
    echo '  "internal_flag": "FLAG{ELENDIL66222658}",'
    echo '  "service": "sshd",'
    echo '  "version": "OpenSSH_7.9p1"'
elif echo "$WEBHOOK_URL" | grep -q "localhost"; then
    echo '  "response": "Internal service accessible",'
    echo '  "status_code": 200'
else
    echo '  "response": "Webhook triggered successfully",'
    echo '  "status_code": 200'
fi

echo "}"
CGISCRIPT
chmod 755 /var/www/local/axis-cgi/webhook.cgi

# Flag #24: Database Credentials (/var/db/axis/)
echo "[+] Flag #24: Database Configuration..."
cat > /var/db/axis/camera_events.db << 'EOF'
SQLite format 3
# Event Database Schema
# Version: 1.0

CREATE TABLE system_config (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    encrypted INTEGER DEFAULT 0
);

INSERT INTO system_config VALUES(1,'db_version','1.0',0);
INSERT INTO system_config VALUES(2,'admin_password_hash','5f4dcc3b5aa765d61d8327deb882cf99',1);
INSERT INTO system_config VALUES(3,'api_secret','FLAG{DENETHOR51483927}',1);
INSERT INTO system_config VALUES(4,'encryption_key','AES256_2024_KEY',1);

CREATE TABLE motion_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    camera_zone INTEGER,
    confidence REAL
);
EOF
chmod 640 /var/db/axis/camera_events.db

# Flag #25: Cryptographic Weakness (/usr/local/axis/lib/)
echo "[+] Flag #25: Weak Crypto Library..."
cat > /usr/local/axis/lib/crypto_weak.so.txt << 'EOF'
# Legacy Cryptographic Library
# WARNING: Uses deprecated algorithms

[Algorithm_Support]
md5=supported
sha1=supported
des=supported
rc4=supported

[Known_Issues]
md5_collisions=possible
sha1_deprecated=true
des_key_size=56bit

[Weak_Implementation]
# Sample weak hash: MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
base64_flag=RkxBR3tTQVJVTUFOX0NPUlJVUFRFRF81ODM5Mjc0Nn0=

[Mitigation]
recommended_upgrade=crypto_strong.so
upgrade_path=/usr/local/axis/lib/crypto_strong.so
EOF
chmod 644 /usr/local/axis/lib/crypto_weak.so.txt

# Flag #26: Recorder Temp Cache (/var/cache/recorder/.temp/)
echo "[+] Flag #26: Recording Temp Cache..."
cat > /var/cache/recorder/.temp/.recording_session_12345 << 'EOF'
# Temporary Recording Session Data
# Session ID: 12345
# Started: 2024-01-01 12:00:00

[Session_Info]
stream_source=rtsp://camera.local/stream1
start_time=1704110400
status=recording

[Temporary_Credentials]
session_token=temp_session_12345_2024
upload_key=u9l0@d_k3y_t3mp
internal_flag=FLAG{GRIMA_WORMTONGUE_76241893}

[Recording_Path]
temp_file=/var/cache/recorder/.temp/session_12345.h264
final_path=/var/cache/recorder/streams/primary/
EOF
chmod 600 /var/cache/recorder/.temp/.recording_session_12345

# Flag #27: Race Condition in Shared Memory (/dev/shm/)
echo "[+] Flag #27: Race Condition Script..."
cat > /usr/local/axis/share/scripts/race_condition_test.sh << 'RACESCRIPT'
#!/bin/sh
# Race Condition Vulnerability Test
# Security audit script - DO NOT USE IN PRODUCTION

TEMP_FILE=/dev/shm/axis/runtime/temp_flag_$$

# Create flag file briefly in shared memory
echo "FLAG{ARAGORN91886362}" > $TEMP_FILE
echo "Race condition window: 100ms"

# Small delay - race condition window
sleep 0.1

# Delete flag
rm -f $TEMP_FILE
echo "Race condition test completed"
RACESCRIPT
chmod 755 /usr/local/axis/share/scripts/race_condition_test.sh

# ============================================================================
# WEB SERVER AND CGI SETUP
# ============================================================================

echo ""
echo "[+] Configuring web services..."

# Create web server configuration
cat > /run/axis/httpd.conf << 'EOF'
# AXIS HTTP Server Configuration
A:*                    # Allow access from anywhere
*.cgi:/bin/sh          # Execute CGI scripts with shell
D:*                    # Enable directory listings (if no index)
EOF

# Set up CGI directories with proper symlinks
mkdir -p /var/www/axis-cgi
mkdir -p /var/www/cgi-bin

# Link local CGI scripts to standard locations
ln -sf /var/www/local/axis-cgi/param.cgi /var/www/axis-cgi/param.cgi 2>/dev/null
ln -sf /var/www/local/axis-cgi/download.cgi /var/www/axis-cgi/download.cgi 2>/dev/null
ln -sf /var/www/local/axis-cgi/webhook.cgi /var/www/axis-cgi/webhook.cgi 2>/dev/null

# Also copy to cgi-bin for alternative access
cp /var/www/local/axis-cgi/*.cgi /var/www/cgi-bin/ 2>/dev/null

# Start HTTP server if not running
if ! ps | grep -v grep | grep httpd > /dev/null; then
    echo "[+] Starting HTTP server..."
    httpd -f -p 80 -h /var/www -c /run/axis/httpd.conf &
    echo "  [✓] HTTP server started (PID: $!)"
else
    echo "  [!] HTTP server already running"
fi

# ============================================================================
# CREATE COMPREHENSIVE SUMMARY AND INDEX
# ============================================================================

echo ""
echo "[+] Creating comprehensive challenge index..."

cat > /var/lib/axis/ctf_challenge_index.txt << 'EOF'
AXIS Camera CTF Challenge Index - v4.0 Maximum Distribution
============================================================

FLAGS DISTRIBUTED ACROSS ALL WRITABLE DIRECTORIES
Flags now hidden in realistic locations across the entire filesystem.

WRITABLE DIRECTORIES USED:
- /mnt/flash          (firmware, bootloader, factory configs)
- /dev/shm            (shared memory, IPC, race conditions)
- /run                (runtime data, services)
- /sys/fs/cgroup      (container/service limits)
- /var                (standard Linux locations)
- /var/cache/recorder (recording stream caches)
- /var/lib/persistent (persistent storage configs)
- /usr/local          (custom applications)

EASY Challenges (5):
1. Default Configuration Exposure      → /var/lib/axis/conf/
2. Information Disclosure via Logs     → /var/log/
3. HTML Source Code Analysis           → /var/www/local/admin/
4. Recording Configuration Exposure    → /var/cache/recorder/
5. Factory Configuration Discovery     → /mnt/flash/config/factory/

MEDIUM Challenges (13):
1. Persistent License File             → /var/lib/persistent/system/
2. Persistent SSH Keys                 → /var/lib/persistent/security/
3. Recording Analytics Metadata        → /var/cache/recorder/analytics/
4. Command Injection (param.cgi)       → /var/www/local/axis-cgi/
5. Firmware Signature Analysis         → /mnt/flash/firmware/signatures/
6. Path Traversal (download.cgi)       → /var/www/local/axis-cgi/
7. Runtime Service Configuration       → /run/axis/services/
8. Custom Application Scripts          → /usr/local/axis/share/scripts/
9. CGroup Service Limits               → /sys/fs/cgroup/axis/
10. UPnP Discovery                     → /run/axis/network/
11. Persistent Certificates            → /var/lib/persistent/network/
12. SUID Binary Exploitation           → /usr/local/axis/bin/
13. Configuration Backups              → /var/backups/config/

HARD Challenges (9):
1. Shared Memory IPC                   → /dev/shm/axis/ipc/
2. Persistent Firmware Backup          → /var/lib/persistent/firmware/
3. Hidden Flash Config Backup          → /mnt/flash/config/.backup/
4. U-Boot Environment                  → /mnt/flash/boot/uboot/
5. Hardware Debug Interface            → /var/lib/axis/conf/
6. SSRF Exploitation (webhook.cgi)     → /var/www/local/axis-cgi/
7. Database Credential Extraction      → /var/db/axis/
8. Cryptographic Weakness              → /usr/local/axis/lib/
9. Race Condition (Shared Memory)      → /dev/shm/axis/runtime/

ENUMERATION STARTING POINTS:
General reconnaissance:
  find /var -type f -name '*.conf' 2>/dev/null
  find /var -type f -name '*.lic' 2>/dev/null
  find /mnt -type f 2>/dev/null
  find /usr/local -type f 2>/dev/null
  ls -laR /dev/shm/ 2>/dev/null
  ls -laR /run/axis/ 2>/dev/null

Specific directory searches:
  find /var/lib/persistent -type f 2>/dev/null
  find /var/cache/recorder -type f 2>/dev/null
  find /mnt/flash -name '.*' 2>/dev/null
  find /sys/fs/cgroup -type f 2>/dev/null
  grep -r 'FLAG' /var/lib/persistent/ 2>/dev/null
  grep -r 'FLAG' /usr/local/axis/ 2>/dev/null

Advanced techniques:
  # Race condition monitoring
  while true; do ls /dev/shm/axis/runtime/ 2>/dev/null; done
  
  # SUID binary discovery
  find /usr/local -perm -4000 2>/dev/null
  
  # Shared memory inspection
  cat /dev/shm/axis/ipc/* 2>/dev/null
  
  # CGroup inspection
  find /sys/fs/cgroup/axis -type f -exec cat {} \; 2>/dev/null

WEB INTERFACE ENDPOINTS:
  http://<camera-ip>/
  http://<camera-ip>/axis-cgi/param.cgi
  http://<camera-ip>/axis-cgi/download.cgi?file=/etc/passwd
  http://<camera-ip>/axis-cgi/webhook.cgi?url=http://127.0.0.1:22
  http://<camera-ip>/local/admin/

TOTAL: 27 FLAGS distributed across 8 writable directory trees
EOF
chmod 644 /var/lib/axis/ctf_challenge_index.txt

# ============================================================================
# CREATE VISUAL FLAG MAP
# ============================================================================

cat > /var/lib/axis/flag_distribution_map.txt << 'EOF'
AXIS Camera CTF - Flag Distribution Map v4.0
=============================================

Directory Tree Visualization:

/mnt/flash/                         [WRITABLE - FIRMWARE & BOOT]
├── boot/
│   ├── uboot/
│   │   └── uboot.env                      → FLAG #21 (HARD)
│   └── kernel/
├── firmware/
│   ├── images/
│   └── signatures/
│       └── firmware_10.5.0.sig            → FLAG #9 (MEDIUM)
└── config/
    ├── factory/
    │   └── device_info.txt                → FLAG #19 (EASY)
    ├── user/
    └── .backup/
        └── .shadow_config                 → FLAG #20 (HARD)

/dev/shm/                           [WRITABLE - SHARED MEMORY]
└── axis/
    ├── runtime/
    │   └── temp_flag_*                    → FLAG #27 (HARD - Race)
    ├── ipc/
    │   └── camera_control.shm             → FLAG #18 (HARD)
    └── streams/

/run/                               [WRITABLE - RUNTIME]
└── axis/
    ├── services/
    │   └── camera_service.conf            → FLAG #11 (MEDIUM)
    ├── network/
    │   └── upnp_description.xml           → FLAG #15 (MEDIUM)
    ├── camera/
    └── locks/

/sys/fs/cgroup/                     [WRITABLE - CGROUPS]
└── axis/
    ├── camera.service/
    │   └── service.conf                   → FLAG #13 (MEDIUM)
    └── network.service/

/var/                               [WRITABLE - STANDARD]
├── lib/
│   ├── axis/
│   │   └── conf/
│   │       ├── vapix.conf                 → FLAG #1 (EASY)
│   │       └── hardware_debug.conf        → FLAG #22 (HARD)
│   └── persistent/                [SUB-WRITABLE]
│       ├── system/
│       │   ├── configs/
│       │   └── licenses/
│       │       └── vapix_pro.lic          → FLAG #2 (MEDIUM)
│       ├── network/
│       │   └── certificates/
│       │       └── server_cert.pem        → FLAG #16 (MEDIUM)
│       ├── security/
│       │   └── keys/
│       │       └── authorized_keys        → FLAG #5 (MEDIUM)
│       └── firmware/
│           └── backups/
│               └── bootloader.img         → FLAG #19 (HARD)
├── cache/
│   └── recorder/                  [SUB-WRITABLE]
│       ├── streams/
│       │   └── primary/
│       │       └── stream_config.conf     → FLAG #14 (EASY)
│       ├── analytics/
│       │   └── metadata/
│       │       └── stream_analysis.json   → FLAG #6 (MEDIUM)
│       └── .temp/
│           └── .recording_session_*       → FLAG #26 (HARD)
├── db/
│   └── axis/
│       └── camera_events.db               → FLAG #24 (HARD)
├── log/
│   └── messages                           → FLAG #4 (EASY)
└── www/
    ├── index.html                         → FLAG #7 (EASY)
    └── local/
        └── axis-cgi/
            ├── param.cgi                  → FLAG #8 (MEDIUM)
            ├── download.cgi               → FLAG #10 (MEDIUM)
            └── webhook.cgi                → FLAG #23 (HARD)

/usr/local/                         [WRITABLE - CUSTOM APPS]
└── axis/
    ├── bin/
    │   └── camera_admin                   → FLAG #17 (MEDIUM - SUID)
    ├── lib/
    │   └── crypto_weak.so.txt             → FLAG #25 (HARD)
    ├── etc/
    └── share/
        └── scripts/
            ├── backup_service.sh          → FLAG #12 (MEDIUM)
            └── race_condition_test.sh     → FLAG #27 (HARD)

LEGEND:
[WRITABLE]     - Primary writable mount point
[SUB-WRITABLE] - Writable subdirectory within /var
→ FLAG #X      - Flag location and difficulty

DIFFICULTY LEVELS:
EASY (5)   - Basic file enumeration and reading
MEDIUM (13) - Requires scripts, tools, or CGI exploitation
HARD (9)   - Advanced techniques (race conditions, SSRF, crypto, etc.)

TOTAL: 27 flags across 8 writable directory trees
EOF
chmod 644 /var/lib/axis/flag_distribution_map.txt

# ============================================================================
# FINAL SUMMARY
# ============================================================================

echo ""
echo "[*] ========================================================================="
echo "[*] CTF Setup Complete - MAXIMUM DISTRIBUTION v4.0"
echo "[*] ========================================================================="
echo ""
echo "[+] Flag Distribution Summary:"
echo "    EASY flags: 5 (basic enumeration)"
echo "    MEDIUM flags: 13 (exploitation required)"
echo "    HARD flags: 9 (advanced techniques)"
echo "    TOTAL: 27 flags"
echo ""
echo "[+] Writable Directories Used (8):"
echo "    ✓ /mnt/flash             - Firmware, bootloader, factory configs"
echo "    ✓ /dev/shm               - Shared memory, IPC, race conditions"
echo "    ✓ /run                   - Runtime services and network"
echo "    ✓ /sys/fs/cgroup         - Container/service control groups"
echo "    ✓ /var                   - Standard Linux locations"
echo "    ✓ /var/cache/recorder    - Recording stream caches"
echo "    ✓ /var/lib/persistent    - Persistent storage configs"
echo "    ✓ /usr/local             - Custom applications and scripts"
echo ""
echo "[+] Deep Directory Structures:"
echo "    • 3-5 levels deep in most locations"
echo "    • Hidden files (.*) in strategic places"
echo "    • Realistic naming conventions"
echo "    • Mixed permissions for realism"
echo ""
echo "[+] Challenge Complexity:"
echo "    • Path traversal vulnerabilities"
echo "    • Command injection points"
echo "    • SSRF exploitation"
echo "    • Race condition scenarios"
echo "    • SUID binary escalation"
echo "    • Cryptographic weaknesses"
echo "    • Shared memory IPC"
echo "    • CGroup configuration"
echo ""
echo "[+] Reference Files:"
echo "    • Challenge index: /var/lib/axis/ctf_challenge_index.txt"
echo "    • Flag map: /var/lib/axis/flag_distribution_map.txt"
echo ""
echo "[+] Web Interface:"
echo "    http://<camera-ip>/"
echo "    http://<camera-ip>/axis-cgi/param.cgi"
echo "    http://<camera-ip>/axis-cgi/download.cgi"
echo "    http://<camera-ip>/axis-cgi/webhook.cgi"
echo ""
echo "[+] Quick Enumeration Commands:"
echo "    find /mnt -type f 2>/dev/null | head -20"
echo "    find /var/lib/persistent -type f 2>/dev/null"
echo "    find /usr/local/axis -type f 2>/dev/null"
echo "    ls -laR /dev/shm/ 2>/dev/null"
echo "    find /sys/fs/cgroup -type f 2>/dev/null"
echo "    find / -name '.*' -type f 2>/dev/null | grep -E '(flash|persistent|recorder)'"
echo ""
echo "[*] Setup completed at: $(date)"
echo "[*] Students must explore ALL writable directories for maximum learning!"
echo "[*] ========================================================================="
