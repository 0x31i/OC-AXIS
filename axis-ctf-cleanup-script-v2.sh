#!/bin/bash
# AXIS Camera CTF Lab Complete Removal Script v2.0
# Removes all vulnerabilities, flags, and configurations created by CTF lab script v2.0
# Specifically updated for v2.0 changes (RTSP buffer overflow, new users, etc.)
# Restores camera to a secure state
# Author: Security Lab Administrator

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CAMERA_IP="192.168.1.132"
CLEANUP_LOG="/var/log/ctf-cleanup-v2-$(date +%Y%m%d_%H%M%S).log"
REMOVED_COUNT=0
ERROR_COUNT=0

echo -e "${RED}==========================================${NC}"
echo -e "${RED}AXIS CAMERA CTF LAB v2.0 REMOVAL SCRIPT${NC}"
echo -e "${RED}This will remove all CTF v2.0 configurations${NC}"
echo -e "${RED}Including RTSP buffer overflow and new users${NC}"
echo -e "${RED}==========================================${NC}"
echo ""
echo -e "${YELLOW}This script will:${NC}"
echo "  • Stop all vulnerable services"
echo "  • Remove RTSP buffer overflow artifacts"
echo "  • Remove all CTF users (including 'user')"
echo "  • Delete all flag files and directories"
echo "  • Restore secure permissions"
echo "  • Remove persistence mechanisms"
echo "  • Clean all CTF v2.0 configurations"
echo ""
read -p "Type 'CLEANUP' to confirm removal: " confirm
if [ "$confirm" != "CLEANUP" ]; then
    echo "Cleanup cancelled."
    exit 1
fi

# Function to log actions
log_action() {
    echo -e "${GREEN}[✓]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: $1" >> "$CLEANUP_LOG"
    REMOVED_COUNT=$((REMOVED_COUNT + 1))
}

# Function to log errors
log_error() {
    echo -e "${RED}[✗]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$CLEANUP_LOG"
    ERROR_COUNT=$((ERROR_COUNT + 1))
}

# Function to log warnings
log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$CLEANUP_LOG"
}

# Create cleanup log
echo "CTF Lab v2.0 Cleanup Started: $(date)" > "$CLEANUP_LOG"
echo "============================================" >> "$CLEANUP_LOG"

# ==========================================
# Step 1: Stop Vulnerable Services
# ==========================================
echo -e "\n${CYAN}Step 1: Stopping vulnerable services...${NC}"

# Kill FTP daemon (telnet removed in v2.0)
if pgrep -x ftpd > /dev/null; then
    pkill -9 ftpd 2>/dev/null && log_action "FTP service stopped" || log_error "Failed to stop FTP"
fi
if pgrep -x tcpsvd > /dev/null; then
    pkill -9 tcpsvd 2>/dev/null && log_action "TCPSVD (FTP) stopped" || log_error "Failed to stop TCPSVD"
fi

# Kill NTP service if running
if pgrep -x ntpd > /dev/null; then
    pkill -9 ntpd 2>/dev/null && log_action "NTP service stopped" || log_error "Failed to stop NTP"
fi

# Kill any RTSP handler processes
if pgrep -f rtsp_handler > /dev/null; then
    pkill -9 -f rtsp_handler 2>/dev/null && log_action "RTSP handler processes stopped" || log_error "Failed to stop RTSP handlers"
fi

# Kill any CGI scripts
if pgrep -f "\.cgi" > /dev/null; then
    pkill -9 -f "\.cgi" 2>/dev/null && log_action "CGI processes stopped" || log_error "Failed to stop CGI"
fi

# Kill any maintenance scripts running
if pgrep -f maintain_ctf > /dev/null; then
    pkill -9 -f maintain_ctf 2>/dev/null && log_action "Maintenance scripts stopped" || log_error "Failed to stop maintenance"
fi

# Kill sleep processes with flag comments (from hidden flags)
pkill -9 -f "sleep 3600" 2>/dev/null || true

# ==========================================
# Step 2: Remove CTF Users (Updated for v2.0)
# ==========================================
echo -e "\n${CYAN}Step 2: Removing CTF v2.0 users...${NC}"

CTF_USERS=(
    "user"              # Changed from "weakuser" in v2.0
    "testuser"
    "camera-admin"
    "iot-device"
    "service-account"
)

for ctf_user in "${CTF_USERS[@]}"; do
    if id "$ctf_user" &>/dev/null; then
        # Kill any processes owned by the user first
        pkill -9 -u "$ctf_user" 2>/dev/null || true
        
        # Remove the user
        deluser "$ctf_user" 2>/dev/null && log_action "Removed user: $ctf_user" || log_error "Failed to remove user: $ctf_user"
        
        # Also remove home directory if exists
        [ -d "/home/$ctf_user" ] && rm -rf "/home/$ctf_user" 2>/dev/null && log_action "Removed home dir: /home/$ctf_user"
    else
        log_warning "User $ctf_user not found"
    fi
done

# ==========================================
# Step 3: Remove RTSP Buffer Overflow Artifacts (New in v2.0)
# ==========================================
echo -e "\n${CYAN}Step 3: Removing RTSP buffer overflow vulnerabilities...${NC}"

# Remove RTSP handler directory and vulnerable code
[ -d /usr/local/bin/rtsp_handler ] && rm -rf /usr/local/bin/rtsp_handler && log_action "Removed RTSP handler directory"

# Remove crash dumps
[ -d /var/crash ] && rm -rf /var/crash && log_action "Removed crash dump directory"

# Remove fuzzing results
[ -f /var/crash/fuzzer_results.txt ] && rm -f /var/crash/fuzzer_results.txt && log_action "Removed fuzzer results"

# ==========================================
# Step 4: Remove Persistence Mechanisms
# ==========================================
echo -e "\n${CYAN}Step 4: Removing persistence mechanisms...${NC}"

# Remove from crontab
if crontab -l 2>/dev/null | grep -q maintain_ctf; then
    crontab -l | grep -v maintain_ctf | crontab - 2>/dev/null && log_action "Removed cron job" || log_error "Failed to remove cron"
else
    log_warning "No CTF cron job found"
fi

# Remove cron.d entries
[ -f /etc/cron.d/ctf-lab-maintenance ] && rm -f /etc/cron.d/ctf-lab-maintenance && log_action "Removed cron.d entry"

# Remove maintenance scripts
[ -f /usr/local/bin/maintain_ctf.sh ] && rm -f /usr/local/bin/maintain_ctf.sh && log_action "Removed maintain_ctf.sh"
[ -f /usr/local/bin/maintain_ctf_lab.sh ] && rm -f /usr/local/bin/maintain_ctf_lab.sh && log_action "Removed maintain_ctf_lab.sh"
[ -f /usr/local/bin/ctf_daily_check.sh ] && rm -f /usr/local/bin/ctf_daily_check.sh && log_action "Removed daily check script"
[ -f /usr/local/bin/backup_ctf_lab.sh ] && rm -f /usr/local/bin/backup_ctf_lab.sh && log_action "Removed backup script"

# Remove systemd service if exists
if [ -f /etc/systemd/system/ctf-lab.service ]; then
    systemctl stop ctf-lab.service 2>/dev/null || true
    systemctl disable ctf-lab.service 2>/dev/null || true
    rm -f /etc/systemd/system/ctf-lab.service
    systemctl daemon-reload
    log_action "Removed systemd service"
fi

# Remove rc.local if it contains CTF content
if [ -f /etc/rc.local ] && grep -q "CTF" /etc/rc.local; then
    rm -f /etc/rc.local && log_action "Removed rc.local"
fi

# ==========================================
# Step 5: Remove Flag Files and Directories (Updated for v2.0)
# ==========================================
echo -e "\n${CYAN}Step 5: Removing flag files and CTF v2.0 directories...${NC}"

# Remove known flag directories (updated for v2.0)
FLAG_DIRS=(
    "/var/camera-config"
    "/var/ftp"
    "/var/upnp"
    "/var/www/html"
    "/var/www/axis-cgi"
    "/var/www/graphql"       # New in v2.0
    "/var/firmware"
    "/var/rtsp"
    "/var/logs"
    "/etc/stream"
    "/etc/ntp"               # New in v2.0 (replacing telnet)
    "/var/backups"
    "/var/sessions"
    "/dev/serial"
    "/sys/jtag"
    "/etc/mqtt"
    "/etc/onvif"
    "/etc/param"
    "/proc/camera"
    "/cgi-bin"
    "/opt/ctf-lab"
    "/opt/backup"
    "/usr/local/bin/rtsp_handler"  # RTSP buffer overflow directory
    "/var/crash"                   # Crash dumps directory
)

for dir in "${FLAG_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        rm -rf "$dir" 2>/dev/null && log_action "Removed directory: $dir" || log_error "Failed to remove: $dir"
    fi
done

# Remove specific flag files (updated for v2.0)
FLAG_FILES=(
    "/tmp/.system_flag"
    "/etc/axis_flag.conf"
    "/etc/versions.txt"
    "/etc/update.conf"
    "/etc/api_keys.txt"
    "/etc/password_policy.conf"
    "/etc/camera_defaults.conf"
    "/etc/debug.conf"
    "/etc/hardware_test.conf"
    "/etc/ntp/ntp.conf"         # New in v2.0
    "/var/lib/random_seed"
    "/var/lib/ctf-flags.txt"
    "/var/lib/ctf-lab-state"
    "/root/.ssh/id_rsa"
    "/root/.ssh/id_rsa.pub"
    "/root/.ssh/id_rsa_flag"
    "/var/backups/sensitive_data.sql"  # New in v2.0
    "/usr/local/bin/rtsp_handler/rtsp_vuln.c"
    "/usr/local/bin/rtsp_handler/exploit_notes.txt"
    "/var/crash/rtsp_crash.dump"
    "/var/crash/fuzzer_results.txt"
)

for file in "${FLAG_FILES[@]}"; do
    if [ -f "$file" ]; then
        rm -f "$file" 2>/dev/null && log_action "Removed file: $file" || log_error "Failed to remove: $file"
    fi
done

# Remove CGI scripts (including vulnerable ones from v2.0)
if [ -d /cgi-bin ]; then
    rm -f /cgi-bin/status.sh 2>/dev/null && log_action "Removed Shellshock vulnerable script"
    rm -f /cgi-bin/exec.cgi 2>/dev/null && log_action "Removed command injection script"
    rm -rf /cgi-bin 2>/dev/null && log_action "Removed entire cgi-bin directory"
fi

# Remove any file with 'flag' in the name (be careful!)
echo -e "${YELLOW}Searching for remaining flag files...${NC}"
find / -type f \( -name "*flag*" -o -name "*FLAG*" \) -not -path "/proc/*" -not -path "/sys/*" -not -path "$CLEANUP_LOG" 2>/dev/null | while read -r flagfile; do
    # Skip system files that might legitimately have 'flag' in the name
    if [[ ! "$flagfile" =~ /proc/|/sys/|/dev/|/lib/|/usr/lib/ ]]; then
        rm -f "$flagfile" 2>/dev/null && log_action "Removed flag file: $flagfile"
    fi
done

# Remove .htaccess from web directories
find /var -name ".htaccess" -type f -delete 2>/dev/null || true

# Remove .profile files that may contain flags
for ctf_user in "${CTF_USERS[@]}"; do
    [ -f "/home/$ctf_user/.profile" ] && rm -f "/home/$ctf_user/.profile" 2>/dev/null
done

# ==========================================
# Step 6: Restore Secure Permissions
# ==========================================
echo -e "\n${CYAN}Step 6: Restoring secure permissions...${NC}"

# Restore secure permissions on sensitive files
chmod 755 /tmp 2>/dev/null && log_action "Secured /tmp permissions (755)" || log_warning "Could not change /tmp permissions"
chmod 755 /var/tmp 2>/dev/null && log_action "Secured /var/tmp permissions (755)" || log_warning "Could not change /var/tmp permissions"
chmod 644 /etc/passwd 2>/dev/null && log_action "Secured /etc/passwd" || log_warning "Could not change /etc/passwd permissions"
chmod 640 /etc/shadow 2>/dev/null && log_action "Secured /etc/shadow" || log_warning "Could not change /etc/shadow permissions"

# Secure SSH directory if it exists
if [ -d /root/.ssh ]; then
    chmod 700 /root/.ssh 2>/dev/null && log_action "Secured /root/.ssh directory"
    [ -f /root/.ssh/authorized_keys ] && chmod 600 /root/.ssh/authorized_keys && log_action "Secured authorized_keys"
    
    # Remove weak SSH keys
    [ -f /root/.ssh/id_rsa ] && [ "$(stat -c %a /root/.ssh/id_rsa)" = "644" ] && rm -f /root/.ssh/id_rsa /root/.ssh/id_rsa.pub && log_action "Removed weak SSH keys"
fi

# ==========================================
# Step 7: Remove Configuration Files
# ==========================================
echo -e "\n${CYAN}Step 7: Removing CTF v2.0 configuration files...${NC}"

# Remove CTF-related configuration files
CONFIG_FILES=(
    "/etc/PlainConfig"
    "/tmp/axis_vulnerable_iot_lab.sh"
    "/tmp/axis_vulnerable_iot_lab_v2.sh"
    "/tmp/verify_flags.sh"
    "/tmp/verify_cleanup.sh"
    "/var/www/html/index.html"
    "/var/www/html/admin.php"
    "/etc/update.conf"
    "/etc/ntp/ntp.conf"
    "/etc/mqtt/broker.conf"
    "/etc/onvif/discovery.xml"
    "/etc/param/System/PlainConfig"
    "/var/www/graphql/schema.json"
)

for config in "${CONFIG_FILES[@]}"; do
    if [ -f "$config" ]; then
        rm -f "$config" 2>/dev/null && log_action "Removed config: $config" || log_error "Failed to remove: $config"
    fi
done

# ==========================================
# Step 8: Clean Up Logs
# ==========================================
echo -e "\n${CYAN}Step 8: Cleaning up CTF logs...${NC}"

# Remove CTF-related logs
LOG_FILES=(
    "/var/log/ctf-lab-maintenance.log"
    "/var/log/ctf-daily.log"
    "/var/log/ctf-maintain.log"
    "/var/log/ctf-lab-startup.log"
    "/var/logs/users.log"
    "/var/logs/motion.log"
)

for logfile in "${LOG_FILES[@]}"; do
    if [ -f "$logfile" ]; then
        rm -f "$logfile" 2>/dev/null && log_action "Removed log: $logfile"
    fi
done

# Clean up auth.log entries for CTF users
if [ -f /var/log/auth.log ]; then
    for ctf_user in "${CTF_USERS[@]}"; do
        sed -i "/$ctf_user/d" /var/log/auth.log 2>/dev/null || true
    done
    log_action "Cleaned auth.log"
fi

# ==========================================
# Step 9: Verify Service Status
# ==========================================
echo -e "\n${CYAN}Step 9: Verifying cleanup...${NC}"

# Check that vulnerable services are stopped
echo -e "${BLUE}Service Status Check:${NC}"
# Note: Telnet removed in v2.0, checking other services
pgrep -x ftpd > /dev/null && log_warning "FTP still running!" || echo "  [✓] FTP stopped"
pgrep -x tcpsvd > /dev/null && log_warning "TCPSVD still running!" || echo "  [✓] TCPSVD stopped"
pgrep -x ntpd > /dev/null && log_warning "NTP still running!" || echo "  [✓] NTP stopped"
pgrep -f rtsp_handler > /dev/null && log_warning "RTSP handler still running!" || echo "  [✓] RTSP handler stopped"

# Check for remaining CTF users
echo -e "${BLUE}User Check:${NC}"
for ctf_user in "${CTF_USERS[@]}"; do
    id "$ctf_user" &>/dev/null && log_warning "User $ctf_user still exists!" || echo "  [✓] User $ctf_user removed"
done

# Check for RTSP buffer overflow artifacts
echo -e "${BLUE}RTSP Buffer Overflow Check:${NC}"
[ -d /usr/local/bin/rtsp_handler ] && log_warning "RTSP handler directory still exists!" || echo "  [✓] RTSP handler removed"
[ -d /var/crash ] && log_warning "Crash dumps directory still exists!" || echo "  [✓] Crash dumps removed"

# Check for remaining flag files
echo -e "${BLUE}Flag File Check:${NC}"
remaining_flags=$(find / -type f \( -name "*flag*" -o -name "*FLAG*" \) -not -path "/proc/*" -not -path "/sys/*" -not -path "/lib/*" -not -path "/usr/lib/*" -not -path "$CLEANUP_LOG" 2>/dev/null | wc -l)
if [ "$remaining_flags" -gt 0 ]; then
    log_warning "Found $remaining_flags potential flag files remaining"
    echo "Run this to list them: find / -type f -name '*flag*' -not -path '/proc/*' -not -path '/sys/*' -not -path '/lib/*' 2>/dev/null"
else
    echo "  [✓] No flag files found"
fi

# ==========================================
# Step 10: Optional Security Hardening
# ==========================================
echo -e "\n${CYAN}Step 10: Optional security hardening...${NC}"
echo -e "${YELLOW}Would you like to apply additional security hardening? (y/n)${NC}"
read -p "Choice: " harden

if [ "$harden" = "y" ] || [ "$harden" = "Y" ]; then
    echo -e "${BLUE}Applying security hardening...${NC}"
    
    # Disable unnecessary services
    # Note: Be careful not to break camera functionality
    
    # Set strong permission on sensitive directories
    chmod 700 /root 2>/dev/null && log_action "Hardened /root directory"
    chmod 700 /etc/ssh 2>/dev/null && log_action "Hardened /etc/ssh directory"
    
    # Remove any .bash_history that might contain sensitive commands
    rm -f /root/.bash_history 2>/dev/null && log_action "Removed bash history"
    rm -f /home/*/.bash_history 2>/dev/null
    
    # Clear command history for current session
    history -c
    
    # Disable unused network services
    if command -v systemctl &>/dev/null; then
        systemctl disable ftpd 2>/dev/null || true
        systemctl disable ntpd 2>/dev/null || true
    fi
    
    echo -e "${GREEN}Security hardening completed${NC}"
else
    echo "Skipping additional hardening"
fi

# ==========================================
# Final Report
# ==========================================
echo -e "\n${GREEN}==========================================${NC}"
echo -e "${GREEN}CTF LAB v2.0 CLEANUP COMPLETE${NC}"
echo -e "${GREEN}==========================================${NC}"
echo ""
echo -e "${CYAN}Cleanup Summary:${NC}"
echo -e "  ${GREEN}Items Removed:${NC} $REMOVED_COUNT"
echo -e "  ${RED}Errors:${NC} $ERROR_COUNT"
echo -e "  ${YELLOW}Log File:${NC} $CLEANUP_LOG"
echo ""

if [ "$ERROR_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠ Warning: Some items could not be removed.${NC}"
    echo -e "${YELLOW}Check the log file for details: $CLEANUP_LOG${NC}"
else
    echo -e "${GREEN}✓ All CTF lab v2.0 components successfully removed!${NC}"
fi

echo ""
echo -e "${CYAN}Recommended Next Steps:${NC}"
echo "  1. Review the cleanup log: cat $CLEANUP_LOG"
echo "  2. Verify no vulnerable services: netstat -tuln"
echo "  3. Check for remaining users: cat /etc/passwd"
echo "  4. Verify RTSP service is secure: ps aux | grep rtsp"
echo "  5. Consider rebooting the camera: reboot"
echo "  6. Re-enable security features via web interface"
echo ""

# Save final status to log
echo "" >> "$CLEANUP_LOG"
echo "============================================" >> "$CLEANUP_LOG"
echo "Cleanup Completed: $(date)" >> "$CLEANUP_LOG"
echo "Total Removed: $REMOVED_COUNT" >> "$CLEANUP_LOG"
echo "Total Errors: $ERROR_COUNT" >> "$CLEANUP_LOG"

# ==========================================
# Create Verification Script
# ==========================================
cat > /tmp/verify_cleanup_v2.sh << 'VERIFY_EOF'
#!/bin/bash
# Post-cleanup verification script for v2.0

echo "=== CTF Lab v2.0 Cleanup Verification ==="
echo ""

# Check services
echo "1. Service Check:"
netstat -tuln | grep -E ":(21|123|554|1883|1900|8080|9999)" && echo "WARNING: Vulnerable services still listening!" || echo "  [✓] No vulnerable services found"

# Check users (updated for v2.0)
echo ""
echo "2. User Check:"
for user in user testuser camera-admin iot-device service-account; do
    id "$user" 2>/dev/null && echo "  [✗] User $user still exists!" || echo "  [✓] User $user removed"
done

# Check RTSP buffer overflow artifacts
echo ""
echo "3. RTSP Buffer Overflow Check:"
[ -d /usr/local/bin/rtsp_handler ] && echo "  [✗] RTSP handler directory still exists!" || echo "  [✓] RTSP handler removed"
[ -d /var/crash ] && echo "  [✗] Crash dumps still exist!" || echo "  [✓] Crash dumps removed"
[ -f /cgi-bin/status.sh ] && echo "  [✗] Shellshock script still exists!" || echo "  [✓] Shellshock script removed"

# Check directories
echo ""
echo "4. Directory Check:"
for dir in /var/camera-config /var/ftp /var/upnp /etc/mqtt /etc/onvif /etc/ntp /var/www/graphql; do
    [ -d "$dir" ] && echo "  [✗] Directory $dir still exists!" || echo "  [✓] Directory $dir removed"
done

# Check cron
echo ""
echo "5. Cron Check:"
crontab -l 2>/dev/null | grep -q ctf && echo "  [✗] CTF cron job still exists!" || echo "  [✓] No CTF cron jobs"

# Check processes
echo ""
echo "6. Process Check:"
ps aux | grep -E "(maintain_ctf|ftpd|rtsp_handler|ntpd)" | grep -v grep && echo "  [✗] CTF processes still running!" || echo "  [✓] No CTF processes"

# Check permissions
echo ""
echo "7. Permission Check:"
[ "$(stat -c %a /tmp 2>/dev/null)" = "777" ] && echo "  [✗] /tmp still world-writable!" || echo "  [✓] /tmp permissions secure"
[ "$(stat -c %a /etc/shadow 2>/dev/null)" = "644" ] && echo "  [✗] /etc/shadow still readable!" || echo "  [✓] /etc/shadow permissions secure"

echo ""
echo "=== Verification Complete ==="
VERIFY_EOF

chmod +x /tmp/verify_cleanup_v2.sh

echo -e "${CYAN}Run verification script: /tmp/verify_cleanup_v2.sh${NC}"
echo ""
echo -e "${GREEN}CTF Lab v2.0 cleanup script finished.${NC}"
echo ""
echo -e "${RED}Note: RTSP buffer overflow artifacts have been removed.${NC}"
echo -e "${RED}Camera RTSP service should now be secure.${NC}"

exit 0