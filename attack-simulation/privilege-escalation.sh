#!/bin/bash
#
# Privilege Escalation Attack Simulation
# MITRE ATT&CK: T1548.003 - Sudo and Sudo Caching
# Tests Detection Rules: 100020, 100021, 100022, 100032
#
# ⚠️  WARNING: Only run in isolated lab environment!
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                          ║${NC}"
echo -e "${BLUE}║     Privilege Escalation Attack Simulation              ║${NC}"
echo -e "${BLUE}║     MITRE ATT&CK: T1548.003 - Sudo Abuse                ║${NC}"
echo -e "${BLUE}║                                                          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Safety check
echo -e "${RED}⚠️  WARNING: This script simulates privilege escalation attacks!${NC}"
echo -e "${YELLOW}Only run in isolated lab environments.${NC}"
echo -e "${YELLOW}This script requires sudo privileges.${NC}"
echo ""
read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo -e "${YELLOW}Simulation cancelled.${NC}"
    exit 0
fi

echo ""
echo -e "${GREEN}[+] Starting privilege escalation simulation...${NC}"
echo ""

# Function to log actions
log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a simulation.log
}

# Test 1: Basic Sudo Usage (Rule 100020 - Baseline)
echo -e "${BLUE}[TEST 1]${NC} Basic sudo command execution"
echo "Expected Detection: Rule 100020 (Informational - sudo usage)"
echo "----------------------------------------"

log_action "Executing basic sudo command"
sudo echo "Testing basic sudo detection"

echo -e "${GREEN}✓ Basic sudo command executed${NC}"
echo "This should trigger Rule 100020 (severity: low/informational)"
sleep 2
echo ""

# Test 2: Suspicious Sudo with Bash (Rule 100021)
echo -e "${BLUE}[TEST 2]${NC} Suspicious sudo command - bash"
echo "Expected Detection: Rule 100021 (Suspicious sudo command)"
echo "----------------------------------------"

log_action "Executing sudo with bash (suspicious pattern)"
sudo bash -c "echo 'This is a suspicious sudo pattern'"

echo -e "${GREEN}✓ Sudo with bash executed${NC}"
echo "This should trigger Rule 100021 (severity: high)"
sleep 2
echo ""

# Test 3: Sudo with Python (Rule 100021)
echo -e "${BLUE}[TEST 3]${NC} Suspicious sudo command - python"
echo "Expected Detection: Rule 100021 (Suspicious sudo command)"
echo "----------------------------------------"

if command -v python3 &> /dev/null; then
    log_action "Executing sudo with python3 (suspicious pattern)"
    sudo python3 -c "print('Testing sudo python detection')"
    echo -e "${GREEN}✓ Sudo with python executed${NC}"
    echo "This should trigger Rule 100021 (severity: high)"
elif command -v python &> /dev/null; then
    log_action "Executing sudo with python (suspicious pattern)"
    sudo python -c "print('Testing sudo python detection')"
    echo -e "${GREEN}✓ Sudo with python executed${NC}"
    echo "This should trigger Rule 100021 (severity: high)"
else
    echo -e "${YELLOW}⚠ Python not found, skipping this test${NC}"
fi

sleep 2
echo ""

# Test 4: Sudo with Netcat (Rule 100021) - if available
echo -e "${BLUE}[TEST 4]${NC} Suspicious sudo command - netcat"
echo "Expected Detection: Rule 100021 (Suspicious sudo command)"
echo "----------------------------------------"

if command -v nc &> /dev/null; then
    log_action "Executing sudo with netcat (suspicious pattern)"
    sudo nc -h > /dev/null 2>&1 || true
    echo -e "${GREEN}✓ Sudo with netcat executed${NC}"
    echo "This should trigger Rule 100021 (severity: high)"
else
    echo -e "${YELLOW}⚠ Netcat not found, skipping this test${NC}"
fi

sleep 2
echo ""

# Test 5: Sudo Shell Escalation (Rule 100022)
echo -e "${BLUE}[TEST 5]${NC} Sudo shell escalation attempt"
echo "Expected Detection: Rule 100022 (Root shell escalation)"
echo "----------------------------------------"

log_action "Simulating sudo shell escalation"

# Simulate sudo -i (interactive root shell)
echo "Simulating: sudo -i"
sudo -i -c "echo 'Interactive root shell simulation'"

echo -e "${GREEN}✓ Sudo shell escalation simulated${NC}"
echo "This should trigger Rule 100022 (severity: high)"
sleep 2
echo ""

# Test 6: User Added to Sudo Group (Rule 100032)
echo -e "${BLUE}[TEST 6]${NC} Adding user to privileged group"
echo "Expected Detection: Rule 100032 (Privileged group modification)"
echo "----------------------------------------"

# Create a temporary test user
TEST_USER="testprivesc$$"

echo "Creating temporary test user: $TEST_USER"
log_action "Creating test user for privilege escalation simulation"

sudo useradd -m "$TEST_USER" 2>/dev/null || {
    echo -e "${YELLOW}⚠ User already exists or creation failed${NC}"
    TEST_USER="testprivesc"
}

sleep 1

# Add user to sudo/wheel group
if getent group sudo > /dev/null 2>&1; then
    echo "Adding $TEST_USER to sudo group..."
    log_action "Adding user to sudo group (privilege escalation)"
    sudo usermod -aG sudo "$TEST_USER"
    echo -e "${GREEN}✓ User added to sudo group${NC}"
    echo "This should trigger Rule 100032 (severity: high)"
elif getent group wheel > /dev/null 2>&1; then
    echo "Adding $TEST_USER to wheel group..."
    log_action "Adding user to wheel group (privilege escalation)"
    sudo usermod -aG wheel "$TEST_USER"
    echo -e "${GREEN}✓ User added to wheel group${NC}"
    echo "This should trigger Rule 100032 (severity: high)"
else
    echo -e "${YELLOW}⚠ No sudo/wheel group found${NC}"
fi

sleep 2
echo ""

# Test 7: Sudoers File Modification (Rule 100032)
echo -e "${BLUE}[TEST 7]${NC} Sudoers file modification detection"
echo "Expected Detection: Rule 100032 (Privileged group modification)"
echo "----------------------------------------"

echo "Simulating sudoers file access..."
log_action "Accessing sudoers file (should trigger FIM)"

# Just read the file (safe operation)
sudo cat /etc/sudoers > /dev/null

echo -e "${GREEN}✓ Sudoers file accessed${NC}"
echo "This may trigger file integrity monitoring"
sleep 2
echo ""

# Cleanup
echo -e "${BLUE}[CLEANUP]${NC} Removing test artifacts"
echo "----------------------------------------"

if id "$TEST_USER" &>/dev/null; then
    echo "Removing test user: $TEST_USER"
    sudo userdel -r "$TEST_USER" 2>/dev/null || sudo userdel "$TEST_USER" 2>/dev/null || true
    log_action "Cleaned up test user"
fi

echo -e "${GREEN}✓ Cleanup complete${NC}"
echo ""

# Summary
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  SIMULATION SUMMARY                      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Simulation Type: Privilege Escalation"
echo "MITRE ATT&CK: T1548.003 - Sudo and Sudo Caching"
echo ""
echo "Tests Executed:"
echo "  1. Basic sudo usage (Rule 100020)"
echo "  2. Sudo with bash (Rule 100021)"
echo "  3. Sudo with python (Rule 100021)"
echo "  4. Sudo with netcat (Rule 100021)"
echo "  5. Sudo shell escalation (Rule 100022)"
echo "  6. User added to sudo group (Rule 100032)"
echo "  7. Sudoers file access (Rule 100032)"
echo ""
echo -e "${GREEN}Expected Wazuh Alerts:${NC}"
echo "  • Rule 100020: Sudo command executed (informational)"
echo "  • Rule 100021: Suspicious sudo command (high severity)"
echo "  • Rule 100022: Root shell escalation (high severity)"
echo "  • Rule 100032: Privileged group modification (high severity)"
echo ""
echo -e "${GREEN}Verification Steps:${NC}"
echo "1. Check Wazuh dashboard for alerts"
echo "2. Or run on Wazuh server:"
echo "   sudo tail -n 100 /var/ossec/logs/alerts/alerts.log | grep '10002[0-2]\\|100032'"
echo ""
echo "Log file: simulation.log"
echo ""

# Verification helper
echo -e "${YELLOW}Would you like to check for alerts now? (requires SSH to Wazuh server)${NC}"
read -p "Check alerts? (yes/no): " check_alerts

if [ "$check_alerts" = "yes" ]; then
    if [ -n "$WAZUH_SERVER" ]; then
        echo ""
        echo "Checking Wazuh server for alerts..."
        ssh "$WAZUH_SERVER" "sudo tail -n 100 /var/ossec/logs/alerts/alerts.log | grep -A 5 'Rule: 10002\\|Rule: 100032'" || \
            echo -e "${RED}Could not connect to Wazuh server${NC}"
    else
        echo -e "${YELLOW}Set WAZUH_SERVER environment variable to enable automatic checking${NC}"
        echo "Example: export WAZUH_SERVER='ubuntu@10.0.1.100'"
    fi
fi

echo ""
echo -e "${GREEN}[✓] Privilege Escalation Simulation Complete!${NC}"
echo ""

# Additional recommendations
echo -e "${BLUE}[INFO]${NC} Additional Testing Recommendations:"
echo "  • Test during different times of day"
echo "  • Try different scripting interpreters (perl, ruby, php)"
echo "  • Test with different user accounts"
echo "  • Combine with other attack techniques"
echo ""
