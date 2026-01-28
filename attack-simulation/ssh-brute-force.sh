#!/bin/bash
#
# SSH Brute Force Attack Simulation
# MITRE ATT&CK: T1110 - Brute Force
# Tests Detection Rules: 100001, 100002, 100003
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

# Configuration
TARGET_HOST="${SSH_TARGET_HOST:-localhost}"
TARGET_USER="${SSH_TARGET_USER:-testuser}"
ATTEMPTS=6
DELAY=2

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                          ║${NC}"
echo -e "${BLUE}║        SSH Brute Force Attack Simulation                ║${NC}"
echo -e "${BLUE}║        MITRE ATT&CK: T1110 - Brute Force                ║${NC}"
echo -e "${BLUE}║                                                          ║${NC}"
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo ""

# Safety check
echo -e "${RED}⚠️  WARNING: This script simulates a brute force attack!${NC}"
echo -e "${YELLOW}Only run in isolated lab environments.${NC}"
echo ""
echo "Target: $TARGET_USER@$TARGET_HOST"
echo "Attempts: $ATTEMPTS"
echo ""
read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo -e "${YELLOW}Simulation cancelled.${NC}"
    exit 0
fi

echo ""
echo -e "${GREEN}[+] Starting SSH brute force simulation...${NC}"
echo ""

# Function to log actions
log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a simulation.log
}

# Test 1: Multiple Failed Login Attempts (Rule 100001)
echo -e "${BLUE}[TEST 1]${NC} Simulating multiple failed SSH login attempts"
echo "Expected Detection: Rule 100001 (SSH brute force - 5+ failures)"
echo "----------------------------------------"

log_action "Starting SSH brute force simulation against $TARGET_HOST"

# Create a temporary password list
TEMP_PASS_FILE=$(mktemp)
cat > "$TEMP_PASS_FILE" << EOF
wrongpass1
wrongpass2
wrongpass3
wrongpass4
wrongpass5
wrongpass6
EOF

echo "Attempting $ATTEMPTS failed logins..."

# Method 1: Using sshpass (if available)
if command -v sshpass &> /dev/null; then
    echo "Using sshpass for automated attempts..."
    
    attempt=1
    while IFS= read -r password; do
        echo -e "${YELLOW}Attempt $attempt/$ATTEMPTS:${NC} Trying password: $password"
        sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            "$TARGET_USER@$TARGET_HOST" "echo test" 2>&1 | grep -q "Permission denied" && \
            echo "  ✗ Failed (expected)" || echo "  ✗ Failed"
        
        log_action "Failed SSH attempt $attempt with password: $password"
        attempt=$((attempt + 1))
        sleep $DELAY
    done < "$TEMP_PASS_FILE"
    
else
    # Method 2: Manual instructions if sshpass not available
    echo -e "${YELLOW}sshpass not installed. Manual testing required.${NC}"
    echo ""
    echo "To simulate this attack manually:"
    echo "1. Run the following command $ATTEMPTS times:"
    echo "   ssh $TARGET_USER@$TARGET_HOST"
    echo "2. Enter a wrong password each time"
    echo "3. Wait $DELAY seconds between attempts"
    echo ""
    echo "Or install sshpass:"
    echo "   Ubuntu/Debian: sudo apt install sshpass"
    echo "   RHEL/CentOS: sudo yum install sshpass"
    echo "   macOS: brew install hudochenkov/sshpass/sshpass"
    echo ""
fi

# Cleanup
rm -f "$TEMP_PASS_FILE"

echo ""
echo -e "${GREEN}[✓] Test 1 Complete${NC}"
echo ""

# Test 2: Successful Login After Failures (Rule 100002)
echo -e "${BLUE}[TEST 2]${NC} Simulating successful login after failed attempts"
echo "Expected Detection: Rule 100002 (Successful login after brute force)"
echo "----------------------------------------"

if [ -n "$SSH_VALID_PASSWORD" ] || [ -n "$SSH_KEY_PATH" ]; then
    echo "Attempting successful login..."
    
    if [ -n "$SSH_KEY_PATH" ]; then
        ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no "$TARGET_USER@$TARGET_HOST" "echo 'Successful login'" && \
            echo -e "${GREEN}✓ Successful login (this should trigger Rule 100002)${NC}" || \
            echo -e "${RED}✗ Login failed${NC}"
    else
        echo "Using password authentication..."
        sshpass -p "$SSH_VALID_PASSWORD" ssh -o StrictHostKeyChecking=no "$TARGET_USER@$TARGET_HOST" "echo 'Successful login'" && \
            echo -e "${GREEN}✓ Successful login (this should trigger Rule 100002)${NC}" || \
            echo -e "${RED}✗ Login failed${NC}"
    fi
    
    log_action "Successful SSH login after failed attempts"
else
    echo -e "${YELLOW}⚠ Skipping Test 2: No valid credentials provided${NC}"
    echo "To test Rule 100002, set one of:"
    echo "  export SSH_VALID_PASSWORD='your_password'"
    echo "  export SSH_KEY_PATH='/path/to/key.pem'"
fi

echo ""
echo -e "${GREEN}[✓] Test 2 Complete${NC}"
echo ""

# Test 3: Off-Hours Login (Rule 100003)
echo -e "${BLUE}[TEST 3]${NC} Off-hours login detection"
echo "Expected Detection: Rule 100003 (Login during unusual hours 2 AM - 6 AM)"
echo "----------------------------------------"

current_hour=$(date +%H)
if [ "$current_hour" -ge 2 ] && [ "$current_hour" -lt 6 ]; then
    echo -e "${YELLOW}Current time is within off-hours window (2 AM - 6 AM)${NC}"
    echo "Any successful login now will trigger Rule 100003"
else
    echo -e "${YELLOW}Current time ($current_hour:00) is NOT in off-hours window${NC}"
    echo "Rule 100003 only triggers between 2 AM - 6 AM"
    echo "To test this rule, run this script during those hours"
fi

echo ""
echo -e "${GREEN}[✓] Test 3 Complete${NC}"
echo ""

# Summary
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  SIMULATION SUMMARY                      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Simulation Type: SSH Brute Force"
echo "MITRE ATT&CK: T1110 - Brute Force"
echo "Target: $TARGET_USER@$TARGET_HOST"
echo "Failed Attempts: $ATTEMPTS"
echo ""
echo "Expected Wazuh Alerts:"
echo "  • Rule 100001: SSH brute force (5+ failures in 2 minutes)"
echo "  • Rule 100002: Successful login after failures (if credentials provided)"
echo "  • Rule 100003: Off-hours login (if during 2 AM - 6 AM)"
echo ""
echo -e "${GREEN}Verification Steps:${NC}"
echo "1. Check Wazuh dashboard for alerts"
echo "2. Or run on Wazuh server:"
echo "   sudo tail -n 100 /var/ossec/logs/alerts/alerts.log | grep '100001\\|100002\\|100003'"
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
        ssh "$WAZUH_SERVER" "sudo tail -n 100 /var/ossec/logs/alerts/alerts.log | grep -A 5 'Rule: 100001\\|Rule: 100002\\|Rule: 100003'" || \
            echo -e "${RED}Could not connect to Wazuh server${NC}"
    else
        echo -e "${YELLOW}Set WAZUH_SERVER environment variable to enable automatic checking${NC}"
        echo "Example: export WAZUH_SERVER='ubuntu@10.0.1.100'"
    fi
fi

echo ""
echo -e "${GREEN}[✓] SSH Brute Force Simulation Complete!${NC}"
echo ""

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    rm -f "$TEMP_PASS_FILE" 2>/dev/null || true
}

trap cleanup EXIT
