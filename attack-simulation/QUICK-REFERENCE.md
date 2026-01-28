# Attack Simulation Guide - Quick Reference

## 🚀 Quick Start

### Linux Simulations

```bash
# SSH to Linux endpoint
ssh -i ~/.ssh/cloud-soc-key.pem ubuntu@LINUX_ENDPOINT_IP

# Clone repository
git clone https://github.com/trewwwsec/tf-aws-soc.git
cd tf-aws-soc/attack-simulation

# Run individual simulation
./privilege-escalation.sh

# Or run all Linux simulations
./run-all-linux.sh
```

### Windows Simulations

```powershell
# RDP to Windows endpoint
# Clone or copy scripts

# Run PowerShell simulation
.\powershell-attacks.ps1

# Run all Windows simulations
.\run-all-windows.ps1
```

## 📋 Available Simulations

| Script | Platform | MITRE Technique | Detection Rules |
|--------|----------|-----------------|-----------------|
| `ssh-brute-force.sh` | Linux | T1110 | 100001, 100002, 100003 |
| `privilege-escalation.sh` | Linux | T1548.003 | 100020, 100021, 100022, 100032 |
| `powershell-attacks.ps1` | Windows | T1059.001 | 100010-100014 |
| `run-all-linux.sh` | Linux | Multiple | All Linux rules |
| `run-all-windows.ps1` | Windows | Multiple | All Windows rules |

## 🎯 Testing Workflow

### 1. Pre-Test Setup
```bash
# On Wazuh server - start monitoring
tail -f /var/ossec/logs/alerts/alerts.log | grep "Rule: 100"
```

### 2. Run Simulation
```bash
# On target endpoint
./privilege-escalation.sh
```

### 3. Verify Alerts
```bash
# Check Wazuh dashboard or run on Wazuh server
sudo grep "100020\|100021\|100022" /var/ossec/logs/alerts/alerts.log
```

### 4. Document Results
```bash
# Record in test log
echo "Test: Privilege Escalation | Status: PASS | Alerts: 100020, 100021, 100022" >> test-results.txt
```

## 📊 Expected Alert Timeline

| Simulation | Alert Time | Rule ID | Severity |
|------------|------------|---------|----------|
| Sudo abuse | < 10 sec | 100021 | High |
| PowerShell encoded | < 10 sec | 100010 | High |
| SSH brute force | < 2 min | 100001 | High |
| Mimikatz | < 10 sec | 100013 | Critical |
| User creation | < 30 sec | 100030 | High |

## ⚠️ Safety Reminders

- ✅ Only run in isolated lab environments
- ✅ Never run on production systems
- ✅ Ensure Wazuh monitoring is active
- ✅ Have rollback procedures ready
- ✅ Document all testing activities

## 🔧 Environment Variables

```bash
# SSH brute force configuration
export SSH_TARGET_HOST="10.0.2.155"
export SSH_TARGET_USER="ubuntu"
export SSH_VALID_PASSWORD="your_password"  # Optional
export SSH_KEY_PATH="/path/to/key.pem"     # Optional

# Wazuh server for verification
export WAZUH_SERVER="ubuntu@10.0.1.100"
```

## 📈 Success Criteria

✅ **Detection Rate**: 95%+ of simulations trigger expected alerts  
✅ **Time to Detect**: < 2 minutes for all critical alerts  
✅ **False Negatives**: < 5% (simulations that don't trigger alerts)  
✅ **Alert Quality**: Alerts contain actionable information  

## 🎓 Learning Objectives

1. **Understand Attack Techniques**: See how real attacks work
2. **Validate Detection Rules**: Confirm rules trigger correctly
3. **Practice Incident Response**: Respond to simulated incidents
4. **Tune Detection**: Identify and fix false positives/negatives
5. **Build Confidence**: Gain hands-on security experience

## 📝 Troubleshooting

### Simulation doesn't trigger alert
1. Check Wazuh agent is running: `sudo systemctl status wazuh-agent`
2. Verify rules are loaded: `sudo grep "rule id=\"100" /var/ossec/etc/rules/local_rules.xml`
3. Check agent connectivity: `sudo /var/ossec/bin/agent_control -l`
4. Review agent logs: `sudo tail -f /var/ossec/logs/ossec.log`

### Permission denied errors
- Ensure you have sudo privileges
- Check script permissions: `chmod +x *.sh`
- Verify you're in the correct directory

### Scripts not found
```bash
# Ensure you're in the attack-simulation directory
cd /path/to/tf-aws-soc/attack-simulation
ls -la *.sh
```

## 🎯 Resume Impact

**Example bullet:**
> *"Executed purple team exercises using Atomic Red Team framework to validate 30+ SIEM detection rules, achieving 95%+ detection rate across 9 MITRE ATT&CK technique categories including brute force, privilege escalation, and credential dumping."*

---

**Quick Reference Card - Keep This Handy!**

```
┌─────────────────────────────────────────────────┐
│ ATTACK SIMULATION QUICK COMMANDS                │
├─────────────────────────────────────────────────┤
│ Run all Linux:    ./run-all-linux.sh            │
│ Privilege Esc:    ./privilege-escalation.sh     │
│ SSH Brute Force:  ./ssh-brute-force.sh          │
│ PowerShell:       .\powershell-attacks.ps1      │
│                                                  │
│ Monitor Alerts:                                  │
│ tail -f /var/ossec/logs/alerts/alerts.log       │
│                                                  │
│ Check Results:                                   │
│ grep "Rule: 100" alerts.log | sort | uniq -c    │
└─────────────────────────────────────────────────┘
```
