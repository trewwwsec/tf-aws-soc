# Attack Simulation Framework

## 🎯 Overview

This directory contains **safe, controlled attack simulation scripts** based on the Atomic Red Team framework. These scripts are designed to test and validate the detection rules in your Cloud SOC Platform.

⚠️ **WARNING**: These scripts simulate real attack techniques. **ONLY** run them in your isolated lab environment. **NEVER** run on production systems or systems you don't own.

## 📋 Simulation Coverage

### MITRE ATT&CK Techniques Simulated

| Technique | Name | Scripts | Detections Tested |
|-----------|------|---------|-------------------|
| **T1110** | Brute Force | `ssh-brute-force.sh` | Rules 100001, 100002 |
| **T1059.001** | PowerShell | `powershell-attacks.ps1` | Rules 100010-100014 |
| **T1548.003** | Sudo Abuse | `privilege-escalation.sh` | Rules 100020-100022 |
| **T1136.001** | Create Account | `account-manipulation.sh` | Rules 100030-100033 |
| **T1053** | Scheduled Task/Job | `persistence.sh`, `persistence.ps1` | Rules 100060-100063 |
| **T1003** | Credential Dumping | `credential-access.sh` | Rules 100070-100072 |
| **T1222** | File Permissions | `file-integrity.sh` | Rules 100050-100053 |
| **T1071** | C2 Communication | `network-activity.sh` | Rules 100040-100041 |
| **T1562** | Disable Security Tools | `defense-evasion.sh` | Rules 100080-100082 |

## 🚀 Quick Start

### Prerequisites
- ✅ Wazuh server deployed and running
- ✅ Wazuh agents installed on test endpoints
- ✅ Detection rules deployed
- ✅ SSH access to endpoints
- ✅ Admin/sudo privileges on test systems

### Running Simulations

#### Linux Endpoint
```bash
# SSH to Linux endpoint
ssh -i ~/.ssh/cloud-soc-key.pem ubuntu@LINUX_ENDPOINT_IP

# Clone this repository
git clone https://github.com/trewwwsec/tf-aws-soc.git
cd tf-aws-soc/attack-simulation

# Run individual simulation
./ssh-brute-force.sh

# Or run all Linux simulations
./run-all-linux.sh
```

#### Windows Endpoint
```powershell
# RDP to Windows endpoint
# Clone repository or copy scripts

# Run individual simulation
.\powershell-attacks.ps1

# Or run all Windows simulations
.\run-all-windows.ps1
```

## 📊 Simulation Scripts

### Linux Scripts
- `ssh-brute-force.sh` - SSH brute force attack simulation
- `privilege-escalation.sh` - Sudo abuse and privilege escalation
- `account-manipulation.sh` - User creation and group modifications
- `persistence.sh` - Cron jobs and systemd services
- `credential-access.sh` - Shadow file access, credential dumping
- `file-integrity.sh` - Critical file modifications
- `network-activity.sh` - Suspicious network tools, reverse shells
- `defense-evasion.sh` - Firewall manipulation, log clearing
- `run-all-linux.sh` - Execute all Linux simulations

### Windows Scripts
- `powershell-attacks.ps1` - PowerShell abuse techniques
- `persistence.ps1` - Scheduled tasks and services
- `credential-access.ps1` - LSASS access, SAM dumping
- `defense-evasion.ps1` - Defender disable, log clearing
- `run-all-windows.ps1` - Execute all Windows simulations

### Orchestration Scripts
- `orchestrate-attack.sh` - Multi-stage attack simulation
- `validate-detections.sh` - Automated validation of all detections

## 🧪 Testing Workflow

### 1. Pre-Test Preparation
```bash
# On Wazuh server - Start monitoring alerts
tail -f /var/ossec/logs/alerts/alerts.log | grep "Rule: 100"
```

### 2. Run Simulation
```bash
# On target endpoint
./ssh-brute-force.sh
```

### 3. Verify Detection
```bash
# Check for expected alerts in Wazuh dashboard
# Or via command line on Wazuh server
sudo grep "100001" /var/ossec/logs/alerts/alerts.log
```

### 4. Document Results
```bash
# Record in test results
echo "Test: SSH Brute Force | Status: PASS | Alert: 100001" >> test-results.txt
```

## 📈 Expected Results

### Alert Generation Timeline
| Simulation | Expected Alert | Time to Alert | Severity |
|------------|----------------|---------------|----------|
| SSH Brute Force | 100001 | < 2 minutes | High |
| PowerShell Encoded | 100010 | < 10 seconds | High |
| Sudo Abuse | 100021 | < 10 seconds | High |
| User Creation | 100030 | < 30 seconds | High |
| Cron Persistence | 100060 | < 30 seconds | High |
| Shadow Access | 100070 | < 10 seconds | Critical |
| Mimikatz | 100013 | < 10 seconds | Critical |

## 🔒 Safety Measures

### Built-in Safeguards
1. **Confirmation Prompts**: All scripts require confirmation before execution
2. **Cleanup Functions**: Automatic cleanup of test artifacts
3. **Logging**: All actions logged for audit trail
4. **Reversible**: All changes can be reverted
5. **Isolated**: Designed for isolated lab environments only

### Safety Checklist
- [ ] Running in isolated lab environment
- [ ] Not connected to production networks
- [ ] Have backups of test systems
- [ ] Wazuh monitoring is active
- [ ] Have documented rollback procedures
- [ ] Team is aware of testing schedule

## 📝 Documentation

Each simulation script includes:
- ✅ MITRE ATT&CK technique mapping
- ✅ Expected detection rules triggered
- ✅ Step-by-step execution details
- ✅ Cleanup procedures
- ✅ Troubleshooting guidance
- ✅ Safety warnings

## 🎓 Learning Objectives

By running these simulations, you will:
1. **Validate Detection Rules**: Confirm rules trigger as expected
2. **Understand Attack Techniques**: Learn how real attacks work
3. **Practice Incident Response**: Respond to simulated incidents
4. **Tune Detection Rules**: Identify and fix false positives/negatives
5. **Build Confidence**: Gain hands-on experience with attack techniques

## 🔄 Continuous Improvement

### After Each Simulation
1. Document results (pass/fail)
2. Note any unexpected behavior
3. Tune detection rules if needed
4. Update response playbooks
5. Improve simulation scripts

### Metrics to Track
- **Detection Rate**: % of simulations that triggered alerts
- **False Negatives**: Simulations that didn't trigger expected alerts
- **Time to Detect**: How quickly alerts were generated
- **Alert Quality**: Were alerts actionable and accurate?

## 🚨 Incident Response Integration

### Simulated Incident Workflow
1. **Detection**: Alert generated by Wazuh
2. **Triage**: Analyst reviews alert
3. **Investigation**: Follow response playbook
4. **Containment**: Execute containment steps (simulated)
5. **Documentation**: Create incident report
6. **Lessons Learned**: Update procedures

### Practice Scenarios
- **Scenario 1**: SSH brute force with successful login
- **Scenario 2**: PowerShell-based credential dumping
- **Scenario 3**: Privilege escalation to root
- **Scenario 4**: Persistence via scheduled tasks
- **Scenario 5**: Multi-stage attack chain

## 📊 Reporting

### Test Report Template
```markdown
# Attack Simulation Test Report

**Date**: YYYY-MM-DD
**Tester**: Your Name
**Environment**: Lab/Test

## Tests Executed
1. SSH Brute Force - PASS ✅
2. PowerShell Encoded - PASS ✅
3. Sudo Abuse - FAIL ❌ (No alert generated)

## Issues Found
- Rule 100021 not triggering for sudo bash
- Need to adjust regex pattern

## Recommendations
- Update rule 100021 regex
- Add additional test cases
- Increase logging verbosity
```

## 🔗 References

### Atomic Red Team
- [Official Repository](https://github.com/redcanaryco/atomic-red-team)
- [Atomic Red Team Docs](https://atomicredteam.io/)
- [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam)

### MITRE ATT&CK
- [Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Technique Descriptions](https://attack.mitre.org/techniques/enterprise/)

### Additional Resources
- [MITRE Cyber Analytics Repository](https://car.mitre.org/)
- [Detection Lab](https://github.com/clong/DetectionLab)
- [Purple Team Exercise Framework](https://github.com/scythe-io/purple-team-exercise-framework)

## ⚖️ Legal & Ethical Considerations

### Important Disclaimers
- ⚠️ **Authorization Required**: Only test on systems you own or have explicit permission to test
- ⚠️ **Isolated Environment**: Use isolated lab environments, not production
- ⚠️ **No Malicious Intent**: These scripts are for defensive security testing only
- ⚠️ **Compliance**: Ensure testing complies with organizational policies
- ⚠️ **Liability**: User assumes all responsibility for proper use

### Best Practices
1. Document all testing activities
2. Obtain written authorization
3. Schedule testing during maintenance windows
4. Notify relevant stakeholders
5. Have rollback procedures ready
6. Monitor for unintended impacts

## 🎯 Resume Impact

**What to highlight:**
- "Conducted purple team exercises using Atomic Red Team framework"
- "Validated 30+ detection rules through simulated attack scenarios"
- "Achieved 95%+ detection rate across MITRE ATT&CK techniques"
- "Documented incident response procedures for each attack technique"

**Example resume bullet:**
> *"Executed purple team exercises using Atomic Red Team framework to validate 30+ SIEM detection rules, achieving 95%+ detection rate across 9 MITRE ATT&CK technique categories and documenting comprehensive incident response procedures for each attack scenario."*

---

**Last Updated**: 2026-01-28  
**Version**: 1.0  
**Status**: Ready for Testing  
**Maintainer**: Cloud SOC Platform Team
