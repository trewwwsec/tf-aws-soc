# Incident Report Template

**Incident ID**: INC-YYYY-MMDD-XXX  
**Report Date**: YYYY-MM-DD  
**Prepared By**: [Analyst Name]  
**Classification**: [Public / Internal / Confidential / Restricted]

---

## Executive Summary

[Provide a 2-3 sentence high-level summary suitable for executive leadership. Include: what happened, impact, and current status.]

---

## Incident Details

| Field | Value |
|-------|-------|
| **Incident ID** | INC-YYYY-MMDD-XXX |
| **Severity** | [P1 / P2 / P3 / P4] |
| **Status** | [Detected / Investigating / Contained / Resolved / Closed] |
| **Detection Time** | YYYY-MM-DD HH:MM:SS UTC |
| **Acknowledgment Time** | YYYY-MM-DD HH:MM:SS UTC |
| **Containment Time** | YYYY-MM-DD HH:MM:SS UTC |
| **Resolution Time** | YYYY-MM-DD HH:MM:SS UTC |
| **Total Duration** | X hours Y minutes |
| **MITRE ATT&CK** | [Technique ID - Technique Name] |
| **Detection Rules** | [Rule IDs that triggered] |

---

## Timeline of Events

| Time (UTC) | Event | Actor | Action Taken |
|------------|-------|-------|--------------|
| YYYY-MM-DD HH:MM:SS | Initial detection | Wazuh SIEM | Alert generated (Rule XXXXX) |
| YYYY-MM-DD HH:MM:SS | Alert acknowledged | [Analyst Name] | Began investigation |
| YYYY-MM-DD HH:MM:SS | [Event description] | [Actor] | [Action] |
| YYYY-MM-DD HH:MM:SS | Containment initiated | [Analyst Name] | [Specific action] |
| YYYY-MM-DD HH:MM:SS | Threat eradicated | [Analyst Name] | [Specific action] |
| YYYY-MM-DD HH:MM:SS | System restored | [Analyst Name] | [Specific action] |
| YYYY-MM-DD HH:MM:SS | Incident closed | [Team Lead] | Post-incident review completed |

---

## Affected Systems

| System Name | IP Address | OS | Role | Impact |
|-------------|------------|-----|------|--------|
| [hostname] | [IP] | [OS version] | [Purpose] | [Description of impact] |
| [hostname] | [IP] | [OS version] | [Purpose] | [Description of impact] |

---

## Impact Assessment

### Technical Impact
- **Systems Affected**: [Number and list]
- **Services Disrupted**: [List of services]
- **Data Accessed**: [Yes/No - If yes, describe]
- **Data Exfiltrated**: [Yes/No - If yes, describe]
- **Malware Deployed**: [Yes/No - If yes, describe]

### Business Impact
- **Service Downtime**: [Duration]
- **Users Affected**: [Number]
- **Revenue Impact**: $[Amount] (if applicable)
- **Reputation Impact**: [Low / Medium / High]
- **Regulatory Impact**: [None / Potential / Confirmed]

### Compliance Impact
- **GDPR**: [Yes/No - If yes, describe]
- **PCI DSS**: [Yes/No - If yes, describe]
- **HIPAA**: [Yes/No - If yes, describe]
- **SOX**: [Yes/No - If yes, describe]
- **Breach Notification Required**: [Yes/No]

---

## Indicators of Compromise (IOCs)

### Network Indicators
| Type | Value | First Seen | Last Seen | Notes |
|------|-------|------------|-----------|-------|
| IP Address | [IP] | [Timestamp] | [Timestamp] | [Description] |
| Domain | [domain.com] | [Timestamp] | [Timestamp] | [Description] |
| URL | [URL] | [Timestamp] | [Timestamp] | [Description] |

### File Indicators
| Type | Value | Location | Notes |
|------|-------|----------|-------|
| MD5 | [hash] | [path] | [Description] |
| SHA256 | [hash] | [path] | [Description] |
| Filename | [filename] | [path] | [Description] |

### Host Indicators
| Type | Value | System | Notes |
|------|-------|--------|-------|
| Process | [process name] | [hostname] | [Description] |
| Registry Key | [key path] | [hostname] | [Description] |
| Service | [service name] | [hostname] | [Description] |
| User Account | [username] | [hostname] | [Description] |

---

## Root Cause Analysis

### Initial Access
[How did the attacker gain initial access to the environment?]

### Attack Vector
[What method/vulnerability was exploited?]

### Contributing Factors
1. [Factor 1 - e.g., Missing security patch]
2. [Factor 2 - e.g., Weak password policy]
3. [Factor 3 - e.g., Lack of network segmentation]

### Why Did It Succeed?
[What security controls failed or were absent?]

---

## Response Actions

### Detection & Analysis
- [Action 1 - e.g., Reviewed Wazuh alerts]
- [Action 2 - e.g., Analyzed authentication logs]
- [Action 3 - e.g., Collected evidence from affected systems]

### Containment
- [Action 1 - e.g., Isolated affected system from network]
- [Action 2 - e.g., Disabled compromised user accounts]
- [Action 3 - e.g., Blocked malicious IP addresses]

### Eradication
- [Action 1 - e.g., Removed malware from systems]
- [Action 2 - e.g., Patched vulnerable software]
- [Action 3 - e.g., Rotated compromised credentials]

### Recovery
- [Action 1 - e.g., Restored systems from clean backups]
- [Action 2 - e.g., Verified system integrity]
- [Action 3 - e.g., Resumed normal operations]

---

## Evidence Collected

| Evidence ID | Type | Description | Location | Chain of Custody |
|-------------|------|-------------|----------|------------------|
| EVD-001 | Log File | Authentication logs | [Path/URL] | [Analyst Name] |
| EVD-002 | Memory Dump | System memory capture | [Path/URL] | [Analyst Name] |
| EVD-003 | Network Capture | PCAP file | [Path/URL] | [Analyst Name] |
| EVD-004 | Disk Image | Full disk image | [Path/URL] | [Analyst Name] |

**Evidence Storage Location**: [Secure storage location]  
**Retention Period**: [Duration per policy]

---

## Lessons Learned

### What Went Well
1. [Positive aspect 1 - e.g., Detection occurred within 2 minutes]
2. [Positive aspect 2 - e.g., Team responded quickly and effectively]
3. [Positive aspect 3 - e.g., Playbook procedures were followed correctly]

### What Could Be Improved
1. [Improvement area 1 - e.g., Escalation process was unclear]
2. [Improvement area 2 - e.g., Evidence collection took too long]
3. [Improvement area 3 - e.g., Communication with stakeholders was delayed]

### Gaps Identified
1. [Gap 1 - e.g., No EDR solution deployed]
2. [Gap 2 - e.g., Insufficient logging on critical systems]
3. [Gap 3 - e.g., Lack of network segmentation]

---

## Recommendations

### Immediate Actions (Within 1 Week)
1. [Action 1 - e.g., Deploy fail2ban on all SSH-accessible systems]
2. [Action 2 - e.g., Implement MFA for all administrative accounts]
3. [Action 3 - e.g., Update incident response playbooks based on findings]

### Short-Term Actions (Within 1 Month)
1. [Action 1 - e.g., Deploy EDR solution]
2. [Action 2 - e.g., Implement network segmentation]
3. [Action 3 - e.g., Conduct security awareness training]

### Long-Term Actions (Within 3-6 Months)
1. [Action 1 - e.g., Implement zero-trust architecture]
2. [Action 2 - e.g., Deploy SIEM correlation rules]
3. [Action 3 - e.g., Establish red team program]

---

## Metrics

### Response Metrics
| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| **MTTD** (Mean Time to Detect) | < 5 min | [X] min | [✓ / ✗] |
| **MTTA** (Mean Time to Acknowledge) | < 5 min | [X] min | [✓ / ✗] |
| **MTTI** (Mean Time to Investigate) | < 30 min | [X] min | [✓ / ✗] |
| **MTTC** (Mean Time to Contain) | < 1 hour | [X] min | [✓ / ✗] |
| **MTTR** (Mean Time to Recover) | < 4 hours | [X] hours | [✓ / ✗] |

### Quality Metrics
- **Playbook Adherence**: [Yes / No / Partial]
- **Documentation Completeness**: [%]
- **Escalation Accuracy**: [Appropriate / Too Early / Too Late]

---

## Communication

### Internal Notifications
| Stakeholder | Notification Time | Method | Content |
|-------------|-------------------|--------|---------|
| SOC Team Lead | [Timestamp] | [Phone/Email/Slack] | [Brief description] |
| Incident Commander | [Timestamp] | [Phone/Email/Slack] | [Brief description] |
| CISO | [Timestamp] | [Phone/Email/Slack] | [Brief description] |
| IT Operations | [Timestamp] | [Phone/Email/Slack] | [Brief description] |

### External Notifications
| Entity | Notification Required | Notification Sent | Method |
|--------|----------------------|-------------------|--------|
| Customers | [Yes/No] | [Yes/No/N/A] | [Method] |
| Regulators | [Yes/No] | [Yes/No/N/A] | [Method] |
| Law Enforcement | [Yes/No] | [Yes/No/N/A] | [Method] |
| Insurance | [Yes/No] | [Yes/No/N/A] | [Method] |

---

## Attachments

1. [Wazuh Alert Details] - [Link/Path]
2. [Evidence Archive] - [Link/Path]
3. [Network Diagrams] - [Link/Path]
4. [Timeline Visualization] - [Link/Path]
5. [Technical Analysis Report] - [Link/Path]

---

## Approval

| Role | Name | Signature | Date |
|------|------|-----------|------|
| **Incident Analyst** | [Name] | [Signature] | [Date] |
| **SOC Team Lead** | [Name] | [Signature] | [Date] |
| **Incident Commander** | [Name] | [Signature] | [Date] |
| **CISO** | [Name] | [Signature] | [Date] |

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | YYYY-MM-DD | [Name] | Initial report |
| 1.1 | YYYY-MM-DD | [Name] | [Description of changes] |

**Classification**: [Public / Internal / Confidential / Restricted]  
**Retention**: [Duration per policy]  
**Next Review**: [Date]

---

**END OF REPORT**
