# High-Level Architecture

## Cloud SOC Platform - System Overview

This diagram shows the complete Cloud SOC Platform architecture including infrastructure, detection, and incident response components.

```mermaid
graph TB
    subgraph "AWS Cloud - VPC 10.0.0.0/16"
        subgraph "Public Subnet - 10.0.1.0/24"
            IGW[Internet Gateway]
            WAZUH[Wazuh SIEM Server<br/>t3.medium<br/>Ubuntu 22.04]
        end
        
        subgraph "Private Subnet - 10.0.2.0/24"
            LINUX[Linux Endpoint<br/>t3.micro<br/>Ubuntu 22.04]
            WINDOWS[Windows Endpoint<br/>t3.micro<br/>Windows Server 2022]
            NAT[NAT Gateway]
        end
        
        subgraph "Security"
            SG1[Security Group<br/>Wazuh Server]
            SG2[Security Group<br/>Endpoints]
        end
    end
    
    subgraph "External Access"
        ANALYST[SOC Analyst]
        ATTACKER[Simulated Attacker]
    end
    
    subgraph "Detection & Response"
        RULES[30 Detection Rules<br/>MITRE ATT&CK Mapped]
        ALERTS[Alert Generation<br/>SIEM Dashboard]
        PLAYBOOKS[Incident Response<br/>Playbooks]
    end
    
    subgraph "Testing & Validation"
        SIMULATIONS[Attack Simulations<br/>Atomic Red Team]
        EVIDENCE[Evidence Collection<br/>Forensic Tools]
    end
    
    %% Connections
    IGW --> WAZUH
    ANALYST --> IGW
    ATTACKER -.->|Simulated Attacks| IGW
    
    WAZUH --> NAT
    NAT --> LINUX
    NAT --> WINDOWS
    
    LINUX -->|Logs & Events| WAZUH
    WINDOWS -->|Logs & Events| WAZUH
    
    WAZUH --> RULES
    RULES --> ALERTS
    ALERTS --> PLAYBOOKS
    
    SIMULATIONS -.->|Test Detections| LINUX
    SIMULATIONS -.->|Test Detections| WINDOWS
    PLAYBOOKS --> EVIDENCE
    
    SG1 -.->|Protects| WAZUH
    SG2 -.->|Protects| LINUX
    SG2 -.->|Protects| WINDOWS
    
    %% Styling
    classDef aws fill:#FF9900,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef server fill:#3B48CC,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef security fill:#DD344C,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef detection fill:#1E8900,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef external fill:#666,stroke:#232F3E,stroke-width:2px,color:#fff
    
    class IGW,NAT aws
    class WAZUH,LINUX,WINDOWS server
    class SG1,SG2 security
    class RULES,ALERTS,PLAYBOOKS,SIMULATIONS,EVIDENCE detection
    class ANALYST,ATTACKER external
```

## Component Details

### Infrastructure Layer
- **AWS VPC**: Isolated network environment (10.0.0.0/16)
- **Public Subnet**: Internet-accessible resources (Wazuh server)
- **Private Subnet**: Protected endpoints (monitored systems)
- **Internet Gateway**: External connectivity
- **NAT Gateway**: Outbound internet for private subnet

### SIEM Layer
- **Wazuh Server**: Central SIEM and log aggregation
  - Receives logs from all endpoints
  - Processes events through detection rules
  - Generates alerts for security incidents
  - Provides web dashboard for analysts

### Endpoint Layer
- **Linux Endpoint**: Ubuntu 22.04 with Wazuh agent
  - Monitors system logs, authentication, file integrity
  - Sends events to Wazuh server
  - Target for attack simulations
  
- **Windows Endpoint**: Windows Server 2022 with Wazuh agent
  - Monitors PowerShell, event logs, registry
  - Sends events to Wazuh server
  - Target for PowerShell attack simulations

### Detection Layer
- **30 Detection Rules**: MITRE ATT&CK mapped
  - SSH brute force (T1110)
  - PowerShell abuse (T1059.001)
  - Privilege escalation (T1548.003)
  - Credential dumping (T1003)
  - Persistence mechanisms (T1053, T1543)
  - And more...

### Response Layer
- **Incident Response Playbooks**:
  - SSH Brute Force (IR-PB-001)
  - Credential Dumping (IR-PB-002)
  - Complete NIST IR lifecycle
  - Evidence collection tools

### Testing Layer
- **Attack Simulations**: Atomic Red Team framework
  - SSH brute force simulation
  - PowerShell attack simulation
  - Privilege escalation simulation
  - Validates detection effectiveness

## Data Flow

1. **Log Collection**: Endpoints send logs to Wazuh server
2. **Event Processing**: Wazuh processes logs through detection rules
3. **Alert Generation**: Matching events trigger alerts
4. **Incident Response**: Analysts follow playbooks
5. **Evidence Collection**: Forensic tools gather evidence
6. **Continuous Improvement**: Lessons learned update detections

## Security Controls

- **Network Segmentation**: Public/private subnet separation
- **Security Groups**: Firewall rules limiting access
- **Least Privilege**: Minimal required permissions
- **Encryption**: TLS for all communications
- **Monitoring**: 24/7 SIEM monitoring
- **Incident Response**: Documented procedures

## Scalability

- **Horizontal**: Add more endpoints as needed
- **Vertical**: Upgrade Wazuh server instance size
- **Multi-Region**: Deploy in multiple AWS regions
- **High Availability**: Add redundant Wazuh servers

## Compliance

- **PCI DSS**: Log monitoring, access control
- **NIST**: Incident response framework
- **GDPR**: Data protection, breach notification
- **HIPAA**: Audit logging, access controls

---

**Diagram Type**: High-Level Architecture  
**Last Updated**: 2026-01-28  
**Version**: 1.0
