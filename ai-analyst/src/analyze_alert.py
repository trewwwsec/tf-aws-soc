#!/usr/bin/env python3
"""
AI-Powered Alert Analyzer
Analyzes Wazuh alerts using LLMs to provide context, summaries, and recommendations.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Optional, Dict, Any

from alert_enricher import AlertEnricher
from ai_client import AIClient
from wazuh_client import WazuhClient

# ANSI Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def print_header(text: str):
    """Print a formatted header."""
    print(f"\n{Colors.CYAN}╔{'═' * 68}╗{Colors.END}")
    print(f"{Colors.CYAN}║{Colors.BOLD}  {text:^64}  {Colors.END}{Colors.CYAN}║{Colors.END}")
    print(f"{Colors.CYAN}╚{'═' * 68}╝{Colors.END}\n")


def print_section(emoji: str, title: str, content: str):
    """Print a formatted section."""
    print(f"{Colors.BOLD}{emoji} {title}:{Colors.END}")
    for line in content.strip().split('\n'):
        print(f"   {line}")
    print()


def load_playbook_mapping() -> Dict[str, str]:
    """Load the mapping of rule IDs to playbooks."""
    return {
        # SSH Brute Force
        "100001": "ssh-brute-force.md",
        "100002": "ssh-brute-force.md",
        "100003": "ssh-brute-force.md",
        # PowerShell Abuse
        "100010": "powershell-abuse.md",
        "100011": "powershell-abuse.md",
        "100012": "powershell-abuse.md",
        "100013": "credential-dumping.md",  # Mimikatz -> credential dumping
        "100014": "powershell-abuse.md",
        # Privilege Escalation
        "100020": "privilege-escalation.md",
        "100021": "privilege-escalation.md",
        "100022": "privilege-escalation.md",
        # Account Management
        "100030": "account-creation.md",
        "100031": "account-creation.md",
        "100032": "privilege-escalation.md",
        "100033": "account-creation.md",
        # Credential Access
        "100070": "credential-dumping.md",
        "100071": "credential-dumping.md",
        "100072": "credential-dumping.md",
        # Persistence
        "100060": "persistence.md",
        "100061": "persistence.md",
        "100062": "persistence.md",
        "100063": "persistence.md",
        # File Integrity
        "100050": "file-integrity.md",
        "100051": "file-integrity.md",
        "100052": "file-integrity.md",
        "100053": "file-integrity.md",
        # Defense Evasion
        "100080": "defense-evasion.md",
        "100081": "defense-evasion.md",
        "100082": "defense-evasion.md",
    }


def get_mitre_info(technique_id: str) -> Dict[str, str]:
    """Get MITRE ATT&CK technique information."""
    mitre_db = {
        "T1110": {
            "name": "Brute Force",
            "tactic": "Credential Access",
            "description": "Adversaries may use brute force techniques to gain access to accounts.",
            "sub_techniques": ["T1110.001 - Password Guessing", "T1110.002 - Password Cracking"]
        },
        "T1059.001": {
            "name": "PowerShell",
            "tactic": "Execution",
            "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
            "sub_techniques": []
        },
        "T1548.003": {
            "name": "Sudo and Sudo Caching",
            "tactic": "Privilege Escalation",
            "description": "Adversaries may abuse sudo to escalate privileges.",
            "sub_techniques": []
        },
        "T1003": {
            "name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "description": "Adversaries may attempt to dump credentials from the operating system.",
            "sub_techniques": ["T1003.001 - LSASS Memory", "T1003.002 - SAM"]
        },
        "T1136.001": {
            "name": "Create Account: Local Account",
            "tactic": "Persistence",
            "description": "Adversaries may create a local account to maintain access.",
            "sub_techniques": []
        },
        "T1053": {
            "name": "Scheduled Task/Job",
            "tactic": "Persistence",
            "description": "Adversaries may abuse task scheduling to execute malicious code.",
            "sub_techniques": ["T1053.003 - Cron", "T1053.005 - Scheduled Task"]
        },
        "T1562": {
            "name": "Impair Defenses",
            "tactic": "Defense Evasion",
            "description": "Adversaries may disable or modify security tools.",
            "sub_techniques": ["T1562.001 - Disable Security Tools"]
        },
    }
    return mitre_db.get(technique_id, {
        "name": "Unknown Technique",
        "tactic": "Unknown",
        "description": "Technique information not found.",
        "sub_techniques": []
    })


class AlertAnalyzer:
    """Main class for analyzing security alerts."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the alert analyzer."""
        self.config = config or {}
        self.ai_client = AIClient()
        self.enricher = AlertEnricher()
        self.wazuh_client = WazuhClient()
        self.playbook_mapping = load_playbook_mapping()
    
    def analyze(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a security alert and return enriched analysis.
        
        Args:
            alert: The raw Wazuh alert dictionary
            
        Returns:
            Enriched analysis with summary, recommendations, etc.
        """
        # Extract key fields
        rule_id = str(alert.get("rule", {}).get("id", "unknown"))
        rule_description = alert.get("rule", {}).get("description", "Unknown alert")
        severity = alert.get("rule", {}).get("level", 0)
        timestamp = alert.get("timestamp", datetime.now().isoformat())
        agent_name = alert.get("agent", {}).get("name", "unknown-agent")
        
        # Extract source IP if present
        src_ip = None
        if "data" in alert:
            src_ip = alert["data"].get("srcip") or alert["data"].get("src_ip")
        
        # Extract user if present
        user = None
        if "data" in alert:
            user = alert["data"].get("dstuser") or alert["data"].get("user")
        
        # Get MITRE technique
        mitre_ids = alert.get("rule", {}).get("mitre", {}).get("id", [])
        mitre_id = mitre_ids[0] if mitre_ids else None
        mitre_info = get_mitre_info(mitre_id) if mitre_id else {}
        
        # Enrich with context
        context = self.enricher.enrich(alert)
        
        # Generate AI analysis
        analysis = self.ai_client.analyze_alert(
            alert=alert,
            context=context,
            mitre_info=mitre_info
        )
        
        # Get relevant playbook
        playbook = self.playbook_mapping.get(rule_id, "general-incident.md")
        playbook_path = f"incident-response/playbooks/{playbook}"
        
        # Determine severity label
        if severity >= 12:
            severity_label = "CRITICAL"
            severity_color = Colors.RED
        elif severity >= 10:
            severity_label = "HIGH"
            severity_color = Colors.RED
        elif severity >= 7:
            severity_label = "MEDIUM"
            severity_color = Colors.YELLOW
        else:
            severity_label = "LOW"
            severity_color = Colors.GREEN
        
        return {
            "alert_title": analysis.get("title", rule_description),
            "rule_id": rule_id,
            "severity": severity,
            "severity_label": severity_label,
            "severity_color": severity_color,
            "timestamp": timestamp,
            "agent": agent_name,
            "source_ip": src_ip,
            "user": user,
            "summary": analysis.get("summary", "No summary available."),
            "context": context,
            "investigation_steps": analysis.get("investigation_steps", []),
            "recommended_actions": analysis.get("recommended_actions", []),
            "mitre_id": mitre_id,
            "mitre_info": mitre_info,
            "playbook": playbook,
            "playbook_path": playbook_path,
            "raw_alert": alert if self.config.get("include_raw") else None
        }
    
    def display_analysis(self, analysis: Dict[str, Any]):
        """Display the analysis in a formatted way."""
        print_header("AI ALERT ANALYSIS")
        
        # Alert title and metadata
        severity_color = analysis.get("severity_color", "")
        print(f"📋 {Colors.BOLD}ALERT: {analysis['alert_title']}{Colors.END}")
        print(f"   Rule: {analysis['rule_id']} | "
              f"Severity: {severity_color}{analysis['severity_label']}{Colors.END} | "
              f"Time: {analysis['timestamp']}")
        print()
        
        # Summary
        print_section("🎯", "SUMMARY", analysis["summary"])
        
        # Context
        context = analysis.get("context", {})
        context_lines = []
        if analysis.get("source_ip"):
            context_lines.append(f"• Source IP: {analysis['source_ip']}")
            if context.get("threat_intel"):
                ti = context["threat_intel"]
                context_lines.append(f"  Threat Intel: {ti.get('reports', 0)} reports, "
                                   f"Confidence: {ti.get('confidence', 0)}%")
        if analysis.get("agent"):
            context_lines.append(f"• Target System: {analysis['agent']}")
        if analysis.get("user"):
            context_lines.append(f"• User: {analysis['user']}")
        if context.get("related_events"):
            context_lines.append(f"• Related Events: {context['related_events']} in last 24h")
        if context.get("first_seen"):
            context_lines.append(f"• First Seen: {context['first_seen']}")
        
        if context_lines:
            print_section("📊", "CONTEXT", "\n".join(context_lines))
        
        # Investigation steps
        if analysis.get("investigation_steps"):
            steps = "\n".join([f"{i+1}. {step}" 
                              for i, step in enumerate(analysis["investigation_steps"])])
            print_section("🔍", "INVESTIGATION STEPS", steps)
        
        # Recommended actions
        if analysis.get("recommended_actions"):
            actions = "\n".join([f"{i+1}. {action}" 
                                for i, action in enumerate(analysis["recommended_actions"])])
            print_section("🛡️", "RECOMMENDED ACTIONS", actions)
        
        # Playbook reference
        print(f"{Colors.BOLD}📖 PLAYBOOK:{Colors.END} {analysis['playbook']}")
        print(f"   Link: {analysis['playbook_path']}")
        print()
        
        # MITRE ATT&CK
        if analysis.get("mitre_id"):
            mitre = analysis["mitre_info"]
            print(f"{Colors.BOLD}🏷️ MITRE ATT&CK:{Colors.END} {analysis['mitre_id']} - {mitre.get('name', 'Unknown')}")
            print(f"   Tactic: {mitre.get('tactic', 'Unknown')}")
        
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AI-Powered Alert Analyzer for Wazuh SIEM"
    )
    parser.add_argument(
        "--alert-id", "-a",
        help="Analyze alert by rule ID"
    )
    parser.add_argument(
        "--alert-file", "-f",
        help="Analyze alert from JSON file"
    )
    parser.add_argument(
        "--recent", "-r",
        type=int,
        help="Analyze N most recent alerts"
    )
    parser.add_argument(
        "--monitor", "-m",
        action="store_true",
        help="Monitor and analyze alerts in real-time"
    )
    parser.add_argument(
        "--output", "-o",
        choices=["terminal", "json", "markdown"],
        default="terminal",
        help="Output format"
    )
    parser.add_argument(
        "--include-raw",
        action="store_true",
        help="Include raw alert data in output"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with demo/sample alert"
    )
    
    args = parser.parse_args()
    
    # Initialize analyzer
    config = {
        "include_raw": args.include_raw,
        "output_format": args.output
    }
    analyzer = AlertAnalyzer(config)
    
    # Process based on mode
    if args.demo:
        # Demo mode with sample alert
        sample_alert = {
            "timestamp": datetime.now().isoformat(),
            "rule": {
                "id": "100001",
                "level": 10,
                "description": "SSH brute force attack detected",
                "mitre": {
                    "id": ["T1110"]
                }
            },
            "agent": {
                "name": "linux-endpoint-01"
            },
            "data": {
                "srcip": "203.0.113.45",
                "dstuser": "root"
            }
        }
        analysis = analyzer.analyze(sample_alert)
        analyzer.display_analysis(analysis)
        
    elif args.alert_file:
        # Analyze from file
        with open(args.alert_file, 'r') as f:
            alert = json.load(f)
        analysis = analyzer.analyze(alert)
        
        if args.output == "json":
            print(json.dumps(analysis, indent=2, default=str))
        elif args.output == "markdown":
            # TODO: Implement markdown output
            print("Markdown output not yet implemented")
        else:
            analyzer.display_analysis(analysis)
            
    elif args.recent:
        # Analyze recent alerts
        print(f"Analyzing {args.recent} most recent alerts...")
        # TODO: Implement Wazuh API integration
        print("Wazuh API integration not yet configured.")
        print("Use --demo flag for demonstration.")
        
    elif args.monitor:
        # Real-time monitoring
        print("Starting real-time alert monitoring...")
        print("Press Ctrl+C to stop.")
        # TODO: Implement real-time monitoring
        print("Real-time monitoring not yet implemented.")
        print("Use --demo flag for demonstration.")
        
    else:
        # Default: show help
        parser.print_help()
        print(f"\n{Colors.YELLOW}Tip: Use --demo flag to see a sample analysis{Colors.END}")


if __name__ == "__main__":
    main()
