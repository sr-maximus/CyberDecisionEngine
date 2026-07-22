from __future__ import annotations


ATTACK_MINIMAL = {
    "tactics": ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"],
    "techniques": {
        "T1566": "Phishing",
        "T1190": "Exploit Public-Facing Application",
        "T1078": "Valid Accounts",
        "T1110": "Brute Force",
        "T1059": "Command and Scripting Interpreter",
        "T1589": "Gather Victim Identity Information",
        "T1595": "Active Scanning",
        "T1486": "Data Encrypted for Impact",
    },
}
