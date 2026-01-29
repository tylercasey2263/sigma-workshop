# Sigma Threat Hunting Workshop

A hands-on workshop for learning threat hunting and Sigma rule development using Splunk's Boss of the SOC (BOTS) Version 1 dataset.

## Quick Start

1. Access the Splunk instance: https://splunk.samsclass.info/en-US/app/search/search or https://bots.splunk.com (you will need to make a Splunk account to utilize this site)
2. Login with `student1` / `student1`
3. Set time range to **August 09-11, 2016** and index to `botsv1`
4. **Part 1:** Complete the [Sigma Rule Writing Practice](labs/sigma_prac_app.md) exercises
5. **Part 2:** Follow the [Workshop Manual](labs/workshop_manual.md) for guided threat hunting

## What You'll Learn

- Sigma rule syntax and structure
- Writing detection logic with selection conditions and field modifiers
- Converting Sigma rules to Splunk queries
- Hunting for malicious activity using structured detection logic
- Tracing complete attack chains from initial access to impact
- Mapping detections to MITRE ATT&CK techniques

## Workshop Content

### Part 1: Sigma Rule Writing Practice

Start here to build foundational skills. The [Sigma Rule Writing Practice](labs/sigma_prac_app.md) provides **5 skeleton Sigma rules** where you complete the detection logic:

| Exercise | Detection Target | MITRE ATT&CK |
|----------|------------------|--------------|
| 1 | Whoami Command Execution | T1033 |
| 2 | Net User Enumeration | T1087.001 |
| 3 | Encoded PowerShell Execution | T1059.001 |
| 4 | Certutil Download Abuse | T1105 |
| 5 | Scheduled Task Persistence | T1053.005 |

### Part 2: Threat Hunting Walkthrough

After completing the practice exercises, move to the [Workshop Manual](labs/workshop_manual.md) which contains **22 Sigma detection rules** across two attack scenarios:

| Scenario | Rules | Description |
|----------|-------|-------------|
| Po1s0n1vy APT | 8 | Web exploitation, webshell deployment, site defacement |
| Cerber Ransomware (WIP) | 12 | Macro malware, lateral movement, file encryption |
| Correlation | 2 | Full attack chain detection |

## Attack Scenarios

### Scenario 1: Po1s0n1vy APT

An APT group targets Wayne Enterprises' Joomla web server (`imreallynotbatman.com`):

| Phase | Activity |
|-------|----------|
| Reconnaissance | Acunetix vulnerability scanning |
| Credential Access | Brute force admin login |
| Persistence | Webshell upload (3791.exe) |
| Execution | Remote command execution |
| Impact | Website defacement |
| C2 | Dynamic DNS communication |

**Target:** 192.168.250.70

### Scenario 2: Cerber Ransomware (WIP)

An employee opens a weaponized Word document from a USB drive:

| Phase | Activity |
|-------|----------|
| Initial Access | USB device insertion |
| Execution | Macro triggers VBScript dropper |
| C2 | Payload download, DNS beaconing to cerberhhyed5frqa.xmfir0.win |
| Impact | Local file encryption |
| Lateral Movement | SMB access to file server |
| Impact | Ransom note creation |

**Patient Zero:** we8105desk (192.168.250.100)
**File Server:** we9041srv (192.168.250.20)

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|------------|
| Reconnaissance | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) |
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/), [T1091](https://attack.mitre.org/techniques/T1091/) |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/), [T1204.002](https://attack.mitre.org/techniques/T1204/002/) |
| Persistence | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) |
| Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Lateral Movement | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) |
| Command & Control | [T1071](https://attack.mitre.org/techniques/T1071/), [T1095](https://attack.mitre.org/techniques/T1095/), [T1105](https://attack.mitre.org/techniques/T1105/) |
| Impact | [T1486](https://attack.mitre.org/techniques/T1486/), [T1491.001](https://attack.mitre.org/techniques/T1491/001/) |

## Repository Structure

```
rules/
├── poisonivy/      # APT detection rules (8)
├── cerber/         # Ransomware detection rules (12)
└── correlation/    # Attack chain rules (2)
labs/
├── sigma_prac_app.md   # Part 1: Sigma rule writing exercises
└── workshop_manual.md  # Part 2: Guided threat hunting walkthrough
scripts/
└── sync_rules.py   # Syncs rules to workshop manual
hooks/
└── pre-commit      # Auto-syncs rules on commit
```

## Setup

After cloning, enable the pre-commit hook:

```bash
git config core.hooksPath hooks
```

This ensures the workshop manual stays in sync with rule changes.

## Maintaining Rules

The `rules/` directory is the source of truth. To manually sync changes:

```bash
python scripts/sync_rules.py
```

The pre-commit hook runs this automatically on each commit.

## Resources

- [Sigma Project](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Splunk Security Content](https://research.splunk.com/)
- [BOTSV1 Dataset](https://github.com/splunk/botsv1)

## License

CC0 - Public Domain (aligned with BOTSV1 dataset)
