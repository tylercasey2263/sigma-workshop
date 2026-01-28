# BOTSV1 Sigma Threat Hunting Workshop

A hands-on workshop teaching threat hunting and Sigma rule development using Splunk's Boss of the SOC (BOTS) Version 1 dataset.

## Overview

This workshop covers **22 Sigma detection rules** across two real-world attack scenarios:

| Scenario | Rules | Attack Type |
|----------|-------|-------------|
| **Po1s0n1vy APT** | 8 | Web exploitation, webshell, defacement |
| **Cerber Ransomware** | 12 | Macro malware, file encryption |
| **Correlation** | 2 | Full attack chain detection |

## Repository Structure

```
sigma-botsv1/
├── README.md                      # This file
├── workshop_manual.md             # Complete workshop guide
├── slides/                        # Presentation materials
├── scripts/
│   └── sync_rules.py              # Syncs rules to workshop manual
└── rules/
    ├── poisonivy/                 # APT attack detection rules
    │   ├── acunetix_scanner.yml
    │   ├── joomla_brute_force.yml
    │   ├── executable_upload.yml
    │   ├── webshell_execution.yml
    │   ├── website_defacement.yml
    │   ├── dynamic_dns.yml
    │   ├── malicious_ip.yml
    │   └── http_brute_force.yml
    ├── cerber/                    # Ransomware detection rules
    │   ├── office_macro_execution.yml
    │   ├── vbscript_temp_execution.yml
    │   ├── cerber_vbscript_traits.yml
    │   ├── payload_download.yml
    │   ├── cerber_dns_queries.yml
    │   ├── mass_file_modification.yml
    │   ├── tmp_file_execution.yml
    │   ├── usb_device_insertion.yml
    │   ├── macro_enabled_document.yml
    │   ├── icmp_traffic_pattern.yml
    │   ├── file_server_smb_activity.yml
    │   └── ransom_note_creation.yml
    └── correlation/               # Attack chain correlation rules
        ├── poisonivy_attack_chain.yml
        └── cerber_attack_chain.yml
```

## Lab Environment

- **Splunk URL:** https://splunk.samsclass.info/en-US/app/search/search
- **Credentials:** `student1` / `student1`
- **Index:** `botsv1`
- **Time Range:** August 10-24, 2016

## Attack Scenarios

### Scenario 1: Po1s0n1vy APT Attack

An Advanced Persistent Threat targets Wayne Enterprises' Joomla web server:

1. **Reconnaissance** - Acunetix vulnerability scanning
2. **Credential Access** - Brute force admin login
3. **Persistence** - Webshell upload (3791.exe)
4. **Execution** - Remote command execution
5. **Impact** - Website defacement
6. **C2** - Dynamic DNS communication

**Target:** `imreallynotbatman.com` (192.168.250.70)

### Scenario 2: Cerber Ransomware

An employee receives a malicious USB with a weaponized Word document:

1. **Initial Access** - USB device insertion
2. **Execution** - Macro-enabled document opened
3. **Execution** - VBScript dropper spawned
4. **C2** - Payload download from solidaritedeproximite.org
5. **C2** - DNS queries to cerber*.win domains
6. **Impact** - Local file encryption
7. **Lateral Movement** - File server encryption
8. **Impact** - Ransom note creation

**Patient Zero:** `we8105desk` (192.168.250.100) - Bob Smith's workstation
**Secondary Target:** `we9041srv` (192.168.250.20) - File server

## Learning Objectives

By completing this workshop, you will:

- Understand Sigma rule syntax and structure
- Convert Sigma rules to Splunk queries
- Hunt for malicious activity using structured detection logic
- Trace complete attack chains from initial access to impact
- Map detections to MITRE ATT&CK techniques

## Quick Start

1. Access the Splunk lab environment
2. Read the [Workshop Manual](workshop_manual.md)
3. Follow along with each detection, writing queries before checking examples
4. Review the individual Sigma rules in the `rules/` directory

## MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|--------|-------------------|
| Reconnaissance | T1595.002 |
| Initial Access | T1190, T1091 |
| Execution | T1059, T1204.002 |
| Persistence | T1505.003 |
| Credential Access | T1110.001 |
| Lateral Movement | T1021.002 |
| Command & Control | T1071, T1095, T1105 |
| Impact | T1486, T1491.001 |

## Maintaining Rules

The `rules/` directory is the **source of truth** for all Sigma rules. The workshop manual contains copies of these rules for easy reading.

### Automatic Sync

A pre-commit hook automatically syncs rule changes to `workshop_manual.md` before each commit. When you edit a rule in `/rules`, the manual updates automatically on your next commit.

### Manual Sync

To manually sync rules to the workshop manual:

```bash
python scripts/sync_rules.py
```

### Adding New Rules

1. Create the `.yml` file in the appropriate `/rules` subdirectory
2. Add the corresponding section in `workshop_manual.md` with a YAML code block containing the rule
3. The sync script matches rules by their `id:` field

## Resources

- [Sigma Project](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Splunk Security Content](https://research.splunk.com/)
- [BOTSV1 Dataset](https://github.com/splunk/botsv1)

## License

Creative Commons CC0 (aligned with BOTSV1 dataset license)
