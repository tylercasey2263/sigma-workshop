# Sigma Rule Writing Practice

## Overview

This exercise will help you develop practical skills in writing Sigma detection rules. You will be given **skeleton rules** with the metadata already filled out, but the **detection logic** and **logsource** sections are incomplete. Your task is to complete these rules so they can detect the specified adversary behavior.

### Learning Objectives
By completing these exercises, you will be able to:
- Understand the structure and syntax of Sigma rules
- Write detection logic using selection conditions
- Apply appropriate field modifiers (contains, endswith, startswith, etc.)
- Select the correct logsource category for different detection scenarios
- Map detections to MITRE ATT&CK techniques

### How to Complete These Exercises

For each scenario:
1. **Read the description** - Understand what adversary behavior you need to detect
2. **Review the hints** - Use the provided guidance on what fields and values to look for
3. **Complete the logsource** - Fill in the appropriate `category` and `product`
4. **Write the detection logic** - Create `selection` criteria and `condition` statement
5. **Test your rule** - Convert to Splunk and validate against the BOTSV1 dataset

### Sigma Detection Syntax Reference

**Common Logsource Categories:**
- `process_creation` - Process execution events (Sysmon EventCode=1)
- `dns` - DNS query events
- `proxy` / `webserver` - HTTP traffic
- `firewall` - Network firewall logs

**Common Field Modifiers:**
- `|contains` - Field contains the value anywhere
- `|startswith` - Field starts with the value
- `|endswith` - Field ends with the value
- `|re` - Regular expression match

**Condition Logic:**
- `selection` - Match all criteria in selection
- `selection1 and selection2` - Both must match
- `selection1 or selection2` - Either can match
- `not filter` - Exclude matches

---

## Exercise 1: Whoami Command Execution

### Scenario Description
After gaining initial access to a system, attackers commonly run the `whoami` command to determine their current user context and privileges. This is a fundamental discovery technique used in almost every intrusion.

**MITRE ATT&CK:** T1033 - System Owner/User Discovery

### What You Need to Detect
Detect any execution of the `whoami` command on a Windows system.

### Hints
- This is a process creation event
- The command could be run directly (`whoami`) or with arguments (`whoami /priv`, `whoami /all`)
- Look at either the `Image` field (process name) or `CommandLine` field

### Skeleton Rule - Complete the logsource and detection sections

```yaml
title: Whoami Command Execution
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects execution of whoami command commonly used for user discovery
references:
    - https://attack.mitre.org/techniques/T1033/
author: Student
date: 2026/01/29
tags:
    - attack.discovery
    - attack.t1033
logsource:
    # TODO: Fill in the logsource
    # Hint: What type of event is process execution on Windows?
    category: ???
    product: ???
detection:
    # TODO: Write the detection logic
    # Hint: What field contains the process name or command line?
    selection:
        ???: ???
    condition: selection
falsepositives:
    - System administrators checking user context
    - Legitimate scripts that verify running user
level: low
```

---

## Exercise 2: Net User Enumeration

### Scenario Description
Attackers frequently enumerate user accounts after compromising a system to identify additional targets for lateral movement or privilege escalation. The `net user` command displays user account information and can reveal domain administrators and service accounts.

**MITRE ATT&CK:** T1087.001 - Account Discovery: Local Account

### What You Need to Detect
Detect execution of `net user` or `net localgroup` commands used to enumerate accounts.

### Hints
- This is also a process creation event
- The process `net.exe` or `net1.exe` is used
- The CommandLine will contain `user` or `localgroup`
- You may need multiple selection criteria

### Skeleton Rule - Complete the logsource and detection sections

```yaml
title: Local Account and Group Enumeration via Net
id: b2c3d4e5-f6a7-8901-bcde-f23456789012
status: experimental
description: Detects enumeration of local users and groups using net.exe commands
references:
    - https://attack.mitre.org/techniques/T1087/001/
author: Student
date: 2026/01/29
tags:
    - attack.discovery
    - attack.t1087.001
logsource:
    # TODO: Fill in the logsource
    category: ???
    product: ???
detection:
    # TODO: Write the detection logic
    # Hint: You need to match the process (net.exe/net1.exe) AND the arguments
    selection_process:
        ???: ???
    selection_args:
        ???:
            - ???
            - ???
    condition: ???
falsepositives:
    - Administrative scripts
    - IT helpdesk troubleshooting
level: medium
```

---

## Exercise 3: Encoded PowerShell Execution

### Scenario Description
Attackers frequently use PowerShell with base64-encoded commands to evade simple detection rules and hide their malicious intent. The `-EncodedCommand` (or `-enc`, `-e`) parameter allows execution of base64-encoded scripts.

**MITRE ATT&CK:** T1059.001 - Command and Scripting Interpreter: PowerShell

### What You Need to Detect
Detect PowerShell execution with encoded command parameters.

### Hints
- The process will be `powershell.exe` or `pwsh.exe`
- Look for command line arguments like `-enc`, `-EncodedCommand`, `-e `
- PowerShell arguments are case-insensitive
- The encoded string is typically a long base64 string

### Skeleton Rule - Complete the logsource and detection sections

```yaml
title: PowerShell Encoded Command Execution
id: c3d4e5f6-a7b8-9012-cdef-345678901234
status: experimental
description: Detects execution of PowerShell with encoded commands often used to obfuscate malicious scripts
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: Student
date: 2026/01/29
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    # TODO: Fill in the logsource
    category: ???
    product: ???
detection:
    # TODO: Write the detection logic
    # Hint: Match PowerShell process AND encoded command arguments
    selection_process:
        ???:
            - ???
            - ???
    selection_encoded:
        ???:
            - ???
            - ???
            - ???
    condition: ???
falsepositives:
    - Legitimate administrative scripts using encoding for special characters
    - Software deployment tools
level: high
```

---

## Exercise 4: Certutil Download Abuse

### Scenario Description
Certutil.exe is a legitimate Windows certificate management tool that attackers abuse to download files from the internet. This "Living off the Land" (LOLBin) technique bypasses application whitelisting since certutil is a trusted Microsoft binary.

**MITRE ATT&CK:** T1105 - Ingress Tool Transfer

### What You Need to Detect
Detect certutil.exe being used with download-related parameters (`-urlcache`, `-split`, `http://`, `https://`).

### Hints
- The process is `certutil.exe`
- Download operations use `-urlcache` parameter
- The `-split` parameter is often used with downloads
- URLs in the command line indicate remote file retrieval

### Skeleton Rule - Complete the logsource and detection sections

```yaml
title: Certutil Download Abuse
id: d4e5f6a7-b8c9-0123-defa-456789012345
status: experimental
description: Detects abuse of certutil.exe to download files from remote URLs
references:
    - https://attack.mitre.org/techniques/T1105/
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
author: Student
date: 2026/01/29
tags:
    - attack.command_and_control
    - attack.t1105
logsource:
    # TODO: Fill in the logsource
    category: ???
    product: ???
detection:
    # TODO: Write the detection logic
    # Hint: Match certutil.exe process with download-related arguments
    selection_process:
        ???: ???
    selection_download:
        ???:
            - ???
            - ???
            - ???
            - ???
    condition: ???
falsepositives:
    - Legitimate certificate downloads by IT administrators
level: high
```

---

## Exercise 5: Scheduled Task Creation for Persistence

### Scenario Description
Attackers create scheduled tasks to maintain persistence on compromised systems. The task runs automatically at specified times or events, allowing malware to survive reboots. The `schtasks.exe` utility is commonly used to create these tasks.

**MITRE ATT&CK:** T1053.005 - Scheduled Task/Job: Scheduled Task

### What You Need to Detect
Detect the creation of scheduled tasks using schtasks.exe with the `/create` parameter.

### Hints
- The process is `schtasks.exe`
- Task creation uses the `/create` parameter
- You may also want to look for `/sc` (schedule type) and `/tr` (task to run)
- Suspicious tasks often run from temp directories or have encoded commands

### Skeleton Rule - Complete the logsource and detection sections

```yaml
title: Scheduled Task Creation via Schtasks
id: e5f6a7b8-c9d0-1234-efab-567890123456
status: experimental
description: Detects creation of scheduled tasks using schtasks.exe which may indicate persistence
references:
    - https://attack.mitre.org/techniques/T1053/005/
author: Student
date: 2026/01/29
tags:
    - attack.persistence
    - attack.t1053.005
logsource:
    # TODO: Fill in the logsource
    category: ???
    product: ???
detection:
    # TODO: Write the detection logic
    # Hint: Match schtasks.exe with /create parameter
    selection_process:
        ???: ???
    selection_create:
        ???: ???
    condition: ???
falsepositives:
    - Legitimate software installation
    - System administration scripts
    - Windows Update
level: medium
```

---

## Answer Key

After attempting all exercises, compare your solutions with the answer key below. Remember, there may be multiple valid approaches to writing detection logic!

<details>
<summary>Click to reveal answers (try the exercises first!)</summary>

### Exercise 1 Answer: Whoami Command Execution

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
```

Alternative using CommandLine:
```yaml
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
```

### Exercise 2 Answer: Net User Enumeration

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
    selection_args:
        CommandLine|contains:
            - ' user'
            - ' localgroup'
    condition: selection_process and selection_args
```

### Exercise 3 Answer: Encoded PowerShell Execution

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_encoded:
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
            - ' -e '
    condition: selection_process and selection_encoded
```

### Exercise 4 Answer: Certutil Download Abuse

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith: '\certutil.exe'
    selection_download:
        CommandLine|contains:
            - '-urlcache'
            - '-split'
            - 'http://'
            - 'https://'
    condition: selection_process and selection_download
```

### Exercise 5 Answer: Scheduled Task Creation via Schtasks

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith: '\schtasks.exe'
    selection_create:
        CommandLine|contains: '/create'
    condition: selection_process and selection_create
```

</details>

---

## Bonus Challenges

Once you've completed the exercises above, try these additional challenges:

1. **Enhance Exercise 1:** Modify the whoami detection to be higher severity when run from unusual parent processes (like cmd.exe spawned from Word or Excel)

2. **Enhance Exercise 3:** Add a filter to reduce false positives from known legitimate encoded PowerShell scripts (e.g., from SCCM or Intune)

3. **Create Your Own:** Write a Sigma rule to detect the use of `ipconfig /all` for network discovery (T1016)

4. **Combine Techniques:** Write a rule that detects when multiple discovery commands are run in sequence (whoami, ipconfig, net user) - indicating automated reconnaissance

---

**Document Version:** 1.0
**Last Updated:** January 29, 2026
**Author:** Tyler Casey
