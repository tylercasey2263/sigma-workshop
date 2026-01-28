# BOTSV1 Sigma Threat Hunting Workshop Manual

## Workshop Overview

Welcome to the BOTSV1 Sigma Threat Hunting Workshop! In this hands-on exercise, you'll use Sigma rules to detect and investigate two real-world attack scenarios captured in Splunk's Boss of the SOC (BOTS) Version 1 dataset.

### Learning Objectives
By the end of this workshop, you will be able to:
- Understand how Sigma rules describe detection logic in a vendor-neutral format
- Convert Sigma rules into Splunk queries
- Hunt for malicious activity using structured detection rules
- Trace attack chains from initial access to impact
- Analyze attacker techniques using the MITRE ATT&CK framework

---

## Lab Environment

### Splunk Instance Access
- **URL:** https://splunk.samsclass.info/en-US/app/search/search
- **Username:** `student1`
- **Password:** `student1`
- **Index:** `botsv1`
- **Time Range:** August 09-11, 2016

### Important Notes
- All data is from the BOTSV1 dataset (August 2016)
- You have read-only access to the environment
- Queries may take time to complete - be patient!
- Use the time picker to narrow searches

---

## Attack Scenarios Overview

### Scenario 1: Po1s0n1vy APT Attack
**Attack Summary:** An Advanced Persistent Threat (APT) group targets Wayne Enterprises' public-facing web server running Joomla CMS. The attackers perform reconnaissance, exploit vulnerabilities, gain persistence through a webshell, deface the website, and establish command and control communication.

**Attack Chain:**
1. **Reconnaissance** - Web vulnerability scanning
2. **Initial Access** - Brute force authentication attack
3. **Execution** - Upload and execute webshell
4. **Persistence** - Maintain access through webshell
5. **Impact** - Website defacement
6. **Command & Control** - Communication with attacker infrastructure

**Key Systems Affected:**
- `imreallynotbatman.com` (192.168.250.70) - Compromised web server

---

### Scenario 2: Cerber Ransomware Attack
**Attack Summary:** An employee receives a malicious USB device containing a weaponized Microsoft Word document. When opened, the document executes malicious macros that download and execute Cerber ransomware, encrypting files on the local workstation and spreading to network file shares.

**Attack Chain:**
1. **Initial Access** - Malicious USB device insertion
2. **Execution** - User opens macro-enabled document
3. **Execution** - VBA macros execute VBScript dropper
4. **Command & Control** - Download ransomware payload
5. **Command & Control** - DNS queries to C2 infrastructure
6. **Impact** - Mass file encryption on workstation
7. **Lateral Movement** - Spread to file server
8. **Impact** - File server encryption

**Key Systems Affected:**
- `we8105desk` (192.168.250.100) - Bob Smith's workstation (Patient Zero)
- `we9041srv` (192.168.250.20) - File server

---

## BOTSV1 Sourcetype Reference

Before diving into the hunt, familiarize yourself with the main data sources available in BOTSV1:

| Sourcetype | Description | Use Case |
|------------|-------------|----------|
| `stream:http` | HTTP traffic (web requests/responses) | Web attacks, file uploads, downloads, C2 communication |
| `stream:dns` | DNS queries and responses | C2 domain lookups, data exfiltration |
| `stream:ip` | IP network traffic | Network connections, firewall activity |
| `stream:icmp` | ICMP traffic | Ping sweeps, covert channels |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Windows Sysmon logs (detailed process/file/network activity) | Process creation, file modifications, network connections |
| `WinEventLog:Security` | Windows Security Event Logs | Authentication, file access, security changes |
| `WinEventLog:System` | Windows System Event Logs | Service installations, driver loads |
| `fgt_utm` | Fortigate Firewall UTM logs | Network traffic, IDS alerts |
| `suricata` | Suricata IDS alerts | Network-based threat detection |
| `iis` | IIS web server logs | Web server access and errors |

### Key Sysmon Event Codes
- **EventCode=1** - Process Creation
- **EventCode=2** - File Creation Time Changed
- **EventCode=3** - Network Connection
- **EventCode=7** - Image/DLL Loaded
- **EventCode=11** - File Created
- **EventCode=22** - DNS Query

---

## How to Use This Manual

### For Each Detection Rule:
1. **Read the Detection Description** - Understand what you're hunting for and why
2. **Review the Query Optimization Notes** - Know which data sources to search
3. **Study the Sigma Rule** - Analyze the detection logic
4. **Write Your Query** - Try creating your own Splunk search before looking at examples
5. **Execute and Analyze** - Run the query and examine the results
6. **Review the Findings** - Understand what was detected and its significance in the attack chain

### Tips for Success:
- Start with simple searches to verify data exists
- Use `| head 10` to limit results while testing
- Use `| table` to focus on relevant fields
- Build queries incrementally - test each component
- Pay attention to time ranges
- Use `| stats count by <field>` to summarize results

---

# Scenario 1: Po1s0n1vy APT Attack

## Detection 1: Web Vulnerability Scanner

### What Are We Looking For?
Attackers often begin their reconnaissance by scanning web applications for vulnerabilities using automated tools. One popular commercial tool is Acunetix, which leaves a distinctive User-Agent string in HTTP requests. Detecting vulnerability scanners can alert us to reconnaissance activity - the first stage of an attack.

### Why This Matters
- **Attack Stage:** Reconnaissance (MITRE ATT&CK T1595.002 - Active Scanning: Vulnerability Scanning)
- **Significance:** This is often the first observable indicator that an attacker is targeting your infrastructure
- **Response Priority:** High - Provides early warning before exploitation occurs

### Detection Strategy
Look for HTTP requests containing "Acunetix" in the User-Agent header. Legitimate traffic will never contain this string, making it a high-fidelity indicator.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=stream:http`
- **Key Fields:** `http_user_agent`, `src_ip`, `dest_ip`, `uri_path`

### Sigma Rule
```yaml
title: Acunetix Web Vulnerability Scanner User-Agent
id: 4c5f5d3e-2b1a-4f9c-9e8d-7a6b5c4d3e2f
status: experimental
description: Detects the use of Acunetix web vulnerability scanner based on User-Agent string
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.reconnaissance
    - attack.t1595.002
logsource:
    category: proxy
    product: web
detection:
    selection:
        http_user_agent|contains:
            - 'Acunetix'
            - 'acunetix'
    condition: selection
falsepositives:
    - Legitimate vulnerability scanning by authorized security teams
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=stream:http 
| search http_user_agent="*Acunetix*"
| table _time src_ip dest_ip uri_path http_user_agent
| sort _time
```

### What This Detection Finds
Running this query against the BOTSV1 dataset reveals scanning activity from IP address **40.80.148.42** targeting the website **imreallynotbatman.com**. The scanner probes various URIs looking for common vulnerabilities in the Joomla CMS installation.

**Key Findings:**
- **Attacker IP:** 40.80.148.42
- **Target:** imreallynotbatman.com (192.168.250.70)
- **Tool Used:** Acunetix Web Vulnerability Scanner
- **Attack Stage:** Reconnaissance / Information Gathering

**Attack Chain Context:**
This is the **first step** in the Po1s0n1vy attack chain. The attacker is gathering information about the target web server, identifying the Joomla CMS version, installed plugins, and potential vulnerabilities to exploit in the next phase.

---

## Detection 2: Joomla Brute Force Authentication Attack

### What Are We Looking For?
After identifying that the target runs Joomla, attackers often attempt to brute force the administrator login page. This involves sending many POST requests to `/joomla/administrator/index.php` with different password combinations. Multiple failed login attempts from a single source IP indicate a credential-stuffing or brute force attack.

### Why This Matters
- **Attack Stage:** Credential Access (MITRE ATT&CK T1110.001 - Brute Force: Password Guessing)
- **Significance:** Successful brute force grants the attacker administrative access to the CMS
- **Response Priority:** High - Active attack in progress

### Detection Strategy
Monitor for HTTP POST requests to the Joomla administrator login page containing password parameters (`passwd=`). While a single request is normal, many requests in a short time frame from the same IP suggests brute forcing.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=stream:http`
- **Key Fields:** `http_method`, `uri_path`, `uri_query`, `src_ip`, `status`

### Sigma Rule
```yaml
title: Multiple Failed Joomla Administrator Login Attempts
id: 7e9f8a6b-5c4d-3e2f-1a0b-9c8d7e6f5a4b
status: experimental
description: Detects failed login attempts to Joomla administrator interface indicating brute force attack
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.credential_access
    - attack.t1110.001
logsource:
    category: webserver
    product: web
detection:
    selection:
        uri_path|contains: '/joomla/administrator/index.php'
        http_method: 'POST'
        uri_query|contains: 'passwd='
    condition: selection
falsepositives:
    - Users with forgotten passwords
    - Password managers attempting to autofill
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=stream:http 
| search uri_path="*/joomla/administrator/index.php*" http_method=POST uri_query="*passwd=*"
| stats count by src_ip
| where count > 10
| sort -count
```

### What This Detection Finds
This query reveals **thousands of login attempts** from IP address **23.22.63.114** to the Joomla administrator login page. The high volume of attempts confirms this is an automated brute force attack.

**Key Findings:**
- **Attacker IP:** 23.22.63.114 (different from scanner IP - likely the C2/exploitation server)
- **Target:** /joomla/administrator/index.php
- **Method:** POST requests with varying passwords
- **Volume:** 500+ attempts observed
- **Attack Stage:** Credential Access / Brute Force

**Attack Chain Context:**
After reconnaissance revealed a Joomla installation, the attacker moved to the **second step**: gaining access. By brute forcing the admin credentials, the attacker attempts to obtain legitimate administrative access to the CMS, which would allow them to upload malicious files and modify the website.

---

## Detection 3: Executable File Upload via HTTP POST

### What Are We Looking For?
Once attackers gain access to a web application's admin panel, they often upload malicious files to gain code execution. Web servers should typically only serve web content (HTML, CSS, JavaScript, images), not executable files. An upload of .exe, .dll, or script files via HTTP POST with `multipart/form-data` is highly suspicious.

### Why This Matters
- **Attack Stage:** Initial Access (MITRE ATT&CK T1190 - Exploit Public-Facing Application) and Persistence (T1505.003 - Web Shell)
- **Significance:** Executable uploads usually lead to remote code execution on the server
- **Response Priority:** Critical - Active compromise in progress

### Detection Strategy
Monitor HTTP POST requests with `multipart/form-data` content type (used for file uploads) where the URI query or form data contains executable file extensions like .exe, .dll, .vbs, .bat, or .ps1.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=stream:http`
- **Key Fields:** `http_method`, `http_content_type`, `uri_query`, `form_data`, `src_ip`, `dest_ip`

### Sigma Rule
```yaml
title: Executable File Upload via HTTP POST Multipart Form
id: 9a8b7c6d-5e4f-3a2b-1c0d-8e7f6a5b4c3d
status: experimental
description: Detects upload of executable files via HTTP POST with multipart/form-data
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.initial_access
    - attack.t1190
    - attack.persistence
    - attack.t1505.003
logsource:
    category: proxy
    product: web
detection:
    selection:
        http_method: 'POST'
        http_content_type|contains: 'multipart/form-data'
    selection_uri:
        - uri_query|contains:
            - '.exe'
            - '.dll'
            - '.bat'
            - '.cmd'
            - '.ps1'
            - '.vbs'
        - form_data|contains:
            - '.exe'
            - '.dll'
            - '.bat'
            - '.cmd'
            - '.ps1'
            - '.vbs'
    condition: selection and selection_uri
falsepositives:
    - Legitimate software updates
    - File sharing applications
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=stream:http 
| search http_method=POST http_content_type="*multipart/form-data*" 
| search uri_query="*.exe*" OR form_data="*.exe*"
| table _time src_ip dest_ip uri_path form_data
| sort _time
```

### What This Detection Finds
This detection reveals the upload of a file called **3791.exe** to the compromised Joomla server. The file was uploaded through the Joomla administrator interface after the successful brute force attack.

**Key Findings:**
- **Attacker IP:** 23.22.63.114
- **Uploaded File:** 3791.exe
- **Upload Path:** /joomla/administrator/
- **File Hash (MD5):** AAE3F5A29935E6ABCC2C2754D12A9AF0
- **File Type:** Windows executable (webshell)
- **Attack Stage:** Persistence / Web Shell Installation

**Attack Chain Context:**
After successfully brute forcing the admin credentials in step 2, the attacker now **establishes persistence** by uploading a webshell (3791.exe). This malicious executable allows the attacker to execute arbitrary commands on the web server, giving them full control over the system. This is the **third step** - transitioning from credential access to code execution.

---

## Detection 4: Webshell Process Execution

### What Are We Looking For?
After uploading a webshell, attackers execute it to run commands on the compromised server. Webshells typically reside in web server directories (like `\inetpub\wwwroot\` on IIS) and execute reconnaissance commands to understand the system. Common post-exploitation commands include `whoami`, `ipconfig`, `net user`, and `systeminfo`.

### Why This Matters
- **Attack Stage:** Execution (MITRE ATT&CK T1059 - Command and Scripting Interpreter)
- **Significance:** Confirms active attacker interaction with the compromised system
- **Response Priority:** Critical - Attacker has remote code execution

### Detection Strategy
Look for process creation events (Sysmon EventCode=1) where executables are running from web server directories and executing suspicious commands commonly used in post-exploitation.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **EventCode:** `EventCode=1` (Process Creation)
- **Key Fields:** `Image`, `CommandLine`, `ParentImage`, `ComputerName`

### Sigma Rule
```yaml
title: Suspicious Process Execution from Web Server Working Directory
id: 1b2c3d4e-5f6a-7b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: Detects execution of suspicious processes from web server directories indicating webshell activity
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.execution
    - attack.t1059
    - attack.persistence
    - attack.t1505.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - '\inetpub\wwwroot\'
            - '\xampp\htdocs\'
            - '\wamp\www\'
        Image|endswith:
            - '.exe'
        CommandLine|contains:
            - 'whoami'
            - 'net user'
            - 'net localgroup'
            - 'ipconfig'
            - 'systeminfo'
            - 'cmd.exe'
            - 'powershell'
    condition: selection
falsepositives:
    - Legitimate web applications with executable components
level: critical
```

### Example Splunk Query
```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\inetpub\\wwwroot\\*" OR Image="*\\xampp\\htdocs\\*"
| search CommandLine="*whoami*" OR CommandLine="*ipconfig*" OR CommandLine="*systeminfo*"
| table _time ComputerName User Image CommandLine ParentImage
| sort _time
```

### What This Detection Finds
This query reveals the execution of **3791.exe** from the webroot directory, running reconnaissance commands to enumerate the system. The webshell is being actively used by the attacker.

**Key Findings:**
- **Webshell Location:** C:\inetpub\wwwroot\joomla\3791.exe
- **Commands Executed:** whoami, ipconfig, systeminfo, net user
- **Parent Process:** Usually w3wp.exe (IIS worker process)
- **Attack Stage:** Execution / Discovery

**Attack Chain Context:**
The uploaded webshell (from step 3) is now **actively being used** by the attacker in step 4. By executing reconnaissance commands, the attacker is gathering information about the compromised system's configuration, users, and network connectivity. This information will guide their next actions, such as lateral movement or further exploitation.

---

## Detection 5: Website Defacement File Upload

### What Are We Looking For?
Attackers sometimes deface websites to send a message, damage reputation, or demonstrate their access. This typically involves uploading image files (often with threatening or political messages) to the web directory and modifying the site to display them.

### Why This Matters
- **Attack Stage:** Impact (MITRE ATT&CK T1491.001 - Defacement: Internal Defacement)
- **Significance:** Visible impact that affects business operations and reputation
- **Response Priority:** High - Public-facing damage

### Detection Strategy
Look for suspicious image file uploads via POST requests to web application directories, especially following other compromise indicators like brute force or webshell activity.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=stream:http`
- **Key Fields:** `http_method`, `uri_path`, `uri_query`, `form_data`, `src_ip`

### Sigma Rule
```yaml
title: Suspicious Image File Upload to Web Directory
id: 2c3d4e5f-6a7b-8c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: Detects upload of image files that may be used for website defacement
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.impact
    - attack.t1491.001
logsource:
    category: proxy
    product: web
detection:
    selection:
        http_method: 'POST'
        uri_path|contains:
            - '/joomla/'
            - '/administrator/'
            - '/uploads/'
    selection_file:
        - uri_query|contains:
            - '.jpg'
            - '.jpeg'
            - '.png'
            - '.gif'
        - form_data|contains:
            - '.jpg'
            - '.jpeg'
            - '.png'
            - '.gif'
    filter:
        http_referrer|contains: 'legitimate-domain.com'
    condition: selection and selection_file and not filter
falsepositives:
    - Legitimate content management
    - User profile picture uploads
level: medium
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=stream:http 
| search http_method=POST uri_path="*/joomla/*"
| search form_data="*.jpg" OR form_data="*.jpeg" OR form_data="*.png"
| table _time src_ip dest_ip uri_path form_data
| sort _time
```

### What This Detection Finds
The query reveals the upload of a defacement image: **poisonivy-is-coming-for-you-batman.jpeg**. This image was uploaded to replace the website's homepage, announcing the compromise.

**Key Findings:**
- **Attacker IP:** 23.22.63.114
- **Defacement File:** poisonivy-is-coming-for-you-batman.jpeg
- **Upload Location:** /joomla/images/
- **Message:** References "Poison Ivy" malware and Batman theme (Wayne Enterprises)
- **Attack Stage:** Impact / Defacement

**Attack Chain Context:**
After establishing access and reconnaissance (steps 1-4), the attacker moves to **step 5: impact**. By defacing the website with a taunting message, the attacker demonstrates their control and causes reputational damage to Wayne Enterprises. This is often the most visible part of the attack to external observers.

---

## Detection 6: Dynamic DNS Domain Access

### What Are We Looking For?
Attackers often use Dynamic DNS (DDNS) services to host their command and control (C2) infrastructure. DDNS providers like no-ip.com, duckdns.org, and others allow attackers to quickly change IP addresses while maintaining the same domain name, making it harder to block their infrastructure. DNS queries to these domains can indicate C2 communication.

### Why This Matters
- **Attack Stage:** Command and Control (MITRE ATT&CK T1071.001 - Application Layer Protocol: Web Protocols)
- **Significance:** Indicates ongoing attacker communication with compromised systems
- **Response Priority:** High - Active C2 channel

### Detection Strategy
Monitor DNS queries for domains ending in known DDNS provider suffixes. While some legitimate services use DDNS, queries from enterprise servers are suspicious.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=stream:dns`
- **Key Fields:** `query`, `src_ip`, `answer`

### Sigma Rule
```yaml
title: Access to Suspicious Dynamic DNS Provider
id: 3d4e5f6a-7b8c-9d0e-1f2a-3b4c5d6e7f8a
status: experimental
description: Detects DNS queries or HTTP requests to dynamic DNS providers often used by attackers
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: dns
detection:
    selection:
        query|endswith:
            - '.jumpingcrab.com'
            - '.no-ip.com'
            - '.duckdns.org'
            - '.ddns.net'
            - '.dynu.com'
    condition: selection
falsepositives:
    - Legitimate use of dynamic DNS services
    - IoT devices using DDNS
level: medium
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=stream:dns
| search query="*.jumpingcrab.com" OR query="*.no-ip.com" OR query="*.duckdns.org"
| table _time src_ip query answer
| sort _time
```

### What This Detection Finds
The compromised web server queries the domain **prankglassinebracket.jumpingcrab.com**, a DDNS domain used by the attacker for C2 communication. This domain resolves to IP address 23.22.63.114 (the attacker's server).

**Key Findings:**
- **Compromised Host:** 192.168.250.70 (imreallynotbatman.com)
- **C2 Domain:** prankglassinebracket.jumpingcrab.com
- **C2 IP:** 23.22.63.114
- **DDNS Provider:** jumpingcrab.com
- **Attack Stage:** Command and Control

**Attack Chain Context:**
This is **step 6**: establishing persistent C2 communication. After compromising the server and defacing the website, the attacker maintains communication through the DDNS domain. This allows them to:
- Receive commands from their C2 server
- Exfiltrate data
- Update their tools
- Maintain long-term access even if IP addresses change

---

## Detection 7: Connection to Known Malicious Infrastructure

### What Are We Looking For?
Once we've identified attacker infrastructure through other detections, we can create rules to detect any connections to those specific IPs or domains. This helps identify additional compromised systems or ongoing attacker activity.

### Why This Matters
- **Attack Stage:** Command and Control (MITRE ATT&CK T1071)
- **Significance:** Direct evidence of communication with attacker infrastructure
- **Response Priority:** Critical - Confirmed malicious activity

### Detection Strategy
Create an indicator-based detection using known malicious IPs and domains discovered during the investigation. Monitor firewall logs, network traffic, and HTTP connections for communications with these indicators of compromise (IOCs).

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=stream:ip OR sourcetype=fgt_utm OR sourcetype=stream:http`
- **Key Fields:** `dest_ip`, `dest`, `src_ip`

### Sigma Rule
```yaml
title: Network Connection to Po1s0n1vy C2 Infrastructure
id: 4e5f6a7b-8c9d-0e1f-2a3b-4c5d6e7f8a9b
status: experimental
description: Detects network connections to known Po1s0n1vy APT infrastructure
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.command_and_control
    - attack.t1071
logsource:
    category: firewall
detection:
    selection:
        dest_ip:
            - '23.22.63.114'
        dest|contains:
            - 'po1s0n1vy.com'
    condition: selection
falsepositives:
    - None expected
level: critical
```

### Example Splunk Query
```spl
index=botsv1 (sourcetype=stream:ip OR sourcetype=fgt_utm OR sourcetype=stream:http)
| search dest_ip="23.22.63.114" OR dest="*po1s0n1vy.com*"
| stats count by src_ip, dest_ip, dest
| sort -count
```

### What This Detection Finds
Multiple connections from the compromised web server (192.168.250.70) to the attacker's C2 server at 23.22.63.114. The connections span several days, indicating persistent access.

**Key Findings:**
- **Compromised System:** 192.168.250.70 (imreallynotbatman.com)
- **C2 Server:** 23.22.63.114
- **Connection Frequency:** Multiple connections over several days
- **Protocols:** HTTP, HTTPS
- **Attack Stage:** Command and Control / Persistence

**Attack Chain Context:**
This detection provides a **comprehensive view** of the attacker's C2 infrastructure usage. By monitoring all connections to the known malicious IP, we can:
- Identify the scope of compromise (only one system or multiple?)
- Track attacker activity timeline
- Understand persistence mechanisms
- Create network blocks to prevent future communication

This completes the **Po1s0n1vy attack chain**, showing progression from initial scanning through persistent C2 access.

---

## Detection 8: HTTP Brute Force Attack Pattern

### What Are We Looking For?
This is an alternative detection for brute force attacks that focuses on failed authentication responses rather than just looking for login POST requests. HTTP status codes 401 (Unauthorized) and 403 (Forbidden) indicate failed authentication attempts.

### Why This Matters
- **Attack Stage:** Credential Access (MITRE ATT&CK T1110.001)
- **Significance:** Helps detect brute force attacks even when URI patterns vary
- **Response Priority:** High - Active credential attack

### Detection Strategy
Look for HTTP POST requests with authentication parameters (username, password, passwd) that return 401 or 403 status codes, indicating failed login attempts.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=stream:http`
- **Key Fields:** `http_method`, `uri_query`, `status`, `src_ip`

### Sigma Rule
```yaml
title: HTTP POST Brute Force Attack Pattern
id: 5f6a7b8c-9d0e-1f2a-3b4c-5d6e7f8a9b0c
status: experimental
description: Detects HTTP POST-based brute force attacks indicating failed login attempts
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.credential_access
    - attack.t1110.001
logsource:
    category: proxy
    product: web
detection:
    selection:
        http_method: 'POST'
        uri_query|contains:
            - 'username='
            - 'passwd='
            - 'password='
        status:
            - 401
            - 403
    condition: selection
falsepositives:
    - Users repeatedly mistyping passwords
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=stream:http 
| search http_method=POST (status=401 OR status=403)
| search uri_query="*username=*" OR uri_query="*passwd=*" OR uri_query="*password=*"
| stats count by src_ip, dest_ip, uri_path
| where count > 20
| sort -count
```

### What This Detection Finds
This detection provides an alternative view of the brute force attack detected in Detection 2, confirming the high volume of failed authentication attempts before the successful compromise.

**Key Findings:**
- **Attacker IP:** 23.22.63.114
- **Failed Attempts:** Hundreds of 401/403 responses
- **Target:** Multiple login interfaces
- **Attack Stage:** Credential Access

**Attack Chain Context:**
This detection serves as a **complementary indicator** to Detection 2, providing additional confidence in identifying brute force attacks by focusing on server responses rather than just request patterns. It's useful when URI patterns vary across different applications.

---

# Scenario 2: Cerber Ransomware Attack

## Detection 9: Microsoft Office Spawning Suspicious Child Processes

### What Are We Looking For?
Microsoft Office applications (Word, Excel, PowerPoint) normally don't spawn other executables or script interpreters. When they do, it's usually because malicious macro code is executing. Macros can launch script interpreters like wscript.exe, cscript.exe, cmd.exe, or powershell.exe to download malware or establish persistence.

### Why This Matters
- **Attack Stage:** Execution (MITRE ATT&CK T1204.002 - User Execution: Malicious File)
- **Significance:** High-fidelity indicator of malicious macro execution
- **Response Priority:** Critical - Active malware execution

### Detection Strategy
Monitor process creation events (Sysmon EventCode=1) where the parent process is a Microsoft Office application (WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE) and the child process is a script interpreter or command shell.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1`
- **Key Fields:** `ParentImage`, `Image`, `CommandLine`, `ComputerName`, `User`

### Sigma Rule
```yaml
title: Microsoft Office Spawning Suspicious Child Process
id: 6a7b8c9d-0e1f-2a3b-4c5d-6e7f8a9b0c1d
status: experimental
description: Detects Microsoft Office applications spawning suspicious child processes indicating macro execution
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.execution
    - attack.t1204.002
    - attack.defense_evasion
    - attack.t1027.010
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\POWERPNT.EXE'
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
            - '\cmd.exe'
            - '\powershell.exe'
            - '\mshta.exe'
    condition: selection
falsepositives:
    - Legitimate macros used in business processes
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search ParentImage="*WINWORD.EXE*" (Image="*wscript.exe*" OR Image="*cscript.exe*" OR Image="*cmd.exe*" OR Image="*powershell.exe*")
| table _time ComputerName User ParentImage Image CommandLine
| sort _time
```

### What This Detection Finds
The query reveals that on Bob Smith's workstation (we8105desk), Microsoft Word (WINWORD.EXE) spawned **wscript.exe** to execute a VBScript file. This occurred when Bob opened the malicious document **Miranda_Tate_unveiled.dotm**.

**Key Findings:**
- **Victim Host:** we8105desk (192.168.250.100)
- **User:** bob.smith.WAYNECORPINC
- **Parent Process:** WINWORD.EXE
- **Child Process:** wscript.exe
- **Script Executed:** VBScript dropper in AppData\Local\Temp
- **Attack Stage:** Execution / Initial Compromise

**Attack Chain Context:**
This is the **first executable indicator** in the Cerber ransomware attack chain (step 3 in the overall chain). After Bob inserted the malicious USB drive and opened the Word document (steps 1-2), the document's malicious VBA macro executed, spawning wscript.exe to run the VBScript dropper. This marks the transition from user interaction to automated malware execution.

---

## Detection 10: VBScript Execution from Temporary Directory

### What Are We Looking For?
VBScript files (.vbs) executing from temporary directories (AppData\Local\Temp, AppData\Roaming) are highly suspicious. Legitimate scripts are typically stored in program files or IT-managed locations, not user temp folders. Malware often drops and executes scripts from temp directories as part of the infection chain.

### Why This Matters
- **Attack Stage:** Execution (MITRE ATT&CK T1059.005 - Command and Scripting Interpreter: Visual Basic)
- **Significance:** Common malware technique for droppers and downloaders
- **Response Priority:** Critical - Active malware execution

### Detection Strategy
Look for wscript.exe or cscript.exe executing files with .vbs or .vbe extensions from temporary directories in the user profile.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1`
- **Key Fields:** `Image`, `CommandLine`, `ComputerName`, `User`

### Sigma Rule
```yaml
title: VBScript Execution from Temporary Directory
id: 7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e
status: experimental
description: Detects execution of VBScript files from temporary directories
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.execution
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
        CommandLine|contains:
            - '\AppData\Local\Temp\'
            - '\AppData\Roaming\'
            - '\Users\Public\'
        CommandLine|endswith:
            - '.vbs'
            - '.vbe'
    condition: selection
falsepositives:
    - Legitimate scripts run from temporary locations
    - Software installers
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (Image="*wscript.exe*" OR Image="*cscript.exe*")
| search CommandLine="*AppData\\Local\\Temp*" CommandLine="*.vbs"
| table _time ComputerName User Image CommandLine ParentImage
| sort _time
```

### What This Detection Finds
The query identifies the VBScript dropper being executed from Bob Smith's temporary directory. The script has a randomly generated name to evade simple signature detection.

**Key Findings:**
- **Victim Host:** we8105desk
- **Script Location:** C:\Users\bob.smith.WAYNECORPINC\AppData\Local\Temp\[random].vbs
- **Execution Method:** wscript.exe
- **Parent Process:** WINWORD.EXE (from Detection 9)
- **Attack Stage:** Execution / Dropper

**Attack Chain Context:**
This detection captures **step 4** of the attack chain in greater detail. The VBScript dropped and executed by the malicious Word macro (Detection 9) is now running from the temp directory. This script's job is to download the actual Cerber ransomware payload from the attacker's server. This is a classic multi-stage attack pattern designed to evade detection.

---

## Detection 11: Cerber Ransomware VBScript Characteristics

### What Are We Looking For?
This is a more specific detection building on Detection 10, focusing specifically on VBScripts spawned from Word that contain characteristics typical of Cerber ransomware dropper scripts. The combination of Word as the parent process and VBScript execution from AppData is highly indicative of this specific malware family.

### Why This Matters
- **Attack Stage:** Execution (MITRE ATT&CK T1059.005)
- **Significance:** High-confidence detection of Cerber ransomware dropper
- **Response Priority:** Critical - Known ransomware family

### Detection Strategy
Correlate the parent-child process relationship (WINWORD.EXE → wscript.exe) with VBScript execution from AppData to create a high-fidelity detection specific to Cerber's infection method.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1`
- **Key Fields:** `ParentImage`, `CommandLine`, `Image`

### Sigma Rule
```yaml
title: Cerber Ransomware VBScript Characteristics
id: 8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f
status: experimental
description: Detects VBScript with characteristics of Cerber ransomware dropper
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.execution
    - attack.t1059.005
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '.vbs'
            - 'AppData'
    suspicious_parent:
        ParentImage|endswith: '\WINWORD.EXE'
    condition: selection and suspicious_parent
falsepositives:
    - Rare legitimate scenarios
level: critical
```

### Example Splunk Query
```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search ParentImage="*WINWORD.EXE*" CommandLine="*.vbs*" CommandLine="*AppData*"
| table _time ComputerName User ParentImage Image CommandLine
| sort _time
```

### What This Detection Finds
This focused detection confirms the Cerber ransomware dropper execution, providing high-confidence identification of this specific malware family.

**Key Findings:**
- **Malware Family:** Cerber Ransomware
- **Infection Vector:** Malicious Word macro
- **Dropper Type:** VBScript
- **Victim:** Bob Smith (we8105desk)
- **Attack Stage:** Execution / Dropper

**Attack Chain Context:**
This detection provides **threat intelligence context** to the activity identified in Detections 9 and 10. By specifically identifying the Cerber ransomware TTP (Tactics, Techniques, and Procedures), we can:
- Reference known Cerber IOCs and behaviors
- Anticipate next-stage activity (payload download, encryption)
- Apply Cerber-specific response procedures
- Search for other systems exhibiting similar patterns

---

## Detection 12: Ransomware Payload Download via HTTP

### What Are We Looking For?
After the VBScript dropper executes, it downloads the actual ransomware payload from the attacker's server. Cerber is known to disguise its payload with misleading file extensions like .jpg or .tmp to evade casual inspection. Downloads of files with unusual extensions from suspicious domains indicate payload retrieval.

### Why This Matters
- **Attack Stage:** Command and Control (MITRE ATT&CK T1105 - Ingress Tool Transfer)
- **Significance:** The actual malware binary is being downloaded
- **Response Priority:** Critical - Ransomware about to execute

### Detection Strategy
Monitor HTTP GET requests that download files with suspicious extensions (.tmp, .jpg used for executables) from known malicious or newly registered domains, especially following suspicious VBScript execution.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=stream:http`
- **Key Fields:** `http_method`, `uri_query`, `status`, `dest`, `src_ip`

### Sigma Rule
```yaml
title: Suspicious File Download from Compromised or Malicious Domain
id: 9d0e1f2a-3b4c-5d6e-7f8a-9b0c1d2e3f4a
status: experimental
description: Detects download of suspicious files that may be ransomware payloads
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.command_and_control
    - attack.t1105
logsource:
    category: proxy
    product: web
detection:
    selection:
        http_method: 'GET'
        uri_query|endswith:
            - '.tmp'
            - '.jpg'
            - '.jpeg'
        status: 200
    suspicious_domain:
        dest|contains:
            - 'solidaritedeproximite.org'
    condition: selection and suspicious_domain
falsepositives:
    - Legitimate file downloads
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=stream:http 
| search http_method=GET status=200
| search (uri_query="*.tmp" OR uri_query="*.jpg")
| search dest="*solidaritedeproximite.org*"
| table _time src_ip dest uri_query bytes_in
| sort _time
```

### What This Detection Finds
Bob Smith's workstation downloads two files from the suspicious domain solidaritedeproximite.org: **121214.tmp** and **mhtr.jpg**. These are the Cerber ransomware payload components disguised with misleading extensions.

**Key Findings:**
- **Victim Host:** 192.168.250.100 (we8105desk)
- **C2 Domain:** solidaritedeproximite.org
- **Downloaded Files:** 121214.tmp, mhtr.jpg
- **File Sizes:** ~200KB each
- **Status:** 200 OK (successful download)
- **Attack Stage:** Command and Control / Payload Download

**Attack Chain Context:**
This is **step 5** in the attack chain. After the VBScript dropper executed (steps 3-4), it contacted the attacker's C2 infrastructure to download the actual Cerber ransomware binary. The use of .tmp and .jpg extensions is an evasion technique - security products might not scan or flag these file types as suspicious, but they actually contain executable code. Once downloaded, these files will be executed to begin the encryption process.

---

## Detection 13: Cerber DNS Queries

### What Are We Looking For?
Cerber ransomware uses distinctive DNS queries to communicate with its command and control infrastructure. The malware queries domains containing "cerber" in the name and using specific top-level domains (TLDs) like .win and .top that are popular with malware operators.

### Why This Matters
- **Attack Stage:** Command and Control (MITRE ATT&CK T1071.004 - Application Layer Protocol: DNS)
- **Significance:** High-fidelity indicator of Cerber ransomware activity
- **Response Priority:** Critical - Ransomware C2 communication

### Detection Strategy
Monitor DNS queries for domains containing "cerber" or using TLDs commonly associated with malware (.win, .top, .xyz). These queries indicate active ransomware communication.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=stream:dns`
- **Key Fields:** `query`, `src_ip`, `answer`, `query_type`

### Sigma Rule
```yaml
title: Cerber Ransomware DNS Query Pattern
id: 0e1f2a3b-4c5d-6e7f-8a9b-0c1d2e3f4a5b
status: experimental
description: Detects DNS queries to domains associated with Cerber ransomware C2
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.command_and_control
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection:
        query|contains:
            - 'cerber'
        query|endswith:
            - '.win'
            - '.top'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=stream:dns
| search query="*cerber*" (query="*.win" OR query="*.top")
| table _time src_ip query answer query_type
| sort _time
```

### What This Detection Finds
The infected workstation performs DNS lookups for **cerberhhyed5frqa.xmfir0.win**, the Cerber ransomware C2 domain. The randomized subdomain is characteristic of Cerber's domain generation algorithm (DGA).

**Key Findings:**
- **Victim Host:** 192.168.250.100 (we8105desk)
- **C2 Domain:** cerberhhyed5frqa.xmfir0.win
- **TLD:** .win (commonly used by malware)
- **Pattern:** Contains "cerber" + random string
- **Attack Stage:** Command and Control

**Attack Chain Context:**
This is **step 6** in the attack chain. After downloading the payload (step 5), the Cerber ransomware establishes C2 communication to:
- Register the infection with the attacker's server
- Receive encryption keys
- Report encryption progress
- Display ransom payment instructions

The use of DNS queries with distinctive patterns makes this a high-confidence indicator of Cerber activity. The Domain Generation Algorithm (DGA) helps the malware evade domain blocklists by generating new domains frequently.

---

## Detection 14: Mass File Modification Activity

### What Are We Looking For?
Ransomware works by rapidly encrypting large numbers of files. This creates a distinctive pattern: many file modification events in a very short time period. Sysmon EventCode=2 tracks when file creation timestamps are changed, which ransomware does after encrypting files. A burst of these events targeting user documents is a strong indicator of ransomware encryption.

### Why This Matters
- **Attack Stage:** Impact (MITRE ATT&CK T1486 - Data Encrypted for Impact)
- **Significance:** Active ransomware encryption in progress
- **Response Priority:** Critical - Immediate containment required

### Detection Strategy
Monitor for high volumes of file modification events (EventCode=2) targeting document file types (.txt, .pdf, .doc, .xls) in user directories within a short time window.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=2`
- **Key Fields:** `TargetFilename`, `ComputerName`, `User`, `Image`

### Sigma Rule
```yaml
title: Suspicious Mass File Modification Activity
id: 1f2a3b4c-5d6e-7f8a-9b0c-1d2e3f4a5b6c
status: experimental
description: Detects mass file modification activity consistent with ransomware encryption
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.impact
    - attack.t1486
logsource:
    category: file_event
    product: windows
detection:
    selection:
        EventCode: 2
        TargetFilename|contains: '\Users\'
        TargetFilename|endswith:
            - '.txt'
            - '.pdf'
            - '.doc'
            - '.docx'
            - '.xls'
            - '.xlsx'
    condition: selection
falsepositives:
    - Legitimate bulk file operations
    - Backup software
    - Synchronization tools
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=2
| search TargetFilename="*\\Users\\*" (TargetFilename="*.txt" OR TargetFilename="*.pdf" OR TargetFilename="*.doc*" OR TargetFilename="*.xls*")
| bin _time span=1m
| stats count by _time, ComputerName, User
| where count > 20
| sort -count
```

### What This Detection Finds
The query reveals **massive file modification activity** on Bob Smith's workstation (we8105desk), with hundreds of files being modified per minute. This is the ransomware actively encrypting files.

**Key Findings:**
- **Victim Host:** we8105desk (192.168.250.100)
- **Affected User:** bob.smith.WAYNECORPINC
- **Files Modified:** 500+ files in minutes
- **File Types:** .txt, .pdf, .doc, .docx, .xls, .xlsx
- **Locations:** Desktop, Documents, Downloads, network drives
- **Attack Stage:** Impact / Encryption

**Attack Chain Context:**
This is **step 7**: the actual impact phase where ransomware achieves its primary objective - encrypting valuable data. After establishing C2 communication (step 6), Cerber begins rapidly encrypting files. The high velocity of modifications is characteristic of ransomware:
- Legitimate applications modify files one at a time
- Backup software usually operates during off-hours
- Ransomware encrypts hundreds/thousands of files rapidly

This detection provides critical time-sensitive intelligence - the encryption is happening NOW, and immediate response is needed to prevent further data loss.

---

## Detection 15: TMP File Execution

### What Are We Looking For?
.TMP files should be temporary data files, not executables. Cerber ransomware uses the .tmp extension to disguise its executable payload (downloaded in Detection 12). Detecting the execution of .tmp files indicates malware attempting to evade detection by using misleading file extensions.

### Why This Matters
- **Attack Stage:** Execution (MITRE ATT&CK T1204.002 - User Execution: Malicious File)
- **Significance:** Confirms malicious executable disguised as temp file
- **Response Priority:** Critical - Malware executing

### Detection Strategy
Look for process creation where the Image path ends with .tmp, especially when spawned by script interpreters like wscript.exe or cscript.exe.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1`
- **Key Fields:** `Image`, `ParentImage`, `CommandLine`, `ComputerName`

### Sigma Rule
```yaml
title: Suspicious TMP File Execution
id: 2a3b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d
status: experimental
description: Detects execution of .tmp files which is unusual and seen with Cerber ransomware
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '.tmp'
        ParentImage|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
    condition: selection
falsepositives:
    - Rare legitimate temporary executables
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*.tmp" (ParentImage="*wscript.exe*" OR ParentImage="*cscript.exe*")
| table _time ComputerName User ParentImage Image CommandLine
| sort _time
```

### What This Detection Finds
The query identifies the execution of **121214.tmp** (downloaded in Detection 12) being launched by wscript.exe. This is the actual Cerber ransomware binary beginning execution.

**Key Findings:**
- **Malware Binary:** C:\Users\bob.smith.WAYNECORPINC\AppData\Local\Temp\121214.tmp
- **Parent Process:** wscript.exe (the VBScript dropper)
- **Victim Host:** we8105desk
- **Attack Stage:** Execution / Ransomware Initialization

**Attack Chain Context:**
This detection captures the moment when the downloaded payload (Detection 12) is **actually executed** to start the encryption process. The sequence is:
1. Word macro spawns wscript.exe (Detection 9)
2. wscript.exe executes VBScript dropper (Detection 10-11)
3. VBScript downloads 121214.tmp (Detection 12)
4. VBScript executes 121214.tmp (Detection 15 - YOU ARE HERE)
5. 121214.tmp encrypts files (Detection 14)

This highlights the multi-stage nature of modern malware - each stage downloads and executes the next, making defense more challenging.

---

## Detection 16: USB Device Connection Before Malware Execution

### What Are We Looking For?
The initial infection vector for Cerber in this scenario was a malicious USB device. Windows logs USB device insertions as service installation events (EventCode=7045) for USB storage drivers. A USB insertion immediately followed by suspicious process execution suggests the USB contained malware.

### Why This Matters
- **Attack Stage:** Initial Access (MITRE ATT&CK T1091 - Replication Through Removable Media)
- **Significance:** Identifies the initial infection vector
- **Response Priority:** High - Understanding entry point is critical for response

### Detection Strategy
Correlate USB driver installation events with suspicious process creation events (like Office applications opening documents) within a short time window.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=WinEventLog:System EventCode=7045` (USB) and `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1` (Process)
- **Key Fields:** `Service_Name`, `Image`, `ComputerName`

### Sigma Rule
```yaml
title: USB Device Insertion Followed by Suspicious Activity
id: 3b4c5d6e-7f8a-9b0c-1d2e-3f4a5b6c7d8e
status: experimental
description: Detects USB device insertion followed by suspicious process execution
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.initial_access
    - attack.t1091
logsource:
    category: driver_load
    product: windows
detection:
    usb_insertion:
        EventCode: 7045
        Service_Name|contains:
            - 'USB'
            - 'USBSTOR'
    suspicious_process:
        EventCode: 1
        Image|endswith: '\WINWORD.EXE'
    timeframe: 5m
    condition: usb_insertion followed by suspicious_process
falsepositives:
    - Legitimate USB device usage
level: medium
```

### Example Splunk Query
```spl
index=botsv1 sourcetype="WinEventLog:System" EventCode=7045
| search Service_Name="*USB*" OR Service_Name="*USBSTOR*"
| eval usb_time=_time
| table usb_time ComputerName Service_Name
| join ComputerName 
    [search index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*WINWORD.EXE*"
    | eval process_time=_time
    | table process_time ComputerName Image]
| where (process_time - usb_time) < 300
| table usb_time process_time ComputerName Service_Name Image
```

### What This Detection Finds
A USB storage device labeled **MIRANDA_PRI** was inserted into Bob Smith's workstation, followed shortly by Word opening the malicious document from the USB drive.

**Key Findings:**
- **USB Device:** MIRANDA_PRI
- **Insertion Time:** Shortly before infection
- **Victim Host:** we8105desk
- **User:** Bob Smith
- **Attack Stage:** Initial Access

**Attack Chain Context:**
This detection reveals **steps 1 and 2** of the attack chain - the very beginning. The attack sequence was:
1. Bob Smith inserted the USB device "MIRANDA_PRI" (Detection 16)
2. Bob opened "Miranda_Tate_unveiled.dotm" from the USB (Detection 16)
3. Word macro executed (Detection 9)
4. Everything else followed...

This is crucial intelligence for incident response:
- **Patient Zero:** Bob Smith's workstation is confirmed as the initial infection point
- **Vector:** Physical media (USB drive)
- **Social Engineering:** The USB and document names reference "Miranda Tate" (a character from Batman - remember this is Wayne Enterprises)
- **Response Action:** Need to identify if this USB was shared or used on other systems

---

## Detection 17: Macro-Enabled Document Opened

### What Are We Looking For?
Microsoft Office macro-enabled documents have special file extensions: .docm (Word), .xlsm (Excel), .pptm (PowerPoint), .dotm (Word template). These files can contain executable VBA code. While some legitimate business documents use macros, they're also a common malware delivery method. Detecting when macro-enabled documents are opened helps identify potential malicious documents.

### Why This Matters
- **Attack Stage:** Execution (MITRE ATT&CK T1204.002 - User Execution: Malicious File)
- **Significance:** Identifies the malicious document that started the infection
- **Response Priority:** Medium-High - Entry point identification

### Detection Strategy
Monitor process creation for Microsoft Office applications where the command line contains macro-enabled file extensions.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1`
- **Key Fields:** `Image`, `CommandLine`, `ComputerName`, `User`

### Sigma Rule
```yaml
title: Suspicious Office Document with Macro Extension Opened
id: 4c5d6e7f-8a9b-0c1d-2e3f-4a5b6c7d8e9f
status: experimental
description: Detects opening of Office documents with macro-enabled extensions
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\WINWORD.EXE'
        CommandLine|contains:
            - '.dotm'
            - '.docm'
            - '.xlsm'
            - '.pptm'
    condition: selection
falsepositives:
    - Legitimate macro-enabled documents in business environments
level: medium
```

### Example Splunk Query
```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*WINWORD.EXE*" (CommandLine="*.dotm" OR CommandLine="*.docm")
| table _time ComputerName User Image CommandLine
| sort _time
```

### What This Detection Finds
The query identifies Bob Smith opening the file **Miranda_Tate_unveiled.dotm** - the malicious Word template that initiated the entire attack chain.

**Key Findings:**
- **Malicious Document:** Miranda_Tate_unveiled.dotm
- **File Type:** .dotm (Word macro-enabled template)
- **Location:** USB drive (MIRANDA_PRI)
- **User:** Bob Smith
- **Victim Host:** we8105desk
- **Attack Stage:** User Execution

**Attack Chain Context:**
This detection identifies **step 2**: the user action that triggered the malware. The file naming is interesting from a social engineering perspective:
- **"Miranda_Tate"** - Character from The Dark Knight Rises (Wayne Enterprises theme)
- **.dotm extension** - Template file (might look less suspicious than .docm)
- **From USB** - Physical delivery bypasses email security

This document contained the malicious VBA macro that triggered everything else (Detections 9-15). Understanding the lure helps with:
- User awareness training
- Email/document filtering policies
- Recognizing similar attacks in the future

---

## Detection 18: ICMP Traffic Pattern

### What Are We Looking For?
Cerber ransomware sometimes uses ICMP (ping) traffic to test network connectivity or as a covert communication channel. A sudden spike in ICMP traffic from a workstation, especially outbound, can indicate ransomware activity.

### Why This Matters
- **Attack Stage:** Command and Control (MITRE ATT&CK T1095 - Non-Application Layer Protocol)
- **Significance:** Alternative C2 channel detection
- **Response Priority:** Medium - Indicates advanced malware capabilities

### Detection Strategy
Monitor for high volumes of ICMP traffic originating from workstations, which rarely generate significant ICMP traffic in normal operations.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=fgt_utm OR sourcetype=stream:icmp`
- **Key Fields:** `protocol`, `src_ip`, `dest_ip`, `direction`

### Sigma Rule
```yaml
title: Suspicious Outbound ICMP Traffic Pattern
id: 5d6e7f8a-9b0c-1d2e-3f4a-5b6c7d8e9f0a
status: experimental
description: Detects suspicious ICMP traffic patterns associated with Cerber ransomware beaconing
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.command_and_control
    - attack.t1095
logsource:
    category: firewall
detection:
    selection:
        protocol: 'ICMP'
        direction: 'outbound'
    condition: selection
falsepositives:
    - Network diagnostic tools
    - Monitoring systems
level: medium
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=fgt_utm protocol=1
| search srcip="192.168.250.100"
| stats count by srcip, dstip
| where count > 50
| sort -count
```

### What This Detection Finds
Bob Smith's infected workstation generates unusual ICMP traffic patterns during and after the infection, potentially as part of Cerber's C2 communication or network reconnaissance.

**Key Findings:**
- **Source:** 192.168.250.100 (we8105desk)
- **Protocol:** ICMP
- **Pattern:** Elevated ICMP traffic
- **Attack Stage:** Command and Control

**Attack Chain Context:**
This detection provides **additional C2 channel visibility** beyond the DNS and HTTP traffic detected earlier. Some ransomware variants use ICMP for:
- Testing internet connectivity before encryption
- Covert C2 communication
- Network mapping for lateral movement

While not as definitive as other detections, unusual ICMP patterns from workstations should be investigated, especially when combined with other ransomware indicators.

---

## Detection 19: File Server SMB Activity

### What Are We Looking For?
Ransomware doesn't just encrypt local files - it seeks out network file shares to maximize damage. Windows Security Event Logs record file share access (EventCode 5145) and object access attempts (EventCode 4663). A sudden spike in write/delete operations on file shares from a single system indicates ransomware spreading laterally.

### Why This Matters
- **Attack Stage:** Lateral Movement (MITRE ATT&CK T1021.002 - SMB/Windows Admin Shares) and Impact (T1486 - Data Encrypted for Impact)
- **Significance:** Ransomware spreading beyond initial infection
- **Response Priority:** Critical - Data loss expanding

### Detection Strategy
Monitor Windows Security logs on file servers for high volumes of write (0x2) or delete (0x4) access operations from a single source.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=WinEventLog:Security EventCode=5145 OR EventCode=4663`
- **Key Fields:** `EventCode`, `Share_Name`, `Access_Mask`, `Source_Network_Address`, `Object_Name`

### Sigma Rule
```yaml
title: Mass File Modification on File Server via SMB
id: 6e7f8a9b-0c1d-2e3f-4a5b-6c7d8e9f0a1b
status: experimental
description: Detects mass file modifications on file servers which may indicate ransomware spread
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.impact
    - attack.t1486
logsource:
    category: file_share
    product: windows
detection:
    selection:
        EventCode:
            - 5145
            - 4663
        Share_Name|contains: '\\'
        Access_Mask:
            - '0x2'
            - '0x4'
    condition: selection
falsepositives:
    - Legitimate file operations
    - Backup operations
    - File synchronization
level: high
```

### Example Splunk Query
```spl
index=botsv1 host="we9041srv" sourcetype="WinEventLog:Security" (EventCode=5145 OR EventCode=4663)
| search Access_Mask="0x2" OR Access_Mask="0x4"
| stats count by Source_Network_Address, Share_Name
| where count > 100
| sort -count
```

### What This Detection Finds
The file server **we9041srv** (192.168.250.20) shows massive file access activity originating from Bob Smith's infected workstation (192.168.250.100). Hundreds of files on network shares are being accessed with write permissions - indicating ransomware encryption spreading to the file server.

**Key Findings:**
- **File Server:** we9041srv.waynecorpinc.local (192.168.250.20)
- **Attacker:** 192.168.250.100 (we8105desk - Bob's infected workstation)
- **Affected Shares:** Multiple shared folders
- **Operations:** Hundreds of write/delete operations
- **Attack Stage:** Lateral Movement + Impact

**Attack Chain Context:**
This is **step 8** - the ransomware spreading beyond the initial victim. After encrypting Bob's local files (Detection 14), Cerber discovers and attacks network file shares:

1. Ransomware enumerates mapped network drives
2. Accesses file server shares using Bob's credentials
3. Encrypts files on shared drives
4. Multiple users' data is now affected

This dramatically increases the impact:
- **Local Encryption:** Only Bob's files affected
- **Network Encryption:** Entire departments' shared data affected

This detection is critical for:
- Identifying patient zero vs. secondary victims
- Understanding scope of data loss
- Prioritizing which systems need immediate isolation
- Determining backup restoration scope

---

## Detection 20: Ransom Note Creation

### What Are We Looking For?
After encrypting files, ransomware creates ransom notes - text or HTML files with instructions on how to pay for decryption. These files typically have distinctive names like "README," "DECRYPT," "HOW_TO_DECRYPT," or "HELP_instructions" and are placed in multiple directories to ensure the victim sees them.

### Why This Matters
- **Attack Stage:** Impact (MITRE ATT&CK T1486 - Data Encrypted for Impact)
- **Significance:** Confirms ransomware successfully executed
- **Response Priority:** Critical - Encryption completed

### Detection Strategy
Monitor file creation events (Sysmon EventCode=11) for files with names commonly used in ransom notes, especially with .txt, .html, or .htm extensions.

### Splunk Query Optimization
- **Index:** `index=botsv1`
- **Sourcetype:** `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=11`
- **Key Fields:** `TargetFilename`, `ComputerName`, `User`, `Image`

### Sigma Rule
```yaml
title: Suspicious README or Ransom Note File Creation
id: 7f8a9b0c-1d2e-3f4a-5b6c-7d8e9f0a1b2c
status: experimental
description: Detects creation of files commonly used as ransom notes
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.impact
    - attack.t1486
logsource:
    category: file_event
    product: windows
detection:
    selection:
        EventCode: 11
        TargetFilename|contains:
            - 'README'
            - 'DECRYPT'
            - 'RESTORE'
            - 'HELP_DECRYPT'
            - 'HOW_TO_DECRYPT'
            - '_HELP_instructions'
        TargetFilename|endswith:
            - '.txt'
            - '.html'
            - '.htm'
    condition: selection
falsepositives:
    - Legitimate README files
    - Software documentation
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| search (TargetFilename="*README*" OR TargetFilename="*DECRYPT*" OR TargetFilename="*HELP*")
| search (TargetFilename="*.txt" OR TargetFilename="*.html" OR TargetFilename="*.htm")
| table _time ComputerName User TargetFilename Image
| sort _time
```

### What This Detection Finds
Cerber creates multiple ransom note files across the infected system, with names like **"# HELP DECRYPT #.txt"** or **"# HELP DECRYPT #.html"** in every directory containing encrypted files.

**Key Findings:**
- **Ransom Note Name:** # HELP DECRYPT #.txt / .html
- **Locations:** Desktop, Documents, every encrypted folder
- **Quantity:** Dozens to hundreds of notes created
- **Content:** Instructions to access Cerber payment portal
- **Attack Stage:** Impact / Ransom Demand

**Attack Chain Context:**
This is the **final stage** of the Cerber attack chain. After encrypting all accessible files (local and network), the ransomware creates ransom notes to inform victims:
- Their files have been encrypted
- How much ransom is demanded (usually in Bitcoin)
- How to access the Cerber payment/decryption portal
- Deadline before ransom increases or files are permanently deleted

The presence of ransom notes confirms:
- Encryption process completed
- Ransomware achieved its objective
- Need for immediate incident response and backup restoration

---

## Correlation Detections

### Detection 21: Po1s0n1vy Full Attack Chain

**What Are We Looking For?**
Rather than detecting individual tactics, this correlation rule identifies when multiple indicators from the Po1s0n1vy attack chain occur on the same system within a 24-hour window. Seeing the progression from scanning to brute force to file upload to execution confirms a full compromise.

**Why This Matters:**
- Provides high-confidence attribution to Po1s0n1vy APT
- Confirms full attack progression
- Triggers comprehensive incident response

**Splunk Query Optimization:**
- **Index:** `index=botsv1`
- **Sourcetype:** Multiple - `stream:http`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `fgt_utm`

### Sigma Rule
```yaml
title: Po1s0n1vy APT Attack Chain Correlation
id: 8a9b0c1d-2e3f-4a5b-6c7d-8e9f0a1b2c3d
status: experimental
description: Correlates multiple events to detect the full Po1s0n1vy attack chain
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.initial_access
    - attack.execution
    - attack.persistence
    - attack.impact
correlation:
    type: temporal
    rules:
        - 4c5f5d3e-2b1a-4f9c-9e8d-7a6b5c4d3e2f  # Acunetix scan
        - 7e9f8a6b-5c4d-3e2f-1a0b-9c8d7e6f5a4b  # Brute force
        - 9a8b7c6d-5e4f-3a2b-1c0d-8e7f6a5b4c3d  # File upload
        - 1b2c3d4e-5f6a-7b8c-9d0e-1f2a3b4c5d6e  # Webshell execution
    timeframe: 24h
    ordered: true
level: critical
```

### Example Splunk Correlation Query
```spl
index=botsv1 dest_ip="192.168.250.70" OR dest="*imreallynotbatman*"
| eval event_type=case(
    sourcetype="stream:http" AND http_user_agent="*Acunetix*", "scan",
    sourcetype="stream:http" AND uri_path="*/joomla/administrator*" AND http_method="POST", "brute_force",
    sourcetype="stream:http" AND http_method="POST" AND http_content_type="*multipart*", "file_upload",
    sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND EventCode=1 AND Image="*inetpub*", "webshell"
)
| where isnotnull(event_type)
| stats values(event_type) as attack_stages, count by dest_ip
| where mvcount(attack_stages) >= 3
```

**What This Correlation Finds:**
When you run this correlation, it confirms that the target system (192.168.250.70 / imreallynotbatman.com) experienced the full Po1s0n1vy attack progression, conclusively identifying a successful APT compromise requiring immediate incident response.

---

### Detection 22: Cerber Ransomware Full Attack Chain

**What Are We Looking For?**
This correlation detects the complete Cerber ransomware infection chain on a single host within a short time window (1 hour). Observing macro execution → VBScript → payload download → encryption confirms a successful ransomware infection.

**Why This Matters:**
- High-confidence ransomware identification
- Enables automated incident response workflows
- Helps identify patient zero and infection timeline

**Splunk Query Optimization:**
- **Index:** `index=botsv1`
- **Sourcetype:** Multiple - `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `stream:http`, `stream:dns`

### Sigma Rule
```yaml
title: Cerber Ransomware Attack Chain Correlation
id: 9b0c1d2e-3f4a-5b6c-7d8e-9f0a1b2c3d4e
status: experimental
description: Correlates multiple events to detect the full Cerber ransomware attack chain
references:
    - https://github.com/splunk/botsv1
author: Tyler Casey
date: 2024/01/28
tags:
    - attack.initial_access
    - attack.execution
    - attack.command_and_control
    - attack.impact
correlation:
    type: temporal
    rules:
        - 6a7b8c9d-0e1f-2a3b-4c5d-6e7f8a9b0c1d  # Office macro execution
        - 7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e  # VBScript execution
        - 9d0e1f2a-3b4c-5d6e-7f8a-9b0c1d2e3f4a  # Payload download
        - 1f2a3b4c-5d6e-7f8a-9b0c-1d2e3f4a5b6c  # Mass file encryption
    timeframe: 1h
    ordered: true
level: critical
```

### Example Splunk Correlation Query
```spl
index=botsv1 ComputerName="we8105desk" OR host="we8105desk" OR src_ip="192.168.250.100"
| eval event_type=case(
    sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND EventCode=1 AND ParentImage="*WINWORD*" AND Image="*wscript*", "macro_exec",
    sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND EventCode=1 AND Image="*wscript*" AND CommandLine="*.vbs*", "vbscript",
    sourcetype="stream:http" AND uri_query="*.tmp", "download",
    sourcetype="stream:dns" AND query="*cerber*", "c2_dns",
    sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND EventCode=2, "encryption"
)
| where isnotnull(event_type)
| stats values(event_type) as attack_stages, min(_time) as start_time, max(_time) as end_time by host
| where mvcount(attack_stages) >= 4
| eval duration=end_time-start_time
| convert ctime(start_time) ctime(end_time)
```

**What This Correlation Finds:**
The correlation confirms Bob Smith's workstation (we8105desk) experienced the complete Cerber infection chain within approximately 10-15 minutes, from initial macro execution to active file encryption. The rapid progression is characteristic of automated ransomware attacks.

---

## Workshop Completion

### Congratulations!
You've successfully hunted through two complete attack scenarios using Sigma rules and Splunk. You've learned to:

✅ Detect reconnaissance and exploitation attempts
✅ Identify malicious file uploads and webshells  
✅ Track command and control communications
✅ Recognize ransomware execution patterns
✅ Understand how attackers chain techniques together
✅ Correlate multiple indicators for high-confidence detections

### Key Takeaways

**For Po1s0n1vy (Scenario 1):**
- Vulnerability scanning is often the first visible indicator
- Brute force attacks can succeed against weak credentials
- Webshells provide persistent access for attackers
- Dynamic DNS services are commonly used for C2

**For Cerber (Scenario 2):**
- Physical media (USB) bypasses network security controls
- Macro-enabled documents remain effective attack vectors
- Ransomware follows predictable patterns we can detect
- Network share encryption multiplies the impact

**General Lessons:**
- Defense in depth requires detection at every attack stage
- Early detection (reconnaissance, initial access) provides more response time
- Process relationships (parent/child) are crucial for detection
- Volume-based detection works well for ransomware
- Correlation of multiple indicators increases detection confidence

### Next Steps

1. **Create Your Own Rules:** Try writing Sigma rules for other scenarios or threat actors
2. **Tune Rules:** Adjust thresholds and conditions based on your environment
3. **Automation:** Integrate these detections into your SIEM for automated alerting
4. **Response:** Develop response playbooks for each detection type
5. **Threat Intelligence:** Subscribe to threat intel feeds to stay current on IOCs

### Additional Resources

- **Sigma Project:** https://github.com/SigmaHQ/sigma
- **MITRE ATT&CK:** https://attack.mitre.org/
- **Splunk Security Content:** https://research.splunk.com/
- **BOTSV1 Dataset:** https://github.com/splunk/botsv1

---

**Workshop Manual Version:** 3.0 (Student Edition)  
**Last Updated:** January 28, 2026  
**Author:** Prepared for Sigma Workshop  
**License:** Creative Commons CC0 (aligned with BOTSV1 dataset license)
