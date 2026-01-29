# Sigma Workshop Manual

## Workshop Overview

Welcome to the Sigma Threat Hunting Workshop! In this hands-on exercise, you'll use Sigma rules to detect and investigate a real-world APT attack scenario captured in Splunk's Boss of the SOC (BOTS) Version 1 dataset.

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
- Queries may take time to complete, it is a large dataset!
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
3. **Write your Sigma Rule** - Attempt to write a Sigma rule to identify the activity, use the example sigma rule as a guide
4. **Convert and deploy your query** - Convert your rule to Splunk
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
    - https://www.acunetix.com/
author: Tyler Casey
date: 2026/01/28
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
    condition: selection
falsepositives:
    - Legitimate vulnerability scanning by authorized security teams
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=stream:http 
http_user_agent IN ("*Acunetix*")
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
        form_data|contains: 'passwd='
    condition: selection
falsepositives:
    - Users with forgotten passwords
    - Password managers attempting to autofill
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=stream:http 
uri_path="*/joomla/administrator/index.php*" http_method="POST" form_data="*passwd=*"
| stats count by src_ip
| where count > 10
| sort -count
```

### What This Detection Finds
This query reveals **hundreds of login attempts** from IP address **23.22.63.114** to the Joomla administrator login page. The high volume of attempts confirms this is an automated brute force attack.

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
        - dest_content|contains:
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
http_method="POST" http_content_type="*multipart/form-data*" uri_query IN ("*.exe*", "*.dll*", "*.bat*", "*.cmd*", "*.ps1*", "*.vbs*") OR form_data IN ("*.exe*", "*.dll*", "*.bat*", "*.cmd*", "*.ps1*", "*.vbs*") OR dest_content IN ("*.exe*", "*.dll*", "*.bat*", "*.cmd*", "*.ps1*", "*.vbs*")
| table _time src_ip dest_ip uri_path form_data dest_content
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
description: Detects execution of suspicious processes from web server directories or spawned by processes in web server directories indicating webshell activity
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
    selection_image:
        Image|contains:
            - '\inetpub\wwwroot\'
            - '\xampp\htdocs\'
            - '\wamp\www\'
        Image|endswith:
            - '.exe'
    selection_parent_image:
        ParentImage|contains:
            - '\inetpub\wwwroot\'
            - '\xampp\htdocs\'
            - '\wamp\www\'
        ParentImage|endswith:
            - '.exe'
    selection_commands:
        CommandLine|contains:
            - 'whoami'
            - 'net user'
            - 'net localgroup'
            - 'ipconfig'
            - 'systeminfo'
            - 'cmd.exe'
            - 'powershell'
    condition: (selection_image or selection_parent_image) and selection_commands
falsepositives:
    - Legitimate web applications with executable components
level: critical
```

### Example Splunk Query
```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image IN ("*\\inetpub\\wwwroot\\*", "*\\xampp\\htdocs\\*", "*\\wamp\\www\\*") Image="*.exe") OR (ParentImage IN ("*\\inetpub\\wwwroot\\*", "*\\xampp\\htdocs\\*", "*\\wamp\\www\\*") ParentImage="*.exe") CommandLine IN ("*whoami*", "*net user*", "*net localgroup*", "*ipconfig*", "*systeminfo*", "*cmd.exe*", "*powershell*")
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
        http_method: 'GET'
    selection_file:
        - uri_path|contains:
            - '.jpg'
            - '.jpeg'
            - '.png'
            - '.gif'
        - form_data|contains:
            - '.jpg'
            - '.jpeg'
            - '.png'
            - '.gif'
    condition: selection and selection_file
falsepositives:
    - Legitimate content management
    - User profile picture uploads
level: medium
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=stream:http
http_method="GET" uri_path IN ("*.jpg*", "*.jpeg*", "*.png*", "*.gif*") OR form_data IN ("*.jpg*", "*.jpeg*", "*.png*", "*.gif*")
| table _time src_ip dest_ip uri_path
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
query IN ("*.jumpingcrab.com", "*.no-ip.com", "*.duckdns.org", "*.ddns.net", "*.dynu.com")
| table _time src_ip query 
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
    selection_ip:
        dest_ip:
            - '23.22.63.114'
    selection_domain:
        dest|contains:
            - 'po1s0n1vy.com'
    condition: selection_ip or selection_domain
falsepositives:
    - None expected
level: critical
```

### Example Splunk Query
```spl
index=botsv1 (sourcetype=stream:ip OR sourcetype=fgt_utm OR sourcetype=stream:http)
 dest_ip="23.22.63.114" OR dest="*po1s0n1vy.com*"
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
        form_data|contains:
            - 'username='
            - 'passwd='
            - 'password='
    selection_status:
        status|startswith:
            - '20'
    condition: selection and not selection_status
falsepositives:
    - Users repeatedly mistyping passwords
level: high
```

### Example Splunk Query
```spl
index=botsv1 sourcetype=stream:http
http_method="POST" form_data IN ("*username=*", "*passwd=*", "*password=*") NOT status="20*"
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

## Workshop Completion

### Congratulations!
You've successfully hunted through the Po1s0n1vy APT attack scenario using Sigma rules and Splunk. You've learned to:

✅ Detect reconnaissance and exploitation attempts
✅ Identify malicious file uploads and webshells
✅ Track command and control communications
✅ Understand how attackers chain techniques together
✅ Correlate multiple indicators for high-confidence detections

### Key Takeaways

**For Po1s0n1vy APT:**
- Vulnerability scanning is often the first visible indicator
- Brute force attacks can succeed against weak credentials
- Webshells provide persistent access for attackers
- Dynamic DNS services are commonly used for C2

**General Lessons:**
- Defense in depth requires detection at every attack stage
- Early detection (reconnaissance, initial access) provides more response time
- Process relationships (parent/child) are crucial for detection
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
**Author:** Tyler Casey
**License:** Creative Commons CC0 (aligned with BOTSV1 dataset license)
