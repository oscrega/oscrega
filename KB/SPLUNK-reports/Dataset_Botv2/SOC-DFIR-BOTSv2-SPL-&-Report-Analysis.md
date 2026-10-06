### Correlation and Audit Validation Assessment

The consolidated document is well-aligned with the practical exercise labs:
- **Lab 1 (SQL Injection):** Confirms automated reconnaissance targeting `INFORMATION_SCHEMA.session_variables` on MySQL host `gacrux`, noting normalization gaps on `client_ip` in raw database transaction events while correlating external scanning to `45.77.65.211`.
- **Lab 2 (HTTP Brute Force / API Enumeration):** Confirms an automated distributed botnet attack probing Magento REST endpoints without producing internal unhandled crashes (HTTP 500), validating that no web authentication was breached at the HTTP presentation layer.
- **Lab 3 (Windows Endpoint Anomalous Logons & Execution):** Validates the pivot to internal lateral movement using valid domain credentials (`service3`), generating volumetric Logon Type 3 network events, invoking WinRM (`wsmprovhost.exe`), applying in-memory AMSI patching via reflection, executing an RC4-encrypted in-memory stager, and exfiltrating data via the `ftp.exe` LOLBin with `winsys32.dll`.

Below is the consolidated, unified technical report and formal DFIR audit report translated into English, incorporating upgraded professional technical register and terminology throughout.

---

# Comprehensive DFIR Audit Report and Threat Hunting Guide: BOTSv2

**Project ID:** SEC-RPT-BOTSV2-CONSOLIDATED  
**Classification:** TLP:AMBER (Internal Use — SOC / Threat Hunting / CIRT)  
**Assessment Type:** Multi-Vector Intrusion Analysis, Perimeter Web Triage, and Windows Memory/Host Forensics  
**Scope:** Frothly / AmberTuring Corporate Infrastructure (index=botsv2)  
**Status:** Completed / Concluded  

---

## 1. Threat Scenario, Telemetry Inventory, and Investigation Baseline

### 1.1 Executive Summary of the Consolidated Incident

The Security Operations Center (SOC) and Incident Response Team (CIRT) correlated an intrusion lifecycle executed against **Frothly / AmberTuring** enterprise assets across three operational phases:

1. **Perimeter Reconnaissance and Database Probing:** Distributed HTTP API fuzzing and automated SQL Injection (SQLi) scanning directed at the Magento e-commerce portal and backend MySQL services on host `gacrux`.
2. **Identity Compromise and Network Lateral Pivoting:** Abuse of compromised service account `service3`, resulting in massive volumetric network authentication events (Logon Type 3) targeting core server `mercury.frothly.local` (internal IP `10.0.1.1`).
3. **Execution, In-Memory Defense Evasion, and Automated Exfiltration:** Remote execution without interactive desktop sessions via Windows Remote Management (`wsmprovhost.exe`), in-memory AMSI neutralization via reflection, execution of a multi-stage RC4-encrypted PowerShell Empire stager, binary masquerading (`splunk-winprintmon.exe`), and scripted data exfiltration using the native LOLBin `ftp.exe -i -s:winsys32.dll`.

### 1.2 Telemetry Ingestion and Sourcetype Catalog (index=botsv2)

Active Index: `botsv2`  
Mount Point: `/opt/splunk/etc/apps/botsv2_data_set/var/lib/splunk/botsv2/db/`

``` bash
index=botsv2 | stats count by sourcetype | sort - count
```

| Sourcetype | Operational Scope | Analytical Value |
|---|---|---|
| `winregistry` | Host registry persistence tracking | Identifies persistence entries (`CurrentVersion\Run`), service alterations, and staged payload keys. |
| `mysql:transaction:details` | Database transactional auditing | Records raw SQL statements (`SQL_TEXT`), system schema queries, and data extraction attempts. |
| `winhostmon` | Endpoint system state monitoring | Maps running system services, hardware baselines, and installed software components. |
| `stream:ip` / `stream:tcp` | Network protocol session tracking | Pinpoints volumetric network anomalies, C2 beaconing streams, port scanning, and exfiltration flows. |
| `stream:http` | Unencrypted Layer 7 HTTP traffic | Captures URIs, HTTP status codes, User-Agent strings, client/server IPs, and payload volumes. |
| `WinEventLog:Security` | Windows identity and access auditing | Tracks authentication validations (Event ID 4624/4625), process creation (4688), and privilege assignments. |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Deep endpoint behavioral telemetry | Correlates parent-child process chains (Event ID 1), raw command lines, file creation (11), and registry keys (13). |
| `suricata` | Network Intrusion Detection (NIDS) | Pre-classified Emerging Threats (ET) signatures, CVE exploitation alerts, and threat severities. |

---

## 2. Technical Investigation Modules

---

### Module 1: Perimeter Database Vector — SQL Injection and Metadata Enumeration

#### 1. Hypothesis Formulation

The security team detected anomalous behavior on the MySQL database server (`gacrux`). An external threat actor is presumed to be executing automated SQL injection payloads to map database engine metadata (`information_schema`) prior to targeting application credential stores.

#### 2. Query Refinement and Execution

Baseline Query:

``` bash
index=botsv2 sourcetype="mysql:transaction:details"
| regex SQL_TEXT="(?i)(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--|\#|\/\*)"
| head 20
| table _time, client_ip, SQL_TEXT
```

Refined Hunting Query:

``` bash
index=botsv2 sourcetype="mysql:transaction:details"
| search SQL_TEXT="*UNION*" OR SQL_TEXT="*--*" OR SQL_TEXT="*OR*1=1*"
| table _time, client_ip, SQL_TEXT
| sort - _time
```

Volumetric Quantification of Malicious Queries:

``` bash
index=botsv2 sourcetype="mysql:transaction:details"
| regex SQL_TEXT="(?i)UNION\s+SELECT"
| stats count as Total_Consultas_Maliciosas
```

Temporal Bounds Calculation:

``` bash
index=botsv2 sourcetype="mysql:transaction:details" SQL_TEXT="*UNION*"
| stats min(_time) as primera_vez, max(_time) as ultima_vez
| convert ctime(primera_vez) ctime(ultima_vez)
```

#### 3. Analytical Findings and Evidence Evaluation

- **Detected Vector:** SQL Injection (SQLi) leveraging `UNION SELECT` operations directed against `INFORMATION_SCHEMA.session_variables`.
- **Query Volume:** 662,286 malicious SQL transactions identified across the dataset.
- **Normalization Gap:** Due to ingestion constraints in the `mysql:transaction:details` sourcetype, field `client_ip` was not extracted from database transaction events. Cross-correlation with perimeter web logs (`stream:http`) resolved source attribution to external IP `45.77.65.211`.
- **Target Analysis:** The adversary queried system metadata rather than user tables (e.g., `mybb_users`), indicating active structural reconnaissance rather than completed data exfiltration on this host.

---

### Module 2: Perimeter Web Vector — HTTP Brute-Force and API Enumeration Triage

#### 1. Hypothesis Formulation

Failed authentication attempts were registered on the web server hosting the forum (`gacrux`). The threat actor is suspected of attempting password brute-forcing against administrative portals.

#### 2. Query Refinement and Execution

Endpoint Authentication Mapping:

``` bash
index=botsv2 sourcetype="stream:http" (uri="*/login*" OR uri="*/auth*")
| stats count by src_ip, status
| sort - count
```

Non-200 Status Code Verification:

``` bash
index=botsv2 sourcetype="stream:http" (uri="*/login*" OR uri="*/auth*") status!=200
| stats count by src_ip, status
| sort - count
```

High-Volume URI Enumeration:

``` bash
index=botsv2 sourcetype="stream:http"
| stats count by src_ip, uri
| sort - count
```

Unhandled Server Fault Inspection (HTTP 500):

``` bash
index=botsv2 sourcetype="stream:http" status=500
| stats count by src_ip, uri
| sort - count
```

User-Agent Profile Analysis:

``` bash
index=botsv2 sourcetype="stream:http" uri="*/login*"
| stats count by http_user_agent
| sort - count
```

#### 3. Analytical Findings and Evidence Evaluation

- **Status Code Correlation:** No HTTP 401 (Unauthorized) errors were returned. Log entries registered HTTP 200 and HTTP 302 responses. In Magento environments, unauthorized attempts to access protected API endpoints return HTTP 302 redirects back to the login index, demonstrating that the application dropped or redirected unauthorized requests.
- **Target Endpoints:** High-frequency requests targeted Magento REST endpoints (`/magento2/rest/default/V1/carts/mine/estimate-shipping-methods` and `/magento2/checkout/cart/add/uenc/...`), reflecting automated API scraping and parameter enumeration rather than a conventional brute-force attack against specific user accounts.
- **Application Stability:** The absence of HTTP 500 errors confirmed that requests did not trigger memory overflows, unhandled exceptions, or database crashes.
- **Client Fingerprinting:** Requests spoofed legacy User-Agent strings (Internet Explorer 9.0/10.0 and iOS 6 WebKit), confirming synthetic scanner traffic originating from distributed source IPs (e.g., `110.78.2.202`, `102.136.241.171`, `185.100.86.100`).

---

### Module 3: Internal Compromise — Anomalous Logons, Remote Execution, and Exfiltration

#### 1. Hypothesis Formulation

Following perimeter scanning, the adversary leveraged compromised credentials for service account `service3` to gain unauthorized access to core server `mercury.frothly.local` (`10.0.1.1`) via network logons (Event ID 4624), deploying remote execution and staging exfiltration channels.

#### 2. Query Refinement and Execution

Identification of Relevant Windows Authentication Fields:

``` bash
index=botsv2 sourcetype="wineventlog:security" EventCode=4624
| head 1
| transpose
```

Volumetric Authentication Profiling (Account `service3`):

``` bash
index=botsv2 earliest="08/31/2017:00:00:00" latest="09/01/2017:00:00:00" sourcetype="WinEventLog:Security" EventCode=4624
| stats count by Account_Name, Logon_Type, Source_Network_Address, ComputerName, Workstation_Name
| sort - count
```

Correlation of Process Creation and Logon Events:

``` bash
index=botsv2 host="mercury" (EventCode=4624 OR EventCode=4688)
| transaction host maxspan=1s
| search Account_Name="service3" AND EventCode=4688
| stats count as "Cantidad de ejecuciones", values(CommandLine) as "Comandos ejecutados" by New_Process_Name
| sort - "Cantidad de ejecuciones"
```

Extraction of Complete Process Command Lines:

``` bash
index=botsv2 host="mercury"
| rex field=_raw "Process Command Line:\s+(?<comando>.+)"
| search comando!=""
| stats values(comando) as "Comandos_Ejecutados" by New_Process_Name
| sort - New_Process_Name
```

Lateral Movement Validation Across Other Hosts:

``` bash
index=botsv2 sourcetype="wineventlog:security" EventCode=4624 Source_Network_Address="10.0.1.1"
| stats count by ComputerName, Account_Name, Source_Network_Address, Logon_Type
```

#### 3. Analytical Findings and Adversary Threat Process Characterization

The compromise of account `service3` generated over 8,600 successful `Logon_Type 3` (Network Logon) authentications within a targeted inspection window (exceeding 300,000 across the full dataset) originating from internal IP `10.0.1.1` toward `mercury.frothly.local`. Process tracking revealed the execution of the following adversary operations:

``` CODE
[svchost.exe] (WinRM Service Hosting)
       |
[wsmprovhost.exe] (T1021.006 - Windows Remote Management Worker)
       |
       +---> [whoami.exe] (/user - Reconnaissance: Security Identifier discovery)
       |
       +---> [reg.exe] (query HKLM\...\Uninstall - Reconnaissance: Software enumeration)
       |
       +---> [netstat.exe] (-nao - Reconnaissance: Active listening port identification)
       |
       +---> [schtasks.exe] (/delete /f /TN "...\Uploader" - Persistence: Task hijacking)
       |
       +---> [splunk-winprintmon.exe] (Masquerading: Binary disguised as Splunk agent)
       |
       +---> [powershell.exe] (-enc Base64 - In-Memory Stager & AMSI Bypass)
       |
       +---> [ftp.exe] (-i -s:winsys32.dll - Exfiltration: Scripted non-interactive transfer)
```

- **Remote Execution Infrastructure (`wsmprovhost.exe`):** Subprocess spawning beneath `wsmprovhost.exe -Embedding` confirms non-interactive execution orchestrated through Windows Remote Management (WinRM).
- **In-Memory Evasion and Deobfuscation (`powershell.exe`):**  
  The Base64 UTF-16LE payload decoded to an in-memory staging module associated with PowerShell Empire:

``` powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') |
  ?{$_} |
  %{$_.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}
```

  - *AMSI Bypass:* Uses reflection to set private static field `amsiInitFailed` to `$true`, forcing the engine to disable script block inspection.
  - *RC4 Decryption:* Configures a pre-shared cryptographic key (`389288edd78e2ad2f54946d3209b16b8`) to decrypt secondary-stage payloads directly in memory.
  - *C2 Beaconing:* Establishes persistent sessions to `https://45.77.65.211:443` transmitting session identifier `Cookie: session=MvCddPqFQ54VL4OWU5ryRTUir8=`.
- **Command-and-Control Artifact Staging (`schtasks.exe` & `splunk-winprintmon.exe`):**  
  The adversary hijacked standard task `Microsoft\Windows\Customer Experience Improvement Program\Uploader` and ran masqueraded binaries imitating legitimate Splunk Universal Forwarder components.
- **Automated Exfiltration (`ftp.exe`):**  
  Invoked via `ftp.exe -i -s:winsys32.dll`. Parameter `-s:winsys32.dll` provided a text command script containing destination IPs, credentials, and `put` directives to exfiltrate collected data without user prompting.

---

## 3. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Identified |
|---|---|---|---|
| **Reconnaissance** | T1595.002 | Active Scanning: Vulnerability Scanning | Automated parameter fuzzing from distributed external IPs (`110.78.2.202`, etc.) and `45.77.65.211`. |
| **Initial Access** | T1190 | Exploit Public-Facing Application | Automated SQLi scanning against Magento application endpoints. |
| **Initial Access** | T1078.002 | Valid Accounts: Domain Accounts | Massive authentication volume leveraging valid credentials for `service3`. |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell | Encoded commands via `powershell.exe -enc` evaluating in-memory download cradles. |
| **Execution** | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Command-line execution invoking native system discovery utilities. |
| **Persistence** | T1053.005 | Scheduled Task/Job: Scheduled Task | Hijacking and modification of native scheduled task `...\Uploader` via `schtasks.exe`. |
| **Privilege Escalation** | T1055 | Process Injection | In-memory evaluation and execution of PowerShell Empire stager modules. |
| **Defense Evasion** | T1562.001 | Impair Defenses: Disable or Modify Tools | Reflection-based neutralization of `AmsiUtils.amsiInitFailed` in memory. |
| **Defense Evasion** | T1027 | Obfuscated Files or Information | UTF-16LE Base64 encoding combined with RC4 symmetric encryption. |
| **Defense Evasion** | T1036.003 | Masquerading: Rename System Utilities | Masquerading malicious binaries under Splunk agent names (`splunk-winprintmon.exe`). |
| **Discovery** | T1033 | System Owner/User Discovery | Execution of `whoami /user` to extract account SID and integrity levels. |
| **Discovery** | T1082 | System Information Discovery | Software enumeration via `reg query HKLM\...\Uninstall`. |
| **Discovery** | T1049 | System Network Connections Discovery | Active network socket mapping via `netstat -nao \| findstr /r "LISTENING"`. |
| **Lateral Movement** | T1021.006 | Remote Services: Windows Remote Management | Remote process execution managed under `wsmprovhost.exe -Embedding`. |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols | C2 beaconing to `https://45.77.65.211:443` presenting custom session cookies. |
| **Exfiltration** | T1048.003 | Exfiltration Over Alternative Protocol: Non-C2 Protocol | Unattended data exfiltration via `ftp.exe -i -s:winsys32.dll`. |

---

## 4. Detection Rules and Security Engineering (Splunk SPL)

### Rule 1: In-Memory AMSI Neutralization via Reflection

``` SPL
index=botsv2 (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) OR (sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)
| eval ScriptData=coalesce(CommandLine, ScriptBlockText)
| regex ScriptData="(?i)AmsiUtils.*amsiInitFailed|\[Ref\]\.Assembly\.GetType\(.*AmsiUtils"
| stats 
    count, 
    earliest(_time) as firstSeen, 
    latest(_time) as lastSeen, 
    values(Computer) as TargetComputers, 
    values(User) as TargetUsers 
    by ScriptData
| convert ctime(firstSeen) ctime(lastSeen)
| eval AlertName="Defense Evasion: In-Memory AMSI Neutralization Attempt"
```

- **Tuning and False Positives:** Manipulating private fields in `AmsiUtils` does not occur in legitimate business applications. False positive expectation is zero.

### Rule 2: Remote WinRM Process Spawning (wsmprovhost.exe)

``` SPL
index=botsv2 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval Parent=lower(ParentImage), Child=lower(Image)
| where match(Parent, "\\wsmprovhost\.exe$") 
    AND match(Child, "\\(powershell|cmd|whoami|reg|net|net1|schtasks|ftp|certutil)\.exe$")
| stats 
    count, 
    earliest(_time) as firstTime, 
    latest(_time) as lastTime 
    by host, User, ParentImage, Image, CommandLine
| convert ctime(firstTime) ctime(lastTime)
| eval AlertName="Lateral Movement: LOLBin Execution via WinRM"
```

- **Tuning and False Positives:** Exclude authorized systems management tools (e.g., Ansible, SCCM) by whitelisting dedicated service accounts and known baseline command lines.

### Rule 3: Unattended Scripted FTP Execution (LOLBin Exfiltration)

``` SPL
index=botsv2 (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) OR (sourcetype="WinEventLog:Security" EventCode=4688)
| eval Process=lower(coalesce(Image, New_Process_Name)), CLI=lower(coalesce(CommandLine, Process_Command_Line, _raw))
| where match(Process, "\\ftp\.exe$") AND match(CLI, "-s:[a-z0-9_\\.-]+")
| rex field=CLI "-s:(?<ScriptFile>[^\s]+)"
| stats 
    count, 
    values(CLI) as CommandLines, 
    values(host) as TargetHosts, 
    values(User) as UserAccounts 
    by ScriptFile
| eval AlertName="Exfiltration: Script-Driven Headless FTP Execution"
```

- **Tuning and False Positives:** Restrict alert triggers to anomalous file extensions (`.dll`, `.tmp`, `.dat`, `.log`) passed to the `-s:` parameter, excluding routine business backup scripts.

---

## 5. Containment, Remediation, and Hardening Plan

### 5.1 Immediate Incident Containment and Eradication

1. **Perimeter Network Isolation:** Block external IP address `45.77.65.211` on perimeter firewalls and WAF systems. Drop inbound connections from identified scanning subnets (`110.78.2.0/24`, `102.136.241.0/24`, `185.100.86.0/24`).
2. **Endpoint Quarantine:** Logically isolate `mercury.frothly.local` (`10.0.1.1`) at the switch or EDR layer to interrupt active C2 channels and prevent further network pivoting.
3. **Identity Remediation:**
   - Disable service account `service3` immediately.
   - Execute a double reset of the Active Directory `krbtgt` account password (spaced 12 to 24 hours apart) to invalidate all existing Kerberos tickets.
4. **Host-Level Artifact Eradication:**
   - Terminate rogue worker processes matching `splunk-winprintmon.exe` and purge related executables residing outside verified Splunk installation paths.
   - Delete FTP staging instruction file `winsys32.dll` and clean temporary directories under `C:\Users\service3\AppData\Local\Temp\*`.
   - Restore native scheduled task `Microsoft\Windows\Customer Experience Improvement Program\Uploader` to its Microsoft-signed default configuration.

### 5.2 Architectural Hardening Recommendations

1. **PowerShell Constrained Language Mode (CLM):** Deploy AppLocker or Windows Defender Application Control (WDAC) policies enforcing Constrained Language Mode on all non-administrative accounts, preventing the execution of arbitrary .NET reflection code and unmanaged API calls.
2. **Deep PowerShell Auditing:** Mandate Script Block Logging (Event ID 4104) and Transcription Logging via Group Policy, ensuring encrypted, in-memory payloads are captured in plain text at runtime.
3. **Transition to Group Managed Service Accounts (gMSA):** Migrate static service accounts to gMSAs, eliminating static passwords and preventing interactive network logons.
4. **WinRM Access Hardening:** Restrict WinRM communication (TCP ports 5985/5986) to designated Privileged Access Workstations (PAWs) via host-based firewalls.
5. **LOLBin Execution Mitigation:** Block direct execution of legacy tools (`ftp.exe`, `tftp.exe`, `certutil.exe`) for unprivileged users, requiring authenticated, modern transfer mechanisms (SFTP over SSH or HTTPS with RBAC).
6. **Web Application Firewall (WAF) Tuning:** Implement strict rate limiting on Magento API endpoints and configure signatures blocking `UNION SELECT` structures targeting `information_schema`.