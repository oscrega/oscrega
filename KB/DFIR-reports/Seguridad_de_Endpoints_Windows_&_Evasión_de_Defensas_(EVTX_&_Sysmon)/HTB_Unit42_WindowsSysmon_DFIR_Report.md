**Classification:** TLP:AMBER  
**Environment / Platform:** Windows 10 Endpoint / Microsoft-Windows-Sysmon Telemetry / HTB Sherlock  
**Target:** Workstation DESKTOP-887GK2L (CyberJunkie User)  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** An intrusion based on a threat campaign tracked by Palo Alto Networks Unit 42 was analyzed, involving the execution of a dropper that delivered a customized version of the **UltraVNC** remote administration tool. The initial malware executable (Preventivo24.02.14.exe.exe) was hosted on and distributed through **Dropbox** infrastructure. Upon execution, the binary manipulated file timestamps (Timestomping), tested Internet connectivity by issuing DNS queries for www.example.com, and opened an outbound TCP connection to 93.184.216.34. Finally, the stager dropped configuration files and scripts (once.cmd) into non-standard user profile directories before terminating.
    
- **Telemetry Sources and Evidence:**
    
    - Microsoft-Windows-Sysmon-Operational.evtx: Endpoint log telemetry parsed with Chainsaw (applying Sigma rules) and jq.
        
    - Sysmon Event IDs correlated: 1 (Process Creation), 2 (File Creation Time Changed), 3 (Network Connection), 5 (Process Terminated), 11 (File Create), and 22 (DNS Query).
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Defense Evasion** | T1036.007 | Masquerading: Double File Extension | Execution of Preventivo24.02.14.exe.exe masquerading as an invoice/document. |
| **Defense Evasion** | T1070.006 | Indicator Removal: Timestomp | File creation timestamps for dropped PDF files and once.cmd backdated to January 2024. |
| **Initial Access / Resource Dev** | T1567.002 | Exfiltration to Cloud Storage / Cloud Staging | Initial payload download sourced from Dropbox content subdomains. |
| **Persistence** | T1219 | Remote Access Software | Deployment of customized UltraVNC binaries for covert remote interactive access. |

#### 3. Infection Chain and Detailed Forensic Analysis

Parsing Sysmon File Create events (Event ID 11) recorded on the endpoint yielded:

- **Total File Create Events (Event ID 11):** **56 events**.
    

1. **Malicious Process Execution (Sysmon Event ID 1):**
    
    - **Full Image Path:** **C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe**
        
    - **Technique:** Double extension .exe.exe designed to evade visual detection when default file extensions are hidden.
        
2. **Cloud Distribution Source (Sysmon Event ID 22 - DNS):**
    
    - The legitimate process firefox.exe resolved the following domains:  
        uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com and d.dropbox.com.
        
    - **Cloud Storage Provider:** **Dropbox**.
        

The dropper altered creation timestamps across dropped components:

1. **Decoy PDF Timestomping:**
    
    - File: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\TempFolder\~.pdf
        
    - **Altered UTC Timestamp (CreationUtcTime):** **2024-01-14 08:10:06.029** (actual creation on disk took place on 2024-02-14 03:41:58 UTC).
        
2. **Staging and Timestomping of "once.cmd":**
    
    - **Full Path on Disk:**  
        **C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd**
        
    - Forged timestamp applied: 2024-01-10 18:12:26.458 UTC.
        

1. **Network Connectivity Validation:**
    
    - Process Preventivo24.02.14.exe.exe (PID 10672) issued a DNS query at 03:41:56 UTC to check internet access:
        
    - **Queried Domain:** **www.example.com**
        
2. **Outbound Network Connection:**
    
    - At 03:41:58 UTC, the process established an outbound TCP connection:
        
    - **Destination IP:** **93.184.216.34** (TCP port 80).
        

Upon finishing decompression, timestomping, and staging of UltraVNC configuration components, the dropper exited:

- **Process Termination Timestamp:** **2024-02-14 03:41:59 UTC**.

``` bash
# Consultas de extracción en Chainsaw/jq sobre el volcado de Sysmon
cat sysmon.out | jq '.[].Event | select(.System.EventID == 2) | select(.EventData.TargetFilename | contains("~.pdf"))'
cat sysmon.out | jq '.[].Event | select(.System.EventID == 3) | select(.EventData.Image | contains("Preventivo"))'
```

#### 4. Detection Rules and Security Engineering

``` Yaml
title: Deteccion de Timestomping Mediante Sysmon Event ID 2
id: 5b91a234-d128-4eb1-9912-sysmontimestomp
status: production
description: Detecta discrepancias significativas entre la fecha de creacion previa y la nueva fecha de creacion asignada a un archivo.
references:
  - https://attack.mitre.org/techniques/T1070/006/
author: Senior DFIR Specialist
date: 2024-02-15
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 2
  condition: selection
level: medium
tags:
  - attack.defense_evasion
  - attack.t1070.006
```

``` SPL
index=sysmon EventCode=1 Image="*.exe.exe" OR Image="*.pdf.exe" OR Image="*.docx.exe"
| table _time, Computer, User, Image, CommandLine, ParentImage
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Endpoint Isolation:** Disconnect workstation DESKTOP-887GK2L from the network.
    
2. **Remediate UltraVNC Components:** Purge the directory path C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\.
    
3. **Enforce File Extension Visibility:** Configure Group Policy to mandate the visibility of file extensions across all endpoints (HideFileExt = 0).
    
4. **Restrict Remote Administration Tools:** Deploy EDR/AppLocker rules blocking the execution of unapproved VNC applications (winvnc.exe, vncviewer.exe, and portable equivalents).