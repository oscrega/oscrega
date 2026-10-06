**Classification:** TLP:AMBER  
**Environment / Platform:** Windows Server / SmartScreen Debug Telemetry & Event Logs / HTB Sherlock  
**Target:** CTO Private File Server (CTO-FILESVR)  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** An intrusion and data destruction event was investigated on the Forela CTO's private file server (Dutch). The host was not domain-joined but was exposed to the internal network (CTO-FILESVR). On January 24, 2025, the adversary logged in via Remote Desktop Protocol (RDP), downloaded and installed utilities (WinRAR, Everything.exe), indexed and exfiltrated confidential Board of Directors documents using cloud synchronization tool **MEGAsync**, and executed file shredding software (**File Shredder**) to delete the local copies. Before disconnecting, the attacker cleared the Windows Security event log (Security.evtx). Because **Windows SmartScreen** debug logging was active (Microsoft-Windows-SmartScreen%4Debug.evtx), the forensic timeline covering downloads, program executions, and file accesses was reconstructed.
    
- **Telemetry Sources and Evidence:**
    
    - Windows event logs analyzed with Chainsaw:
        
        - Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational.evtx (Event ID 1149).
            
        - Microsoft-Windows-SmartScreen%4Debug.evtx (Event ID 1003).
            
        - Security.evtx and System.evtx (Event IDs 1102 and 104 - Log Cleared).
            

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Initial Access** | T1078.003 | Valid Accounts: Local Accounts | Authenticated RDP logon established under the Dutch user profile (Event ID 1149). |
| **Discovery** | T1083 | File and Directory Discovery | Download and execution of portable utility Everything.exe for file location and indexing. |
| **Exfiltration** | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Installation and usage of MEGAsync to transfer confidential documents offsite. |
| **Impact** | T1485 | Data Destruction | Destruction and anti-forensic overwriting of target documents using file shredder. |
| **Defense Evasion** | T1070.001 | Indicator Removal: Clear Windows Event Logs | Deliberate clearing of the Windows Security event log (Event ID 1102). |

#### 3. Infection Chain and Detailed Forensic Analysis

RemoteConnectionManager/Operational logs revealed the attacker's initial remote session:

- **Event ID:** **1149**
    
- **Target User:** **Dutch**
    
- **Logon Timestamp (UTC):** **2025-01-24 10:15:14 UTC** (2025-01-24T10:15:14.456012Z).
    
- **Source Address:** Local/tunneled IPv6 address recorded in Param3.
    

SmartScreen telemetry captured the execution and analysis of each downloaded component:

1. **Utility Staging (Archive Extractor):**
    
    - The adversary installed **WinRAR** (analyzed at 10:17:14 UTC, executed at 10:17:27 UTC).
        
2. **File Discovery Utility:**
    
    - Download and execution of portable Everything:
        
    - **Execution Path:** **C:/Users/Dutch/Downloads/Everything.exe**
        
    - **Execution Timestamp:** **2025-01-24 10:17:33 UTC** (field executionTime: 8701).
        

The adversary utilized Everything.exe to locate and access sensitive documents:

- **First Compromised File:**  
    **C:\Users\Dutch\Documents\2025- Board of directors Documents\Ministry Of Defense Audit.pdf**
    
- **Second Compromised File:**  
    **C:\Users\Dutch\Documents\2025- Board of directors Documents\2025-BUDGET-ALLOCATION-CONFIDENTIAL.pdf**
    

1. **Cloud Exfiltration:**
    
    - The attacker deployed the **MEGAsync** desktop synchronization agent.
        
    - **Execution Timestamp:** **2025-01-24 10:22:19 UTC** (recorded across SmartScreen events for MEGAsync.exe and MEGAsync.lnk).
        
2. **Data Destruction (Anti-Forensics):**
    
    - To prevent file recovery via file carving techniques, the attacker installed and executed:
        
    - **Destruction Utility:** **file shredder** (file_shredder_setup.exe).
        

Before terminating the session, the attacker attempted to eliminate forensic traces:

- **Security Event Log Cleared (Event ID 1102):**
    
    - **Timestamp:** **2025-01-24 10:28:41 UTC** (2025-01-24T10:28:41.933849Z).
        
    - **Executing User:** Dutch (SID S-1-5-21-3088055692-629932344-1786574096-1003, LogonId 0xe1d52).
        
    - Log Description: The audit log was cleared.

``` bash
# Extracción de eventos de SmartScreen y borrado de logs en Chainsaw
cat todos_los_logs | jq '.[] | select(.Event.System.EventID == 1003) | 
{
  Time: .Event.System.TimeCreated_attributes.SystemTime,
  Path: .Event.EventData.FilePath,
  ExecutionTime: .Event.EventData.executionTime
}'
cat todos_los_logs | jq '.[] | select(.Event.System.EventID == 1102)'
```

#### 4. Detection Rules and Security Engineering

``` Yaml
title: Vaciado del Registro de Seguridad de Windows (EventLog Cleared)
id: d9a10234-f811-4bb2-9a11-securitylogcleared
status: production
description: Detecta el vaciado deliberado del registro de auditoria de seguridad (Event ID 1102).
references:
  - https://attack.mitre.org/techniques/T1070/001/
author: Senior DFIR Specialist
date: 2025-01-25
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1102
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
```

``` SPL
index=sysmon EventCode=1 (Image="*MEGAsync*" OR Image="*file_shredder*" OR Image="*Everything.exe*")
| table _time, Computer, User, Image, CommandLine, ParentImage
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Network Disconnection:** Disconnect CTO-FILESVR from the network.
    
2. **Account Remediation:** Reset the local account password for Dutch and disable interactive logons on the system.
    
3. **Data Breach Assessment:** Consider Ministry of Defense and budget documents compromised and initiate incident reporting procedures in accordance with corporate and legal frameworks.
    
4. **Disable Direct Inbound RDP:** Disable RDP on systems containing high-value assets or mandate connections through a Jump Host enforcing MFA.
    
5. **AppLocker Software Restrictions:** Enforce WDAC policies preventing the execution of non-whitelisted cloud synchronizers (MEGAsync, Dropbox, OneDrive) and data-destruction utilities (File Shredder, SDelete).