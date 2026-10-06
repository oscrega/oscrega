**Classification:** TLP:AMBER  
**Environment / Platform:** Windows 10 Endpoint / Native EVTX Artifacts / HTB Sherlock  
**Target:** Workstation DESKTOP-887GK2L (CyberJunkie User)  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** A forensic analysis was conducted on Windows event logs to investigate malicious post-exploitation activity executed by user CyberJunkie. Correlation across multiple channels (Security, System, Firewall, Defender, and PowerShell) confirmed that the user initiated an interactive logon, modified system audit policies to suppress alerts, altered Windows Firewall configurations to permit outbound connections to a **Metasploit** C2 framework, established a persistent scheduled task (HTB-AUTOMATION) running a PowerShell payload (Automation-HTB.ps1), downloaded the Active Directory discovery utility **SharpHound** (which was quarantined by Windows Defender), and cleared the Windows Firewall log to conceal changes.
    
- **Telemetry Sources and Evidence:**
    
    - Security.evtx: Event IDs 4624, 4698, 4719.
        
    - Windows Firewall-Firewall.evtx: Event ID 2004.
        
    - Windows Defender-Operational.evtx: Event ID 1117.
        
    - Powershell-Operational.evtx: Event ID 4104.
        
    - System.evtx: Event ID 104 (Log file cleared).
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Defense Evasion** | T1562.004 | Impair Defenses: Disable or Modify System Firewall | Outbound firewall rule created named "Metasploit C2 Bypass". |
| **Persistence / Execution** | T1053.005 | Scheduled Task/Job: Scheduled Task | Creation of scheduled task HTB-AUTOMATION targeting Automation-HTB.ps1. |
| **Discovery** | T1069.002 | Permission Groups Discovery: Domain Groups | Download and attempted execution of the SharpHound-v1.1.0.zip reconnaissance utility. |
| **Defense Evasion** | T1070.001 | Indicator Removal: Clear Windows Event Logs | Windows Firewall event log cleared, recorded under Event ID 104 in System.evtx. |

#### 3. Infection Chain and Detailed Forensic Analysis

1. **Interactive User Logon (Security Event ID 4624):**
    
    - **Logon Timestamp (UTC):** **2023-03-27 14:37:09 UTC** (2023-03-27T14:37:09.879891Z).
        
    - User Account: CyberJunkie (SID S-1-5-21-3393683511-3463148672-371912004-1001, Logon Type 2).
        
2. **Firewall Rule Modification (Firewall Log Event ID 2004):**
    
    - The attacker launched MMC (C:\Windows\System32\mmc.exe) and created a rule:
        
    - **Rule Name:** **Metasploit C2 Bypass**
        
    - **Direction:** **Outbound** (Direction: 2).
        
    - Remote Allowed Port: 4444 (default Metasploit/Meterpreter listener port).
        
    - Modification Timestamp: 2023-03-27 14:44:43 UTC.
        

At 14:50:03 UTC, the user modified system audit policies:

- **Modified Subcategory:** **Other Object Access Events** `(SubcategoryGuid: 0CCE9227-69AE-11D9-BED3-505054503030, SubcategoryId: %%12804)`.
    

At 14:51:21 UTC, a persistent scheduled task was created:

- **Task Name:** **HTB-AUTOMATION** (\HTB-AUTOMATION).
    
- **Target File Path:**  
    **C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1**
    
- **Execution Arguments:**  
    **-A cyberjunkie@hackthebox.eu**
    

1. **Malicious Tool Identification:**
    
    - At 14:42:34 UTC, Windows Defender intercepted a download:
        
    - **Tool Name:** **SharpHound** (HackTool:MSIL/SharpHound!MSR).
        
2. **Target File Path:**  
    **C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip**
    
3. **Mitigation Action Taken:** **Quarantine** (Action ID: 2, applied successfully).
    
4. **PowerShell Execution (Event ID 4104):**
    
    - At 14:58:33 UTC, the user verified the script hash via PowerShell:
        
    - **Executed Command:** **Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1**
        
5. **Event Log Cleared (System Event ID 104):**
    
    - At **2023-03-27 15:01:56 UTC**, the attacker cleared the Windows Firewall log to conceal rule modifications:
        
    - **Cleared Log Channel:**  
        **Microsoft-Windows-Windows Firewall With Advanced Security/Firewall**
        
    - Executing User: CyberJunkie.

``` bash
# Extracción de la regla de firewall y tarea programada en Chainsaw
cat windows_firewall.json | jq '.[] | select(.Event.EventData.RuleName == "Metasploit C2 Bypass")'
cat security.json | jq '.[] | select(.Event.System.EventID == 4698)'
cat system.json | jq '.[] | select(.Event.System.EventID == 104)'
```

#### 4. Detection Rules and Security Engineering

``` Yaml
title: Creacion de Regla de Firewall con Referencia a Herramientas C2
id: 9a810234-c471-4221-a119-firewallc2bypass
status: production
description: Detecta la creacion de reglas de firewall salientes que referencien puertos o nombres de frameworks ofensivos.
references:
  - https://attack.mitre.org/techniques/T1562/004/
author: Senior DFIR Specialist
date: 2023-03-28
logsource:
  product: windows
  service: firewall
detection:
  selection:
    EventID: 2004
    RuleName|contains|any:
      - 'Metasploit'
      - 'C2'
      - 'Bypass'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.004
```

``` SPL
index=wineventlog EventCode=104 Channel="System"
| table _time, Computer, SubjectUserName, Channel, BackupPath
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Firewall Rule Removal:** Delete rule "Metasploit C2 Bypass" in Windows Defender Firewall.
    
2. **Scheduled Task Removal:**
    
    ``` CMD
    schtasks /delete /tn "HTB-AUTOMATION" /f
    ```
    
3. **Payload Remediation:** Delete script C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1.
    
4. **Account Suspension:** Disable the CyberJunkie local user account pending further investigation.
    
5. **Centralized Event Log Forwarding:** Configure Windows Event Forwarding (WEF) or SIEM agents (Splunk/Wazuh) to ensure logs are ingested into an immutable central repository, preventing attackers from covering their tracks via local log clearing (Event IDs 104 and 1102).
    
6. **Restrict Scheduled Task Creation:** Restrict task creation privileges for standard users using local security policies and alert on tasks that execute PowerShell with network flags.