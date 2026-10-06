**Classification:** TLP:AMBER  
**Environment / Platform:** Windows 10 Endpoint / Sysmon & PowerShell Event Log Forensics / HTB Sherlock  
**Target:** Compromised Workstation / Security Controls Tampering (Dr. Reyes Investigation)  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** A defense evasion sequence aimed at blinding endpoint detection mechanisms prior to payload execution was investigated. Analysis of Microsoft-Windows-Powershell-Operational.evtx and Microsoft-Windows-Sysmon-Operational.evtx demonstrated that the attacker disabled LSA Protection in the Windows Registry, turned off Microsoft Defender components via PowerShell administrative cmdlets, patched the in-memory AMSI API function (AmsiScanBuffer), modified the Boot Configuration Data (BCD) using bcdedit to force Safe Mode with Networking, and disabled PowerShell command history logging (SaveNothing).
    
- **Telemetry Sources and Evidence:**
    
    - Microsoft-Windows-Powershell-Operational.evtx: Script Block Logging records (Event ID 4104).
        
    - Microsoft-Windows-Sysmon-Operational.evtx: Process creation monitoring (Event ID 1) and Registry manipulation (Event IDs 12 and 13).
        
    - Extraction tools: Chainsaw and jq queries.
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Defense Evasion** | T1562.001 | Impair Defenses: Disable or Modify Tools | Microsoft Defender disabled via Set-MpPreference and LSA Protection weakened. |
| **Defense Evasion** | T1562.001 | Impair Defenses: AMSI Bypass | In-memory patching of API function AmsiScanBuffer inside amsi.dll. |
| **Defense Evasion** | T1562.009 | Impair Defenses: Safe Mode Boot | BCD configuration altered with bcdedit.exe /set safeboot network. |
| **Defense Evasion** | T1070.004 | Indicator Removal: File Deletion / History | Command history disabled via Set-PSReadLineOption -HistorySaveStyle SaveNothing. |

#### 3. Infection Chain and Detailed Forensic Analysis

The attacker altered Local Security Authority (LSA) Registry values to enable unprivileged processes to read memory from lsass.exe:

- **Registry Key Path:**  
    **HKLM\System\CurrentControlSet\Control\Lsa**
    
- Manipulated target values: RunAsPPL, RunAsPPLBoot, LsaCfgFlagsDefault.
    

In the PowerShell Operational log (Event ID 4104), a cmdlet execution was identified that disabled all primary real-time Defender engines:

- **Executed PowerShell Command:**  
    **Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true**
    
- Operational Impact: Neutralized behavioral heuristics, script scanning, download file inspection (IOAV), and network intrusion prevention systems (IPS).
    

The adversary loaded a C# reflection payload in PowerShell to hook and neutralize the Antimalware Scan Interface:

- **Extracted Code Fragment:**  
    
    ``` C#
    IntPtr a = GetProcAddress(h, "A" + "m" + "s" + "i" + "S" + "c" + "a" + "n" + "B" + "u" + "f" + "f" + "e" + "r");
    ```
    
- **Target Function Hooked:** **AmsiScanBuffer** (located in amsi.dll). By patching the initial bytes of this function to return AMSI_RESULT_CLEAN, subsequent malicious scripts execute without analysis by local AV software.
    

To boot into an environment where endpoint security software is prevented from loading, the attacker modified boot parameters:

- **Executed Command:** **bcdedit.exe /set safeboot network**
    
- Tactical Objective: Force the system into Safe Mode with Networking, an operational mode where third-party EDR sensors and AV drivers do not start by default.
    

To prevent actions from logging to %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt:

- **Executed Command:** **Set-PSReadLineOption -HistorySaveStyle SaveNothing**

``` bash
# Extracción en Chainsaw de los comandos de evasión en Event ID 4104
cat powershell_operational | jq -r '.[] | select(.Event.System.EventID == 4104) | .Event.EventData.ScriptBlockText'
```

#### 4. Detection Rules and Security Engineering

``` Yaml
title: Modificacion Maliciosa de Windows Defender via Set-MpPreference
id: 4a2109bc-7e81-4221-b118-disabledefenderprefs
status: production
description: Detecta intentos de deshabilitar la monitorizacion en tiempo real o el escaneo de comportamiento mediante Set-MpPreference.
references:
  - https://attack.mitre.org/techniques/T1562/001/
author: Senior DFIR Specialist
date: 2025-12-27
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains|all:
      - 'Set-MpPreference'
    ScriptBlockText|contains|any:
      - '-DisableRealtimeMonitoring $true'
      - '-DisableBehaviorMonitoring $true'
      - '-DisableScriptScanning $true'
  condition: selection
level: critical
tags:
  - attack.defense_evasion
  - attack.t1562.001
```

``` SPL
index=sysmon EventCode=1 Image="*\\bcdedit.exe" CommandLine="*safeboot*"
| table _time, Computer, User, Image, CommandLine, ParentImage
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Revert Boot Configuration:**
    
    ``` cmd
    bcdedit /deletevalue safeboot
    ```
    
2. **Re-enable Microsoft Defender:**
    
    ``` Powershell
    Set-MpPreference -DisableRealtimeMonitoring $false -DisableScriptScanning $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableIntrusionPreventionSystem $false
    ```
    
3. **Network Isolation:** Isolate the endpoint from the network to prevent staging of second-stage payloads or ransomware.
    
4. **Enable Tamper Protection:** Enable Tamper Protection for Microsoft Defender to prevent administrative accounts or scripts from altering Set-MpPreference.
    
5. **Restrict BCD Modifications:** Block unprivileged and scripted access to bcdedit.exe via WDAC.
    
6. **Enforce LSA Protection (RunAsPPL):** Configure Group Policy to mandate RunAsPPL=dword:00000001 combined with UEFI variable protection.