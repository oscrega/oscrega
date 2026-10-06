**Classification:** TLP:AMBER  
**Environment / Platform:** Windows 10 Endpoint / Windows Prefetch & USN Journal / HTB Sherlock  
**Target:** Compromised Workstation / Lateral Movement via PsExec  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** An intrusion involving lateral movement alerts for the Sysinternals administration utility PsExec was investigated on an enterprise workstation. Forensic analysis of Prefetch artifacts (PSEXESVC.EXE-AD70946C.pf), the NTFS USN Journal ($Extend\$J), and Sysmon telemetry (Microsoft-Windows-Sysmon%4Operational.evtx) established the lateral traversal activity. It was confirmed that the adversary operated from host **FORELA-WKSTN001**, issuing remote commands across 9 distinct execution instances via the PSEXESVC.EXE service binary. Temporal correlation isolated the 5th execution event, identifying its associated encryption key files (.KEY) and SMB Named Pipes.
    
- **Telemetry Sources and Evidence:**
    
    - Prefetch artifacts: C:\Windows\prefetch\PSEXESVC.EXE-AD70946C.pf analyzed with PECmd.exe v1.5.1.0.
        
    - NTFS Change Journal: C:\$Extend\$J parsed with MFTECmd.exe.
        
    - Sysmon operational logs: Event IDs 17 and 18 (Pipe Created / Pipe Connected).
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Lateral Movement** | T1021.002 | Remote Services: SMB/Windows Admin Shares | Remote staging and execution of the PSEXESVC.exe service over ADMIN$ shares. |
| **Execution** | T1569.002 | System Services: Service Execution | Interactive command execution under NT AUTHORITY\SYSTEM context via the PsExec service wrapper. |
| **Command and Control** | T1570 | Lateral Tool Transfer | Transfer and staging of authentication key files (.KEY) within C:\Windows\. |

#### 3. Infection Chain and Detailed Forensic Analysis

Parsing of the .pf artifact with PECmd confirmed continuous usage of the tool:

- **Service Binary Executed:** **PSEXESVC.EXE** (Service binary deployed by PsExec on the remote target host).
    
- **Total Execution Count (Run Count):** **9 executions**.
    
- **Complete Run History (UTC):**
    
    1. 2023-09-07 12:10:03 (Most recent execution)
        
    2. 2023-09-07 12:09:09
        
    3. 2023-09-07 12:08:54
        
    4. 2023-09-07 12:08:23
        
    5. **2023-09-07 12:06:54** (5th execution / primary forensic focus)
        
    6. 2023-09-07 11:57:53
        
    7. 2023-09-07 11:57:43
        
    8. 2023-09-07 11:55:44
        
    9. 2023-09-07 11:55:44
        

PsExec generates temporary key files in C:\Windows\ using standard naming conventions: `PSEXEC-<HOSTNAME>-<KEY_ID>.KEY`.

- **Source Hostname:** **FORELA-WKSTN001**.
    
- **Key File Correlated to the 5th Execution:**  
    Matching the 12:06:54 UTC execution timestamp against the file references recorded in Prefetch identified the artifact:  
    **PSEXEC-FORELA-WKSTN001-95F03CFE.KEY**
    
- **Disk Creation Timestamp (USN Journal - $J):**  
    The journal dump recorded the creation of this key file one second following service invocation: **2023-09-07 12:06:55 UTC** (07/09/2023 12:06:55).
    

PsExec provides standard I/O redirection through SMB Named Pipes for stdin, stdout, and stderr. Sysmon operational logs recorded the creation of the Named Pipe corresponding to the 5th execution:

- **Creation Timestamp:** 2023-09-07 12:06:55 UTC.
    
- **Standard Error (stderr) Pipe Architecture:** The created pipe ending in stderr corresponded to session 95F03CFE: \psexec-FORELA-WKSTN001-95F03CFE-stderr (or \PSEXESVC-*-stderr).

``` bash
# Comandos de extracción pericial con herramientas de Zimmerman
PECmd.exe -f "C:\Windows\Prefetch\PSEXESVC.EXE-AD70946C.pf" --json Output_Prefetch
MFTECmd.exe -f "C:\$Extend\$J" --json Output_J --jsonf j.json
cat j.json | jq '.[] | select(.Name | contains("PSEXEC-FORELA-WKSTN001-95F03CFE"))'
```

#### 4. Detection Rules and Security Engineering

``` Yaml
title: Deteccion de Movimiento Lateral Mediante PsExec
id: d4b19283-e182-4211-9a18-psexeclateralmovement
status: production
description: Identifica la creacion del servicio PSEXESVC o la presencia de archivos .key caracteristicos de PsExec en C:\Windows.
references:
  - https://attack.mitre.org/techniques/T1021/002/
author: Senior DFIR Specialist
date: 2023-09-08
logsource:
  product: windows
  service: system
detection:
  selection_service:
    EventID: 7045
    ServiceName: 'PSEXESVC'
  selection_file:
    EventID: 11
    TargetFilename|startswith: 'C:\Windows\PSEXEC-'
    TargetFilename|endswith: '.key'
  condition: selection_service or selection_file
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.002
```

``` SPL
index=sysmon (EventCode=17 OR EventCode=18) PipeName="*psexec*" OR PipeName="*PSEXESVC*"
| stats count, values(Image) as Binarios by Computer, PipeName, _time
| table _time, Computer, PipeName, Binarios, count
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Host Isolation:** Isolate both the affected endpoint and the source device **FORELA-WKSTN001**.
    
2. **Service and Artifact Eradication:** Stop the PSEXESVC service if still running, unregister it, and remove residual .key files from C:\Windows\.
    
3. **Administrative Share Hardening:** Block inbound access to ADMIN$ and IPC$ on user workstations using host-based firewalls.
    
4. **Peer-to-Peer SMB Segmentation:** Apply network microsegmentation to block TCP port 445 traffic between workstations in the same client subnets.