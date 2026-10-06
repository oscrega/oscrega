**Classification:** TLP:AMBER  
**Environment / Platform:** Active Directory / Windows Server 2019 Domain Controller / HTB Sherlock  
**Target:** Domain Controller DC01.forela.local  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** Anomalous execution of the legitimate system binary vssadmin.exe (LOLBin) was identified on the primary Domain Controller (DC01). The threat actor, operating under delegated or compromised administrative privileges, manipulated the Volume Shadow Copy Service (VSS) to circumvent operating system exclusive file locks on the Active Directory database (NTDS.dit). Through this mechanism, the adversary generated a shadow copy and extracted a copy of NTDS.dit alongside the SYSTEM registry hive into a staging directory (backup_sync_Dc), establishing the prerequisites for offline decryption of all domain account password hashes (NTHash/LM).
    
- **Telemetry Sources and Evidence:**
    
    - Windows event logs: System.evtx, Security.evtx, and Microsoft-Windows-Ntfs/Operational.evtx.
        
    - File system audit records: Master File Table ($MFT) parsed with MFTECmd and exported to JSON.
        
    - Service artifacts: Interactions involving the VSSVC.exe binary (Volume Shadow Copy Service).
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Credential Access** | T1003.003 | OS Credential Dumping: NTDS | Unauthorized extraction of NTDS.dit and the SYSTEM hive to the staging folder C:\Users\Administrator\Documents\backup_sync_Dc\. |
| **Defense Evasion** | T1006 | Direct Volume Access | Abuse of Volume Shadow Copies to bypass kernel-level file locks on ntds.dit. |
| **Discovery** | T1069.002 | Permission Groups Discovery: Domain Groups | Automated enumeration of Administrators and Backup Operators groups performed by VSSVC.exe (Event ID 4799). |
| **Execution** | T1047 | Windows Management Instrumentation / LOLBins | Invocation of vssadmin to interact with the underlying system VSS provider infrastructure. |

#### 3. Infection Chain and Detailed Forensic Analysis

1. **VSS Service State Transition (System Log - Event ID 7036):**
    
    - The Volume Shadow Copy service entered the running state at **2024-05-14 03:42:16 UTC**, indicating the initiation of volume snapshot procedures by the adversary.
        
    - Event parameters: param1 = Volume Shadow Copy, param2 = running.
        
2. **Privilege Validation and Process Context (Security Log - Event ID 4799):**
    
    - Responsible service process: C:\Windows\System32\VSSVC.exe.
        
    - **Process ID (PID):** ProcessId: 0x1190 was logged in the event hexadecimal metadata, which maps to **PID 4496**.
        
    - Security Context: DC01$ (Local computer account of the Domain Controller).
        
    - Target groups queried to validate low-level read/write privileges: **Administrators** and **Backup Operators**.
        
3. **Shadow Copy Creation and Mount (NTFS Operational - Event ID 10):**
    
    - Upon volume snapshot creation, the system assigned the global volume identifier:
        
    - **Volume ID / GUID:** **{06c4a997-cca8-11ed-a90f-000c295644f9}**.
        

Forensic analysis of the Master File Table ($MFT) revealed the on-disk staging sequence:

- **Full NTDS Dump Path:** **C:\Users\Administrator\Documents\backup_sync_Dc\Ntds.dit**
    
- **Disk Creation Timestamp ($Created0x30 / $FILE_NAME):** **2024-05-14 03:44:22 UTC**.
    
- **Encryption Key Exfiltration (Registry Hive Dumping):**
    
    - Within the same directory (backup_sync_Dc), at **2024-05-14 03:44:42 UTC** (20 seconds after the database copy), the adversary extracted the **SYSTEM** registry hive.
        
    - Forensic Assessment: The ntds.dit file stores Password Encryption Keys (PEK) encrypted with the BootKey (or Syskey), which resides exclusively in the SYSTEM hive. Without this hive, NTLM hashes dumped from NTDS.dit cannot be decrypted.

``` bash
# Extracción forense del evento 4799 asociado a VSSVC en Chainsaw
cat events.json | jq '.[] | select(.Event.System.EventID == 4799) | 
select(.Event.EventData.CallerProcessName | contains("VSSVC.exe")) | 
{
  Time: .Event.System.TimeCreated_attributes.SystemTime,
  TargetGroup: .Event.EventData.TargetUserName,
  CallerProcess: .Event.EventData.CallerProcessName,
  ProcessID_Hex: .Event.EventData.CallerProcessId,
  Account: .Event.EventData.SubjectUserName
}'
```

#### 4. Detection Rules and Security Engineering

``` Yaml
title: Creacion Anomala de Instantanea VSS o Acceso a NTDS.dit
id: 9a38d721-e8d1-4122-b531-ntdsdumpvssadmin
status: production
description: Detecta la ejecucion de vssadmin o la creacion de shadow copies seguida de acceso a la base de datos de Active Directory.
references:
  - https://attack.mitre.org/techniques/T1003/003/
author: Senior DFIR Specialist
date: 2024-05-15
logsource:
  product: windows
  service: security
detection:
  selection_process:
    EventID: 4688
    NewProcessName|endswith:
      - '\vssadmin.exe'
      - '\wmic.exe'
    CommandLine|contains|all:
      - 'create'
      - 'shadow'
  selection_service:
    EventID: 7036
    ServiceName: 'VSS'
  condition: selection_process or selection_service
level: high
tags:
  - attack.credential_access
  - attack.t1003.003
```

``` SPL
index=wineventlog (EventCode=4688 OR EventCode=1) Image="*\\vssadmin.exe" CommandLine="*create shadow*"
| join type=outer host [
    search index=wineventlog EventCode=4799 CallerProcessName="*\\VSSVC.exe"
    | stats values(TargetUserName) as EnumeratedGroups by host, _time
]
| table _time, host, SubjectUserName, Image, CommandLine, EnumeratedGroups
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Domain Controller Containment:** Purge directory C:\Users\Administrator\Documents\backup_sync_Dc\ utilizing low-level secure deletion tools to remove local copies of Ntds.dit and SYSTEM.
    
2. **Domain Cryptographic Infrastructure Revocation:** Enforce a double reset of the **krbtgt** account password (spaced 12 to 24 hours apart) to invalidate Golden Tickets that could be forged with the compromised hashes.
    
3. **Global Credential Reset:** Force an immediate password change across all privileged domain accounts (Domain Admins, Enterprise Admins, critical service accounts).
    
4. **Access Restrictions on Snapshot Utilities:**
    
    - Restrict vssadmin.exe execution to authorized backup software contexts using WDAC or AppLocker policies.
        
5. **Critical Staging Directory Monitoring:**
    
    - Deploy SACL audit rules and EDR behavioral rules to alert on .dit file creation outside the legitimate directory path (%SystemRoot%\NTDS\).