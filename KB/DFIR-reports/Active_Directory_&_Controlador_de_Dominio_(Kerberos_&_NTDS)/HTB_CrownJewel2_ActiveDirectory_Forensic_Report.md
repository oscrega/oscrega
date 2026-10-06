**Classification:** TLP:AMBER  
**Environment / Platform:** Active Directory / Windows Server 2019 / HTB Sherlock  
**Target:** Domain Controller DC01.forela.local  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** Following the initial containment of the previous incident, the threat actor regained administrative access to the Domain Controller via uneradicated persistence mechanisms. In this second intrusion, the attacker abused the legitimate Active Directory management utility **ntdsutil.exe**, utilizing the Install From Media (IFM) dumping directive. This technique directly invokes the **ESENT** (Extensible Storage Engine) database engine to generate a consistent dump of NTDS.dit into a temporary directory (C:\Windows\Temp\dump_tmp\Active Directory\), attempting to conceal the extraction activity under standard Windows maintenance operations.
    
- **Telemetry Sources and Evidence:**
    
    - APPLICATION.evtx: ESENT transactional database engine logs (Event IDs 325, 327).
        
    - SYSTEM.evtx: System service status monitoring (Event ID 7036).
        
    - SECURITY.evtx: Authentication auditing and Kerberos sessions (Event IDs 4768, 4769, 4799, 5379).
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Credential Access** | T1003.003 | OS Credential Dumping: NTDS | Full Active Directory database dump using ntdsutil.exe directed to C:\Windows\Temp\dump_tmp\Active Directory\ntds.dit. |
| **Defense Evasion** | T1036.005 | Masquerading: Device / Utility Masquerading | Use of native administrative utilities (ntdsutil) to evade direct memory injection alerts against lsass.exe. |
| **Discovery** | T1069.002 | Permission Groups Discovery: Domain Groups | Automated group membership checks for privileged groups: Administrators and Backup Operators (Event ID 4799). |
| **Credential Access** | T1555.004 | Credentials from Password Stores: Windows Credential Manager | Access to credentials stored in Windows Credential Manager immediately prior to the dump (Event ID 5379). |

#### 3. Infection Chain and Detailed Forensic Analysis

1. **Volume Shadow Copy Service Activation to Support IFM (System Log - Event ID 7036):**
    
    - To generate a consistent snapshot without taking Active Directory offline, ntdsutil.exe invokes the VSS service.
        
    - Last timestamp when the service transitioned to the running state: **2024-05-15 05:39:55 UTC**.
        
2. **ESENT Database Engine Activity (Application Log):**
    
    - **Event Source:** **ESENT** (Extensible Storage Engine / JET Blue Engine).
        
    - **Database Creation / Initialization (Event ID 325):**
        
        - Logged at **2024-05-15 05:39:56 UTC**.
            
        - Documents the creation of the dump file at the physical path:  
            **C:\Windows\Temp\dump_tmp\Active Directory\ntds.dit**
            
    - **Database Termination and Detachment (Event ID 327):**
        
        - Logged at **2024-05-15 05:39:58 UTC**.
            
        - The event confirms that the database was detached cleanly, consistently, and left ready for file staging/exfiltration by the attacker.
            
3. **Account Privilege Validation (Security Log - Event ID 4799):**
    
    - Exactly two seconds before the database was finalized, the ntdsutil.exe process performed membership enumeration queries on two security groups: **Administrators** and **Backup Operators**.
        

Correlation of events in Security.evtx determined the exact time the compromised session initiated its activity:

- **Session Timestamp:** **2024-05-15 05:36:31 UTC**.
    
- **Concurrent Event Chain:**
    
    1. Event ID 4768: Successful Kerberos TGT request for the Administrator account.
        
    2. Event ID 4769: TGS ticket request for local DC services.
        
    3. Event ID 5379: Protected credential reading from the Windows Credential Manager, a typical operation preceding interactive dumping commands.
        

``` bash
# Filtrado de eventos ESENT para certificar la ruta del volcado NTDS
cat application.json | jq '.[] | select(.Event.System.Provider_attributes.Name == "ESENT") | 
select(.Event.System.EventID == 325 or .Event.System.EventID == 327) | 
{
  Time: .Event.System.TimeCreated_attributes.SystemTime,
  EventID: .Event.System.EventID,
  Description: .Event.EventData
}'
```

#### 4. Detection Rules and Security Engineering

``` Yaml
title: Volcado de NTDS.dit Mediante Ntdsutil (IFM)
id: 1198c4d2-f472-4d1a-8219-ntdsutilifmdump
status: production
description: Detecta el uso de ntdsutil.exe con parametros diseñados para volcar la base de datos de Active Directory en disco.
references:
  - https://attack.mitre.org/techniques/T1003/003/
author: Senior DFIR Specialist
date: 2024-05-16
logsource:
  product: windows
  service: security
detection:
  selection_ntdsutil:
    EventID: 4688
    NewProcessName|endswith: '\ntdsutil.exe'
    CommandLine|contains|all:
      - 'ac'
      - 'i'
      - 'ntds'
  selection_ifm:
    CommandLine|contains|any:
      - 'create full'
      - 'ifm'
  condition: selection_ntdsutil and selection_ifm
level: critical
tags:
  - attack.credential_access
  - attack.t1003.003
```

``` Spl
index=wineventlog (source="*Application" SourceName="ESENT" (EventCode=325 OR EventCode=327)) OR (source="*Security" EventCode=4688 NewProcessName="*\\ntdsutil.exe")
| transaction host maxspan=30s
| search CommandLine="*ifm*" OR CommandLine="*create full*"
| table _time, host, SubjectUserName, CommandLine, Message
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Total Isolation of the Affected DC:** Isolate DC01 from the corporate network, preserving only controlled forensic connectivity.
    
2. **Rebuilding Domain Trust:** In light of two consecutive compromises of NTDS.dit, the Active Directory forest must be deemed completely compromised. Plan a complete rebuild of the KDC and primary Domain Controllers from verified baseline images.
    
3. **Key Lockout and Re-rotation:** Execute a second rotation of the krbtgt account password and revoke certificates issued by Active Directory Certificate Services (AD CS).
    
4. **Strict Process Creation Auditing (CommandLine Auditing):** Enforce via GPO the "Include command line in process creation events" policy (Event ID 4688) to guarantee traceability over arguments passed to ntdsutil.exe.
    
5. **Administrative Privilege Restriction:** Implement a tiered administration model (Tier Model / Enterprise Access Model) preventing Domain Admins from logging on to any system other than dedicated Domain Controllers.