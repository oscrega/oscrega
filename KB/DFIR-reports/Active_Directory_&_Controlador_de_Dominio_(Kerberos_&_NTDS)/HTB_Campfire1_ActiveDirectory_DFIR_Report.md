**Classification:** TLP:AMBER  
**Environment / Platform:** Active Directory / Windows Enterprise / HTB Sherlock  
**Target:** Alonzo Workstation (172.17.79.129) / FORELA.LOCAL Domain  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** An adversary intrusion was investigated on the workstation assigned to user Alonzo (172.17.79.129). The threat actor obtained interactive command execution, bypassed the local PowerShell execution policy (-ep bypass), and loaded the PowerView audit framework directly into memory to perform discovery of domain objects possessing ServicePrincipalName (SPN) attributes. Subsequently, the attacker deployed the compiled offensive utility Rubeus.exe into the user's Downloads directory to execute a **Kerberoasting** attack, requesting a Ticket Granting Service (TGS) ticket negotiated with weak RC4-HMAC encryption (0x17) for the MSSQLService service account for offline cracking.
    
- **Telemetry Sources and Evidence:**
    
    - SECURITY-DC.evtx: KDC Security log (Event ID 4769).
        
    - Microsoft-Windows-PowerShell%4Operational.evtx: Endpoint Script Block Logging events (Event ID 4104).
        
    - C:\Windows\Prefetch\RUBEUS.EXE-B488C951.pf: Execution artifact analyzed with PECmd.
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell | Interactive invocation of powershell.exe -ep bypass and in-memory loading of PowerView modules (Event ID 4104). |
| **Defense Evasion** | T1562.001 | Impair Defenses: Disable or Modify Tools | Bypassing local script signing policies via -ExecutionPolicy Bypass. |
| **Discovery** | T1087.002 | Account Discovery: Domain Account | Execution of PowerView functions: Convert-NameToSid, ConvertFrom-UACValue, Export-PowerViewCSV. |
| **Credential Access** | T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Coerced request of an RC4-encrypted (0x17) TGS ticket for MSSQLService utilizing Rubeus.exe. |

#### 3. Infection Chain and Detailed Forensic Analysis

In Microsoft-Windows-PowerShell%4Operational.evtx, at **2024-05-21 03:16:29 UTC**, an Event ID 4104 (Script Block Logging) was recorded at the Information level, documenting the in-memory definition of Active Directory reconnaissance functions from the **PowerView** suite:

- **Identified Signatures:** Export-PowerViewCSV, Set-MacAttribute, Convert-NameToSid, and ConvertFrom-UACValue.
    
- **Tactical Objective:** Enumerate all user accounts within the KDC having a populated servicePrincipalName attribute, excluding computer accounts (*$) and core infrastructure accounts (krbtgt).
    

Forensic parsing of the Prefetch file on Alonzo's endpoint confirmed the compiled binary's execution:

- **Analyzed File:** C:\Windows\Prefetch\RUBEUS.EXE-B488C951.pf
    
- **Executable Path:** **C:\Users\Alonzo\Downloads\Rubeus.exe**
    
- **First File System Record:** 2024-05-21 03:16:32 UTC.
    
- **Last Execution Timestamp (Run Time UTC):** **2024-05-21 03:18:08 UTC**.
    
- **Run Count:** 1.
    
- **Runtime Loaded Dependencies:** NTDLL.DLL, KERNEL32.DLL, MSCOREE.DLL, CLR.DLL (confirming a standalone application built on C#/.NET Framework).
    

Exactly one second after the recorded execution in Prefetch, at **2024-05-21 03:18:09 UTC**, the Domain Controller registered the issuance of the TGS ticket:

- **Event ID:** **4769** (A Kerberos service ticket was requested).
    
- **TargetUserName:** **MSSQLService@FORELA.LOCAL**
    
- **ServiceName:** MSSQLService
    
- **ServiceSid:** **S-1-5-21-3814545217-1834241598-1324545322-1108**
    
- **TicketOptions:** 0x40810000 (Forwardable, Renewable, Canonicalize).
    
- **TicketEncryptionType:** **0x17** (KERB_ETYPE_RC4_HMAC_MD5).
    
- **Client IP Address:** ::ffff:172.17.79.129 (Alonzo's Workstation).
    
- **Client Port:** 49832.
    
- Forensic Assessment: The explicit request for 0x17 encryption confirms an intentional downgrade to facilitate offline dictionary attacks using cracking suites such as Hashcat (mode 13100).

``` bash
# Invocación pericial de PECmd sobre el artefacto Prefetch de Rubeus
PECmd.exe -f "C:\Windows\Prefetch\RUBEUS.EXE-B488C951.pf" --json "C:\Analysis\Output"
```

#### 4. Detection Rules and Security Engineering

``` Yaml
title: Deteccion de Kerberoasting por Downgrade de Cifrado RC4
id: 593b4a22-3ceb-4d43-9828-98e204769kerb
status: production
description: Identifica solicitudes de tickets Kerberos TGS (Event ID 4769) emitidas contra cuentas de servicio que fuerzan cifrado RC4 (0x17).
references:
  - https://attack.mitre.org/techniques/T1558/003/
author: Senior DFIR Specialist
date: 2024-05-22
logsource:
  product: windows
  service: security
detection:
  selection_tgs:
    EventID: 4769
    TicketEncryptionType: '0x17'
    Status: '0x0'
  filter_machine:
    ServiceName|endswith: '$'
  filter_krbtgt:
    ServiceName: 'krbtgt'
  condition: selection_tgs and not filter_machine and not filter_krbtgt
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

``` Spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17" ServiceName!="*$" ServiceName!="krbtgt" Status="0x0"
| eval ClientIP=replace(IpAddress, "::ffff:", "")
| stats count, values(ServiceName) as Servicios_Solicitados by ClientIP, TargetUserName, _time
| sort - _time
| table _time, ClientIP, TargetUserName, Servicios_Solicitados, count
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Endpoint Isolation:** Isolate workstation 172.17.79.129 from the network using the EDR sensor.
    
2. **Service Account Credential Reset:** Immediately change the password of the MSSQLService account (S-1-5-21-3814545217-1834241598-1324545322-1108), assigning a complex password with at least 32 high-entropy characters.
    
3. **Transition to Group Managed Service Accounts (gMSA):** Migrate MSSQLService to a gMSA, removing static legacy passwords and delegating 128-character cryptographic automatic rotations to Active Directory.
    
4. **Disable Weak Encryption (RC4) in Active Directory:**
    
    - Enforce modern encryption suites via GPO:  
        Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Network security: Configure encryption types allowed for Kerberos.
        
    - Select exclusively: AES128_HMAC_SHA1, AES256_HMAC_SHA1, and Future encryption types.
        
5. **Execution Restrictions (AppLocker / WDAC):** Prevent execution of binaries and scripts located within unprivileged user directories (C:\Users\*\Downloads\*, C:\Users\*\AppData\*).