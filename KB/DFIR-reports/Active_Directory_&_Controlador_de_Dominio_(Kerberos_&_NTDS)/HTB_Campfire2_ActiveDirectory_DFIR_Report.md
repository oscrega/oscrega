**Classification:** TLP:AMBER  
**Environment / Platform:** Active Directory / Windows Server 2019 Domain Controller / HTB Sherlock  
**Target:** Domain Controller DC01.forela.local  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** A security alert within the FORELA.LOCAL domain infrastructure regarding Kerberos authentication ticket requests (AS-REQ / AS-REP) linked to a dormant administrative user account (arthur.kyle) was investigated. Forensic analysis of security audit logs (Security.evtx) confirmed an **AS-REP Roasting** attack. The threat actor leveraged the absence of Kerberos preauthentication (DONT_REQ_PREAUTH) on this account to request a Ticket Granting Ticket (TGT) encrypted with RC4-HMAC (0x17), enabling offline extraction of cryptographic material for brute-force/dictionary cracking. Subsequent telemetry identified concurrent use of an additional user account (happy.grunwald@FORELA.LOCAL) originating from the same compromised workstation (172.17.79.129), indicating established persistence and privilege escalation within the internal boundary.
    
- **Telemetry Sources and Evidence:**
    
    - DC01.forela.local Security.evtx parsed and structured into JSON format using the Chainsaw forensic tool.
        
    - Kerberos audit event correlation: Event ID 4768 (A Kerberos authentication ticket (TGT) was requested) and Event ID 4769 (A Kerberos service ticket was requested).
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Credential Access** | T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | Successful TGT request without preauthentication (PreAuthType: 0) for user arthur.kyle negotiating weak RC4 encryption (0x17). Event ID 4768. |
| **Initial Access / Discovery** | T1087.002 | Account Discovery: Domain Account | Targeted requests directed at accounts with the DONT_REQ_PREAUTH bit set in the userAccountControl attribute. |
| **Lateral Movement** | T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting / Service Requests | Ticket Granting Service (TGS) request for the DC01$ SPN under the context of happy.grunwald@FORELA.LOCAL from the hostile source IP. Event ID 4769. |

#### 3. Infection Chain and Detailed Forensic Analysis

1. **Identification of Vulnerable Account:** The targeted user account was identified as arthur.kyle, with relative identifier (RID) 1601 (TargetSid: S-1-5-21-3239415629-1862073780-2394361899-1601).
    
2. **AS-REP Roasting Exploitation (Event ID 4768):**
    
    - **UTC Timestamp:** 2024-05-29 06:36:40.246362Z
        
    - **Event Record ID:** Record ID 6241
        
    - **Source Host / IP Address:** ::ffff:172.17.79.129 (IPv4-mapped IPv6)
        
    - **Source Ephemeral Port:** 61965
        
    - **Service Name:** krbtgt (SID S-1-5-21-3239415629-1862073780-2394361899-502)
        
    - **PreAuthType:** 0 (Indicates that Kerberos preauthentication was neither required nor provided, confirming the DONT_REQ_PREAUTH flag was set).
        
    - **TicketEncryptionType:** 0x17 (KERB_ETYPE_RC4_HMAC_MD5). The adversary deliberately forced this cipher type to streamline offline password recovery via Hashcat (mode 18200: Kerberos 5 AS-REP etype 23).
        
    - **TicketOptions:** 0x40800010 (Forwardable, Renewable, Canonicalize).
        
    - **Status:** 0x0 (Operation completed successfully by the KDC).
        

Approximately 69 seconds following the AS-REP Roasting event, at 2024-05-29 06:37:49.227372Z (Record ID 6242), a TGS request (EventID: 4769) originated from the same hostile IP address (172.17.79.129, port 61975):

- **TargetUserName:** happy.grunwald@FORELA.LOCAL
    
- **ServiceName:** DC01$
    
- **ServiceSid:** S-1-5-21-3239415629-1862073780-2394361899-1000
    
- **TicketEncryptionType:** 0x12 (AES256-CTS-HMAC-SHA1-96)
    
- **TicketOptions:** 0x40810000
    
- **LogonGuid:** 543ACECF-87DD-45D9-CF0D-6C1F28070DC3
    

This evidence confirms that the attacker already possessed valid credentials or an active session under the context of happy.grunwald on workstation 172.17.79.129, from which reconnaissance and the AS-REP request for arthur.kyle were executed.

``` bash
# Invocación de extracción y filtrado en Chainsaw/jq para aislar la actividad del atacante
cat security.json | jq -r '.[] | select(.Event.System.EventID == 4768 and .Event.EventData.PreAuthType == "0") | 
{
  Timestamp: .Event.System.TimeCreated_attributes.SystemTime,
  User: .Event.EventData.TargetUserName,
  SID: .Event.EventData.TargetSid,
  ClientIP: .Event.EventData.IpAddress,
  ClientPort: .Event.EventData.IpPort,
  Encryption: .Event.EventData.TicketEncryptionType,
  Status: .Event.EventData.Status
}'
```

#### 4. Detection Rules and Security Engineering

``` Yaml
title: Deteccion de Ataque AS-REP Roasting en Active Directory
id: a7d398f1-e3d8-4f81-9b16-4768asreproast
status: production
description: Detecta eventos de solicitud de TGT (Event ID 4768) donde la preautenticacion esta deshabilitada (PreAuthType 0) y se utiliza cifrado debil RC4 (0x17).
references:
  - https://attack.mitre.org/techniques/T1558/004/
author: Senior DFIR Specialist
date: 2024-05-30
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
    Status: '0x0'
  filter_machine_accounts:
    TargetUserName|endswith: '$'
  condition: selection and not filter_machine_accounts
falsepositives:
  - Cuentas legacy que explícitamente requieran compatibilidad con sistemas operativos desactualizados (deben mitigarse).
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

``` SPL
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0" NOT TargetUserName="*$"
| eval ClientIP=replace(IpAddress, "::ffff:", "")
| stats count, min(_time) as Primer_Intento, max(_time) as Ultimo_Intento by ClientIP, TargetUserName, TargetSid, TicketOptions
| convert ctime(Primer_Intento) ctime(Ultimo_Intento)
| table Primer_Intento, Ultimo_Intento, ClientIP, TargetUserName, TargetSid, TicketOptions, count
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Network Isolation:** Disconnect and strictly quarantine workstation 172.17.79.129 utilizing perimeter firewall rules and EDR network containment.
    
2. **Account Lockout and Credential Reset:**
    
    - Immediately disable the compromised account arthur.kyle (S-1-5-21-3239415629-1862073780-2394361899-1601).
        
    - Force a credential reset for happy.grunwald@FORELA.LOCAL, terminating all active Kerberos sessions by revoking existing tokens.
        
3. **Active Session Auditing:** Inspect all remote sessions, open SMB connections, and WMI sessions originating from 172.17.79.129 to other network assets.
    
4. **Remediation of DONT_REQ_PREAUTH Flag:**
    
    - Audit all domain accounts with Kerberos preauthentication disabled via PowerShell:
        
        ``` Powershell
        Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth | Select-Object SamAccountName, DistinguishedName, Enabled
        ```
        
    - Enforce preauthentication on all identified objects:
        
        ``` Powershell
        Set-ADAccountControl -Identity "arthur.kyle" -DoesNotRequirePreAuth $False
        ```
        
5. **Disable RC4 Encryption in Kerberos:**
    
    - Configure Group Policy (GPO) to restrict permitted Kerberos encryption suites strictly to AES (AES128_HMAC_SHA1 and AES256_HMAC_SHA1) under:  
        Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Network security: Configure encryption types allowed for Kerberos.
        
6. **Account Lifecycle Management:** Implement automated review workflows to disable or remove dormant administrative accounts.