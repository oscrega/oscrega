**Classification:** TLP:AMBER  
**Environment / Platform:** Windows 10 Endpoint / VHDX Disk Image / HTB Sherlock  
**Target:** Pathology Lab Workstation (Susan) / Forela International Hospital  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** A virtual disk triage image (.vhdx) acquired from a Pathology Department workstation (Susan) was analyzed. The user reported system errors when extracting an email attachment, although a lure PDF document ultimately displayed on screen. Low-level forensic analysis of the Master File Table ($MFT) and NTFS change journal ($UsnJrnl) confirmed the exploitation of a remote code execution vulnerability in **WinRAR** (consistent with in-the-wild RomCom campaigns / CVE-2023-38831). Opening the lure Genotyping_Results_B57_Positive.pdf triggered the covert extraction and execution of malicious payload ApbxHelper.exe, which established immediate persistence via a fraudulent shortcut (Display Settings.lnk) placed in the user's Startup folder.
    
- **Telemetry Sources and Evidence:**
    
    - Disk image: 2025-09-02T083211_pathology_department_incidentalert.vhdx.
        
    - Read-only NTFS mount processed via guestmount.
        
    - File system metadata files: $MFT, $Extend\$J (USN Journal), and CopyLog.csv audit logs.
        
    - Forensic tools: MFTECmd.exe v1.3.0.0 (.NET build).
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment | Delivery of an archive container using structural spoofing to simulate clinical laboratory results. |
| **Execution** | T1203 | Exploitation for Client Execution | Exploitation of the WinRAR file spoofing vulnerability upon opening the PDF lure. |
| **Persistence** | T1547.009 | Boot or Logon Autostart Execution: Shortcut Modification | Deployment of Display Settings.lnk to the Startup directory referencing ApbxHelper.exe. |
| **Defense Evasion** | T1036.005 | Masquerading: Match Legitimate Name | Misusing legitimate system terminology (Display Settings.lnk) to conceal autostart persistence. |

#### 3. Infection Chain and Detailed Forensic Analysis

Directory structure reconstruction and timestamp correlation within $MFT established the execution timeline:

1. **Malicious Container Staging:**
    
    - Archive file creation on disk: **2025-09-02 08:13:50 UTC**.
        
    - Last access recorded against the container: **2025-09-02 08:14:04 UTC**.
        
2. **Exploitation Mechanism (CVE-2023-38831 / CVE-2025-8088):**
    
    - The archive was weaponized with a decoy file (Genotyping_Results_B57_Positive.pdf) and a directory sharing the same name containing an executable payload. Double-clicking the PDF from within the WinRAR UI caused the application to extract and execute the payload from the sibling directory instead of the PDF:
        
    - **Executed Malicious Binary:** **ApbxHelper.exe**
        
    - **Disk Creation Timestamp ($Created0x10):** **2025-09-02 08:14:18 UTC**.
        
    - **Full Disk Path:** C:\Users\Susan\AppData\Local\Temp\ApbxHelper.exe (staged in Temp prior to execution).
        

Simultaneously with exploit execution (08:14:18 UTC), the malicious process placed a shortcut file into the user's autostart directory:

- **Persistence Artifact:** **Display Settings.lnk**
    
- **Creation Timestamp ($Created0x10):** **2025-09-02 08:14:18 UTC**.
    
- **Deployment Path:** C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk
    
- **Target Path:** Points directly to ApbxHelper.exe to maintain persistence across user logons.
    

To avoid user suspicion, the malware initiated the display of the benign decoy PDF:

- **Decoy File:** Genotyping_Results_B57_Positive.pdf
    
- **User Display Timestamp:** **2025-09-02 08:15:05 UTC**.
    
- Forensic Assessment: The user observed the PDF document at 08:15:05 UTC, believing the file opened normally, while the backdoor had been planted and established persistence 47 seconds prior (08:14:18 UTC).

``` bash
# Comandos utilizados para montar la imagen de disco y parsear el $MFT
sudo guestmount -a 2025-09-02T083211_pathology_department_incidentalert.vhdx -m /dev/sda1 --ro /mnt/vhdx
dotnet MFTECmd.dll -f /mnt/vhdx/C/\$MFT --json output_mft
cat output_mft/*.json | jq '.[] | select(.FileName | contains("ApbxHelper") or contains("Display Settings")) | 
{
  FileName: .FileName,
  ParentPath: .ParentPath,
  Created0x10: .Created0x10,
  Created0x30: .Created0x30
}'
```

#### 4. Detection Rules and Security Engineering

``` Yaml
title: Creacion de Acceso Directo Anomalo en Carpeta Startup
id: 8b7d9214-e21a-4c28-9811-startuplnkpersistence
status: production
description: Detecta la creacion de archivos .lnk dentro de la carpeta Startup por procesos no estandar (como descompresores o carpetas temporales).
references:
  - https://attack.mitre.org/techniques/T1547/009/
author: Senior DFIR Specialist
date: 2025-09-03
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 11
    TargetFilename|contains: '\Start Menu\Programs\Startup\'
    TargetFilename|endswith: '.lnk'
  filter_installers:
    Image|startswith: 'C:\Windows\System32\'
  condition: selection and not filter_installers
level: high
tags:
  - attack.persistence
  - attack.t1547.009
```

``` SPL
index=sysmon EventCode=1 ParentImage="*\\winrar.exe"
| where NOT match(Image, "(?i)\\AppData\\\\Local\\\\Temp\\\\.*\.pdf$")
| table _time, Computer, User, ParentImage, Image, CommandLine
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Endpoint Isolation:** Disconnect Susan's workstation from the clinical hospital VLAN.
    
2. **Persistence Eradication:** Remove Display Settings.lnk from the Startup folder and delete the ApbxHelper.exe executable.
    
3. **Mandatory Software Updates:** Update all WinRAR installations to patched versions (version >= 6.23) that resolve extension spoofing and directory traversal execution flaws.
    
4. **Execution Prevention from Temp:** Deploy WDAC or AppLocker policies preventing the execution of binary executables directly from AppData\Local\Temp\*.