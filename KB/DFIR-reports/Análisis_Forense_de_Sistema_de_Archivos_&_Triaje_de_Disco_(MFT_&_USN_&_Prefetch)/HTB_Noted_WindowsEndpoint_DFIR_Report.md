**Classification:** TLP:AMBER  
**Environment / Platform:** Windows 10 Endpoint / Notepad++ Artifact Analysis / HTB Sherlock  
**Target:** Simón Stark Workstation (Simon.stark)  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** A source code exfiltration and extortion incident affecting a software engineer's workstation (Simon.stark) was investigated. The threat actor obtained local system access and, exploiting the installed development environment, modified a Java source file (LootAndPurge.java) located on the user's Desktop using the native Notepad++ editor. This script collected sensitive files, compressed them into a password-protected ZIP archive (Forela-Dev-Data.zip), and the attacker subsequently left a ransom note threatening to release Forela's intellectual property on the dark web unless an Ethereum ransom was paid.
    
- **Telemetry Sources and Evidence:**
    
    - Local Notepad++ artifacts under C:\Users\Simon.stark\AppData\Roaming\Notepad++\:
        
        - config.xml (Recent file access history and application settings).
            
        - session.xml (Active session metadata, backup pointers, and FILETIMEs).
            
        - backup\ directory containing shadow copies of modified files: LootAndPurge.java@2023-07-24_145332 and YOU HAVE BEEN HACKED.txt@2023-07-24_150548.
            

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Collection** | T1005 | Data from Local System | Script LootAndPurge.java designed to traverse the Desktop directory and harvest target extensions (docx, pdf, zip, etc.). |
| **Collection** | T1560.001 | Archive Collected Data: Archive via Utility | Password-protected compression of sensitive files into Forela-Dev-Data.zip. |
| **Impact** | T1486 | Data Encrypted for Impact / Extortion | Deployment of extortion note YOU HAVE BEEN HACKED.txt demanding Ethereum payment. |
| **Discovery** | T1083 | File and Directory Discovery | config.xml history demonstrating discovery and opening of internal AWS management scripts. |

#### 3. Infection Chain and Detailed Forensic Analysis

1. **Reconnaissance of Sensitive Scripts:**  
    Within the `<History>` node of config.xml, evidence was identified confirming the inspection of an internal automation script:
    
    - **Full Path:** **C:\Users\Simon.stark\Documents\Dev_Ops\AWS_objects migration.pl**
        
2. **Identification of Active Session Documents:**  
    The session.xml file recorded the last two open files being edited:
    
    - Document 1: C:\Users\Simon.stark\Desktop\LootAndPurge.java
        
    - Document 2: C:\Users\Simon.stark\Desktop\YOU HAVE BEEN HACKED.txt
        

Analysis of the artifact recovered from the backup\ folder (LootAndPurge.java@...) exposed the collection logic:

- **Target Directory:** Current user's Desktop path (C:\Users\<username>\Desktop\).
    
- **Target File Extensions:** zip, docx, ppt, xls, md, txt, pdf.
    
- **Output Archive File:** **Forela-Dev-Data.zip**.
    
- **Archive Password:** **sdklY57BLghvyh5FJ#fion_7**.
    

In session.xml, the file modification attributes of LootAndPurge.java were stored as signed 32-bit integers representing the low and high DWORDs of a 64-bit Windows FILETIME:

- originalFileLastModifTimestamp (Low DWORD): -1354503710
    
- originalFileLastModifTimestampHigh (High DWORD): 31047188
    
- **Python Reconstruction Logic:**  
    
    ```
    (31047188≪32)+(−1354503710 & 0xFFFFFFFF)=133346468030000000 100-nanosecond intervals since 01/01/1601.
    ```
    
- **Calculated UTC Timestamp:** **2023-07-24 09:53:23 UTC**.
    

The ransom file YOU HAVE BEEN HACKED.txt contained links to password-protected Pastebin and Pastecode posts. Using the password recovered from the Java script (sdklY57BLghvyh5FJ#fion_7), the contents were accessed:

- **Ethereum Wallet Address:** **0xca8fa8f0b631ecdb18cda619c4fc9d197c8affca**
    
- **Threat Actor Contact:** **CyberJunkie@mail2torjgmxgexntbrmhvgluavhj7ouul5yar6ylbvjkxwqf6ixkwyd.onion**

``` Python
# Script pericial de conversión FILETIME a formato legible UTC
import datetime
low = -1354503710
high = 31047188
low_unsigned = low & 0xFFFFFFFF
filetime = (high << 32) + low_unsigned
timestamp = filetime / 10000000
epoch = datetime.datetime(1601, 1, 1)
print("Fecha UTC:", epoch + datetime.timedelta(seconds=timestamp))
```

#### 4. Detection Rules and Security Engineering

``` Yara
rule Suspicious_Java_Data_Harvester {
    meta:
        description = "Detecta scripts Java diseñados para empaquetar y cifrar archivos de usuario"
        author = "Senior DFIR Specialist"
        date = "2026-10-02"
    strings:
        $s1 = "ZipOutputStream" ascii
        $s2 = "Forela-Dev-Data.zip" ascii wide
        $s3 = "sdklY57BLghvyh5FJ#fion_7" ascii wide
        $ext = "Arrays.asList(\"zip\", \"docx\", \"ppt\", \"xls\"" ascii
    condition:
        all of ($s*) or ($s1 and $ext)
}
```

``` SPL
index=sysmon EventCode=11 TargetFilename="*\\Desktop\\*.zip"
| where match(Image, "(?i)(java\.exe|javaw\.exe|powershell\.exe|cmd\.exe)$")
| table _time, Computer, User, Image, TargetFilename
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Account Lockout and Rotation:** Immediately disable Simon.stark's Active Directory account and force credential rotations across all code repositories and cloud portals (Git, AWS, Jira).
    
2. **Container Recovery and Scoping:** Locate and preserve Forela-Dev-Data.zip on the host. Utilizing the recovered password (sdklY57BLghvyh5FJ#fion_7), unpack the container in a secure environment to perform a comprehensive data exposure assessment.
    
3. **Endpoint Compiler Control:** Remove software compilation tools (javac, C# build utilities) from general-purpose workstations, restricting them strictly to segregated development environments or VDI instances.
    
4. **Data Loss Prevention (DLP):** Deploy endpoint DLP policies alerting on or blocking batch archiving of sensitive files (.docx, .pdf, .xls) into password-protected archives.