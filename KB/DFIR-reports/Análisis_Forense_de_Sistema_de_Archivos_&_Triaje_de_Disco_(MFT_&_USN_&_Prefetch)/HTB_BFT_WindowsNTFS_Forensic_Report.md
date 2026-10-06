**Classification:** TLP:AMBER  
**Environment / Platform:** Windows NTFS Filesystem / Eric Zimmerman Tools / HTB Sherlock  
**Target:** Drive C:\ of Simón Stark / Analysis of Artifact $MFT  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** A digital forensic analysis of the NTFS Master File Table ($MFT) was conducted on a workstation compromised on February 13, 2024. The incident began with a phishing email delivering a link to an archive file hosted on Google Cloud Storage. The user downloaded the archive, which led to the extraction of a chain of artifacts culminating in a malicious batch file (invoice.bat). Low-level analysis demonstrated that the script operated as a resident file inside the $MFT record itself, designed to establish a C2 reverse shell connection to 43.204.110.203:6666.
    
- **Telemetry Sources and Evidence:**
    
    - Volume C: $MFT record file.
        
    - Parsing tool: MFTECmd.exe v1.3.0.0 (Eric Zimmerman) focusing on attributes $FILE_NAME (0x30), $DATA (0x80), and Zone.Identifier (Mark of the Web - MotW) streams.
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Initial Access** | T1566.002 | Phishing: Spearphishing Link | Download of Stage-20240213T093324Z-001.zip via a malicious URL pointing to Google Cloud Storage. |
| **Defense Evasion** | T1553.005 | Subvert Trust Controls: Mark of the Web Bypass | Nested archive extraction used to break the inheritance of the Zone.Identifier Alternate Data Stream. |
| **Execution** | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Execution of stager batch script invoice.bat. |
| **Command and Control** | T1071 | Application Layer Protocol | Outbound connection configured toward 43.204.110.203:6666. |

#### 3. Infection Chain and Detailed Forensic Analysis

$MFT records confirmed the initial download by user Simón Stark:

- **Downloaded ZIP Archive Name:** **Stage-20240213T093324Z-001.zip**.
    
- **Zone Identifier Analysis (MotW):**  
    Parsing the Alternate Data Stream (:Zone.Identifier) recovered the origin HostUrl:
    
    - **Target URL:**  
        **https://storage.googleapis.com/drive-bulk-export-anonymous/20240213T093324.039Z/4133399871716478688/a40aecd0-1cf3-4f88-b55a-e188d5c1c04f/1/c277a8b4-afa9-4d34-b8ca-e1eb5e5f983c?authuser**
        

File system timestamps revealed the nested unpacking chain:

1. Decompression of Stage-20240213T093324Z-001.zip -> Extracted invoices.zip and .lnk shortcuts.
    
2. Decompression of invoices.zip -> Dropped final payload.
    

- **Malicious File Location:**  
    **C:\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\Stage\invoice\invoices\invoice.bat**
    
- **Creation Timestamp ($Created0x30 / $FILE_NAME):**  
    **2024-02-13 16:38:39 UTC**.
    

- **MFT Entry Number:** **23436** (Sequence 0x9).
    
- **Hexadecimal Offset in $MFT:** **0x16E3000** (calculated by multiplying entry index by the 1024-byte record size:
    
    ``` TEXT
    23436×1024=23998464=0x16E3000
    ```
    
    ).
    
- **Resident Data Attribute Analysis:**  
    Because the size of invoice.bat was smaller than the available space within the MFT record for unnamed $DATA attributes (<700 bytes), the file content was stored directly inside the $MFT record without allocating external disk clusters.
    
- **C2 Configuration Analysis:**  
    Direct hex inspection of the resident attribute revealed the reverse connection parameters:
    
    - **C2 Destination IP and Port:** **43.204.110.203:6666**.

``` bash
# Invocación pericial de MFTECmd para inspeccionar la entrada residente
MFTECmd.exe -f "$MFT" --de 23436
```

#### 4. Detection Rules and Security Engineering

``` Snort
alert tcp any any -> 43.204.110.203 6666 (msg:"ALERTA CTI - Conexion Stager C2 Detectada (Caso BFT)"; flow:to_server,established; sid:1000921; rev:1;)
```

``` SPL
index=sysmon EventCode=1 Image="*\\cmd.exe" CommandLine="*invoice.bat*"
| table _time, Computer, User, ParentImage, CommandLine
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Perimeter IP Block:** Implement firewall blocks for external IP 43.204.110.203 and port 6666.
    
2. **File System Remediation:** Securely delete staging artifacts located under C:\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\.
    
3. **Secure Email Gateway (SEG) Filtering:** Block inbound emails delivering links to anonymous cloud file sharing services (storage.googleapis.com, drive.google.com).
    
4. **Script Execution Hardening:** Configure endpoints to block execution of scripts (.bat, .cmd, .vbs) from user profiles and Downloads folders.