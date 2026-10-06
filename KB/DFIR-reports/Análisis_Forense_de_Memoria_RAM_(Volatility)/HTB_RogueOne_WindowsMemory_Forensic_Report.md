**Classification:** TLP:AMBER  
**Environment / Platform:** Windows 10 (Build 19041 / 20H1) / Volatility 3 / HTB Sherlock  
**Target:** Simón Stark Workstation (172.17.79.131)  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** An active intrusion on Simón Stark's workstation was investigated following repeated SIEM alerts signaling Command and Control (C2) network activity. Initial Task Manager inspections failed to identify anomalous activity because the malware was masquerading under the name of a core Windows process (svchost.exe). Physical memory analysis (20230810.mem) utilizing Volatility 3 revealed that the malicious process was executing from the user's Downloads directory (PID 6812), maintaining an interactive reverse shell connected to a remote AWS infrastructure server (13.127.155.166:8888). The binary was identified as the **Rozena** trojan, frequently associated with Metasploit operations.
    
- **Telemetry Sources and Evidence:**
    
    - RAM memory dump: 20230810.mem (Windows 10 x64, version 15.19041).
        
    - Triage tool: Volatility 3 Framework v2.28.0.
        
    - Executed plugins: windows.info, windows.pslist, windows.cmdline, windows.cmdscan, windows.dumpfiles, windows.netscan.
        
    - External threat intelligence: VirusTotal API correlation.
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Defense Evasion** | T1036.005 | Masquerading: Match Legitimate Name | Execution of svchost.exe from the anomalous path C:\Users\simon.stark\Downloads\svchost.exe. |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols / TCP Shell | Persistent C2 connection established with 13.127.155.166:8888. |
| **Execution** | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | The malware spawned a cmd.exe child process (PID 4364) to provide interactive remote shell access. |

#### 3. Infection Chain and Detailed Forensic Analysis

Command-line inspection (windows.cmdline) combined with process listing (windows.pslist) identified a process bearing a native binary name running from an anomalous path:

- **Malicious Process:** svchost.exe
    
- **Full Path:** **C:\Users\simon.stark\Downloads\svchost.exe**
    
- **Process ID (PID):** **6812**
    
- **Parent Process ID (PPID):** 7436 (explorer.exe, demonstrating interactive execution by the user).
    
- **Physical Memory Offset:** **0x9e8b87762080**.
    

The malicious process spawned a command interpreter as a remote control mechanism:

- **Child Process:** cmd.exe
    
- **Child Process PID:** **4364** (PPID 6812).
    
- **Creation Timestamp:** 2023-08-10 11:30:57.000000 UTC.
    
- Associated subprocess: conhost.exe (PID 9204, PPID 4364).
    

Inspection of active network sockets using windows.netscan filtered by PID 6812 exposed the communication channel:

- **Protocol:** TCPv4
    
- **Source IP (Victim):** 172.17.79.131 (Port 64254)
    
- **C2 Destination IP and Port (Attacker):** **13.127.155.166:8888**
    
- **Connection State:** ESTABLISHED
    
- **Execution and C2 Establishment Timestamp:** **2023-08-10 11:30:03 UTC** (10/08/2023 11:30:03).
    

The executable was dumped from memory via windows.dumpfiles --pid 6812, producing the ImageSectionObject file:

- **MD5 Hash:** **5bd547c6f5bfc4858fe62c8867acfbb5**
    
- **SHA-256 Hash:** **eaf09578d6eca82501aa2b3fcef473c3795ea365a9b33a252e5dc712c62981ea**
    
- **Malware Family:** **Rozena** Trojan.
    
- **First VirusTotal Submission:** Identified in VirusTotal historical telemetry as first submitted on **10/08/2023 11:58:10 UTC**.

``` bash
# Comandos de Volatility 3 para aislar el proceso y conexiones
vol3 -f 20230810.mem windows.pslist | grep 6812
vol3 -f 20230810.mem windows.netscan | grep 6812
vol3 -f 20230810.mem -o ./dumps windows.dumpfiles --pid 6812
md5sum dumps/file.0x9e8b91ec0140.0x9e8b957f24c0.ImageSectionObject.svchost.exe.img
```

#### 4. Detection Rules and Security Engineering

``` Yaml
title: Proceso Svchost.exe Ejecutado Fuera de System32
id: 3c91f092-4112-4eb1-b219-svchostabnormalpath
status: production
description: Detecta la ejecucion de svchost.exe en directorios de usuario o temporales, indicador critico de suplantacion de procesos.
references:
  - https://attack.mitre.org/techniques/T1036/005/
author: Senior DFIR Specialist
date: 2023-08-11
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    NewProcessName|endswith: '\svchost.exe'
  filter_legit:
    NewProcessName|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
  condition: selection and not filter_legit
level: critical
tags:
  - attack.defense_evasion
  - attack.t1036.005
```

``` SPL
index=sysmon EventCode=3 Image="*\\svchost.exe"
| where NOT (DestinationPort IN (80, 443, 53, 88, 389, 636, 3268, 3269))
| where NOT (match(Image, "(?i)^C:\\\\Windows\\\\System32\\\\svchost\.exe$") OR match(Image, "(?i)^C:\\\\Windows\\\\SysWOW64\\\\svchost\.exe$"))
| table _time, Computer, User, Image, DestinationIp, DestinationPort
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Process Termination:** Terminate processes PID 6812 and PID 4364 immediately.
    
2. **EDR Network Containment:** Isolate workstation 172.17.79.131 from outbound communications.
    
3. **Perimeter Blocking:** Implement bidirectional firewall drop rules for IP 13.127.155.166 and port 8888.
    
4. **Attack Surface Reduction (ASR) Rules:**
    
    - Enable the ASR rule: "Block executable files from running unless they meet a prevalence, age, or trusted list criterion."
        
    - Enable the rule: "Block process creations originating from PSExec and WMI commands."
        
5. **AppLocker Execution Restrictions:** Enforce an AppLocker policy preventing execution of binary files (.exe, .dll) from C:\Users\*\Downloads\*.