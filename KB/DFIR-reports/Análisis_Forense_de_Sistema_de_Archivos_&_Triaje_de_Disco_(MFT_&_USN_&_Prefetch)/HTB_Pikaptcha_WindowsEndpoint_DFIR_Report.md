
**Classification:** TLP:AMBER  
**Environment / Platform:** Windows 10 Endpoint / PowerShell Event Log Forensics / HTB Sherlock  
**Target:** PowerShell Scripting Engine / Evasion and Anti-Analysis Assessment  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** PowerShell audit logs were investigated to assess defense evasion techniques deployed by a threat actor seeking to identify analysis environments or sandboxes. Analysis of operational (Windows-Powershell-Operational.evtx) and engine (Microsoft-Windows-Powershell.evtx) logs revealed the staging and execution of an environmental enumeration script structured around function **Check-VM**. The adversary performed WMI queries, queried Windows Registry keys associated with virtualization drivers, and enumerated hypervisor-specific processes to identify **VMware**, **Hyper-V**, **VirtualBox**, and **Xen** platforms.
    
- **Telemetry Sources and Evidence:**
    
    - Windows-Powershell-Operational.evtx: Script Block Logging records (Event ID 4104) and command execution events (Event IDs 4103, 4105, 4106).
        
    - Microsoft-Windows-Powershell.evtx: PowerShell engine lifecycle events (Event IDs 400, 600, 800).
        
    - Extraction tools: Chainsaw and jq for script block parsing and normalization.
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Defense Evasion / Discovery** | T1497.001 | Virtualization/Sandbox Evasion: System Checks | Systematic validation of manufacturer strings, hardware attributes, and drivers to detect virtualized systems. |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell | In-memory execution of the Check-VM function (Event ID 4104). |
| **Discovery** | T1047 | Windows Management Instrumentation | WMI queries targeting Win32_ComputerSystem and motherboard ACPI thermal zone sensors. |
| **Discovery** | T1012 | Query Registry | Enumeration of hypervisor service keys under HKLM:\SYSTEM\ControlSet001\Services. |
| **Discovery** | T1057 | Process Discovery | Process enumeration checking for guest additions (vboxservice.exe, vboxtray.exe). |

#### 3. Infection Chain and Detailed Forensic Analysis

Event ID 4104 demonstrated the execution of WMI queries designed to profile the underlying hardware:

1. **Hardware and System Identification:**
    
    - **Target WMI Class:** **Win32_ComputerSystem**
        
    - Objective: Extract the Manufacturer and Model properties (which typically identify strings such as "VMware, Inc.", "VirtualBox", or "KVM").
        
2. **Thermal Sensor Verification:**
    
    - **Executed WMI Query:**  
        **SELECT * FROM MSAcpi_ThermalZoneTemperature**
        
    - Objective: Standard virtual machines and sandboxes rarely emulate physical motherboard ACPI thermal sensors. If the query returns null or generates an error, the script determines it is running within a virtual environment.
        

- **Script Function Name:** **Check-VM**
    
- **Registry Service Inspection:**  
    To verify whether VirtualBox or Xen hypervisors were present, the script inspected the following registry key:
    
    - **Registry Key:** **HKLM:\SYSTEM\ControlSet001\Services**
        
    - Analyzed variables: $vb (checking for VirtualBox services such as VBoxService, VBoxGuest) and $xen (checking for Xen services such as xenevtchn).
        
- **VirtualBox Process Enumeration:**  
    Using Get-Process, the script queried for running instances of VirtualBox guest integration executables:
    
    - **Target Processes:** **vboxservice.exe, vboxtray.exe**
        
- **Virtualization Platforms Identified During Execution:**  
    The script contained console print routines prefixed with 'This is a'. Reviewing the logged output strings confirmed positive detections for two technologies:
    
    - **Detected Platforms:** **Hyper-V, vmware**

``` bash
# Extracción de bloques de código de detección en Chainsaw
cat powershell_operational | jq -r '.[] | select(.Event.System.EventID == 4104) | 
.Event.EventData.ScriptBlockText | select(contains("Check-VM") or contains("ThermalZone"))'
```

#### 4. Detection Rules and Security Engineering

``` Yaml
title: Deteccion de Comprobaciones Anti-Virtualizacion en PowerShell
id: f98a2134-c711-4eb2-8911-powershellantivm
status: production
description: Identifica bloques de script de PowerShell que consultan clases WMI y registros especificos utilizados para evadir entornos de analisis y sandboxes.
references:
  - https://attack.mitre.org/techniques/T1497/001/
author: Senior DFIR Specialist
date: 2025-12-26
logsource:
  product: windows
  service: powershell
detection:
  selection_wmi:
    EventID: 4104
    ScriptBlockText|contains|all:
      - 'MSAcpi_ThermalZoneTemperature'
      - 'Win32_ComputerSystem'
  selection_services:
    EventID: 4104
    ScriptBlockText|contains|all:
      - 'ControlSet001\Services'
      - 'vboxservice'
  condition: selection_wmi or selection_services
level: high
tags:
  - attack.defense_evasion
  - attack.t1497.001
```

``` SPL
index=wineventlog EventCode=4104 ScriptBlockText="*MSAcpi_ThermalZoneTemperature*" OR ScriptBlockText="*vboxservice*"
| table _time, Computer, User, ScriptBlockId, ScriptBlockText
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Process Suspension:** Identify and suspend the parent process that spawned the PowerShell session running Check-VM and capture a process memory dump.
    
2. **Telemetry Scoping:** Because anti-VM checks typically precede payload delivery, review network and execution logs 5 minutes prior to and following script execution.
    
3. **Enforce PowerShell Constrained Language Mode (CLM):**
    
    - Enforce CLM for non-administrative accounts using system environment variables (__PSLockdownPolicy = 4) or via AppLocker/WDAC.
        
4. **WMI Access Restrictions:** Restrict access permissions on sensitive WMI namespaces (such as root\wmi) for standard user accounts.
    
5. **Sandbox Hardening:** Configure analysis sandboxes to emulate physical hardware attributes (populating SMBIOS tables, providing ACPI thermal responses, and renaming default hypervisor network and driver strings).