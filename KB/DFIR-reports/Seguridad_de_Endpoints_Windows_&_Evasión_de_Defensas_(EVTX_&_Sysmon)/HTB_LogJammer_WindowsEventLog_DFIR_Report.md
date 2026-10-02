### [HTB-LOGJAMMER: WINDOWS EVENT LOG FORENSICS & POST-EXPLOITATION TRIAGE]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Windows 10 Endpoint / Native EVTX Artifacts / HTB Sherlock  
**Objetivo:** Estación de trabajo DESKTOP-887GK2L (Usuario CyberJunkie)

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se realizó una evaluación forense integral sobre los registros de eventos de Windows para investigar las acciones maliciosas ejecutadas por el usuario CyberJunkie. El análisis multidisciplinar (registros de Security, System, Firewall, Defender y PowerShell) determinó que el usuario inició sesión interactiva, manipuló las políticas de auditoría del sistema para suprimir alertas, modificó las reglas del Firewall de Windows para habilitar una vía de salida a un C2 de **Metasploit**, creó una tarea programada maliciosa (HTB-AUTOMATION) que ejecutó un script en PowerShell (Automation-HTB.ps1), descargó la herramienta de reconocimiento de Active Directory **SharpHound** (la cual fue detectada y puesta en cuarentena por Windows Defender) y finalmente eliminó el registro de eventos del Firewall para encubrir la regla creada.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Security.evtx: Event IDs 4624, 4698, 4719.
        
    - Windows Firewall-Firewall.evtx: Event ID 2004.
        
    - Windows Defender-Operational.evtx: Event ID 1117.
        
    - Powershell-Operational.evtx: Event ID 4104.
        
    - System.evtx: Event ID 104 (Log file cleared).
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Defense Evasion**|T1562.004|Impair Defenses: Disable or Modify System Firewall|Creación de regla de salida permisiva denominada Metasploit C2 Bypass.|
|**Persistence / Execution**|T1053.005|Scheduled Task/Job: Scheduled Task|Creación de la tarea HTB-AUTOMATION apuntando a Automation-HTB.ps1.|
|**Discovery**|T1069.002|Permission Groups Discovery: Domain Groups|Descarga y tentativa de ejecución de la suite SharpHound-v1.1.0.zip.|
|**Defense Evasion**|T1070.001|Indicator Removal: Clear Windows Event Logs|Vaciado selectivo del log del Firewall registrado bajo el Event ID 104 en System.evtx.|

#### 3. Cadena de Infección y Análisis Forense Detallado

1. **Inicio de Sesión Interactivo (Security Event ID 4624):**
    
    - **Timestamp UTC:** **2023-03-27 14:37:09 UTC** (2023-03-27T14:37:09.879891Z).
        
    - Usuario: CyberJunkie (SID S-1-5-21-3393683511-3463148672-371912004-1001, Logon Type 2).
        
2. **Modificación de Reglas del Firewall (Firewall Log Event ID 2004):**
    
    - El atacante abrió la consola de administración mmc.exe (C:\Windows\System32\mmc.exe) y añadió una regla personalizada:
        
    - **Nombre de la Regla:** **Metasploit C2 Bypass**
        
    - **Dirección de la Regla:** **Outbound** (Direction: 2).
        
    - Puerto Remoto Permitido: 4444 (puerto por defecto de listeners de Metasploit/Meterpreter).
        
    - Timestamp de Modificación: 2023-03-27 14:44:43 UTC.
        

A las 14:50:03 UTC, el usuario alteró las políticas de auditoría del sistema operativo:

- **Subcategoría Modificada:** **Other Object Access Events** `(SubcategoryGuid: 0CCE9227-69AE-11D9-BED3-505054503030, SubcategoryId: %%12804)`.
    

A las 14:51:21 UTC, se registró la creación de una tarea persistente en el Programador de Tareas:

- **Nombre de la Tarea:** **HTB-AUTOMATION** (\HTB-AUTOMATION).
    
- **Ruta Completa del Archivo Programado:**  
    **C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1**
    
- **Argumentos de Invocación:**  
    **-A cyberjunkie@hackthebox.eu**
    

1. **Identificación de la Amenaza:**
    
    - A las 14:42:34 UTC, Windows Defender interceptó una descarga maliciosa:
        
    - **Nombre de la Herramienta:** **SharpHound** (HackTool:MSIL/SharpHound!MSR).
        
2. **Ruta Completa del Archivo:**  
    **C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip**
    
3. **Acción Tomada por el Antivirus:** **Quarantine** (Action ID: 2, aplicada con éxito).
    

4. **Comando de PowerShell Ejecutado (Event ID 4104):**
    
    - A las 14:58:33 UTC, el usuario ejecutó un comando interactivo en PowerShell para verificar la integridad del script de automatización:
        
    - **Comando Exacto:** **Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1**
        
5. **Vaciado del Registro de Eventos (System Event ID 104):**
    
    - A las **2023-03-27 15:01:56 UTC**, el atacante borró selectivamente el registro del firewall para ocultar la creación de la regla Metasploit C2 Bypass:
        
    - **Canal de Registro Borrado:**  
        **Microsoft-Windows-Windows Firewall With Advanced Security/Firewall**
        
    - Usuario Responsable: CyberJunkie.
        


``` bash
# Extracción de la regla de firewall y tarea programada en Chainsaw
cat windows_firewall.json | jq '.[] | select(.Event.EventData.RuleName == "Metasploit C2 Bypass")'
cat security.json | jq '.[] | select(.Event.System.EventID == 4698)'
cat system.json | jq '.[] | select(.Event.System.EventID == 104)'
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yaml
title: Creacion de Regla de Firewall con Referencia a Herramientas C2
id: 9a810234-c471-4221-a119-firewallc2bypass
status: production
description: Detecta la creacion de reglas de firewall salientes que referencien puertos o nombres de frameworks ofensivos.
references:
  - https://attack.mitre.org/techniques/T1562/004/
author: Senior DFIR Specialist
date: 2023-03-28
logsource:
  product: windows
  service: firewall
detection:
  selection:
    EventID: 2004
    RuleName|contains|any:
      - 'Metasploit'
      - 'C2'
      - 'Bypass'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.004
```


``` SPL
index=wineventlog EventCode=104 Channel="System"
| table _time, Computer, SubjectUserName, Channel, BackupPath
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Revocación de Reglas del Firewall:** Eliminar de forma inmediata la regla Metasploit C2 Bypass en Windows Defender Firewall.
    
2. **Desmantelamiento de la Tarea Programada:**
    
    ``` CMD
    schtasks /delete /tn "HTB-AUTOMATION" /f
    ```
    
3. **Purga de Archivos en Desktop:** Eliminar el script C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1.
    
4. **Suspensión de Cuenta:** Inhabilitar la cuenta local CyberJunkie hasta completar la auditoría pericial.
    

5. **Centralización de Event Logs (SIEM Forwarding):** Configurar Windows Event Forwarding (WEF) o agentes SIEM (Splunk/Wazuh) para reenviar los registros en tiempo real; de este modo, aunque un atacante local borre los canales locales (Event ID 104 o 1102), la telemetría permanece preservada e inmutable en el repositorio central.
    
6. **Restricción de Creación de Tareas Programadas:** Bloquear la creación de tareas por usuarios no privilegiados mediante directivas de seguridad local y monitorizar ejecuciones que invoquen scripts de PowerShell con argumentos de red.