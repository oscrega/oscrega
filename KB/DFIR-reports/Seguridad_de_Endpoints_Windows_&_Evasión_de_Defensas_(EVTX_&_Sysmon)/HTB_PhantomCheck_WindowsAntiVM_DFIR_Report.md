### [HTB-PHANTOMCHECK: WINDOWS DEFENSE EVASION & ANTI-VM ANALYSIS]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Windows 10 Endpoint / PowerShell Event Log Forensics / HTB Sherlock  
**Objetivo:** Scripting Engine de PowerShell / Evaluación de Evasión Anti-Análisis

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigaron los registros de auditoría de PowerShell para evaluar los controles de evasión de defensas desplegados por un actor de amenaza con el objetivo de evitar su análisis en entornos de sandbox o máquinas virtuales. El análisis forense de los registros operativos (Windows-Powershell-Operational.evtx) y de motor (Microsoft-Windows-Powershell.evtx) reveló la carga y ejecución de un script de evaluación ambiental estructurado bajo la función **Check-VM**. El adversario ejecutó consultas exhaustivas contra el repositorio WMI, inspeccionó claves del Registro de Windows vinculadas a controladores de virtualización y enumeró procesos específicos de hipervisores para identificar plataformas **VMware**, **Hyper-V**, **VirtualBox** y **Xen**.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Windows-Powershell-Operational.evtx: Registros de Script Block Logging (Event ID 4104) e invocación de comandos (Event IDs 4103, 4105, 4106).
        
    - Microsoft-Windows-Powershell.evtx: Ciclo de vida del motor (Event IDs 400, 600, 800).
        
    - Herramientas de extracción: Chainsaw y jq para normalización y parseo de bloques de script.
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Defense Evasion / Discovery**|T1497.001|Virtualization/Sandbox Evasion: System Checks|Comprobaciones sistemáticas de fabricante, hardware y servicios para detectar ejecución en entornos virtualizados.|
|**Execution**|T1059.001|Command and Scripting Interpreter: PowerShell|Ejecución de la función de triaje Check-VM en memoria (Event ID 4104).|
|**Discovery**|T1047|Windows Management Instrumentation|Consultas WMI sobre Win32_ComputerSystem y sensores térmicos de la placa base.|
|**Discovery**|T1012|Query Registry|Búsqueda de claves de servicio de hipervisores bajo HKLM:\SYSTEM\ControlSet001\Services.|
|**Discovery**|T1057|Process Discovery|Comprobación de procesos de guest additions (vboxservice.exe, vboxtray.exe).|

#### 3. Cadena de Infección y Análisis Forense Detallado

El análisis del Event ID 4104 demostró la ejecución de comandos WMI dirigidos a perfilar el hardware subyacente:

1. **Identificación de Fabricante y Modelo:**
    
    - **Clase WMI Consultada:** **Win32_ComputerSystem**
        
    - Finalidad: Extraer los valores de los atributos Manufacturer y Model (donde hipervisores suelen delatar cadenas como "VMware, Inc.", "VirtualBox" o "KVM").
        
2. **Comprobación de Sensores de Temperatura:**
    
    - **Consulta WMI Ejecutada:**  
        **SELECT * FROM MSAcpi_ThermalZoneTemperature**
        
    - Finalidad: Los hipervisores y sandboxes estándar rara vez emulan los sensores térmicos de la arquitectura ACPI de placas base físicas. Si la consulta devuelve nulo o genera error, el script infiere que se encuentra en un entorno virtual.
        

- **Nombre de la Función:** **Check-VM**
    
- **Inspección de Servicios en el Registro:**  
    Para identificar la presencia de hipervisores VirtualBox o Xen, el script consultó la siguiente clave del registro de Windows:
    
    - **Clave del Registro:** **HKLM:\SYSTEM\ControlSet001\Services**
        
    - Variables de asignación analizadas: $vb (servicios de VirtualBox como VBoxService, VBoxGuest) y $xen (servicios de Xen como xenevtchn).
        
- **Enumeración de Procesos de VirtualBox:**  
    Mediante el cmdlet Get-Process, el script buscó de forma explícita los siguientes ejecutables correspondientes a las utilidades de integración de VirtualBox:
    
    - **Procesos:** **vboxservice.exe, vboxtray.exe**
        
- **Plataformas de Virtualización Detectadas en la Ejecución:**  
    El script contenía una rutina de impresión por consola formateada con el prefijo 'This is a'. La evaluación de las salidas registradas en los bloques de ejecución certificó la detección positiva de dos tecnologías:
    
    - **Hipervisores Detectados:** **Hyper-V, vmware**
        


``` bash
# Extracción de bloques de código de detección en Chainsaw
cat powershell_operational | jq -r '.[] | select(.Event.System.EventID == 4104) | 
.Event.EventData.ScriptBlockText | select(contains("Check-VM") or contains("ThermalZone"))'
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


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

#### 5. Plan de Contención, Erradicación y Hardening

1. **Contención del Proceso Host:** Identificar el proceso padre que instanció la sesión de PowerShell que ejecutó Check-VM y proceder a su suspensión y volcado de memoria.
    
2. **Revisión de Alertas Precedentes:** Dado que las comprobaciones Anti-VM constituyen la fase previa a la ejecución del payload final, analizar la actividad de red en los 5 minutos inmediatamente anteriores y posteriores a la ejecución del script.
    

3. **Habilitación Obligatoria de PowerShell Constrained Language Mode (CLM):**
    
    - Forzar CLM para todos los usuarios no administradores mediante variables de entorno del sistema (__PSLockdownPolicy = 4) o acoplado a AppLocker/WDAC.
        
4. **Restricción de WMI:** Restringir mediante políticas de seguridad los permisos de lectura sobre namespaces sensibles de WMI (root\wmi) para cuentas estándar.
    
5. **Hardening de Sandboxes de Análisis:** Configurar los entornos sandbox corporativos para emular de forma transparente las características de hardware de equipos físicos (poblado de tablas SMBIOS, emulación ACPI térmica y eliminación de nombres genéricos en adaptadores de red y controladores).