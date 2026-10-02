### [HTB-SMOKEMIRRORS: WINDOWS DEFENSE EVASION & SECURITY CONTROLS TAMPERING]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Windows 10 Endpoint / Sysmon & PowerShell Event Log Forensics / HTB Sherlock  
**Objetivo:** Estación de trabajo comprometida / Manipulación de Controles de Seguridad (Dr. Reyes Investigation)

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó una intrusión sigilosa en la que el adversario desplegó una sofisticada cadena de evasión de defensas (Defense Evasion) para neutralizar las capacidades de detección del endpoint antes de ejecutar sus actividades principales. El análisis de los registros de Microsoft-Windows-Powershell-Operational.evtx y Microsoft-Windows-Sysmon-Operational.evtx demostró que el atacante deshabilitó la protección LSA en el Registro de Windows, apagó de forma integral los motores de protección de Windows Defender mediante cmdlets de administración, parcheó la función de la API de memoria de AMSI (AmsiScanBuffer), configuró el arranque del sistema en Modo Seguro con soporte de red mediante bcdedit para evitar la carga de controladores de seguridad y deshabilitó el registro del historial de comandos de PowerShell (SaveNothing).
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Microsoft-Windows-Powershell-Operational.evtx: Registros de Script Block Logging (Event ID 4104).
        
    - Microsoft-Windows-Sysmon-Operational.evtx: Monitorización de creación de procesos (Event ID 1) y modificación de claves del Registro (Event IDs 12 y 13).
        
    - Herramientas de extracción: Chainsaw y consultas jq.
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Defense Evasion**|T1562.001|Impair Defenses: Disable or Modify Tools|Desactivación de Windows Defender mediante Set-MpPreference y mitigación de LSA.|
|**Defense Evasion**|T1562.001|Impair Defenses: AMSI Bypass|Parcheo en memoria de la función AmsiScanBuffer en amsi.dll.|
|**Defense Evasion**|T1562.009|Impair Defenses: Safe Mode Boot|Modificación del BCD con bcdedit.exe /set safeboot network.|
|**Defense Evasion**|T1070.004|Indicator Removal: File Deletion / History|Supresión del historial de comandos mediante Set-PSReadLineOption -HistorySaveStyle SaveNothing.|

#### 3. Cadena de Infección y Análisis Forense Detallado

El atacante modificó la configuración de Local Security Authority (LSA) para permitir la lectura de memoria de lsass.exe por procesos no protegidos:

- **Ruta Completa de la Clave de Registro:**  
    **HKLM\System\CurrentControlSet\Control\Lsa**
    
- Valores manipulados observados: RunAsPPL, RunAsPPLBoot, LsaCfgFlagsDefault.
    

En el registro de PowerShell Operational (Event ID 4104), se identificó la ejecución del comando que desactivó la totalidad de los subsistemas de protección en tiempo real:

- **Comando Exacto Ejecutado:**  
    **Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true**
    
- Impacto: Neutralización simultánea de la monitorización heurística, análisis de scripts, inspección de descargas (IOAV) y sistema de prevención de intrusiones (IPS).
    

El adversario cargó un bloque de código C# compilado en memoria mediante reflexión en PowerShell para interceptar y cegar el Antimalware Scan Interface:

- **Fragmento de Código Localizado:**
    
    
    
    ``` C#
    IntPtr a = GetProcAddress(h, "A" + "m" + "s" + "i" + "S" + "c" + "a" + "n" + "B" + "u" + "f" + "f" + "e" + "r");
    ```
    
- **Función en la DLL Parcheada:** **AmsiScanBuffer** (dentro de amsi.dll). Al sobrescribir los primeros bytes de esta función con una instrucción de retorno (RET o código de error AMSI_RESULT_CLEAN), cualquier script malicioso posterior es procesado sin ser analizado por el antivirus.
    

Para preparar un entorno con controladores EDR deshabilitados, el atacante alteró los datos de arranque del sistema:

- **Comando Ejecutado:** **bcdedit.exe /set safeboot network**
    
- Propósito Táctico: Forzar al sistema operativo a iniciar en Modo Seguro con funciones de red habilitadas, un entorno donde la mayoría de los servicios EDR y agentes antivirus de terceros no se cargan por directiva de kernel.
    

Para evitar que sus comandos posteriores quedaran grabados en el archivo %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt:

- **Comando Ejecutado:** **Set-PSReadLineOption -HistorySaveStyle SaveNothing**
    


``` bash
# Extracción en Chainsaw de los comandos de evasión en Event ID 4104
cat powershell_operational | jq -r '.[] | select(.Event.System.EventID == 4104) | .Event.EventData.ScriptBlockText'
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yaml
title: Modificacion Maliciosa de Windows Defender via Set-MpPreference
id: 4a2109bc-7e81-4221-b118-disabledefenderprefs
status: production
description: Detecta intentos de deshabilitar la monitorizacion en tiempo real o el escaneo de comportamiento mediante Set-MpPreference.
references:
  - https://attack.mitre.org/techniques/T1562/001/
author: Senior DFIR Specialist
date: 2025-12-27
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains|all:
      - 'Set-MpPreference'
    ScriptBlockText|contains|any:
      - '-DisableRealtimeMonitoring $true'
      - '-DisableBehaviorMonitoring $true'
      - '-DisableScriptScanning $true'
  condition: selection
level: critical
tags:
  - attack.defense_evasion
  - attack.t1562.001
```


``` SPL
index=sysmon EventCode=1 Image="*\\bcdedit.exe" CommandLine="*safeboot*"
| table _time, Computer, User, Image, CommandLine, ParentImage
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Reversión del Estado de Arranque:**
    
    
    ``` cmd
    bcdedit /deletevalue safeboot
    ```
    
2. **Reactivación Forzada de Defender:**
    
    
    ``` Powershell
    Set-MpPreference -DisableRealtimeMonitoring $false -DisableScriptScanning $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableIntrusionPreventionSystem $false
    ```
    
3. **Aislamiento de Red:** Aislar el host para evitar que complete la fase de exfiltración o despliegue de ransomware.
    

4. **Habilitación de Tamper Protection (Protección Contra Alteraciones):** Activar la directiva de Tamper Protection en Microsoft Defender para bloquear que administradores locales o scripts modifiquen Set-MpPreference a través del registro o PowerShell.
    
5. **Bloqueo de Modificación de BCD:** Restringir el acceso al binario bcdedit.exe mediante directivas de control de aplicaciones (WDAC).
    
6. **Habilitación Obligatoria de LSA Protection (RunAsPPL):** Configurar por GPO el flag RunAsPPL=dword:00000001 junto con el bloqueo por UEFI de variables seguras para impedir que lsass.exe sea degradado.