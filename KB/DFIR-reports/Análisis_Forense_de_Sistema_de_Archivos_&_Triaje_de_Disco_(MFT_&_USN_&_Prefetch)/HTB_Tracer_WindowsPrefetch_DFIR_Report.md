### [HTB-TRACER: PSEXEC LATERAL MOVEMENT & PREFETCH FORENSICS]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Windows 10 Endpoint / Windows Prefetch & USN Journal / HTB Sherlock  
**Objetivo:** Estación de trabajo comprometida / Movimiento Lateral vía PsExec

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó una intrusión en la que un analista del SOC reportó alertas de ejecución de la herramienta de administración remota PsExec de Sysinternals en una estación de trabajo corporativa. El análisis forense de los artefactos de ejecución prefetch (PSEXESVC.EXE-AD70946C.pf), del diario USN de NTFS ($Extend\$J) y de los registros de Sysmon (Microsoft-Windows-Sysmon%4Operational.evtx) permitió reconstruir de forma inequívoca el patrón de movimiento lateral. Se confirmó que el adversario operó desde el host **FORELA-WKSTN001**, ejecutando comandos remotos en 9 ocasiones independientes a través del binario de servicio PSEXESVC.EXE. La correlación temporal aisló la quinta ejecución del servicio, sus archivos de intercambio criptográfico (.KEY) y sus Named Pipes asociados.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Carpeta de Prefetch: C:\Windows\prefetch\PSEXESVC.EXE-AD70946C.pf analizado con PECmd.exe v1.5.1.0.
        
    - Diario de cambios de NTFS: C:\$Extend\$J parseado con MFTECmd.exe.
        
    - Registros operativos de Sysmon: Event ID 17 y 18 (Pipe Created / Pipe Connected).
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Lateral Movement**|T1021.002|Remote Services: SMB/Windows Admin Shares|Instalación y ejecución remota del servicio PSEXESVC.exe a través de los recursos compartidos administrativos ADMIN$.|
|**Execution**|T1569.002|System Services: Service Execution|Ejecución interactiva de comandos bajo el contexto de NT AUTHORITY\SYSTEM mediante el servicio de PsExec.|
|**Command and Control**|T1570|Lateral Tool Transfer|Transferencia y materialización de archivos clave (.KEY) en C:\Windows\.|

#### 3. Cadena de Infección y Análisis Forense Detallado

El procesado del archivo .pf mediante PECmd confirmó el uso continuado de la herramienta:

- **Binario del Servicio Desplegado:** **PSEXESVC.EXE** (Servicio temporal instanciado por PsExec en el host destino).
    
- **Contador Total de Ejecuciones (Run Count):** **9 ejecuciones**.
    
- **Historial Completo de Ejecuciones (UTC):**
    
    1. 2023-09-07 12:10:03 (Última ejecución)
        
    2. 2023-09-07 12:09:09
        
    3. 2023-09-07 12:08:54
        
    4. 2023-09-07 12:08:23
        
    5. **2023-09-07 12:06:54** (Quinta ejecución más reciente / foco pericial)
        
    6. 2023-09-07 11:57:53
        
    7. 2023-09-07 11:57:43
        
    8. 2023-09-07 11:55:44
        
    9. 2023-09-07 11:55:44
        

PsExec genera archivos de clave temporal en C:\Windows\ utilizando la nomenclatura estándar: `PSEXEC-<HOSTNAME>-<KEY_ID>.KEY.`

- **Hostname de la Estación de Trabajo Origen:** **FORELA-WKSTN001**.
    
- **Archivo Clave Asociado a la Quinta Ejecución:**  
    Al correlacionar el timestamp 12:06:54 UTC con los registros referenciados en el archivo prefetch, se identificó el artefacto específico:  
    **PSEXEC-FORELA-WKSTN001-95F03CFE.KEY**
    
- **Marca de Tiempo de Creación en Disco (USN Journal -
    
    ```
    J):∗∗Elvolcadode‘J):∗∗Elvolcadode‘
    ```
    
    Jdocumentó la creación de este archivo un segundo después de la activación del binario: **2023-09-07 12:06:55 UTC** (07/09/2023 12:06:55`).
    

PsExec implementa canales de comunicación cliente-servidor a través de tuberías con nombre (Named Pipes) sobre SMB para redirigir stdin, stdout y stderr. En Microsoft-Windows-Sysmon%4Operational.evtx se registró la creación del pipe correspondiente a la quinta ejecución:

- **Timestamp de Creación:** 2023-09-07 12:06:55 UTC.
    
- **Estructura del Pipe de Error Estándar (stderr):** El pipe generado terminando en la palabra clave stderr correspondió a la sesión 95F03CFE asociada a la ejecución: \psexec-FORELA-WKSTN001-95F03CFE-stderr (o \PSEXESVC-*-stderr).
    


``` bash
# Comandos de extracción pericial con herramientas de Zimmerman
PECmd.exe -f "C:\Windows\Prefetch\PSEXESVC.EXE-AD70946C.pf" --json Output_Prefetch
MFTECmd.exe -f "C:\$Extend\$J" --json Output_J --jsonf j.json
cat j.json | jq '.[] | select(.Name | contains("PSEXEC-FORELA-WKSTN001-95F03CFE"))'
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yaml
title: Deteccion de Movimiento Lateral Mediante PsExec
id: d4b19283-e182-4211-9a18-psexeclateralmovement
status: production
description: Identifica la creacion del servicio PSEXESVC o la presencia de archivos .key caracteristicos de PsExec en C:\Windows.
references:
  - https://attack.mitre.org/techniques/T1021/002/
author: Senior DFIR Specialist
date: 2023-09-08
logsource:
  product: windows
  service: system
detection:
  selection_service:
    EventID: 7045
    ServiceName: 'PSEXESVC'
  selection_file:
    EventID: 11
    TargetFilename|startswith: 'C:\Windows\PSEXEC-'
    TargetFilename|endswith: '.key'
  condition: selection_service or selection_file
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.002
```


``` SPL
index=sysmon (EventCode=17 OR EventCode=18) PipeName="*psexec*" OR PipeName="*PSEXESVC*"
| stats count, values(Image) as Binarios by Computer, PipeName, _time
| table _time, Computer, PipeName, Binarios, count
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Aislamiento Cruzado de Estaciones:** Aislar tanto la estación receptora como el equipo de origen hostil **FORELA-WKSTN001**.
    
2. **Purgado de Servicios y Archivos Huérfanos:** Detener el servicio PSEXESVC si permanece activo y eliminar los residuos .key en el directorio C:\Windows\.
    

3. **Restricción de Recursos Administrativos (Admin Shares):** Bloquear el acceso a ADMIN$ e IPC$ entre estaciones de trabajo cliente mediante directivas de Firewall perimetral y de endpoint.
    
4. **Deshabilitación de Tráfico SMB Punto a Punto:** Implementar microsegmentación de red para prohibir la comunicación en el puerto TCP 445 entre estaciones de trabajo pertenecientes a la misma subred.