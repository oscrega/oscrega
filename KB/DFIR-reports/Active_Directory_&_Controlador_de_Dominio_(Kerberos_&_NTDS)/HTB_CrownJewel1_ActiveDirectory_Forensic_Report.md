### [HTB-CROWNJEWEL1: ACTIVE DIRECTORY NTDS.DIT EXTRACTION VIA VSSADMIN]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Active Directory / Windows Server 2019 Domain Controller / HTB Sherlock  
**Objetivo:** Controlador de Dominio DC01.forela.local

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se detectó la ejecución anómala del binario legítimo del sistema vssadmin.exe (LOLBin) en el Controlador de Dominio principal (DC01). El actor de amenaza, operando bajo privilegios administrativos delegados o comprometidos, manipuló el servicio de instantáneas de volumen (Volume Shadow Copy Service - VSS) para eludir el bloqueo de lectura exclusivo del sistema operativo sobre la base de datos de Active Directory (NTDS.dit). Mediante este mecanismo, el adversario creó una instantánea en la sombra, extrajo una copia de NTDS.dit junto con la colmena de registro SYSTEM en un directorio de puesta en escena (backup_sync_Dc), permitiendo el descifrado offline de todos los hashes de contraseñas (NTHash/LM) de las cuentas del dominio.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Registros de eventos de Windows: System.evtx, Security.evtx y Microsoft-Windows-Ntfs/Operational.evtx.
        
    - Registro de auditoría del sistema de archivos: Master File Table ($MFT) parseado mediante MFTECmd y volcado a JSON.
        
    - Artefactos de servicio: Interacción con el binario VSSVC.exe (Volume Shadow Copy Service).
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Credential Access**|T1003.003|OS Credential Dumping: NTDS|Extracción forzada del archivo NTDS.dit y de la colmena SYSTEM hacia el directorio de staging C:\Users\Administrator\Documents\backup_sync_Dc\.|
|**Defense Evasion**|T1006|Direct Volume Access|Abuso de Volume Shadow Copies para evadir los mecanismos de bloqueo de archivos del kernel sobre ntds.dit.|
|**Discovery**|T1069.002|Permission Groups Discovery: Domain Groups|Enumeración automatizada de los grupos Administrators y Backup Operators ejecutada por el proceso VSSVC.exe (Event ID 4799).|
|**Execution**|T1047|Windows Management Instrumentation / LOLBins|Invocación de vssadmin para interactuar con la infraestructura del proveedor VSS del sistema.|

#### 3. Cadena de Infección y Análisis Forense Detallado

1. **Transición del Servicio VSS (System Log - Event ID 7036):**
    
    - El servicio Volume Shadow Copy entró en estado de ejecución (running) a las **2024-05-14 03:42:16 UTC**, marcando el inicio formal de las operaciones de snapshot de volumen iniciadas por el adversario.
        
    - Parámetros del evento: param1 = Volume Shadow Copy, param2 = running.
        
2. **Validación de Privilegios y Contexto de Proceso (Security Log - Event ID 4799):**
    
    - El proceso de servicio responsable fue C:\Windows\System32\VSSVC.exe.
        
    - **PID del Proceso:** En los metadatos hexadecimales de auditoría se registró ProcessId: 0x1190, que convertido a decimal corresponde al **PID 4496**.
        
    - Contexto de Identidad: DC01$ (Cuenta de máquina local del Controlador de Dominio).
        
    - Grupos consultados para validar privilegios de lectura/escritura de bajo nivel: **Administrators** y **Backup Operators**.
        
3. **Montaje y Creación de la Instantánea de Sombra (NTFS Operational - Event ID 10):**
    
    - Al generarse la instantánea para el volumen principal, el sistema le asignó el identificador de volumen global:
        
    - **Volume ID / GUID:** **{06c4a997-cca8-11ed-a90f-000c295644f9}**.
        

El análisis forense de la Master File Table ($MFT) reveló la secuencia de vertido en el disco:

- **Ruta Completa del Volcado NTDS:** **C:\Users\Administrator\Documents\backup_sync_Dc\Ntds.dit**
    
- **Marca de Tiempo de Creación en Disco ($Created0x30 / $FILE_NAME):** **2024-05-14 03:44:22 UTC**.
    
- **Exfiltración de Claves de Cifrado (Registry Hive Dumping):**
    
    - En la misma carpeta de destino (backup_sync_Dc), a las **2024-05-14 03:44:42 UTC** (20 segundos después de la copia de la base de datos), el adversario volcó la colmena de registro **SYSTEM**.
        
    - Justificación pericial: El archivo ntds.dit almacena las claves PEK (Password Encryption Key) cifradas con la BootKey (o Syskey), la cual reside exclusivamente en la colmena SYSTEM. Sin este hive, los hashes NTLM extraídos de NTDS.dit no pueden descifrarse.
        

``` bash
# Extracción forense del evento 4799 asociado a VSSVC en Chainsaw
cat events.json | jq '.[] | select(.Event.System.EventID == 4799) | 
select(.Event.EventData.CallerProcessName | contains("VSSVC.exe")) | 
{
  Time: .Event.System.TimeCreated_attributes.SystemTime,
  TargetGroup: .Event.EventData.TargetUserName,
  CallerProcess: .Event.EventData.CallerProcessName,
  ProcessID_Hex: .Event.EventData.CallerProcessId,
  Account: .Event.EventData.SubjectUserName
}'
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yaml
title: Creacion Anomala de Instantanea VSS o Acceso a NTDS.dit
id: 9a38d721-e8d1-4122-b531-ntdsdumpvssadmin
status: production
description: Detecta la ejecucion de vssadmin o la creacion de shadow copies seguida de acceso a la base de datos de Active Directory.
references:
  - https://attack.mitre.org/techniques/T1003/003/
author: Senior DFIR Specialist
date: 2024-05-15
logsource:
  product: windows
  service: security
detection:
  selection_process:
    EventID: 4688
    NewProcessName|endswith:
      - '\vssadmin.exe'
      - '\wmic.exe'
    CommandLine|contains|all:
      - 'create'
      - 'shadow'
  selection_service:
    EventID: 7036
    ServiceName: 'VSS'
  condition: selection_process or selection_service
level: high
tags:
  - attack.credential_access
  - attack.t1003.003
```


``` SPL
index=wineventlog (EventCode=4688 OR EventCode=1) Image="*\\vssadmin.exe" CommandLine="*create shadow*"
| join type=outer host [
    search index=wineventlog EventCode=4799 CallerProcessName="*\\VSSVC.exe"
    | stats values(TargetUserName) as EnumeratedGroups by host, _time
]
| table _time, host, SubjectUserName, Image, CommandLine, EnumeratedGroups
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Contención del Domain Controller:** Purgar el directorio C:\Users\Administrator\Documents\backup_sync_Dc\ mediante borrado seguro de bajo nivel para eliminar las copias locales de Ntds.dit y SYSTEM.
    
2. **Revocación de la Infraestructura Criptográfica del Dominio:** Forzar la rotación doble de la contraseña de la cuenta **krbtgt** (con un espacio de 12 a 24 horas entre rotaciones) para invalidar cualquier Golden Ticket que el adversario haya podido forjar con los hashes extraídos.
    
3. **Restablecimiento Global de Credenciales:** Forzar el cambio masivo de contraseñas de todas las cuentas privilegiadas del dominio (Domain Admins, Enterprise Admins, cuentas de servicio críticas).
    

4. **Restricción de Acceso a Utilidades de Instantáneas:**
    
    - Bloquear la ejecución de vssadmin.exe para cualquier contexto que no pertenezca a software de backup autorizado mediante directivas WDAC o AppLocker.
        
5. **Monitorización de Directorios Críticos de Staging:**
    
    - Implementar reglas de SACL y monitorización EDR sobre escrituras de archivos con extensión .dit fuera de su ruta legítima (%SystemRoot%\NTDS\).