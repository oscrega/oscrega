### [HTB-SMARTSCREEN: WINDOWS REGISTRY & TELEMETRY FORENSICS]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Windows Server / SmartScreen Debug Telemetry & Event Logs / HTB Sherlock  
**Objetivo:** Servidor de Archivos del CTO (CTO-FILESVR)

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó una intrusión y sabotaje contra el servidor de archivos privado del CTO de Forela (Dutch), equipo aislado del dominio pero expuesto a la red interna (CTO-FILESVR). El 24 de enero de 2025, el atacante accedió vía Remote Desktop Protocol (RDP), descargó e instaló utilidades de soporte (WinRAR, Everything.exe), localizó y exfiltró documentos confidenciales de la Junta Directiva mediante la aplicación de sincronización cloud **MEGAsync**, y finalmente empleó un software de borrado seguro (**File Shredder**) para destruir los archivos originales. Antes de abandonar el sistema, el adversario eliminó el registro de eventos de Seguridad (Security.evtx). Gracias a la activación previa de la telemetría de depuración de **Windows SmartScreen** (Microsoft-Windows-SmartScreen%4Debug.evtx), se pudo reconstruir con absoluta precisión la cronología de descargas, ejecuciones y accesos a documentos.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Registros de eventos de Windows procesados mediante Chainsaw:
        
        - Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational.evtx (Event ID 1149).
            
        - Microsoft-Windows-SmartScreen%4Debug.evtx (Event ID 1003).
            
        - Security.evtx y System.evtx (Event IDs 1102 y 104 - Log Cleared).
            

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Initial Access**|T1078.003|Valid Accounts: Local Accounts|Acceso RDP autenticado exitosamente bajo la identidad de Dutch (Event ID 1149).|
|**Discovery**|T1083|File and Directory Discovery|Descarga y ejecución de la versión portátil de Everything.exe para búsqueda de documentos.|
|**Exfiltration**|T1567.002|Exfiltration Over Web Service: Exfiltration to Cloud Storage|Instalación y uso de MEGAsync para transferir documentación confidencial fuera de la red.|
|**Impact**|T1485|Data Destruction|Destrucción de archivos y borrado seguro de datos mediante file shredder.|
|**Defense Evasion**|T1070.001|Indicator Removal: Clear Windows Event Logs|Vaciado deliberado del registro de eventos de Seguridad (Event ID 1102).|

#### 3. Cadena de Infección y Análisis Forense Detallado

En los registros de RemoteConnectionManager/Operational, se aisló el inicio de sesión del atacante:

- **Event ID:** **1149**
    
- **Usuario Utilizado:** **Dutch**
    
- **Timestamp de Conexión (UTC):** **2025-01-24 10:15:14 UTC** (2025-01-24T10:15:14.456012Z).
    
- **Dirección Origen:** Dirección IPv6 local / tunelada registrada en Param3.
    

La telemetría de SmartScreen documentó el análisis y ejecución de cada componente descargado por el atacante:

1. **Primera Herramienta (Descompresor):**
    
    - El atacante descargó e instaló **WinRAR** (analizado a las 10:17:14 UTC, ejecutado a las 10:17:27 UTC).
        
2. **Herramienta de Búsqueda Rápida de Archivos:**
    
    - Descarga de la versión portátil de Everything:
        
    - **Ruta Completa de Ejecución:** **C:/Users/Dutch/Downloads/Everything.exe**
        
    - **Timestamp de Ejecución:** **2025-01-24 10:17:33 UTC** (campo executionTime: 8701).
        

El adversario utilizó Everything.exe para indexar y abrir archivos de la Junta Directiva almacenados en el perfil:

- **Primer Documento Comprometido:**  
    **C:\Users\Dutch\Documents\2025- Board of directors Documents\Ministry Of Defense Audit.pdf**
    
- **Segundo Documento Comprometido:**  
    **C:\Users\Dutch\Documents\2025- Board of directors Documents\2025-BUDGET-ALLOCATION-CONFIDENTIAL.pdf**
    

1. **Utilidad de Nube para Exfiltración:**
    
    - El atacante instaló el cliente de sincronización de **MEGAsync**.
        
    - **Timestamp de Ejecución:** **2025-01-24 10:22:19 UTC** (registrado en eventos de SmartScreen sobre MEGAsync.exe y MEGAsync.lnk).
        
2. **Destrucción de Información (Antiforense):**
    
    - Para impedir la recuperación de los archivos originales mediante técnicas forenses de carving, el atacante ejecutó la utilidad:
        
    - **Nombre de la Herramienta:** **file shredder** (file_shredder_setup.exe).
        

En un intento de eliminar el rastro de la intrusión, el atacante ejecutó el borrado de logs:

- **Borrado del Registro de Seguridad (Event ID 1102):**
    
    - **Timestamp:** **2025-01-24 10:28:41 UTC** (2025-01-24T10:28:41.933849Z).
        
    - **Usuario Responsable:** Dutch (SID S-1-5-21-3088055692-629932344-1786574096-1003, LogonId 0xe1d52).
        
    - Mensaje: The audit log was cleared.
        


``` bash
# Extracción de eventos de SmartScreen y borrado de logs en Chainsaw
cat todos_los_logs | jq '.[] | select(.Event.System.EventID == 1003) | 
{
  Time: .Event.System.TimeCreated_attributes.SystemTime,
  Path: .Event.EventData.FilePath,
  ExecutionTime: .Event.EventData.executionTime
}'
cat todos_los_logs | jq '.[] | select(.Event.System.EventID == 1102)'
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yaml
title: Vaciado del Registro de Seguridad de Windows (EventLog Cleared)
id: d9a10234-f811-4bb2-9a11-securitylogcleared
status: production
description: Detecta el vaciado deliberado del registro de auditoria de seguridad (Event ID 1102).
references:
  - https://attack.mitre.org/techniques/T1070/001/
author: Senior DFIR Specialist
date: 2025-01-25
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1102
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
```


``` SPL
index=sysmon EventCode=1 (Image="*MEGAsync*" OR Image="*file_shredder*" OR Image="*Everything.exe*")
| table _time, Computer, User, Image, CommandLine, ParentImage
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Aislamiento de Red del Servidor:** Desconectar CTO-FILESVR de la red corporativa de inmediato.
    
2. **Revocación de Credenciales:** Resetear de forma urgente la contraseña de la cuenta local Dutch y deshabilitar temporalmente el acceso interactivo sobre dicho activo.
    
3. **Análisis de Fuga de Información:** Considerar comprometidos los documentos de la Junta de Defensa y activar los protocolos legales de notificación de brecha de datos de acuerdo con el marco regulatorio correspondiente.
    

4. **Deshabilitación de RDP Directo:** Deshabilitar el protocolo RDP en servidores de archivos críticos que contengan propiedad intelectual o requerir acceso exclusivo a través de una pasarela bastión (Jump Server) con MFA obligatorio.
    
5. **Restricción de Software No Autorizado:** Implementar directivas WDAC estrictas que impidan la ejecución de instaladores o ejecutables portables de sincronización cloud (MEGAsync, Dropbox, OneDrive) y herramientas de borrado seguro (File Shredder, SDelete).