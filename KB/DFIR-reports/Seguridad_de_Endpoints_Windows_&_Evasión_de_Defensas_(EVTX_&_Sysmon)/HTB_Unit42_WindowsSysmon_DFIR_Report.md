### [HTB-UNIT42: SYSMON ANALYSIS & ULTRAVNC BACKDOOR CAMPAIGN]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Windows 10 Endpoint / Microsoft-Windows-Sysmon Telemetry / HTB Sherlock  
**Objetivo:** Estación de trabajo DESKTOP-887GK2L (Usuario CyberJunkie)

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó una intrusión basada en la campaña analizada por la unidad de inteligencia de amenazas Unit 42 de Palo Alto Networks, en la que se distribuyó un ejecutable malicioso que desplegó una variante modificada de la herramienta de control remoto **UltraVNC**. El malware inicial (Preventivo24.02.14.exe.exe) fue distribuido a través de la infraestructura de almacenamiento cloud de **Dropbox**. Tras su ejecución, el binario empleó técnicas de manipulación temporal de marcas de tiempo (Timestomping), verificó la conectividad a Internet mediante consultas contra www.example.com y estableció una conexión TCP externa con 93.184.216.34. Finalmente, el stager depositó archivos de configuración y scripts (once.cmd) en carpetas anómalas antes de autodestruirse.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Microsoft-Windows-Sysmon-Operational.evtx: Registro completo de telemetría de endpoint analizado mediante Chainsaw (reglas Sigma integradas) y consultas jq.
        
    - Correlación de Event IDs de Sysmon: 1 (Process Creation), 2 (File Creation Time Changed), 3 (Network Connection), 5 (Process Terminated), 11 (File Create) y 22 (DNS Query).
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Defense Evasion**|T1036.007|Masquerading: Double File Extension|Ejecución de Preventivo24.02.14.exe.exe simulando una factura o documento preventivo.|
|**Defense Evasion**|T1070.006|Indicator Removal: Timestomp|Alteración artificial de la fecha de creación del archivo PDF y de once.cmd a enero de 2024.|
|**Initial Access / Resource Dev**|T1567.002|Exfiltration to Cloud Storage / Cloud Staging|Descarga de la carga maliciosa inicial alojada en subdominios de Dropbox.|
|**Persistence**|T1219|Remote Access Software|Despliegue de variante personalizada de UltraVNC para acceso interactivo encubierto.|

#### 3. Cadena de Infección y Análisis Forense Detallado

El filtrado y conteo de eventos de creación de archivos (EventID: 11) dentro del registro de Sysmon arrojó un total de:

- **Total de Eventos File Create (ID 11):** **56 eventos**.
    

1. **Proceso Malicioso (Sysmon Event ID 1):**
    
    - **Ruta Completa:** **C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe**
        
    - **Técnica:** Doble extensión .exe.exe diseñada para engañar al usuario en entornos donde las extensiones conocidas están ocultas.
        
2. **Servicio Cloud de Distribución (Sysmon Event ID 22 - DNS):**
    
    - El proceso legítimo firefox.exe ejecutó consultas hacia:  
        uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com y d.dropbox.com.
        
    - **Servicio de Almacenamiento Utilizado:** **Dropbox**.
        

El malware alteró deliberadamente las fechas de creación para mimetizarse con el sistema de archivos:

1. **Modificación de Archivo PDF Trampa:**
    
    - Archivo: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\TempFolder\~.pdf
        
    - **Fecha/Hora UTC Falsificada (CreationUtcTime):** **2024-01-14 08:10:06.029** (cuando la creación real en disco ocurrió el 2024-02-14 03:41:58 UTC).
        
2. **Despliegue y Timestomping de "once.cmd":**
    
    - **Ruta Completa en Disco:**  
        **C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd**
        
    - Fecha falsificada asignada: 2024-01-10 18:12:26.458 UTC.
        

1. **Comprobación de Acceso a Internet:**
    
    - El proceso Preventivo24.02.14.exe.exe (PID 10672) realizó una consulta DNS a las 03:41:56 UTC hacia un dominio ficticio de control:
        
    - **Dominio Consultado:** **www.example.com**
        
2. **Conexión de Red Establecida:**
    
    - A las 03:41:58 UTC, el proceso inició un socket TCP hacia la dirección IP resuelta:
        
    - **Dirección IP Destino:** **93.184.216.34** (Puerto TCP 80).
        

Tras completar la descompresión, el timestomping y la configuración de los componentes de UltraVNC, el proceso inicial terminó:

- **Timestamp de Terminación del Proceso:** **2024-02-14 03:41:59 UTC**.
    


``` bash
# Consultas de extracción en Chainsaw/jq sobre el volcado de Sysmon
cat sysmon.out | jq '.[].Event | select(.System.EventID == 2) | select(.EventData.TargetFilename | contains("~.pdf"))'
cat sysmon.out | jq '.[].Event | select(.System.EventID == 3) | select(.EventData.Image | contains("Preventivo"))'
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yaml
title: Deteccion de Timestomping Mediante Sysmon Event ID 2
id: 5b91a234-d128-4eb1-9912-sysmontimestomp
status: production
description: Detecta discrepancias significativas entre la fecha de creacion previa y la nueva fecha de creacion asignada a un archivo.
references:
  - https://attack.mitre.org/techniques/T1070/006/
author: Senior DFIR Specialist
date: 2024-02-15
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 2
  condition: selection
level: medium
tags:
  - attack.defense_evasion
  - attack.t1070.006
```


``` SPL
index=sysmon EventCode=1 Image="*.exe.exe" OR Image="*.pdf.exe" OR Image="*.docx.exe"
| table _time, Computer, User, Image, CommandLine, ParentImage
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Aislamiento del Endpoint:** Aislar la estación DESKTOP-887GK2L de la red.
    
2. **Eliminación de la Estructura de UltraVNC:** Purgar completamente el árbol de directorios C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\.
    

3. **Visualización Obligatoria de Extensiones:** Forzar mediante GPO la visualización obligatoria de extensiones de archivo conocidas en todos los endpoints (HideFileExt = 0).
    
4. **Restricción de Software de Acceso Remoto:** Implementar reglas de EDR/AppLocker que bloqueen la ejecución de software VNC no corporativo (winvnc.exe, vncviewer.exe, variantes portables).