### [HTB-ROGUEONE: WINDOWS 10 MEMORY FORENSICS & ROZENA C2 TRIAGE]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Windows 10 (Build 19041 / 20H1) / Volatility 3 / HTB Sherlock  
**Objetivo:** Estación de trabajo de Simón Stark (172.17.79.131)

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó una intrusión activa en la estación de trabajo de Simón Stark tras la generación de alertas reiteradas en el SIEM que indicaban conexiones de Comando y Control (C2). Las inspecciones preliminares del Administrador de Tareas no detectaron anomalías debido a que el malware utilizó técnicas de enmascaramiento con el nombre de un proceso crítico de Windows (svchost.exe). El análisis forense de la memoria RAM (20230810.mem) utilizando Volatility 3 descubrió que el proceso malicioso operaba desde el directorio de descargas del usuario (PID 6812), manteniendo una sesión de reverse shell interactiva conectada a un servidor remoto en la infraestructura de AWS (13.127.155.166:8888). El binario fue identificado como el troyano **Rozena**, comúnmente empleado en operaciones con Metasploit.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Volcado de memoria RAM: 20230810.mem (Windows 10 x64, versión 15.19041).
        
    - Herramienta de triaje: Volatility 3 Framework v2.28.0.
        
    - Plugins aplicados: windows.info, windows.pslist, windows.cmdline, windows.cmdscan, windows.dumpfiles, windows.netscan.
        
    - Inteligencia de amenazas externa: Correlación con VirusTotal API.
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Defense Evasion**|T1036.005|Masquerading: Match Legitimate Name|Ejecución de svchost.exe desde la ruta anómala C:\Users\simon.stark\Downloads\svchost.exe.|
|**Command and Control**|T1071.001|Application Layer Protocol: Web Protocols / TCP Shell|Conexión C2 persistente establecida contra 13.127.155.166:8888.|
|**Execution**|T1059.003|Command and Scripting Interpreter: Windows Command Shell|El malware generó un proceso hijo cmd.exe (PID 4364) para otorgar control remoto interactivo.|

#### 3. Cadena de Infección y Análisis Forense Detallado

Mediante el análisis de líneas de comandos (windows.cmdline) y el listado de procesos (windows.pslist), se detectó un proceso con nombre de binario nativo pero ruta de ejecución fraudulenta:

- **Proceso Malicioso:** svchost.exe
    
- **Ruta Completa:** **C:\Users\simon.stark\Downloads\svchost.exe**
    
- **Process ID (PID):** **6812**
    
- **Parent Process ID (PPID):** 7436 (explorer.exe, lo que demuestra ejecución interactiva por el usuario).
    
- **Offset de Memoria Física:** **0x9e8b87762080**.
    

El proceso malicioso generó un intérprete de comandos como mecanismo de control remoto:

- **Proceso Hijo:** cmd.exe
    
- **PID del Proceso Hijo:** **4364** (PPID 6812).
    
- **Timestamp de Creación:** 2023-08-10 11:30:57.000000 UTC.
    
- Subproceso asociado: conhost.exe (PID 9204, PPID 4364).
    

La inspección de sockets de red activos mediante el plugin windows.netscan filtrando por el PID 6812 arrojó el canal de comunicación establecido:

- **Protocolo:** TCPv4
    
- **Dirección IP Origen (Víctima):** 172.17.79.131 (Puerto 64254)
    
- **Dirección IP y Puerto C2 (Atacante):** **13.127.155.166:8888**
    
- **Estado de la Conexión:** ESTABLISHED
    
- **Timestamp de Ejecución y Establecimiento C2:** **2023-08-10 11:30:03 UTC** (10/08/2023 11:30:03).
    

El binario fue extraído de la memoria mediante windows.dumpfiles --pid 6812 arrojando el archivo ImageSectionObject:

- **Hash MD5:** **5bd547c6f5bfc4858fe62c8867acfbb5**
    
- **Hash SHA-256:** **eaf09578d6eca82501aa2b3fcef473c3795ea365a9b33a252e5dc712c62981ea**
    
- **Familia del Malware:** Troyano **Rozena**.
    
- **Primera Sumisión a VirusTotal:** Verificado en la telemetría histórica de VirusTotal como enviado por primera vez el **10/08/2023 11:58:10 UTC**.
    


``` bash
# Comandos de Volatility 3 para aislar el proceso y conexiones
vol3 -f 20230810.mem windows.pslist | grep 6812
vol3 -f 20230810.mem windows.netscan | grep 6812
vol3 -f 20230810.mem -o ./dumps windows.dumpfiles --pid 6812
md5sum dumps/file.0x9e8b91ec0140.0x9e8b957f24c0.ImageSectionObject.svchost.exe.img
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


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

#### 5. Plan de Contención, Erradicación y Hardening

1. **Terminación de Procesos:** Matar los procesos con PID 6812 y PID 4364 inmediatamente.
    
2. **Aislamiento en EDR:** Bloquear toda comunicación saliente en la estación 172.17.79.131.
    
3. **Bloqueo Perimetral:** Incorporar en el Firewall de borde el bloqueo bidireccional para la IP 13.127.155.166 y el puerto 8888.
    

4. **Reglas de Reducción de Superficie de Ataque (ASR):**
    
    - Habilitar la regla ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion.
        
    - Habilitar la regla: Block process creations originating from PSExec and WMI commands.
        
5. **Bloqueo AppLocker en Descargas:** Implementar una directiva obligatoria que restrinja la ejecución de cualquier binario (.exe, .dll) desde C:\Users\*\Downloads\*.