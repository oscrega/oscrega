### [HTB-BFT: WINDOWS NTFS MASTER FILE TABLE ($MFT) ANALYSIS]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Windows NTFS Filesystem / Eric Zimmerman Tools / HTB Sherlock  
**Objetivo:** Unidad C:\ de Simón Stark / Análisis del Artefacto $MFT

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se llevó a cabo un análisis forense sobre la Master File Table ($MFT) del sistema de archivos NTFS de una estación de trabajo corporativa comprometida el 13 de febrero de 2024. El incidente se originó a través de un correo de phishing con un enlace a un archivo comprimido alojado en la infraestructura de Google Cloud Storage. El usuario descargó el contenedor, extrayendo una cadena de artefactos que culminó en un script por lotes malicioso (invoice.bat). El análisis de bajo nivel demostró que el script era un stager residente dentro del propio registro $MFT, diseñado para abrir un canal C2 con la dirección IP 43.204.110.203:6666.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Archivo $MFT de la unidad C:.
        
    - Herramienta de procesado: MFTECmd.exe v1.3.0.0 (Eric Zimmerman) con análisis de atributos $FILE_NAME (0x30), $DATA (0x80) y registros de Zone Identifier (Mark of the Web - MotW).
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Initial Access**|T1566.002|Phishing: Spearphishing Link|Descarga de Stage-20240213T093324Z-001.zip desde Google Cloud Storage mediante enlace web.|
|**Defense Evasion**|T1553.005|Subvert Trust Controls: Mark of the Web Bypass|Extracción en cascada de archivos comprimidos para romper la propagación del Alternate Data Stream Zone.Identifier.|
|**Execution**|T1059.003|Command and Scripting Interpreter: Windows Command Shell|Script malicioso invoice.bat utilizado para el despliegue del stager.|
|**Command and Control**|T1071|Application Layer Protocol|Configuración de llamada reversa a la dirección 43.204.110.203:6666.|

#### 3. Cadena de Infección y Análisis Forense Detallado

El análisis del $MFT confirmó la descarga inicial realizada por Simón Stark:

- **Nombre del Archivo ZIP Descargado:** **Stage-20240213T093324Z-001.zip**.
    
- **Análisis de Zone Identifier (MotW):**  
    A través del Alternate Data Stream (:Zone.Identifier), se extrajo el campo HostUrl original que fungió como IoC principal:
    
    - **URL Completa:**  
        **https://storage.googleapis.com/drive-bulk-export-anonymous/20240213T093324.039Z/4133399871716478688/a40aecd0-1cf3-4f88-b55a-e188d5c1c04f/1/c277a8b4-afa9-4d34-b8ca-e1eb5e5f983c?authuser**
        

La secuencia temporal del sistema de archivos evidenció la siguiente jerarquía de extracción:

1. Descompresión de Stage-20240213T093324Z-001.zip -> Generación de invoices.zip y accesos directos .lnk.
    
2. Descompresión de invoices.zip -> Materialización del payload final.
    

- **Ruta Completa del Archivo Malicioso:**  
    **C:\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\Stage\invoice\invoices\invoice.bat**
    
- **Marca de Tiempo de Creación Real ($Created0x30 / $FILE_NAME):**  
    **2024-02-13 16:38:39 UTC**.
    

- **Número de Entrada (MFT Entry):** **23436** (Secuencia 0x9).
    
- **Offset Hexadecimal en el Archivo $MFT:** **0x16E3000** (calculado multiplicando el número de entrada por el tamaño de bloque de 1024 bytes del registro MFT:
    
    ``` TEXT
    23436×1024=23998464=0x16E300023436×1024=23998464=0x16E3000
    ```
    
    ).
    
- **Análisis de Residencia (Resident Data Attribute):**  
    Dado que el tamaño de invoice.bat era inferior al espacio libre del registro MFT asignado a atributos $DATA no nombrados (
    
    ``` TEXT
    <700 bytes<700 bytes
    ```
    
    ), el contenido del archivo no se asignó a clusters externos del disco, sino que quedó almacenado de forma residente dentro de la propia tabla $MFT.
    
- **Inspección del Stager C2:**  
    El análisis directo del volcado hexadecimal de la entrada reveló el comando de conexión de reversa:
    
    - **Dirección IP y Puerto C2:** **43.204.110.203:6666**.
        


``` bash
# Invocación pericial de MFTECmd para inspeccionar la entrada residente
MFTECmd.exe -f "$MFT" --de 23436
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Snort
alert tcp any any -> 43.204.110.203 6666 (msg:"ALERTA CTI - Conexion Stager C2 Detectada (Caso BFT)"; flow:to_server,established; sid:1000921; rev:1;)
```


``` SPL
index=sysmon EventCode=1 Image="*\\cmd.exe" CommandLine="*invoice.bat*"
| table _time, Computer, User, ParentImage, CommandLine
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Bloqueo IP Perimetral:** Bloquear inmediatamente en el firewall de frontera la IP hostil 43.204.110.203 y el puerto 6666.
    
2. **Purga de Archivos:** Eliminar de forma segura la estructura completa del directorio temporal C:\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\.
    

3. **Filtrado de Pasarela de Correo (Secure Email Gateway - SEG):** Bloquear correos con enlaces a servicios anónimos de almacenamiento compartido en la nube (storage.googleapis.com, drive.google.com) dirigidos a cuentas corporativas.
    
4. **Deshabilitación de Ejecución de Scripts en Perfiles:** Forzar mediante directiva que archivos .bat, .cmd o .vbs requieran elevación explícita o se ejecuten en entornos sandbox restringidos.