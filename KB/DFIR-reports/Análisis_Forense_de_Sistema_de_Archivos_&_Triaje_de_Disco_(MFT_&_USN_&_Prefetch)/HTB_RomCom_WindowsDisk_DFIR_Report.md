### [HTB-ROMCOM: WINDOWS DISK FORENSICS & WINRAR EXPLOITATION REPORT]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Windows 10 Endpoint / VHDX Disk Image / HTB Sherlock  
**Objetivo:** Estación de trabajo del Laboratorio de Patología (Susan) / Hospital Internacional de Forela

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó una imagen de triaje de disco virtual (.vhdx) perteneciente al equipo de una investigadora del Laboratorio de Patología (Susan). La usuaria reportó anomalías y múltiples mensajes de error al intentar descomprimir un archivo recibido por correo electrónico, si bien el señuelo en formato PDF llegó a desplegarse en pantalla. El análisis forense de bajo nivel sobre la Master File Table ($MFT) y el diario de transacciones NTFS ($UsnJrnl) confirmó la explotación de una vulnerabilidad de ejecución remota de código en **WinRAR** (asociada a la explotación en estado salvaje de familias tipo RomCom / CVE-2023-38831). La apertura del señuelo Genotyping_Results_B57_Positive.pdf provocó la descompresión y ejecución encubierta del binario malicioso ApbxHelper.exe, el cual estableció persistencia inmediata en el sistema mediante la creación de un acceso directo fraudulento (Display Settings.lnk) en la carpeta de inicio del usuario.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Imagen de disco virtual extendida: 2025-09-02T083211_pathology_department_incidentalert.vhdx.
        
    - Sistema de archivos NTFS montado en modo sólo lectura vía guestmount.
        
    - Registros de metadatos analizados: $MFT, $Extend\$J (USN Journal) y archivo de auditoría CopyLog.csv.
        
    - Herramientas periciales: MFTECmd.exe v1.3.0.0 compilado sobre entorno .NET.
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Initial Access**|T1566.001|Phishing: Spearphishing Attachment|Entrega de archivo comprimido con estructura maliciosa simulando resultados de laboratorio.|
|**Execution**|T1203|Exploitation for Client Execution|Explotación de la vulnerabilidad en WinRAR para ejecutar código al abrir el documento señuelo.|
|**Persistence**|T1547.009|Boot or Logon Autostart Execution: Shortcut Modification|Creación de Display Settings.lnk en la carpeta Startup apuntando a ApbxHelper.exe.|
|**Defense Evasion**|T1036.005|Masquerading: Match Legitimate Name|Uso del nombre de configuración legítimo Display Settings.lnk para ocultar la persistencia.|

#### 3. Cadena de Infección y Análisis Forense Detallado

La estructura de directorios y la correlación de marcas de tiempo en el $MFT demostraron la secuencia de ejecución:

1. **Materialización del Contenedor Malicioso:**
    
    - Creación del archivo trampa en disco: **2025-09-02 08:13:50 UTC**.
        
    - Último acceso registrado sobre el contenedor: **2025-09-02 08:14:04 UTC**.
        
2. **Mecanismo de Explotación (CVE-2023-38831 / CVE-2025-8088):**
    
    - El atacante estructuró el archivo ZIP/RAR de forma que existía un señuelo (Genotyping_Results_B57_Positive.pdf) y una carpeta con el mismo nombre conteniendo ejecutables. Al hacer doble clic en el PDF desde la interfaz de WinRAR, la aplicación ejecutó el archivo ejecutable contenido en la carpeta hermana en lugar del PDF:
        
    - **Binario Malicioso Desplegado:** **ApbxHelper.exe**
        
    - **Timestamp de Creación en Disco ($Created0x10):** **2025-09-02 08:14:18 UTC**.
        
    - **Ruta Completa en Disco:** C:\Users\Susan\AppData\Local\Temp\ApbxHelper.exe (extraído a temporal antes de ejecución).
        

En el mismo segundo en que se ejecutó el exploit (08:14:18 UTC), el proceso malicioso generó un acceso directo en la carpeta de ejecución automática del usuario:

- **Archivo de Persistencia:** **Display Settings.lnk**
    
- **Timestamp de Creación ($Created0x10):** **2025-09-02 08:14:18 UTC**.
    
- **Ruta de Despliegue:** C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk
    
- **Destino del Enlace:** Apunta directamente a ApbxHelper.exe para asegurar su reactivación tras cada reinicio de sesión de la investigadora.
    

Para evitar sospechas, el malware procedió a abrir la instancia visible del documento PDF señuelo:

- **Documento:** Genotyping_Results_B57_Positive.pdf
    
- **Timestamp de Apertura Real por el Usuario:** **2025-09-02 08:15:05 UTC**.
    
- Conclusión pericial: La víctima observó el documento médico legítimo en pantalla a las 08:15:05 UTC creyendo que se trataba de una apertura limpia, cuando en realidad el backdoor ya había sido instalado y persistido en el sistema 47 segundos antes (08:14:18 UTC).
    


``` bash
# Comandos utilizados para montar la imagen de disco y parsear el $MFT
sudo guestmount -a 2025-09-02T083211_pathology_department_incidentalert.vhdx -m /dev/sda1 --ro /mnt/vhdx
dotnet MFTECmd.dll -f /mnt/vhdx/C/\$MFT --json output_mft
cat output_mft/*.json | jq '.[] | select(.FileName | contains("ApbxHelper") or contains("Display Settings")) | 
{
  FileName: .FileName,
  ParentPath: .ParentPath,
  Created0x10: .Created0x10,
  Created0x30: .Created0x30
}'
```

#### 4. Reglas de Detección e Ingeniería de Seguridad



``` Yaml
title: Creacion de Acceso Directo Anomalo en Carpeta Startup
id: 8b7d9214-e21a-4c28-9811-startuplnkpersistence
status: production
description: Detecta la creacion de archivos .lnk dentro de la carpeta Startup por procesos no estandar (como descompresores o carpetas temporales).
references:
  - https://attack.mitre.org/techniques/T1547/009/
author: Senior DFIR Specialist
date: 2025-09-03
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 11
    TargetFilename|contains: '\Start Menu\Programs\Startup\'
    TargetFilename|endswith: '.lnk'
  filter_installers:
    Image|startswith: 'C:\Windows\System32\'
  condition: selection and not filter_installers
level: high
tags:
  - attack.persistence
  - attack.t1547.009
```



``` SPL
index=sysmon EventCode=1 ParentImage="*\\winrar.exe"
| where NOT match(Image, "(?i)\\AppData\\\\Local\\\\Temp\\\\.*\.pdf$")
| table _time, Computer, User, ParentImage, Image, CommandLine
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Aislamiento del Endpoint:** Desconectar la estación de Susan de la VLAN médica/hospitalaria.
    
2. **Erradicación de la Persistencia:** Eliminar el archivo Display Settings.lnk de la carpeta Startup y purgar el binario ejecutable ApbxHelper.exe.
    

3. **Actualización Obligatoria de Software de Terceros:** Actualizar inmediatamente todas las instancias de WinRAR a versiones parcheadas (versión
    
    ```
    ≥6.23≥6.23
    ```
    
    o superior) que solucionan la vulnerabilidad de spoofing de extensiones y ejecución arbitraria.
    
4. **Restricción de Ejecución desde Temp:** Bloquear mediante directivas AppLocker/WDAC la ejecución directa de binarios portables desde subdirectorios bajo AppData\Local\Temp\*.