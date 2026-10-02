### [HTB-NOTED: NOTEPAD++ FORENSICS & DATA EXTORTION ANALYSIS]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Windows 10 Endpoint / Notepad++ Artifact Analysis / HTB Sherlock  
**Objetivo:** Estación de trabajo de Simón Stark (Simon.stark)

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó un caso de exfiltración de código fuente y extorsión cibernética contra la estación de trabajo de un ingeniero de software (Simon.stark). El actor de amenaza obtuvo acceso local al equipo y, aprovechando el entorno de desarrollo instalado, modificó un archivo fuente Java (LootAndPurge.java) directamente en el escritorio del usuario mediante el editor de texto legítimo Notepad++. Este script recopiló archivos confidenciales, los empaquetó en un contenedor ZIP protegido por contraseña (Forela-Dev-Data.zip) y posteriormente el atacante desplegó una nota de rescate amenazando con divulgar la propiedad intelectual de Forela en la dark web si no se transfería un pago en criptomonedas.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Artefactos locales de Notepad++ bajo C:\Users\Simon.stark\AppData\Roaming\Notepad++\:
        
        - config.xml (Historial de archivos recientes y configuraciones del entorno).
            
        - session.xml (Metadatos de sesión activa, punteros de backup y FILETIMEs).
            
        - Carpeta backup\ conteniendo copias en sombra de los archivos modificados: LootAndPurge.java@2023-07-24_145332 y YOU HAVE BEEN HACKED.txt@2023-07-24_150548.
            

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Collection**|T1005|Data from Local System|Script LootAndPurge.java diseñado para recorrer el escritorio y recopilar extensiones críticas (docx, pdf, zip, etc.).|
|**Collection**|T1560.001|Archive Collected Data: Archive via Utility|Empaquetado cifrado de la información sensible en Forela-Dev-Data.zip.|
|**Impact**|T1486|Data Encrypted for Impact / Extortion|Despliegue de la nota de extorsión YOU HAVE BEEN HACKED.txt con exigencia de pago en Ethereum.|
|**Discovery**|T1083|File and Directory Discovery|Historial de config.xml evidenciando exploración de scripts internos de AWS.|

#### 3. Cadena de Infección y Análisis Forense Detallado

1. **Exploración Previa de Scripts Críticos:**  
    En el historial de config.xml, dentro del nodo `<History>`, se descubrió que el usuario o el atacante abrieron un script de automatización cloud:
    
    - **Ruta Completa:** **C:\Users\Simon.stark\Documents\Dev_Ops\AWS_objects migration.pl**
        
2. **Identificación de los Archivos en Sesión:**  
    El archivo session.xml documentó los dos últimos documentos en edición activa en el editor:
    
    - Documento 1: C:\Users\Simon.stark\Desktop\LootAndPurge.java
        
    - Documento 2: C:\Users\Simon.stark\Desktop\YOU HAVE BEEN HACKED.txt
        

El análisis del artefacto recuperado de la carpeta backup\ (LootAndPurge.java@...) reveló la lógica de recolección:

- **Directorio Objetivo:** Directorio de escritorio del usuario en sesión (C:\Users\<username>\Desktop\).
    
- **Extensiones Filtradas:** zip, docx, ppt, xls, md, txt, pdf.
    
- **Archivo de Salida / Contenedor:** **Forela-Dev-Data.zip**.
    
- **Contraseña del Archivo Cifrado:** **sdklY57BLghvyh5FJ#fion_7**.
    

En session.xml, los atributos de modificación de LootAndPurge.java estaban representados en valores enteros de 32 bits para las partes baja y alta de una marca de tiempo Windows de 64 bits (FILETIME):

- originalFileLastModifTimestamp (Low DWORD): -1354503710
    
- originalFileLastModifTimestampHigh (High DWORD): 31047188
    
- **Algoritmo de Reconstrucción en Python:**  
    
    ```
    (31047188≪32)+(−1354503710 & 0xFFFFFFFF)=133346468030000000 intervalos de 100 ns desde el 01/01/1601.(31047188≪32)+(−1354503710 & 0xFFFFFFFF)=133346468030000000 intervalos de 100 ns desde el 01/01/1601.
    ```
    
- **Marca de Tiempo Real UTC:** **2023-07-24 09:53:23 UTC**.
    

El archivo YOU HAVE BEEN HACKED.txt contenía enlaces a repositorios Pastebin y Pastecode protegidos por contraseña. Utilizando la contraseña recuperada del script Java (sdklY57BLghvyh5FJ#fion_7), se accedió al contenido protegido:

- **Billetera de Criptomonedas (Ethereum):** **0xca8fa8f0b631ecdb18cda619c4fc9d197c8affca**
    
- **Canal de Contacto del Actor:** **CyberJunkie@mail2torjgmxgexntbrmhvgluavhj7ouul5yar6ylbvjkxwqf6ixkwyd.onion**
    


``` Python
# Script pericial de conversión FILETIME a formato legible UTC
import datetime
low = -1354503710
high = 31047188
low_unsigned = low & 0xFFFFFFFF
filetime = (high << 32) + low_unsigned
timestamp = filetime / 10000000
epoch = datetime.datetime(1601, 1, 1)
print("Fecha UTC:", epoch + datetime.timedelta(seconds=timestamp))
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yara
rule Suspicious_Java_Data_Harvester {
    meta:
        description = "Detecta scripts Java diseñados para empaquetar y cifrar archivos de usuario"
        author = "Senior DFIR Specialist"
        date = "2026-10-02"
    strings:
        $s1 = "ZipOutputStream" ascii
        $s2 = "Forela-Dev-Data.zip" ascii wide
        $s3 = "sdklY57BLghvyh5FJ#fion_7" ascii wide
        $ext = "Arrays.asList(\"zip\", \"docx\", \"ppt\", \"xls\"" ascii
    condition:
        all of ($s*) or ($s1 and $ext)
}
```


``` SPL
index=sysmon EventCode=11 TargetFilename="*\\Desktop\\*.zip"
| where match(Image, "(?i)(java\.exe|javaw\.exe|powershell\.exe|cmd\.exe)$")
| table _time, Computer, User, Image, TargetFilename
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Desactivación de Cuenta y Rotación:** Bloquear inmediatamente la cuenta de dominio de Simon.stark y rotar todas las credenciales de repositorios de código (Git, AWS, Jira).
    
2. **Recuperación y Análisis del Contenedor:** Localizar y aislar el archivo Forela-Dev-Data.zip en el endpoint. Al poseer la contraseña recuperada (sdklY57BLghvyh5FJ#fion_7), abrir el contenedor en un entorno seguro para determinar el alcance exacto de la información sensible comprometida.
    

3. **Control de Compilación en Endpoints:** Desinstalar compiladores de desarrollo (javac, utilidades de compilación C#) de estaciones de trabajo no dedicadas a desarrollo o restringir su uso a entornos VDI específicos.
    
4. **Data Loss Prevention (DLP):** Implementar reglas de DLP en endpoint para bloquear la creación o compresión masiva de documentos corporativos (.docx, .pdf, .xls) en archivos comprimidos protegidos por contraseña.