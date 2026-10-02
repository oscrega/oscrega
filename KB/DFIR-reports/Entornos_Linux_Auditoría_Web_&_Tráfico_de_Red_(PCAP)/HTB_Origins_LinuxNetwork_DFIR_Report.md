### [HTB-ORIGINS: LINUX NETWORK & FTP FORENSICS REPORT]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Linux Enterprise / Network Traffic Analysis (PCAP) / HTB Sherlock  
**Objetivo:** Servidor FTP Corporativo (172.31.45.144:21) / Exfiltración hacia Infraestructura AWS S3

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó una intrusión crítica originada en un servidor FTP expuesto a Internet (172.31.45.144). El atacante, operando desde una instancia de AWS EC2 ubicada en la India (15.206.185.207), perpetró un ataque de fuerza bruta exitoso contra el servicio **vsFTPd 3.0.5**, obteniendo acceso mediante credenciales débiles (forela-ftp:ftprocks69$). Una vez autenticado, el adversario utilizó el modo pasivo extendido (EPSV) y el comando RETR para exfiltrar documentación interna sensible. Entre los archivos sustraídos se recuperaron notas de mantenimiento con credenciales en texto plano para servidores SSH de respaldo (B@ckup2024!) y listados de cubos Amazon S3 utilizados posteriormente para el robo masivo de aproximadamente 20 GB de datos corporativos y posterior extorsión.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Captura de tráfico de red: ftp.pcap (microsecond timestamps, little-endian).
        
    - Herramientas de análisis: Wireshark, tshark y NetworkMiner para la reconstrucción de flujos TCP y extracción de artefactos binarios transferidos.
        
    - Telemetría de geolocalización IP (IP-API).
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Credential Access**|T1110.001|Brute Force: Password Guessing|Múltiples intentos de autenticación FTP secuenciales desde 15.206.185.207 contra el puerto TCP 21.|
|**Initial Access**|T1078.003|Valid Accounts: Local Accounts|Acceso exitoso al servidor FTP mediante la cuenta forela-ftp.|
|**Collection**|T1005|Data from Local System|Descarga de documentación técnica confidencial (Maintenance-Notice.pdf y s3_buckets.txt).|
|**Exfiltration**|T1048.003|Exfiltration Over Alternative Protocol: FTP|Transferencia de archivos remota mediante la invocación del comando RETR.|
|**Credential Access**|T1552.001|Credentials In Files|Extracción de contraseña de servidor SSH de backup embebida en un archivo PDF.|

#### 3. Cadena de Infección y Análisis Forense Detallado

- **Dirección IP del Atacante:** **15.206.185.207**.
    
- **Dirección IP del Servidor Objetivo:** **172.31.45.144** (Puerto TCP 21).
    
- **Atribución Geográfica (GeoIP):**
    
    - Ciudad: **Mumbai**
        
    - País: **India**
        
    - ASN / ISP: AS16509 Amazon.com, Inc. (Instancia de Amazon AWS EC2 en la región ap-south-1).
        

1. **Banner Grabbing e Identificación del Software:**  
    El flujo TCP inicial expuso la versión exacta del servicio FTP:
    
    - **Software y Versión:** **vsFTPd 3.0.5** (Very Secure FTP Daemon).
        
2. **Inicio del Ataque de Fuerza Bruta:**
    
    - La primera ráfaga de respuestas de fallo de autenticación (530 Login incorrect) se registró a las:  
        **2024-05-03 04:12:54 UTC**.
        
3. **Credenciales Comprometidas:**  
    Tras múltiples intentos fallidos, el atacante envió un paquete USER forela-ftp seguido de PASS ftprocks69$, recibiendo el código 230 Login successful:
    
    - **Credenciales:** **forela-ftp:ftprocks69$**
        

- **Mecanismo de Descarga:** El adversario conmutó al modo pasivo extendido mediante el comando EPSV y recuperó los archivos del servidor invocando la directiva estándar:
    
    - **Comando FTP:** **RETR**
        
- **Artefactos Exfiltrados Reconstruidos (NetworkMiner):**
    
    1. Maintenance-Notice.pdf:
        
        - El análisis pericial del documento recuperado reveló credenciales de infraestructura crítica:
            
        - **Contraseña del Servidor SSH de Respaldo:** **B@ckup2024!**
            
    2. s3_buckets.txt:
        
        - El documento detallaba la topología de almacenamiento cloud de Forela:
            
        - **URL del Bucket S3 de Almacenamiento 2023:** **https://2023-coldstorage.s3.amazonaws.com**
            
        - **Dirección de Correo Interna (Campaña de Phishing/Ingeniería Social):** **archivebackups@forela.co.uk**  
            (Evidencia: "[https://2022-warmstor.s3.amazonaws.com](https://www.google.com/url?sa=E&q=https%3A%2F%2F2022-warmstor.s3.amazonaws.com) auditoría pendiente, envíe un correo electrónico a alonzo a [archivebackups@forela.co.uk](https://www.google.com/url?sa=E&q=mailto%3Aarchivebackups%40forela.co.uk) para cualquier autorización").
            



``` bash
# Filtrado de credenciales y comandos RETR en tshark
tshark -r ftp.pcap -Y "ftp.request.command in {\"USER\",\"PASS\",\"RETR\",\"EPSV\"}" -T fields -e frame.time_epoch -e ip.src -e ftp.request.command -e ftp.request.arg
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Snort
alert tcp any any -> 172.31.45.144 21 (msg:"ALERTA CTI - Posible Fuerza Bruta FTP (vsFTPd)"; flow:to_server,established; content:"USER"; nocase; threshold:type threshold, track by_src, count 10, seconds 60; sid:1000941; rev:1;)
```



``` SPL
index=network sourcetype="pcap:ftp" dest_port=21
| stats count(eval(searchmatch("530 Login incorrect"))) as Fallidos, 
        count(eval(searchmatch("230 Login successful"))) as Exitosos,
        values(ftp_user) as Usuarios_Probados by src_ip
| where Fallidos > 10 AND Exitosos >= 1
| table src_ip, Usuarios_Probados, Fallidos, Exitosos
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Aislamiento de Perímetro:** Bloquear en el cortafuegos de frontera todo el tráfico originado desde la subred hostil de AWS 15.206.185.0/24.
    
2. **Rotación Inmediata de Secretos:**
    
    - Cambiar la contraseña del usuario forela-ftp.
        
    - Rotar de urgencia la contraseña del servidor SSH de backup (B@ckup2024!).
        
    - Auditar las políticas IAM y revocar las access keys asociadas a los buckets 2023-coldstorage y 2022-warmstor.
        

3. **Decomiso de Protocolos en Texto Plano:** Reemplazar el servicio FTP por protocolos seguros como SFTP (SSH File Transfer Protocol) o FTPS (FTP sobre TLS implícito), forzando el cifrado del canal de autenticación y datos.
    
4. **Restricción de Acceso Administrativo:** Implementar listas de control de acceso (ACLs) para que el servicio de transferencia de archivos solo sea accesible desde rangos IP corporativos autorizados o mediante VPN corporativa.