### [HTB_JINGLEBELL] — Informe Técnico de SOC & Threat Hunting

**Clasificación:** TLP:AMBER (Uso Interno — SOC / Incident Response)  
**Plataforma / Entorno:** Windows Endpoint / SQLite Database Forensics / DB Browser for SQLite  
**Objetivo / Infraestructura:** Estación de trabajo de Torrin (C:\Users\Torrin) / Base de datos WPN

#### 1. Escenario y Contexto de la Amenaza

- **Resumen Ejecutivo:** Se investigó un presunto caso de amenaza interna (Insider Threat) protagonizado por el empleado Torrin en la red corporativa de Forela. Las sospechas iniciales de fuga de datos no arrojaron evidencias en los registros tradicionales de almacenamiento debido a que el usuario desinstaló aplicaciones no autorizadas antes de la inspección. No obstante, el análisis forense de la base de datos de notificaciones del sistema operativo (**wpndatabase.db**) permitió recuperar los registros transaccionales generados por la aplicación **Slack**. La reconstrucción de las alertas Toast y NotificationHandler demostró que Torrin estableció contacto con un agente de la empresa rival **PrimeTech Innovations** (Cyberjunkie-PrimeTechDev), coordinó la fuga de planes petroleros de Forela en Angola a través de un canal encubierto (forela-secrets-leak), proporcionó la contraseña del servidor de archivos corporativo y aceptó un soborno de **£10,000** tras transferir la información hacia una carpeta externa de Google Drive.
    
- **Fuentes de Telemetría y Contenido del Dataset:** Artefactos de la base de datos de Windows Push Notifications (WPN): wpndatabase.db, wpndatabase.db-wal (Write-Ahead Logging) y wpndatabase.db-shm. Ubicación: C:\Users\Torrin\AppData\Local\Microsoft\Windows\Notifications\.
    

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de la Técnica|Evidencia / Log Específico Hallado|
|**Exfiltration**|T1567.002|Exfiltration to Cloud Storage|Fuga de archivos sensibles hacia un enlace público de Google Drive proporcionado por el competidor.|
|**Exfiltration**|T1048|Exfiltration Over Alternative Protocol|Uso de la aplicación de mensajería no corporativa Slack para transmitir credenciales del servidor de archivos.|
|**Defense Evasion**|T1070.006|Indicator Removal: File Deletion|Desinstalación de la aplicación Slack para eliminar el historial local en el sistema de archivos.|
|**Credential Access**|T1552|Unsecured Credentials|Filtración explícita de la contraseña corporativa Tobdaf8Qip$re@1.|

#### 3. Cadena de Investigación Forense y Análisis de Telemetría

- **Hipótesis de Búsqueda:** Identificar manejadores de notificaciones en la base de datos WPN que apunten a aplicaciones no autorizadas desinstaladas del perfil de usuario.
    
- **Consultas y Comandos Operativos:**
    


``` SQL
SELECT RecordId, PrimaryId, AppId FROM NotificationHandler WHERE PrimaryId LIKE '%slack%' OR AppId LIKE '%slack%';
```

- **Desglose Técnico de Evidencias:**
    
    - En la tabla NotificationHandler, el registro ID **164** correspondió al paquete de escritorio: **com.squirrel.slack.slack**.
        
    - En la tabla Notification, los payloads XML revelaron invocaciones activas al protocolo de mensajería: **slack://**.
        
    - **Aplicación Utilizada:** **Slack**.
        

- **Hipótesis de Búsqueda:** Analizar los fragmentos XML en la tabla Notification para extraer títulos, remitentes y entidades externas en las conversaciones de Slack.
    
- **Consultas y Comandos Operativos:**
    


``` SQL
SELECT Id, HandlerId, Type, Payload FROM Notification WHERE HandlerId = 164;
```

- **Desglose Técnico de Evidencias:**
    
    - El adversario/competidor fue identificado en una notificación de invitación de Slack:
        
        - **Empresa Competidora:** **PrimeTech Innovations**.
            
        - **Identidad del Contacto:** **Cyberjunkie-PrimeTechDev**.
            
    - Las comunicaciones se mantuvieron dentro de un canal dedicado:
        
        - **Nombre del Canal:** **forela-secrets-leak**.
            

- **Hipótesis de Búsqueda:** Inspeccionar el cuerpo de los mensajes en busca de credenciales corporativas o accesos transferidos a la entidad rival.
    
- **Desglose Técnico de Evidencias:**
    
    - Torrin transmitió la clave de acceso a los repositorios de Forela:
        
        - Mensaje: "Password for archive server is: ..."
            
        - **Contraseña Revelada:** **Tobdaf8Qip$re@1**.
            
        - Justificación del Atacante: "Solo para confirmar, ya que no queremos que el equipo de TI de Forela se ponga sospechoso."
            

- **Hipótesis de Búsqueda:** Extraer URLs de servicios cloud utilizados como buzón de entrega y marcas de tiempo de las transacciones.
    
- **Desglose Técnico de Evidencias:**
    
    - El contacto de PrimeTech proporcionó un repositorio para la carga masiva de los proyectos petroleros de Angola:
        
        - **URL de Exfiltración:**  
            https://drive.google.com/drive/folders/1vW97VBmxDZUIEuEUG64g5DLZvFP-Pdll?usp=sharing
            
    - **Timestamp de Envío del Enlace:**
        
        - Valor Unix registrado en la base de datos: 1681986889.660179.
            
        - **Fecha y Hora UTC:** **2023-04-20 10:34:49 UTC**.
            
    - **Monto del Soborno (Compensación):**
        
        - En el último mensaje de la conversación, el agente de PrimeTech confirmó el pago:
            
        - Mensaje: "Número de cuenta bancaria: 03135905179789. Envié 10.000 £ a la cuenta anterior como prometí, saludos."
            
        - **Monto Transferido:** **£10,000**.
            

#### 4. Ingeniería de Detección (Reglas de Alerta & Correlación)


``` Yaml
title: Ejecucion de Cliente Slack en Endpoint No Autorizado
id: 3c91a421-d112-4fb1-9a11-slackunauthorized
status: production
description: Detecta la ejecucion de binarios o instaladores de Slack desde carpetas de usuario no estandar.
references:
  - https://attack.mitre.org/techniques/T1567/
author: Senior Threat Hunter
date: 2026-04-02
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|contains:
      - '\AppData\Local\slack\'
      - '\slack.exe'
  condition: selection
level: medium
tags:
  - attack.exfiltration
  - attack.t1567
```

- **Consideraciones de Falso Positivo:** Equipos o departamentos que tengan Slack formalmente aprobado como herramienta de comunicación corporativa.
    
- **Tuning:** Filtrar máquinas asignadas a equipos de TI o desarrollo autorizados.
    


``` SPL
index=proxy sourcetype="pan:traffic" (dest_host="*drive.google.com*" OR dest_host="*dropbox.com*" OR dest_host="*mega.nz*")
| where bytes_out > 50000000
| stats sum(bytes_out) as total_subido values(dest_host) as destinos by user, src_ip
| table user, src_ip, destinos, total_subido
```

- **Consideraciones de Falso Positivo:** Usuarios con permisos para sincronizar copias de seguridad legítimas con cuentas corporativas de Google Workspace.
    
- **Tuning:** Requerir inspección SSL/TLS (descifrado en proxy) para validar si la cuenta de autenticación es corporativa (@forela.co.uk) o personal.
    

#### 5. Recomendaciones de Contención, Remedición y Hardening

1. **Revocación Inmediata de Credenciales:** Cambiar de forma urgente la contraseña del servidor de archivos corporativo (Tobdaf8Qip$re@1) y auditar todas las conexiones activas al servidor.
    
2. **Acción Legal y Administrativa:** Remitir las evidencias forenses a la Dirección Legal y de Recursos Humanos para la rescisión laboral y acciones legales por revelación de secretos industriales.
    
3. **Petición de Abuso / Take-Down:** Notificar a Google Abuse sobre la carpeta de Google Drive involucrada para bloquear el acceso a los documentos confidenciales.
    

4. **Control de Aplicaciones (AppLocker / WDAC):** Restringir la ejecución de binarios que utilicen el gestor Squirrel o se ubiquen en %LOCALAPPDATA%, impidiendo que los usuarios instalen software no corporativo sin privilegios de administrador.
    
5. **Políticas de Data Loss Prevention (DLP):** Implementar agentes DLP en endpoints para supervisar e interceptar la subida de archivos confidenciales (.pdf, .docx, esquemas CAD) hacia servicios de almacenamiento cloud no autorizados.