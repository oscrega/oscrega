### [HTB_COMPROMISED] — Informe Técnico de SOC & Threat Hunting

**Clasificación:** TLP:AMBER (Uso Interno — SOC / Incident Response)  
**Plataforma / Entorno:** Wireshark / Tshark / Network Analysis / Splunk Enterprise ES  
**Objetivo / Infraestructura:** Host interno 172.16.1.191 / C2 Externo 162.252.172.54 & steasteel.net

#### 1. Escenario y Contexto de la Amenaza

- **Resumen Ejecutivo:** Se analizó una captura de tráfico de red (capture.pcap) tras identificarse conexiones anómalas originadas desde un equipo corporativo (172.16.1.191). La investigación forense determinó que el acceso inicial ocurrió el **17 de mayo de 2023** cuando el host descargó un payload ejecutable mediante una petición HTTP GET anómala dirigida a la IP externa **162.252.172.54**. La muestra recuperada correspondió a un loader de la familia de malware **Pikabot** (SHA256: 9b8ffdc8ba2b2caa485cca56a82b2dcbd251f65fb30bc88f0ac3da6704e4d3c6). Tras la infección, el malware estableció sesiones C2 cifradas mediante HTTPS en puertos no estándar (2078, 2222, 32999) utilizando certificados digitales autofirmados con metadatos anómalos (Pyopneumopericardium), e inició un canal de persistencia y exfiltración mediante DNS Tunneling contra la infraestructura de **steasteel.net**.
    
- **Fuentes de Telemetría y Contenido del Dataset:** Captura de paquetes capture.pcap (11.7 MB). Protocolos analizados: HTTP (descarga inicial de payloads), TLS/SSL (inspección de certificados autofirmados en puertos altos), TCP (análisis de flags SYN/RST) y DNS (consultas tunneling).
    

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de la Técnica|Evidencia / Log Específico Hallado|
|**Initial Access / Execution**|T1204.002|User Execution: Malicious File|Descarga y ejecución del loader malicioso Pikabot desde 162.252.172.54/9GQ5A8/6ctf5JL.|
|**Command and Control**|T1573.002|Encrypted Channel: Asymmetric Cryptography|Uso de HTTPS con certificados SSL autofirmados para evadir inspección de tráfico.|
|**Command and Control**|T1571|Non-Standard Port|Comunicaciones C2 dirigidas a los puertos TCP 2078, 2222 y 32999.|
|**Command and Control**|T1071.004|Application Layer Protocol: DNS|Implementación de canal encubierto DNS Tunneling contra steasteel.net.|

#### 3. Cadena de Investigación Forense y Análisis de Telemetría

- **Hipótesis de Búsqueda:** Localizar el primer intento de conexión saliente hacia direcciones IP no corporativas que involucre la descarga de objetos binarios o cierres anómalos de sesión TCP.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r capture.pcap -Y "http.request" -T fields -e frame.time -e ip.src -e ip.dst -e http.request.method -e http.request.uri
tshark -r capture.pcap -Y "ip.addr == 162.252.172.54 && tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e frame.time -e ip.src -e ip.dst
```

- **Desglose Técnico de Evidencias:**
    
    - El host interno **172.16.1.191** inició la conexión mediante una bandera SYN a las **15:32:45 UTC** del **2023-05-17**.
        
    - **Dirección IP del Acceso Inicial:** **162.252.172.54**.
        
    - El equipo emitió una petición GET /9GQ5A8/6ctf5JL, recibiendo una respuesta HTTP 200 OK que entregó el payload encubierto bajo una cabecera de imagen/gif.
        
    - La conexión TCP no se cerró de forma estándar (FIN), sino que fue terminada abruptamente mediante flags **RST/ACK** a las 15:32:50 UTC, comportamiento típico de loaders que descargan su etapa inicial y finalizan el canal.
        

- **Hipótesis de Búsqueda:** Extraer el objeto HTTP transferido y calcular sus hashes criptográficos para correlación en plataformas de CTI.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r capture.pcap --export-objects "http,./extracted_pikabot"
sha256sum extracted_pikabot/*
```

- **Desglose Técnico de Evidencias:**
    
    - **Hash SHA-256 del Malware:**  
        **9b8ffdc8ba2b2caa485cca56a82b2dcbd251f65fb30bc88f0ac3da6704e4d3c6**.
        
    - **Familia del Malware:** **pikabot** (troyano de acceso inicial/loader comúnmente utilizado para descargar Cobalt Strike o ransomware).
        
    - **Primer Avistamiento en Estado Salvaje (First Seen In The Wild):** **2023-05-19 14:01:21 UTC**.
        

- **Hipótesis de Búsqueda:** Analizar los handshakes TLS establecidos hacia puertos no estándar e inspeccionar los campos del certificado X.509.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r capture.pcap -Y "tls.handshake.type == 11" -T fields -e ip.src -e tcp.srcport -e x509sat.printableString
```

- **Desglose Técnico de Evidencias:**
    
    - El malware estableció conexiones HTTPS contra IPs hostiles (como 45.85.235.39 y 193.122.200.171) utilizando puertos no convencionales:
        
        - **Puertos Utilizados (menor a mayor):** **2078, 2222, 32999**.
            
    - **Inspección del Certificado en la Primera IP Maliciosa (45.85.235.39 / Puerto 2078):**
        
        - Parámetro de localidad (id-at-localityName): **Pyopneumopericardium**.
            
        - Validez Temporal (notBefore UTC): **2023-05-14 08:36:52 UTC**.
            

- **Hipótesis de Búsqueda:** Identificar consultas DNS que utilicen el protocolo de nombres como túnel encubierto para tráfico C2.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | grep -v "in-addr.arpa" | sort -u | head -n 10
```

- **Desglose Técnico de Evidencias:**
    
    - El tráfico expuso ráfagas de consultas a subdominios de alta entropía dirigidas hacia el servidor de nombres 78.141.214.249:
        


``` TEXT
ridoj4.26fa3eb6.dns.steasteel.net
```

- **Dominio Utilizado para el Túnel:** **steasteel.net**.
    

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Suricata
alert tls $HOME_NET any -> $EXTERNAL_NET [2078,2222,32999] (msg:"SOC - Deteccion de Trafico C2 Pikabot / Puertos No Estandar"; flow:to_server,established; tls.cert_subject; content:"Pyopneumopericardium"; fast_pattern; classtype:trojan-activity; sid:20260411; rev:1;)
```

- **Consideraciones de Falso Positivo:** Ninguna en entornos de producción. La combinación de puertos inusuales y cadenas de certificado médicas/sintéticas es altamente indicativa de actividad C2 de Pikabot.
    
- **Tuning:** Monitorizar cualquier conexión saliente iniciada desde subredes de usuario hacia puertos superiores al TCP 1024 que transporte tráfico TLS no autorizado.
    


``` SPL
index=network sourcetype="stream:dns" (query="*.steasteel.net" OR query="*steasteel.net*")
| stats count, dc(query) as subdominios, values(query) as muestras by src, dest
| table _time, src, dest, subdominios, count, muestras
```

- **Consideraciones de Falso Positivo:** Cero falsos positivos esperados; el dominio steasteel.net es una infraestructura conocida de amenaza.
    
- **Tuning:** Integrar feeds de inteligencia de amenazas (CTI) para actualizar automáticamente listas de dominios apex asociados a campañas de Pikabot y QakBot.
    

#### 5. Recomendaciones de Contención, Remedición y Hardening

1. **Aislamiento Inmediato del Host:** Aislar el equipo 172.16.1.191 de la red mediante agente EDR para contener el despliegue de módulos secundarios.
    
2. **Bloqueo Perimetral de Infraestructura C2:**
    
    - Denegar el tráfico hacia las IPs 162.252.172.54, 45.85.235.39 y 193.122.200.171.
        
    - Bloquear el tráfico saliente por los puertos 2078, 2222 y 32999.
        
    - Incorporar steasteel.net en la zona de sinkhole del DNS corporativo.
        
3. **Erradicación del Loader:** Extraer y neutralizar los artefactos binarios asociados al hash 9b8ffdc8ba2b2caa485cca56a82b2dcbd251f65fb30bc88f0ac3da6704e4d3c6 en los directorios de ejecución del usuario.
    

4. **Egress Filtering Estricto:** Prohibir por política de cortafuegos perimetral que las estaciones de trabajo cliente establezcan conexiones directas hacia Internet en puertos diferentes al TCP 80, 443 o puertos estándar autorizados.
    
5. **Inspección SSL/TLS (Deep Packet Inspection):** Implementar descifrado e inspección SSL en la pasarela de seguridad web para interceptar payloads ejecutables encubiertos bajo cabeceras MIME manipuladas (ej. ejecutables camuflados como imágenes GIF).