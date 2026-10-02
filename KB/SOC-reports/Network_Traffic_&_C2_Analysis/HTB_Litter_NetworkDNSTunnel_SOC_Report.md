### [HTB_LITTER] — Informe Técnico de SOC & Threat Hunting

**Clasificación:** TLP:AMBER (Uso Interno — SOC / Incident Response)  
**Plataforma / Entorno:** Wireshark / Tshark / PCAP Network Forensics / Splunk Enterprise ES  
**Objetivo / Infraestructura:** Host de pruebas interno (192.168.157.144) / Servidor DNS C2 (192.168.157.145)

#### 1. Escenario y Contexto de la Amenaza

- **Resumen Ejecutivo:** Se investigó una intrusión activa en una máquina de pruebas administrada por el usuario Khalid (192.168.157.144). El activo, situado en una zona desmilitarizada con acceso a recursos internos, fue comprometido por un adversario que operó desde la dirección IP 192.168.157.145. El atacante desplegó una herramienta personalizada de **DNS Tunneling** (versión 0.07), la cual intentó enmascarar en disco bajo el nombre win_installer.exe. Mediante este canal encubierto, el actor de amenaza ejecutó comandos interactivos de reconocimiento (whoami), inspeccionó directorios de almacenamiento en la nube (OneDrive) y localizó un repositorio de datos de clientes (C:\Users\test\Documents\client data optimisation\user details.csv). Finalmente, exfiltró **721 registros de Información de Identificación Personal (PII)** encapsulando los datos codificados en consultas DNS hacia el dominio fraudulento microsoft360.com.
    
- **Fuentes de Telemetría y Contenido del Dataset:** Captura de paquetes crudos suspicious_traffic.pcap (42.3 MB). Protocolos analizados: DNS (consultas y respuestas con etiquetas de longitud anómala), TCP (escaneo de puertos) y ARP. Delimitación temporal: sesión interactiva y exfiltración masiva de datos estructurados vía túnel DNS.
    

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de la Técnica|Evidencia / Log Específico Hallado|
|**Command and Control**|T1071.004|Application Layer Protocol: DNS|Establecimiento de canal C2 bidireccional mediante DNS Tunneling contra microsoft360.com.|
|**Defense Evasion**|T1036.005|Masquerading: Match Legitimate Name|Renombrado de la utilidad de túnel en el host víctima como win_installer.exe.|
|**Discovery**|T1033|System Owner/User Discovery|Ejecución del comando interactivo whoami transmitido como instrucción dentro del túnel.|
|**Discovery**|T1083|File and Directory Discovery|Inspección de directorios de OneDrive y localización de la carpeta client data optimisation.|
|**Collection**|T1005|Data from Local System|Lectura directa del archivo user details.csv mediante el comando del sistema type.|
|**Exfiltration**|T1048.003|Exfiltration Over Alternative Protocol: DNS|Exfiltración de 721 registros PII fragmentados y codificados en subdominios DNS.|

#### 3. Cadena de Investigación Forense y Análisis de Telemetría

- **Hipótesis de Búsqueda:** Aislar protocolos con volúmenes de transferencia y frecuencias de petición desproporcionadas respecto al perfil de tráfico estándar.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r suspicious_traffic.pcap -q -z io,phs
tshark -r suspicious_traffic.pcap -Y "dns" -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -nr
```

- **Desglose Técnico de Evidencias:**
    
    - El protocolo **DNS** concentró la anomalía principal, evidenciando un tráfico masivo de consultas consecutivas con etiquetas de longitud variable hacia el dominio **microsoft360.com**.
        
    - **Dirección IP de la Víctima:** **192.168.157.144**.
        
    - **Dirección IP del Servidor DNS Hostil / C2:** **192.168.157.145**.
        

- **Hipótesis de Búsqueda:** Extraer los nombres de consulta DNS enviados por el cliente y decodificar el payload hexadecimal/base32 para reconstruir la sesión de shell.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r suspicious_traffic.pcap -Y "dns && ip.src == 192.168.157.145" -T fields -e dns.qry.name | xxd -r -p > exfil.txt
strings exfil.txt | head -n 30
```

- **Desglose Técnico de Evidencias:**
    
    - **Primer Comando Transmitido:** El adversario inició la interacción con el comando de reconocimiento **whoami**.
        
    - **Versión del Software de Túnel:** Las cadenas iniciales de negociación del túnel expusieron la versión de la herramienta: **0.07**.
        
    - **Renombrado del Artefacto (Evasión):** El atacante intentó renombrar el binario dejado en el host para camuflarlo entre los procesos del sistema, asignándole el nombre: **win_installer.exe**.
        

- **Hipótesis de Búsqueda:** Analizar los comandos de navegación emitidos por el atacante dentro del flujo decodificado.
    
- **Consultas y Comandos Operativos:**
    


``` bash
strings exfil.txt | grep -i -C 5 "onedrive"
strings exfil.txt | grep -i -C 5 "type "
```

- **Desglose Técnico de Evidencias:**
    
    - **Inspección de Cloud Storage:** El atacante ejecutó comandos para listar el directorio local de OneDrive; la salida reportó un tamaño de **0 bytes** (sin archivos sincronizados en ese momento).
        
    - **Localización del Repositorio PII:** En la línea 651 del volcado, el atacante ejecutó la lectura del archivo de clientes:
        


``` Cmd
type "C:\Users\test\Documents\client data optimisation\user details.csv"
```

- **Ruta Completa Identificada:** **C:\Users\test\Documents\client data optimisation\user details.csv**.
    

- **Hipótesis de Búsqueda:** Aislar la estructura de datos transmitida para determinar el número exacto de clientes comprometidos.
    
- **Consultas y Comandos Operativos:**
    


``` Bash
strings exfil.txt | sed -n '650,5180p' > stolen.txt
head -n 5 stolen.txt
tail -n 5 stolen.txt
```

- **Desglose Técnico de Evidencias:**
    
    - El archivo extraído presentaba una estructura secuencial con identificadores numéricos.
        
    - El primer registro inició en el ID 0 y el último concluyó en el ID 720.
        
    - **Total de Registros PII Exfiltrados:** Exactamente **721 registros de clientes** (incluyendo nombres, correos electrónicos y datos de empresas).
        

#### 4. Ingeniería de Detección (Reglas de Alerta & Correlación)


``` Suricata
alert dns $HOME_NET any -> any 53 (msg:"SOC - Sospecha de DNS Tunneling / Exfiltracion (microsoft360.com)"; dns.query; content:".microsoft360.com"; isdataat:30,relative; pcre:"/^[a-f0-9]{20,}\.microsoft360\.com$/i"; classtype:bad-unknown; sid:20260410; rev:1;)
```

- **Consideraciones de Falso Positivo:** Ninguna contra dominios no registrados por Microsoft. microsoft360.com es un dominio malicioso que no pertenece a la infraestructura legítima de Microsoft.
    
- **Tuning:** Configurar umbrales de frecuencia para alertar ante más de 100 consultas por minuto con patrones regex de alta entropía.
    


``` SPL
index=network sourcetype="stream:dns" query_type="A" OR query_type="TXT"
| eval query_len=len(query)
| where query_len > 50
| stats count, dc(query) as subdominios_unicos, values(query) as muestras by src, dest
| where subdominios_unicos > 50
| table src, dest, subdominios_unicos, count, muestras
```

- **Consideraciones de Falso Positivo:** Mecanismos de protección antivirus/antispam basados en DNSBL (RBL) o redes CDN complejas.
    
- **Tuning:** Excluir servidores DNS internos autorizados y listas blancas de proveedores CDN conocidos (ej. Akamai, Cloudflare).
    

#### 5. Recomendaciones de Contención, Remedición y Hardening

1. **Aislamiento del Host:** Desconectar inmediatamente la máquina de pruebas 192.168.157.144 del segmento de red.
    
2. **Bloqueo DNS Perimetral:**
    
    - Crear una regla en el firewall/DNS Sinkhole bloqueando cualquier resolución hacia el dominio **microsoft360.com**.
        
    - Aislar la IP interna hostil **192.168.157.145**.
        
3. **Notificación de Brecha de Datos:** Activar el protocolo de notificación a los 721 clientes cuyos datos personales fueron expuestos, de acuerdo con las directivas del RGPD / regulaciones locales.
    

4. **Restricción de Resoluciones DNS Directas:** Forzar a todos los endpoints a resolver exclusivamente a través de los servidores DNS corporativos internos, bloqueando en el firewall perimetral las salidas directas por el puerto UDP/TCP 53 hacia servidores externos.
    
5. **Inspección de DNS de Próxima Generación:** Habilitar motores de análisis de reputación y detección de túneles DNS en el firewall perimetral o pasarela DNS (ej. Cisco Umbrella, Infoblox BloxOne).