### [HTB_CUIDADO] — Informe Técnico de SOC & Threat Hunting

**Clasificación:** TLP:AMBER (Uso Interno — SOC / Incident Response)  
**Plataforma / Entorno:** Wireshark / Tshark / Linux Network & Artifact Forensics / Splunk Enterprise ES  
**Objetivo / Infraestructura:** Estación de trabajo interna (192.168.1.152) / Despliegue de Botnet de Minería RedTail

---

#### 1. Escenario y Contexto de la Amenaza

- **Resumen Ejecutivo:** Se investigó una serie de alertas generadas tras la descarga reiterada de aplicaciones potencialmente no deseadas (PUAs) en la estación de trabajo 192.168.1.152. La captura y posterior inspección forense del tráfico de red (network_capture.pcap) evidenció una intrusión orientada al secuestro de recursos (Cryptojacking). El host interno estableció comunicación HTTP con el servidor malicioso 94.156.177.109:80 para descargar un script de shell inicial (sh). Dicho script perfiló la arquitectura de la CPU mediante uname -mp, eludió particiones de almacenamiento con restricciones noexec, ejecutó un script de sanitización (clean) para erradicar mineros competidores y cron jobs rivales, y descargó el payload compilado de 64 bits (x86_64). El binario fue empaquetado con UPX v4.23 y renombrado en disco como el archivo oculto .redtail, identificándose como una variante activa de la botnet de minería **RedTail** (muestra histórica redtail.cuidado).
    
- **Fuentes de Telemetría y Contenido del Dataset:** Captura de paquetes network_capture.pcap (2.1 MB). Artefactos HTTP reensamblados: scripts shell (sh, clean) y binario ELF empaquetado (x86_64). Métricas de entropía analizadas con la utilidad ent y desempaquetado con upx.
    

---

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de la Técnica|Evidencia / Log Específico Hallado|
|**Execution**|T1059.004|Command and Scripting Interpreter: Unix Shell|Descarga y ejecución de scripts Bash (sh y clean) para orquestar la infección.|
|**Impact**|T1496|Resource Hijacking|Ejecución del minero .redtail con el fin de monopolizar ciclos de CPU en el host víctima.|
|**Defense Evasion**|T1027.002|Obfuscated Files or Information: Software Packing|Binario x86_64 empaquetado con UPX v4.23 (entropía post-unpacking de 6.488449).|
|**Defense Evasion**|T1562.001|Impair Defenses: Disable or Modify Tools|Neutralización de mineros rivales vía systemctl disable c3pool_miner y purga de crontabs.|
|**Defense Evasion**|T1564.001|Hide Artifacts: Hidden Files and Directories|Renombrado del ejecutable a .redtail y uso de archivos temporales ocultos (.testfile, .testfile2).|
|**Discovery**|T1082|System Information Discovery|Invocación de uname -mp para mapear la arquitectura antes de descargar el binario afín.|

---

#### 3. Cadena de Investigación Forense y Análisis de Telemetría

- **Hipótesis de Búsqueda:** Identificar la IP interna origen que presenta el mayor número de conexiones HTTP salientes hacia infraestructuras no categorizadas.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r network_capture.pcap -q -z conv,ip
tshark -r network_capture.pcap -Y "http.request.method == \"GET\"" -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri
```

- **Desglose Técnico de Evidencias:**
    
    - **Dirección IP de la Víctima:** **192.168.1.152** (mayor consumidor de ancho de banda y conexiones externas).
        
    - **Dirección IP del Atacante (Servidor de Descarga):** **94.156.177.109** (puerto TCP **80**).
        
    - **Primer Archivo Descargado:** Petición GET /sh HTTP/1.1, retornando un script ejecutable Bash.
        

- **Hipótesis de Búsqueda:** Reconstruir las funciones de red y los mecanismos de evasión de políticas de almacenamiento definidos en el loader.
    
- **Consultas y Comandos Operativos:**
    


``` bash
tshark -r network_capture.pcap --export-objects "http,./extracted_files"
cat extracted_files/sh
```

- **Desglose Técnico de Evidencias:**
    
    - **Función de Descarga:** Definición de **dlr()**, la cual implementa redundancia mediante wget y curl -O, con un fallback de bajo nivel que abre un descriptor de socket directo hacia /dev/tcp/94.156.177.109/80.
        
    - **Evasión de Particiones noexec:** El script consulta /proc/mounts para listar y descartar cualquier punto de montaje que tenga activo el flag noexec.
        
    - **Prueba de Escritura en Disco:** Valida la capacidad de escritura en /tmp, /var/tmp y /dev/shm generando archivos de prueba. El tamaño del segundo archivo (.testfile2), generado con dd if=/dev/zero of=.testfile2 bs=2M count=1, es exactamente de **2 MB**.
        
    - **Identificación de Arquitectura:** El script perfila el entorno mediante la invocación directa de:
        


``` bash
ARCH=$(uname -mp)
```

- **Payload Descargado:** Al validar coincidencia con x86_64/amd64, invoca dlr x86_64 y renombra la muestra a **.redtail**.
    

- **Hipótesis de Búsqueda:** Analizar las acciones ejecutadas por el segundo script invocado (clean) en el sistema de archivos del endpoint.
    
- **Desglose Técnico de Evidencias:**
    
    - El atacante busca eliminar mineros preexistentes para asegurar el consumo exclusivo de la CPU:
        


``` bash
systemctl disable c3pool_miner
systemctl stop c3pool_miner
```

- **Sanitización de Tareas Programadas:** Retira atributos inmutables (chattr -ia) en /var/spool/cron/crontabs/* y /etc/cron*, purgando cualquier línea que contenga comandos como wget, curl, base64 o /dev/tcp.
    

- **Hipótesis de Búsqueda:** Determinar el empaquetador del binario, medir su nivel de entropía tras el desempaquetado y extraer identificadores CTI.
    
- **Consultas y Comandos Operativos:**
    


``` bash
strings extracted_files/x86_64 | grep -i "upx"
upx -d extracted_files/x86_64 -o ./x86_64_unpacked
ent ./x86_64_unpacked
```

- **Desglose Técnico de Evidencias:**
    
    - **Versión del Packer:** El binario fue protegido utilizando **UPX 4.23** ($Id: UPX 4.23 Copyright (C) 1996-2024 the UPX Team$).
        
    - **Entropía del Malware Desempaquetado:** **6.488449 bits por byte**, métrica estándar para código ejecutable compilado nativo libre de capas de cifrado.
        
    - **Atribución CTI (VirusTotal):** Nombre con el que la muestra fue enviada por primera vez al repositorio: **redtail.cuidado**.
        
    - **Clasificación de Amenaza:** Botnet de minería **RedTail** (asociada al uso de binarios XMRig embebidos para minería de Monero).
        

---

#### 4. Ingeniería de Detección (Reglas de Alerta & Correlación)


``` Suricata
alert http 94.156.177.109 80 -> $HOME_NET any (msg:"SOC - Descarga de Stager RedTail Cryptominer (Funcion dlr)"; flow:from_server,established; file_data; content:"dlr()"; content:"/dev/tcp/94.156.177.109"; fast_pattern; classtype:trojan-activity; sid:20260420; rev:1;)
```

- **Consideraciones de Falso Positivo:** Nulas en tráfico corporativo estándar; la combinación de la función dlr() y la llamada explícita a /dev/tcp/ hacia una IP pública es estrictamente anómala.
    
- **Tuning:** Aplicar la regla a toda la pasarela de salida web sin restringir por IP de origen interna.
    


``` SPL
index=os_logs sourcetype=auditd (comm="sh" OR comm="bash") (a0="*/.redtail*" OR a1="*/.redtail*" OR a0="*/.testfile*" OR a1="*c3pool_miner*")
| stats count min(_time) as primer_evento max(_time) as ultimo_evento values(comm) as binario values(a1) as argumentos by host, ppid, pid, uid
| convert ctime(primer_evento) ctime(ultimo_evento)
| table primer_evento, ultimo_evento, host, ppid, pid, uid, binario, argumentos, count
```

- **Consideraciones de Falso Positivo:** Scripts de mantenimiento de TI que utilicen directorios temporales, aunque rara vez emplean nombres con punto inicial (.redtail).
    
- **Tuning:** Filtrar servicios de monitorización legítimos agregando listas blancas por UID y firma criptográfica del binario padre.
    

---

#### 5. Recomendaciones de Contención, Remedición y Hardening

1. **Aislamiento del Host:** Desconectar la estación de trabajo 192.168.1.152 de la red corporativa mediante cuarentena en el agente EDR.
    
2. **Terminación de Procesos:** Matar cualquier proceso asociado a la ejecución de .redtail o llamadas a sockets Bash:
    


``` bash
pkill -9 -f "\.redtail"
```

1. **Bloqueo Perimetral:** Incorporar en el firewall perimetral y DNS sinkhole el bloqueo bidireccional de la dirección IP **94.156.177.109**.
    
2. **Erradicación de Archivos en Disco:** Localizar y purgar todos los artefactos generados en /tmp, /var/tmp y /dev/shm:
    


``` bash
find / -name ".redtail" -o -name ".testfile*" -exec rm -rf {} +
```

1. **Directivas de Montaje de Almacenamiento Temporal (noexec):** Configurar /etc/fstab para forzar las opciones noexec,nosuid,nodev en /tmp, /var/tmp y /dev/shm, neutralizando la capacidad del stager de invocar binarios compilados en rutas temporales.
    
2. **Restricción de Sockets de Red en Shell:** Auditar y bloquear el uso interactivo de /dev/tcp mediante políticas AppArmor o SELinux en modo Enforcing.
    
3. **Monitoreo de Integridad de Tareas Programadas:** Implementar reglas de auditd para detectar escrituras o cambios de atributos (chattr) sobre /var/spool/cron/ y /etc/cron*.