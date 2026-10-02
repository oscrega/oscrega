
El siguiente ejercicio tiene como finalidad el aprendizaje del lenguaje SPL utilizado en la herramienta Splunk y el objetivo de detectar ataques de inyección SQL anómalos.


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

|**Sourcetype**|**¿Por qué es vital?|
|---|---|
|**winregistry|Detecta persistencia de malware. Si un atacante quiere quedarse en el sistema, modificará el registro.|
|**mysql:transaction:details|Esencial para detectar SQL Injection. Aquí verás las consultas exactas que llegan a la base de datos.|
|**winhostmon|Te dice qué está pasando a nivel de sistema: qué servicios están activos y qué software está instalado.|
|**stream:ip / stream:tcp|Tu visibilidad de red. Aquí detectarás exfiltración de datos, comunicaciones C2 (Commando y Control) y escaneos.|
|**wineventlog:security|La "biblia" de Windows. Autenticaciones, intentos fallidos de login (Brute Force) y cambios de permisos.|
|**suricata|Logs de un IDS (Intrusion Detection System). Ya vienen etiquetados con firmas de ataque, ideal para practicar detección rápida.|

### Fase de hipótesis

###### Enunciado

El equipo de seguridad ha detectado un comportamiento anómalo en el servidor de base de datos MySQL (gacrux). Se sospecha de un intento de extracción de información no autorizada mediante ataques de Inyección SQL. Como analista, tu objetivo es identificar las consultas maliciosas, localizar al atacante y documentar el alcance del intento de intrusión.

###### Preguntas y objetivos

*Para completar este ejercicio en tu bitácora, debes resolver los siguientes puntos basándote en los resultados obtenidos del commando anterior:

Confirmación: ==¿La búsqueda arrojó resultados sospechosos? (Indica sí o no).

Identificación del Atacante: ==¿Cuál es la dirección IP (client_ip) con mayor cantidad de consultas maliciosas detectadas?

Análisis de Impacto: ==¿Qué tablas de la base de datos aparecen en las consultas SQL_TEXT realizadas por esa IP? (Ejemplo: mybb_users, mybb_threads, etc.).

Evaluación: ==¿Consideras que este ataque fue exitoso o simplemente un sondeo (escaneo) por parte del atacante? (Argumenta brevemente basándote en lo que ves en los resultados).

###### Commando inicial

``` bash
index=botsv2 sourcetype="mysql:transaction:details"
| regex SQL_TEXT="(?i)(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--|\#|\/\*)"
| head 20
| table _time, client_ip, SQL_TEXT
```

###### Evidencia

Aparecen varias consultas aparentemente legítimas de una aplicación tipo foro (mybb) realizando operaciones normals y comunes.

![[Pasted image 20260607152627.png]]


### Fase de investigación

Utilizaremos el siguiente commando para filtrar por consultas a la base de datos, ignorando consultas normals de aplicaciones y buscando patrones comunes de inyección SQL.

###### Commando utilizado para detectar inyección SQL

``` bash
index=botsv2 sourcetype="mysql:transaction:details"
| search SQL_TEXT="*UNION*" OR SQL_TEXT="*--*" OR SQL_TEXT="*OR*1=1*"
| table _time, client_ip, SQL_TEXT
| sort - _time
```

###### Explicación del commando

`index=botsv2 sourcetype="mysql:transaction:details"`: 

- index=botsv2: ==Filtra los datos para que Splunk busque únicamente dentro del índice donde están guardados los eventos de tu laboratorio de Threat Hunting.

- sourcetype="mysql:transaction:details": ==Restringe la búsqueda a los logs que provienen específicamente de las transacciones de MySQL. Esto elimina el ruido de otros logs (como web, firewall o DNS) para que la búsqueda sea mucho más rápida y precisa.

``
`| regex SQL_TEXT="(?i)(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--|\#|\/\*)"`

- regex: ==Indica que vamos a buscar mediante expresiones regulares, que son más potentes que una simple búsqueda de texto plano.

- SQL_TEXT: ==Es el campo de los logs que contiene la consulta SQL enviada a la base de datos.

- (?i): ==Esta bandera activa la insensibilidad a mayúsculas/minúsculas. Buscará tanto "SELECT" como "select" o "SeLeCt".

- **(UNION|SELECT|...|\/\*): ==Es una lista de commandos y caracteres que, en un contexto de base de datos, son altamente sospechosos. Por ejemplo: UNION, SELECT, INSERT, etc., son palabras clave usadas para extraer o modificar datos ilegalmente. --, # y /* son los caracteres de comentario en SQL. Un atacante los usa para "anular" el resto de la consulta original del desarrollador y así poder inyectar su propio código malicioso.


`head 20`: ==Le ordena a Splunk que, de todos los eventos que encontró, solo te entregue los 20 más recientes.

`| table _time, client_ip, SQL_TEXT`

- table: ==Define cómo quieres visualizar la información. En lugar de ver el evento completo (que es muy largo y lleno de datos técnicos innecesarios), creamos una tabla limpia con tres columnas clave:

- __time: ¿Cuándo ocurrió la consulta? (Vital para crear tu línea de tiempo).

- client_ip: ¿Quién lo hizo? (Es la pieza de evidencia más importante para identificar al atacante).

- SQL_TEXT: ¿Qué intentó hacer? (Para ver la intención maliciosa en el código).


###### Evidencias

![[Pasted image 20260607155702.png]]

En la evidencia se pueden observar una series de consultas que confirman la fase de reconocimiento de un atacante. Este comportamiento es un indicador de compromiso de tipo SQL Injection. El atacante no está buscando un usuario específico todavía, sino que está usando UNION y SELECT para forzar el servidor y conseguir información sobre la configuración del sistema, probablemente, para posteriormente escalar privilegios o identificar tablas de usuarios.

###### Informe de incidente

**Vector de ataque detectado: SQL Injection (SQLi).

**Técnica: Enumeración de base de datos mediante UNION SELECT sobre INFORMATION_SCHEMA.

**Evidencia: Consultas masivas recurrentes solicitando variables de sesión del servidor (information_schema.session_variables).

**Estado del ataque: Sondeo activo. El atacante está mapeando la estructura de la base de datos para preparar una exfiltración posterior.

**Próximo paso: Identificar la IP del atacante con stats count by client_ip y verificar si hay eventos posteriores donde consulte mybb_users.


###### Identificación del atacante

En este apartado debemos de identificar al atacante, así como la IP con mayor cantidad de consultas maliciosas.

Para ello, se utilizaron varios commandos pero ninguno dio resultado. Se llego a la conclusión de que debido a una deficiencia en la normalización de los logs, no fue possible extraer la client_ip de los eventos de base de datos (mysql:transaction:details).

No obstante se han detectado 662,286 eventos maliciosos de inyección SQL en el dataset completo utilizando el siguiente commando

``` bash
index=botsv2 sourcetype="mysql:transaction:details"
| regex SQL_TEXT="(?i)UNION\s+SELECT"
| stats count as Total_Consultas_Maliciosas
```

![[Pasted image 20260607161544.png]]

Para detectar el rango de fechas de estos 662,286 eventos se ha utilizado el siguiente commando

``` bash
index=botsv2 sourcetype="mysql:transaction:details" SQL_TEXT="*UNION*"
| stats min(_time) as primera_vez, max(_time) as ultima_vez
| convert ctime(primera_vez) ctime(ultima_vez)
```

![[Pasted image 20260607161729.png]]


### Conclusión

1. Confirmación: ¿La búsqueda arrojó resultados sospechosos?

	Respuesta: ==Sí. Se han identificado patrones claros de inyección SQL (SQLi) mediante el uso de UNION SELECT, una técnica utilizada para combinar resultados de consultas legítimas con datos extraídos de tablas del sistema.

2. Identificación del atacante: ¿Cuál es la dirección IP (client_ip) con mayor cantidad de consultas maliciosas detectadas?

	Respuesta: ==Se utilizaron varios commandos pero ninguno dio resultado. Se llego a la conclusión de que debido a una deficiencia en la normalización de los logs, no fue possible extraer la client_ip de los eventos de base de datos (mysql:transaction:details).

3. Análisis de Impacto: ¿Qué tablas de la base de datos aparecen en las consultas SQL_TEXT realizadas por esa IP?

    Respuesta: ==El atacante se ha centrado específicamente en INFORMATION_SCHEMA.session_variables. Esto indica que no está consultando tablas de contenido del foro (como mybb_users o mybb_threads) en esta fase, sino que está realizando una enumeración de metadatos para entender la configuración, el puerto y el nombre de la base de datos del servidor gacrux.

4. Evaluación: ¿Consideras que este ataque fue exitoso o simplemente un sondeo (escaneo)?

    Respuesta: ==Es un sondeo (escaneo) activo. El ataque fue "exitoso" en términos de ejecución (la base de datos respondió a las consultas), pero el impacto se limita a una fase de reconocimiento. El atacante ha logrado mapear la estructura de variables del servidor, lo cual es el paso previo necesario para intentar una exfiltración de datos sensibles o una escalada de privilegios en fases posteriores del ataque.

