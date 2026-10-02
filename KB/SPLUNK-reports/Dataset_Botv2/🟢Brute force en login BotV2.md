
El siguiente ejercicio tiene como finalidad el aprendizaje del lenguaje SPL utilizado en la herramienta Splunk y el objetivo de detectar ataques de fuerza bruta en relación a logins de usuarios (Para este ejercicio el objetivo es la detección de brute force en logins pero no la detección de logins anómalos como tal).


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

Hemos detectado intentos de autenticación fallidos en el servidor web que aloja el foro (gacrux). El equipo de seguridad teme que un atacante esté intentando adivinar contraseñas de cuentas de administrador (ataque de fuerza bruta). Tu objetivo es encontrar qué usuario está siendo atacado y si alguno de esos intentos resultó en un login exitoso.

Para ello utilizaremos el siguiente commando incial, el cual nos ayudará a buscar eventos de log que tengan una relación con el proceso de login.

El primer commando nos ayuda a identificar todos los sourcetype 

``` bash
index=botsv2
| head 50
| table sourcetype, _raw
```
Se puede observar que el sourcetype correto para detectar logins anómalos es stream:http

![[Pasted image 20260607183956.png]]

El siguiente commando nos ayuda a identificar IPs, código de estado y conteo del número de inicios de sesión 

``` bash
index=botsv2 sourcetype="stream:http" (uri="*/login*" OR uri="*/auth*")
| stats count by src_ip, status
| sort - count
```

![[Pasted image 20260607184041.png]]

Se puede observar que hay muchos inicios de sesión con status 200. En caso de ataque de fuerza bruta deben aparecer varios intentos de inicio de sesión con status 401.

En la fase de investigación mejoraremos el commando de búsqueda para encontrar los intentos de inicio de sesión que no sean exitosos.

### Fase de investigación

A continuación se detallan los commandos utilizados para encontrar inicios de sesión con status 401 (diferentes a 200).

###### Commando utilizado

``` bash
index=botsv2 sourcetype="stream:http" (uri="*/login*" OR uri="*/auth*") status!=200
| stats count by src_ip, status
| sort - count
```

###### Evidencia

![[Pasted image 20260607184716.png]]

Se pueden observar que solo hay intentos de inicio de sesión con status 200 y 302.

El status de 302 en inicios de sesión HTTP significan redirecciones en este caso, a continuación se detalla porque.

En las plataformas de comercio electrónico como Magento, cuando un usuario no autenticado intenta forzar el acceso a un recurso protegido (o cuando un script interactúa con ciertos endpoints de sesión), el servidor suele responder con un 302 para redirigir el tráfico de vuelta a la página principal de login o al índice indexado. Por lo tanto, esos 302 que ves en tus logs son la confirmación de que la plataforma web estuvo rebotando expulsado al atacante hacia fuera de las zonas restringidas de la API. Esto refuerza tu conclusión de que la intrusión fue negativa.

Vamos a ver qué URIs están solicitando y quién está haciendo peticiones a gran volumen, sin importar el código de estado con el siguiente commando:

###### Commando utilizado

``` bash
index=botsv2 sourcetype="stream:http"
| stats count by src_ip, uri
| sort - count
```

###### Evidencia

![[Pasted image 20260608002105.png]]
![[Pasted image 20260608002118.png]]

Las capturas muestran un possible ataque distribuido contra la plataforma Magento 2. 

las URLs `(/magento2/rest/default/V1/carts/mine/estimate-shipping-methods` y `/magento2/checkout/cart/add/uenc/...)`. No son usuarios navegando normalmente; son peticiones automatizadas a la API REST de Magento.

El atacante está utilizando un ataque de tipo "Enumeración de API". Al interactuar con el endpoint de estimate-shipping-methods y checkout/cart, un atacante suele buscar:


El siguiente paso es determinar si el tráfico tuvo algún tipo de éxito filtrando por errores con status 500, a continuación se detalla el porqué:

Un Error 500 significa que el servidor intentó procesar la petición del atacante, pero su código interno falló catastróficamente.

¿Por qué sucede esto en un ataque?

1. **Desbordamiento (Overflow): El atacante envió un paquete de datos tan largo o complejo que la aplicación no supo manejarlo y se desbordó la memoria.

2. **Excepción no controlada: El atacante envió un carácter especial (como una comilla ' en una inyección SQL) que el código del sitio web no esperaba. Al no estar preparado para ese carácter, el motor de la base de datos o el código PHP/Python "se bloquea" o se cierra inesperadamente.

3. **Falla de lógica: El atacante intentó forzar una función (como un carrito de compras) con parámetros que no tienen sentido, y el servidor se quedó sin saber qué hacer, abortando la operación.

###### Commando utilizado

``` bash
index=botsv2 sourcetype="stream:http" status=500
| stats count by src_ip, uri
| sort - count
```

###### Evidencia

![[Pasted image 20260608003017.png]]

No aparece ningún resultado con status 500, esto significa que si los atacantes están bombardeando la API con peticiones malformadas pero no generan errores 500, significa que el servidor Magento 2 está gestionando las peticiones de manera "limpia" (posiblemente devolviendo errores 400 o 404 controlados, o simplemente ignorándolas). Esto es una excelente noticia desde el punto de vista de defensa, ya que indica que, al menos por ahora, el atacante no ha logrado desestabilizar el núcleo de la aplicación o encontrar una inyección que cause un colapso del sistema.

Ya hemos descartado el inicio de sesión exitoso de cualquier usuario, a continuación vamos a identificar si el comportamiento y las firmas del tráfico coinciden con las de un humano o las de una herramienta maliciosa con el siguiente commando

###### Commando

``` bash
index=botsv2 sourcetype="stream:http" uri="*/login*"
| stats count by http_user_agent
| sort - count
```

###### Evidencia

![[Pasted image 20260608004744.png]]

Podemos observar lo siguiente:

- MSIE 10.0 y MSIE 9.0: Internet Explorer 9 y 10 son navegadores obsoletos (de have más de una década). Es extremadamente raro ver un volumen tan alto (555 y 338 peticiones) de usuarios reales usando versiones tan viejas hoy en día.

- AppleWebKit/536.26: Este User-Agent corresponde a dispositivos iOS muy antiguos (versión 6).

Vamos a proceder a responder las preguntas que ha propuesto el equipo directivo.

###### Preguntas de Investigación

Identificación: ==¿Qué usuario parece set el objetivo principal de los intentos de login?

**Respuesta: No se ha identificado ningún usuario específico siendo atacado mediante brute force tradicional.

El atacante no esta realizando un ataque de fuerza bruta dirigido a nombres de usuarios comunes o conocidos. En este caso el atacante realizó una enumeración de API contra los endpoints de Magento.

**Conclusión: No hay un usuario como objetivo sino un objetivo contra la infraestructura.

Volumen: ==¿Desde qué client_ip provienen la mayoría de los intentos fallidos?

**Respuesta: Se trata de una Botnet distribuida. Encontramos múltiples IPs (como 110.78.2.202, 102.136.241.171, entre otras) enviando peticiones simultáneas. Este es un comportamiento táctico para evitar set detectados por bloqueos de IP simples.

Éxito vs. Fracaso: ==¿Hubo algún intento de login exitoso (status 200) después de una racha de fallos para ese mismo usuario?

**Respuesta: Aunque observamos respuestas 200 OK en las peticiones a /login, al analizar el tamaño de la respuesta (bytes), los valores son idénticos para todas las peticiones.

**Conclusión: Estas respuestas 200 corresponden a la carga exitosa del formulario de login (la página web carga correctamente), no a una autenticación exitosa del usuario. No hay evidencia de que el atacante haya logrado superar la barrera de credenciales.

Impacto: ==Basado en el user_agent, ¿parece que el atacante está usando un navegador real o un script (como Python-requests o sqlmap)?


# Conclusión

###### Estado de la Intrusión: ==Negativo.

- **Análisis del comportamiento: Se identificó una campaña de enumeración automatizada (botnet distribuida) dirigida a endpoints de la API de Magento y páginas de autenticación.

###### Justificación:

- **Ausencia de errores críticos: No se detectaron códigos 500, lo que indica que la aplicación mantuvo su integridad frente al escaneo.

- **Patrón de respuesta uniforme: Las peticiones al formulario de login (código 200) mostraron una consistencia en el tamaño de respuesta (bytes), lo que descarta el acceso exitoso a perfiles de usuario o paneles de administración.

- **Suplantación de identidad: El atacante no está usando navegadores reales. Está configurando su herramienta (probablemente sqlmap u otro escáner de vulnerabilidades) para "hacerse pasar" por navegadores legítimos y antiguos.

- **La evidencia: Un usuario humano real que navega por internet suele tener un navegador actualizado. Ver un volumen tan masivo de peticiones provenientes de versiones de Internet Explorer 9/10 es un indicador de compromiso (IoC) claro de que un script está recorriendo el sitio y usando headers falsos para evadir detecciones básicas que bloquean peticiones sin User-Agent.

- **Resultado: El atacante utilize automatización programada para rotar identidades de navegador y así intentar pasar desapercibido entre el tráfico legítimo.

###### Recomendaciones 

==Bloqueo y Filtrado (Contención Inmediata):

- **Blacklisting: Implementar el bloqueo inmediato de las IPs detectadas en la botnet (ej. 110.78.2.202, 185.100.86.100, etc.) en el Firewall de Aplicaciones Web (WAF).

- **Rate Limiting: Configurar límites de peticiones por IP. Por ejemplo: No permitir más de 10 peticiones a /login o a la API por minuto desde una misma dirección IP. Esto neutralizaría el escaneo automatizado que vimos.

==Endurecimiento de la Aplicación (Prevención):

- **Bloqueo por User-Agent: Configurar una regla en el WAF para descartar peticiones que provengan de navegadores obsoletos (como los IE 9/10 que detectamos) si no son necesarios para tu base de clientes legítimos.

- **Autenticación reforzada: Implementar Multi-Factor Authentication (MFA). Aunque el atacante lograra adivinar una contraseña, el MFA detendría la intrusión inmediatamente.

- **WAF Rule Tuning: Ajustar las reglas del WAF para detectar específicamente patrones de UNION SELECT y INFORMATION_SCHEMA, que son firmas inconfundibles de SQL Injection (SQLi).

==Monitoreo Continuo:

- Configurar alertas en Splunk para cuando el volumen de códigos de estado 401 o 403 supere un umbral crítico desde una sola IP. Esto nos avisaría de un ataque antes de que se convierta en una botnet masiva.

