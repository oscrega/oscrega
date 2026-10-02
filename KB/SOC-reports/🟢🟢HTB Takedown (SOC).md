
## Enunciado

Hemos identificado un patrón inusual en la actividad de nuestra red, lo que indica una possible brecha de seguridad. Nuestro equipo sospecha de una intrusión no autorizada en nuestros sistemas, que podría comprometer datos sensibles. Tu tarea es investigar este incidente.
# Preparación y análisis

Vamos a descomprimir el archivo que nos proporciona el reto, analizar el archivo descomprimido (tipo de archivo) y elegir que herra



mientas utilizaremos para responder a las preguntas y resolver el reto

``` bash
┌──(myenv)─(root㉿beginer)-[/home/…/maquinas/blue/soc/takedown]
└─# ls
takedown.zip
                                                                                                              
┌──(myenv)─(root㉿beginer)-[/home/…/maquinas/blue/soc/takedown]
└─# 7z x takedown.zip

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=es_ES.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 810068 bytes (792 KiB)

Extracting archive: takedown.zip
--
Path = takedown.zip
Type = zip
Physical Size = 810068

    
Enter password (will not be echoed):
Everything is Ok    

Size:       2186075
Compressed: 810068
                                                                                                              
┌──(myenv)─(root㉿beginer)-[/home/…/maquinas/blue/soc/takedown]
└─# ls
Takedown.pcap  takedown.zip
```


Podemos observar que estamos ante un archivo de captura de tráfico de red con formato o extensión .pcap

Para analizar este archivo utilizaremos la herramienta Wireshark y un tshark como pipeline.

# Preguntas

==1. ¿Desde qué dominio se descargó el script VBS?

Un script VBS es un archivo de script escrito en VBScript (Visual Basic Scripting Edition), que es un lenguaje de scripting desarrollado por Microsoft. Se utilize principalmente en entornos Windows para automatizar tareas y manipular objetos del sistema operativo.

Podemos observar en la siguiente evidencia que el usuario atacante intentó leer el archivo y obtenerlo pero resultó varias veces en error, tras varios intentos se puede observar una petición de lectura y seguidamente una respuesta del servidor en la que no se aprecian errores, esto significa que el usuario consiguió leer el archivo tras varios intento sin éxito

![[Pasted image 20260314143022.png]]

Entre eventos se puede observar desconexiones con el servicio IPC y COULD referente al dominio de escuelademarina.com, esto significa que el usuario estuvo navegando entre varios servicios del dominio.
Al obtener una respuesta del servidor referente a la conexión significa que el usuario logró autentificarse con NTLM, ya que arriba de las dos evidencias marcadas aparece NTLMSSP_AUTH.

![[Pasted image 20260314143057.png]]

Respuesta correcta: escuelademarina.com


==2. ¿Cuál fue la dirección IP asociada con el dominio de la pregunta #1 que se utilizó en este ataque?

Esta pregunta es simple y se responde con las evidencias anteriores.

El usuario se autentifica desde la 10.3.19.101 hacia la 165.22.16.55, esta misma luego devuelve un respuesta a la 10.3.19.101, esto significa que el usuario logró autentificarse en el dominio ecuelamarina.com con IP 165.22.16.55

![[Pasted image 20260314143852.png]]

Respuesta correcta: 165.22.16.55


==3. ¿Cuál es el nombre del archivo del script VBS usado para el acceso inicial?

Esta pregunta también es sencilla y aparece en las evidencias anteriores

Se pueden observar varios intento fallidos pero, al final el usuario logra utilizar el archivo para conseguir permisos mayores.

![[Pasted image 20260314144610.png]]

Respuesta correcta: AZURE_DOC_OPEN.vbs

==4. ¿Cuál fue la URL utilizada para obtener un script de PowerShell?

Si analizamos el archivo de captura de red podemos analizar varios eventos relacionados con el protocolo HTTP, en ellos podemos observar peticiones de tipo GET, al analizarlas observamos lo siguiente:

![[Pasted image 20260315184359.png]]

Si analizamos la petición podemos observar que el evento registrado tiene relación con powershell

![[Pasted image 20260315184442.png]]

Lo más probable es que el atacante descargase un script malicioso utilizando powershell

![[Pasted image 20260315184750.png]]

Para unir la URL completa debemos unir el HOST con la URL, el resultado es: badbutperfect.com/nrwncpwo

Al analizar los archivos descargados podemos concluir en lo siguiente

![[Pasted image 20260315185358.png]]

En uno de los archivos se analiza la descarga del archivo llamado nrwncpwo

![[Pasted image 20260315185511.png]]

Respuesta correcta:  badbutperfect.com/nrwncpwo

==5. ¿Qué binario probablemente legítimo se descargó en la máquina víctima?

![[Pasted image 20260315193408.png]]

Podemos analizar que el contenido del archivo llamado nrwncpwo que descargó el atacante mediante el protocolo HTTP es un commando ofuscado que ejecuta lo siguiente

Primero crea el entorno

- ni 'C:/rimz' -Type Directory -Force: El commando ni es el alias de New-Item. Crea una carpeta llamada rimz en la raíz del disco C. El parámetro -Force asegura que se cree incluso si ya existe (sobreescribiendo o ignorando errores).

- cd C:/rimz: Cambia el directorio de trabajo a esa nueva carpeta.

Seguidamente descarga los siguientes archivos:

| Archivo        | Nombre en el Script | Función Técnica      | Descripción en el ataque                                                                                  |
| -------------- | ------------------- | -------------------- | --------------------------------------------------------------------------------------------------------- |
| **`test2`**    | `AutoHotkey.exe`    | **Intérprete       | Una copia legítima de AutoHotkey usada para ejecutar el script malicioso sin levantar sospechas.          |
| **`jvtobaqj`** | `script.ahk`        | **Loader / Dropper | El script ofuscado que inyecta el malware en la memoria.                                                  |
| **`ozkpfzju`** | `test.txt`          | **RAT (Malware)**    | El troyano final (posiblemente **Remcos** o **AsyncRAT). Se descarga como `.txt` para evadir firewalls. |

Respuesta correcta AutoHotKey.exe


==6. ¿Desde qué URL se descargó el malware utilizado con el binario de la pregunta #5?

Podemos analizar lo siguiente:

| Archivo        | Nombre en el Script | Función Técnica      | Descripción en el ataque                                                                                  |
| -------------- | ------------------- | -------------------- | --------------------------------------------------------------------------------------------------------- |
| **`nrwncpwo`** | (Stager)            | **Downloader (PS)  | Script de PowerShell que crea la carpeta `C:/rimz`, descarga los components y oculta el rastro.          |
| **`test2`**    | `AutoHotkey.exe`    | **Intérprete       | Una copia legítima de AutoHotkey usada para ejecutar el script malicioso sin levantar sospechas.          |
| **`jvtobaqj`** | `script.ahk`        | **Loader / Dropper | El script ofuscado que inyecta el malware en la memoria.                                                  |
| **`ozkpfzju`** | `test.txt`          | **RAT (Malware)**    | El troyano final (posiblemente **Remcos** o **AsyncRAT). Se descarga como `.txt` para evadir firewalls. |

Evidencias:

![[Pasted image 20260318221056.png]]


Se descargaron los archivos como se menciona a continuación

En wireshark, en el apartado del menú desplegable (Archivo > Exportar HTTP) podemos encontrar los archivos que se descargaron mediante el protocolo HTTP

![[Pasted image 20260318221324.png]]

Al descargarlos y analizarlos encontramos un binario (test2), el cual descarga AutoHotKey.exe para ejecutar el malware sin levantar sospechas, un script que inyecta el malware (jvtobaqj) y el propio malware en formato binario (ozkpfzju)

Entonces el malware en si es binario (ozkpfzju) y es ejecutado por otro binario, el programa AutoHotKey.exe.

La pregunta es confusa porque pregunta por el malware, el cual es ozkpfzju, aunque sin el archivo jvtobaqj, el payload, este troyano es inofensivo.

Podemos analizar las URLs observando el contenido del script que descargó el atacante para poder descargar los archivos que se comentaron anteriormente:

![[Pasted image 20260318222407.png]]

Respuesta correcta:  http://badbutperfect.com/jvtobaqj

==7. ¿Qué nombre de archivo se le asignó al malware de la pregunta #6 en el disco?

Podemos observar lo siguiente, después de la URL "http://badbutperfect.com/test2" el archivo se nombra como AutoHotkey.exe, para la URL "http://badbutperfect.com/jvtobaqj" el archivo final se nombra como script.ahk, para la URL "http://badbutperfect.com/ozkpfzju" se nombra el archivo como test.txt.

Después se ejecuta `start 'AutoHotkey.exe' -a 'script.ahk';attrib +h 'C:/rimz'` lo cual ejecuta AutoHotKey.exe, un programa que a su vez ejecuta el malware script.ahk, el cual llamará a test.txt, para se inyectado, es decir, su payload.

![[Pasted image 20260318222541.png]]

Respuesta correcta: script.ahk

==8. ¿Cuál es el TLSH del malware?

Podemos utilizar la herramienta online de virus total. Arrastramos el archivo malware script.ahk y en detalles podemos observar su TLSH

![[Pasted image 20260318225126.png]]

Respuesta correcta: 
T15E430A36DBC5202AD8E3074270096562FE7DC0215B4B32659C9EF16835CF6FF9B6A1B8 

==9. ¿Cuál es el nombre asignado a este malware? Usa el nombre que emplean McAfee, Ikarus y alejandro.sanchez.

Tras buscar en internet encontré el siguiente blog

![[Pasted image 20260318225733.png]]

Extracto del blog

``` bash
McAfee Labs ha descubierto recientemente una novedosa cadena de infección asociada con el malware DarkGate. Esta cadena comienza con un punto de entrada basado en HTML y avanza para explotar la utilidad de AutoHotkey en sus etapas posteriores. DarkGate, un Trojan de Acceso Remoto (RAT) desarrollado usando Borland Delphi, ha sido comercializado como una oferta de Malware-as-a-Service (MaaS) en un foro de cibercrimen en ruso desde al menos 2018. Este software malicioso cuenta con una serie de funcionalidades, como inyección de proceso, descarga y ejecución de archivos, robo de datos, ejecución de comandos de shell, capacidades de teclagging, entre otras. 
```

Respuesta correcta: DarkGate

==10. ¿Cuál es la cadena user-agent de la máquina infectada?

Podemos encontrarlo al analizar la petición POST, es decir, en las peticiones que se realizan cuando la ,máquina ya esta infectada.

![[Pasted image 20260318231616.png]]

Respuesta correcta: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36

(La HTB lo exige sin el prefijo User-Agent y sin "\r\n" al final)

==11. ¿A qué IP se conecta el RAT de la pregunta anterior?

La respuesta es sencilla, a la IP de la máquina víctima

![[Pasted image 20260318231753.png]]

Respuesta correcta: 103.124.105.78

# Conclusión

El usuario descarga un archivo VBS con el cual consigue iniciar sesión, posteriormente descarga un script de Powreshell, el cual a su vez descarga, el programa legítimo AutoHotKey.exe, un payload nombrado como test.txt y el propio malware script.ahk, posteriormente el script ejecuta el archivo AutoHotKey.exe, el cual carga el malware script.ahk mdeiante el payload test.txt. La maquina ya está infectada y se detectan varios eventos de protocolos HTTP los cuales se sabe que incorporan peticiones POST, desde el usuario atacante con IP 10.3.19.101 hasta el usuario o entidad víctima con IP 103.124.105.78.

Parece set que el malware envió datos robados o confirmando que sigue vivo al servidor del atacante mediante el protocolo HTTP (puerto 80).

![[Pasted image 20260318232622.png]]