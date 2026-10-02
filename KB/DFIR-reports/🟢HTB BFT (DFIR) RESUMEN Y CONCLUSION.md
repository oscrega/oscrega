
# Enunciado 

**En este Sherlock, te familiarizarás con la forense del MFT (Master File Table o Tabla Maestra de Archivos).**  

**Se te presentarán herramientas y metodologías conocidas para analizar los artefactos del MFT y así identificar actividades maliciosas. Durante nuestro análisis, utilizarás la herramienta MFTECmd para analizar el archivo MFT proporcionado, TimeLine Explorer para abrir y analizar los resultados del MFT parseado, y un editor hexadecimal para recuperar el contenido de los archivos a partir del MFT.**

# Preparación

**Al descomprimir el archivo que nos proporciona la máquina podemos encontrar el directorio 'C' con el archivo 'MFT'.**

**El archivo 'MFT' actúa como una base de datos central que mantiene información sobre cada archivo en el sistema. En lugar de almacenar los archivos y sus datos directamente, este archivo guarda metadatos cruciales que describen cómo se encuentran organizados los archivos en el disco**

###### Descompresión del archivo del reto


``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/bft]
└─# 7z x BFT.zip   

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=es_ES.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 32911496 bytes (32 MiB)

Extracting archive: BFT.zip
--
Path = BFT.zip
Type = zip
Physical Size = 32911496

    
Enter password (will not be echoed):
Everything is Ok

Folders: 1
Files: 1
Size:       322437120
Compressed: 32911496
                                                                                                             
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/bft]
└─# ls
BFT.zip  C
                                                                                                             
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/bft]
└─# cd C  
                                                                                                             
┌──(root㉿beginer)-[/home/…/blue/difr/bft/C]
└─# ls
'$MFT'

```


###### Parseo del archivo 'MFT' en formato JSON

**Estos archivos deben parsearse para poder analizarlos o leerlos, en este caso usaremos la herramienta chainsaw para parsear el archivo en formato json.**

``` bash
┌──(root㉿beginer)-[/home/…/blue/difr/bft/C]
└─# chainsaw dump \$MFT --json >> mft.json
```

# Preguntas

**==1. Simon Stark fue blanco de atacantes el 13 de febrero. Descargó un archivo ZIP desde un enlace recibido en un correo electrónico. ¿Cuál fue el nombre del archivo ZIP que descargó desde el enlace?==**

**Respuesta correcta: Stage-20240213T093324Z-001.zip**

**El usuario descargo dos archivos:**

**Archivos descargados:**

 - El archivo **`Stage-20240213T093324Z-001.zip`** proviene de un enlace que está relacionado con **Google Cloud Storage** (lo que sugiere que es un archivo que podría haber sido descargado desde un enlace **legítimo enviado en un correo).
        
 - El archivo **`KAPE.zip`** tiene un enlace a **justbeam.it**, que es un servicio de transferencia de archivos en línea, y podría estar relacionado con **un enlace malicioso.**


**Contexto del archivo "Stage-20240213T093324Z-001.zip":**
    
- El archivo **`Stage-20240213T093324Z-001.zip`** parece seguir un formato de nombre relacionado con un **evento o timestamp**: **20240213T093324Z**, lo cual es muy probable que sea un nombre asociado a una acción de descarga de un archivo desde un enlace legítimo, posiblemente relacionado con un **correo electrónico de un atacante.

--- 

![[Pasted image 20260102183032.png]]

--- 

**==2. Examina el contenido del Zone Identifier del archivo ZIP descargado inicialmente. Este campo revela el HostUrl desde donde se descargó el archivo, lo que sirve como un valioso Indicador de Compromiso (IOC) en nuestra investigación/análisis. ¿Cuál es la URL completa del host desde donde se descargó este archivo ZIP?==**

**En la anterior evidencia se puede observar la URL completa del host desde el cual se descargó dicho archivo.**

**Repuesta correcta: https://storage.googleapis.com/drive-bulk-export-anonymous/20240213T093324.039Z/4133399871716478688/a40aecd0-1cf3-4f88-b55a-e188d5c1c04f/1/c277a8b4-afa9-4d34-b8ca-e1eb5e5f983c?authuser**

--- 

![[Pasted image 20260102183114.png]]

--- 
  
**==3. ¿Cuál es la ruta completa y el nombre del archivo malicioso que ejecutó código malicioso y se conectó a un servidor C2?==**

**Respuesta correcta: C:\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\Stage\invoice\invoices\invoice.bat**

**Hay un archivo relacionado con el archivo Stage-20240213T093324Z-001.zip**

--- 

![[Pasted image 20260102190105.png]]

--- 

**Esto sugiere que el usuario descomprimió Stage-20240213T093324Z-001.zip dando como resultado los archivos invoices.zip, Stage y Stage-20240213T093324Z-001.lnk.**

--- 

![[Pasted image 20260102190345.png]]

--- 

**En la segunda descompresión el usuario descomprime invoices.zip dando como resultado el archivo invoice.bat, invoice y invoice.**

--- 

![[Pasted image 20260102190534.png]]

--- 
##### Explicación

- **`invoices.zip`**: Es el **contenedor de la carga útil (payload). Los atacantes lo envían comprimido para evitar que los sistemas de seguridad perimetral (como filtros de correo) analicen el contenido interno o detecten firmas de malware directamente.
    
- **`invoice.bat`**: Este es el **archivo ejecutable malicioso. Un archivo `.bat` (Batch script) es un script de Windows que ejecuta commandos secuencialmente.
    
    - **Función técnica: Probablemente contiene commandos de PowerShell o `bitsadmin` para descargar la carga útil real (el malware final) desde un servidor C2 (Command & Control) o para ejecutar commandos maliciosos silenciosamente en segundo plano.
        
- **`.lnk` (LNK file): Es un acceso directo de Windows. En ataques, se usan frecuentemente para ejecutar scripts de manera oculta (por ejemplo, el archivo `.lnk` puede estar configurado para llamar al archivo `.bat` añadiendo parámetros para ocultar la ventana del terminal).
    
- **`Zone.Identifier`**: Estos archivos, que ves como `invoices.zip:Zone.Identifier`, son flujos de datos alternativos (ADS) de NTFS conocidos como **"Mark of the Web" (MotW).
    
    - **¿Para qué sirven?:** Windows los crea automáticamente cuando descargas un archivo de Internet. El sistema operativo utilize esta "etiqueta" para aplicar políticas de seguridad más restrictivas, como bloquear macros en archivos de Office o mostrar advertencias de ejecución. En forense, **son oro puro, porque te dicen exactamente desde qué URL y en qué fecha se descargó el archivo original.


**==4. Analiza la marca de tiempo $Created0x30 del archivo identificado anteriormente. ¿Cuándo fue creado este archivo en el disco?==**

**Respuesta correcta: invoice.bat fue creado en fecha y hora: 2024-02-13 16:38:39**

--- 

![[Pasted image 20260102190715.png]]

--- 

**==5. Encontrar el offset hex de un registro MFT es útil en muchos escenarios investigativos. Encuentra el offset hex del archivo stager de la Pregunta 3.==**

**Respuesta correcta: Offset: 0x16E3000**

**El archivo invoice.bat tiene un entry number de 23436**

--- 

![[Pasted image 20260102193624.png]]

--- 

**Sabiendo el entry number podemos descifrar el offset hex desde MFTECmd.exe utilizando el complemento '--de' de la propia herramienta. Se puede realizar de la siguiente forma.**


``` bash
C:\Users\oscar\Desktop>MFTECmd.exe -f $MFT --de 23436
MFTECmd version 1.3.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/MFTECmd

Command line: -f $MFT --de 23436

Warning: Administrator privileges not found!

File type: Mft

Processed $MFT in 5,7287 seconds

$MFT: FILE records found: 171.927 (Free records: 142.905) File size: 307,5MB


Dumping details for file record with key 00005B8C-00000009

Entry-seq: 0x5B8C-0x9, "Offset: 0x16E3000", Flags: InUse, Log seq : 0x594BFF05, Base Record entry-seq: 0x0-0x0
Reference count: 0x1, FixUp Data Expected: 03-00, FixUp Data Actual: 30-61 | 00-00 (FixUp OK: True)
```




**==6. Cada registro MFT tiene un tamaño de 1024 bytes. Si un archivo en disco tiene un tamaño menor a 1024 bytes, puede almacenarse directamente en el propio archivo MFT. Estos se conocen como archivos residentes en MFT. Durante una investigación del sistema de archivos de Windows, es crucial buscar archivos maliciosos/sospechosos que puedan estar residentes en el MFT. De esta manera, podemos encontrar el contenido de archivos/scripts maliciosos. Encuentra el contenido del stager malicioso identificado en la Pregunta 3 y responde con la IP y el puerto C2.==**

**Respuesta correcta: la IP y el puerto del stager malicioso es 43.204.110.203:6666**

**El commando que usamos antes `MFTECmd.exe -f $MFT --de 23436` también nos proporciona esta información.**

--- 

![[Pasted image 20260102194050.png]]

--- 

Un **stager**  malicioso es un componente clave en la arquitectura de un ataque informático. Su función principal es **actuar como un puente: es un código pequeño, ligero y difícil de detectar cuyo único propósito es descargar o "traer" al sistema el cuerpo principal del malware (el _payload_ real).
