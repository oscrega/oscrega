
## Enunciado

**Alonzo Spotted Weird archivos en su computadora e informó al recién reunido SOC Team. Evaluando la situación se cree que un ataque de Kerberoasting pudo haber ocurrido en la red. Es su trabajo confirmar los hallazgos analizando la evidencia presentada. Se le proporciona: 1- Registros de seguridad del controlador de dominio 2- Registros de la Opera de PowerShell de la estación de trabajo afectada 3- Archivos de prefetch de la estación de trabajo afectada**

## Preparación

**Importamos el archivo SECURITY-DC al visor de eventos de windows**

![[Pasted image 20251113143114.png]]


## PECmd

**Se analizaron todos los archivos ubicados en el directorio`C:\Users\oscar\Desktop\campfire-1\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch` usando la herramienta PECmd y creando la salida de resultado en archivos CSV**

###### Comando utilizado

``` bash
PECmd.exe -d C:\Users\oscar\Desktop\campfire-1\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch --csv C:\Users\oscar\Desktop\campfire-1\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\
```

###### Resultado

```
---------- Processed C:\Users\oscar\Desktop\campfire-1\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch\WWAHOST.EXE-2CFA09D4.pf in 0,32569820 seconds ----------
Processed 207 out of 212 files in 10,9674 seconds

Failed files
  C:\Users\oscar\Desktop\campfire-1\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch\FILESYNCCONFIG.EXE-1C1104B5.pf ==> (Invalid signature! Should be 'SCCA')
  C:\Users\oscar\Desktop\campfire-1\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch\MICROSOFT.SHAREPOINT.EXE-EECBA9B3.pf ==> (Invalid signature! Should be 'SCCA')
  C:\Users\oscar\Desktop\campfire-1\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch\SVCHOST.EXE-6A4A44E7.pf ==> (Invalid signature! Should be 'SCCA')
  C:\Users\oscar\Desktop\campfire-1\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch\SVCHOST.EXE-77C41F85.pf ==> (Invalid signature! Should be 'SCCA')
  C:\Users\oscar\Desktop\campfire-1\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch\SVCHOST.EXE-B6F285B2.pf ==> (Invalid signature! Should be 'SCCA')

CSV output will be saved to C:\Users\oscar\Desktop\campfire-1\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\20251209142626_PECmd_Output.csv
CSV time line output will be saved to C:\Users\oscar\Desktop\campfire-1\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\20251209142626_PECmd_Output_Timeline.csv
```

**Se generaron los siguientes archivos CSV realizando.

![[Pasted image 20251209153133.png]]
## Preguntas


**==1. Analizando los registros de seguridad del controlador de dominio, puede confirmar la fecha y hora en que se produjo la actividad de kerberoasting?==**

**Se encontró la fecha y hora cuando se produjo la actividad Kerberoasting.**

![[Pasted image 20251209165453.png]]

**Se convirtió la hora a formato UTC**

![[Pasted image 20251209165948.png]]

**Cuando PECmd convirtió el horario a UTC muestra en los logs las horas referentes a las 3AM.**

![[Pasted image 20251209170207.png]]

**La fecha es: 2024-05-21 03:18:09**

**==2. Cuál es el Nombre de Servicio que fue atacado?==**

**El usuario atacó el siguiente servicio.**

![[Pasted image 20251113150904.png]]

**==3. Es muy importante identificar la Workstation de la que se produjo esta actividad. Cuál es la dirección IP de la estación de trabajo?==**

**Puesto que solo encontramos una IP y esta IP no ha cambiado solo puede ser esta.**

**IP: 172.17.79.129**

![[Pasted image 20251113143356.png]]


**==4. Ahora que hemos identificado la estación de trabajo, un triaje que incluye los registros de PowerShell y los archivos Prefetch se proporcionan a usted para algunas ideas más profundas para que podamos entender cómo esta actividad ocurrió en el punto final. Cuál es el nombre del archivo utilizado para Enumerar objetos de directorio Active y posiblemente encontrar cuentas Kerberoastable en la red?==**

## Intento ejecución de commandos fallida

![[Pasted image 20251113151650.png]]

## Cambio políticas de ejecución de comandos


**powersell -ep bypass:**

- **Ignora la política de ejecución actual solo para esa sesión.**

- **No pide confirmación ni muestra advertencias.**

- **Permite ejecutar cualquier script, incluso los que normalmente estarían bloqueados.

![[Pasted image 20251113152708.png]]

## Ejecución del script

**Después de cambiar la política de ejecución el usuario ejecuto el script deseado.**

![[Pasted image 20251113152847.png]]

## ¿Qué hace el script?

| **Bloque / Función**                                | **Descripción**                                                                                                                                                                                                        |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Creación dinámica de estructuras (`$StructBuilder`) | Define campos de estructuras .NET en tiempo de ejecución, incluyendo atributos de marshaling y tamaño. Permite obtener el tamaño de la estructura (`GetSize`) y convertir desde un puntero (`IntPtr`) a la estructura. |
| Export-PowerViewCSV                                 | Exporta objetos de PowerShell a CSV de manera segura en hilos (thread-safe) usando un mutex, evitando colisiones al escribir en el archivo.                                                                            |
| Set-MacAttribute                                    | Ajusta las fechas de modificación, acceso y creación (MAC) de un archivo según otro archivo o valores especificados. Similar a `touch` en Unix.                                                                        |
| Copy-ClonedFile                                     | Copia un archivo a otro destino asegurando que las fechas MAC del archivo de destino coincidan con las del origen.                                                                                                     |
| Get-IPAddress                                       | Resuelve un nombre de host a su dirección IPv4. Por defecto devuelve la IP local si no se proporciona host.                                                                                                            |
| Convert-NameToSid                                   | Convierte un nombre de usuario o grupo (ej. `DOMAIN\user`) en un SID de Windows.                                                                                                                                       |
| Convert-SidToName                                   | Convierte un SID de Windows en un nombre de usuario o grupo, incluyendo SIDs internos predefinidos.                                                                                                                    |
| Convert-NT4toCanonical                              | Convierte nombres en formato NT4 (`DOMAIN\user`) a formato canónico (`user@domain.com` o similar) usando COM `NameTranslate`.                                                                                          |
| Convert-CanonicaltoNT4                              | Convierte nombres canónicos (`user@fqdn`) a formato NT4 (`DOMAIN\user`) usando COM `NameTranslate`.                                                                                                                    |
| ConvertFrom-UACValue                                | Bloque incompleto en el código compartido, generalmente usado para convertir valores de control de cuentas de usuario (UAC) a un formato legible.                                                                      |

**==5. Cuándo se ejecutó este guión?==**

*![[Pasted image 20251209153737.png]]*

**Usamos los archivos con formato CSV generados con la herramienta PECmd para el filtrado de logs.**

## Reemplazo horas del archivo

**Las horas tenian '.' en vez de ':' así que se modificó el archivo**

![[Pasted image 20251209163312.png]]

## Transformación horas en UTC (resta 1 hora por DST o horario de verano)

![[Pasted image 20251209162943.png]]

## Filtrado por fecha

**Se encontró la fecha correcta de la ejecución del archivo malicioso**

![[Pasted image 20251209163550.png]]

**Fecha de ejecución: 2024-05-21 03:16:29**

**==6. Cuando se ejecutó la herramienta para voltear credenciales?==**

**Se realizó una búsqueda de herramientas utilizadas para explotación kerberoast y se encontró la herramienta de Rubeus, la cual se utilizó en el ataque, su uso se muestra en la pregunta 7.**

![[Pasted image 20251113143913.png]]

**En el siguiente evento muestra la realización del ataque kerberoast, en el cual se ejecutaron múltiples comandos remotos en un tiempo corto.**

![[Pasted image 20251209171601.png]]

**En la anterior evidencia se muestra la hora a la que el ataque empezó, no obstante debemos transformar la hora a UTC** 

![[Pasted image 20251209171646.png]]

**Fecha y hora del ataque: 2024-05-21 03:16:32**

**==7. Cuál es el camino completo de la herramienta utilizada para realizar el ataque real de kerberoasting?==**

**El ejecutable Rubeus.exe de la herramienta Rubeus se ejecutó en fecha: 2024-05-21 03:18:08**

![[Pasted image 20251209164334.png]]
