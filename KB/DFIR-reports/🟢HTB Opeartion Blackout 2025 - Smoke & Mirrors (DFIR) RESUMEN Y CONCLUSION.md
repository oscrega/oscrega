
## Enunciado

**El doctor Reyes está investigando un ataque sigiloso después del robo donde varios registros de seguridad esperados y las alertas de Windows Defender parecen estar desaparecidas. Sostiene que el atacante empleó técnicas de evasión de defensa para desactivar o manipular los controles de seguridad, complicando significativamente los esfuerzos de detección.**

**Usando los registros del evento exportados, su objetivo es descubrir cómo el atacante comprometió las defensas del sistema para permanecer sin set detectado.**

# Preparación

Usaremos Chainsaw para leer los documentos .evtx y guardar su contenido en un archivo .json para poder ordenarlo y filtrar fácilmente

``` bash
┌──(root㉿beginer)-[~beginer/maquinas/blue/difr/operation_smoke_mirrors]
└─# 7z x Smoke-and-Mirrors.zip 

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=es_ES.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 367495 bytes (359 KiB)

Extracting archive: Smoke-and-Mirrors.zip
--
Path = Smoke-and-Mirrors.zip
Type = zip
Physical Size = 367495

    
Enter password (will not be echoed):
Everything is Ok                                    

Files: 3
Size:       5451776
Compressed: 367495
                                                                                                              
┌──(root㉿beginer)-[~beginer/maquinas/blue/difr/operation_smoke_mirrors]
└─# ls
Microsoft-Windows-Powershell.evtx              Microsoft-Windows-Sysmon-Operational.evtx
Microsoft-Windows-Powershell-Operational.evtx  Smoke-and-Mirrors.zip
                                                                                                              
┌──(root㉿beginer)-[~beginer/maquinas/blue/difr/operation_smoke_mirrors]
└─# chainsaw dump Microsoft-Windows-Powershell.evtx  --json >> powershell_windows                            

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Microsoft-Windows-Powershell.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (1.1 MiB)
[+] Done
                                                                                                              
┌──(root㉿beginer)-[~beginer/maquinas/blue/difr/operation_smoke_mirrors]
└─# chainsaw dump Microsoft-Windows-Powershell-Operational.evtx  --json >> powershell_operational 

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Microsoft-Windows-Powershell-Operational.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (2.1 MiB)
[+] Done
                                                                                                              
┌──(root㉿beginer)-[~beginer/maquinas/blue/difr/operation_smoke_mirrors]
└─# chainsaw dump Microsoft-Windows-Sysmon-Operational.evtx  --json >> windows_sysmon 

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Microsoft-Windows-Sysmon-Operational.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (2.1 MiB)
[+] Done

```


Una vez hecho el paso anterior filtraremos los ID de los eventos del archivo y los guardaremos en el documento correspondiente

###### Ejemplo

``` bash
┌──(root㉿beginer)-[~beginer/maquinas/blue/difr/operation_smoke_mirrors]
└─# cat powershell_operational | jq '.[].Event.System.EventID' | sort -n | uniq                  
4103
4104
4105
4106
40961
40962
53504
                                                                                                              
┌──(root㉿beginer)-[~beginer/maquinas/blue/difr/operation_smoke_mirrors]
└─# cat powershell_operational | jq '.[].Event.System.EventID' | sort -n | uniq >> id_powershell_operational 
                                                                                                              
┌──(root㉿beginer)-[~beginer/maquinas/blue/difr/operation_smoke_mirrors]
└─# nano id_powershell_operational 
                                                                                                              
┌──(root㉿beginer)-[~beginer/maquinas/blue/difr/operation_smoke_mirrors]
└─# cat id_powershell_operational                                                                           
4103            Registro de módulos y cmdlets que se cargan y ejecutan.
4104            Registra el código PowerShell completo que se ejecuta.
4105            Muestra la ejecución de canalizaciones (|) dentro de PowerShell.
4106            Registro de invocaciones de comandos.
40961           Indica que el motor de PowerShell se inició.
40962           Indica que el motor de PowerShell se cerró.
53504           Evento generado por el proveedor interno de PowerShell, a veces son errores                              
```

Lo mismo con los demás archivos (2) restantes

``` bash
┌──(root㉿beginer)-[~beginer/maquinas/blue/difr/operation_smoke_mirrors]
└─# cat id_powershell_windows
400             Indica que PowerShell se inició.
600             Indica que PowerShell cargó un proveedor o módulo.
800             Registra que un comando PowerShell fue ejecutado.
```


``` bash
┌──(root㉿beginer)-[~beginer/maquinas/blue/difr/operation_smoke_mirrors]
└─# cat id_windows_sysmon
1               Se creó un nuevo proceso.
3               Un proceso inició una conexión de red.
4               El servicio de Sysmon cambió de estado.
5               Un proceso terminó.
8               Un proceso creó un hilo en otro proceso.
11              Se creó un archivo.
12              Se creó o eliminó una clave de registro.
13              Se modificó un valor del registro.
22              Un proceso hizo una consulta DNS.
```

Se recomienda ordenar el contenido

``` bash
┌──(root㉿beginer)-[~beginer/…/blue/difr/operation_smoke_mirrors/eventos_json]
└─# ls
ID  powershell_operational  powershell_windows  windows_sysmon
```


# Preguntas


**==1. El atacante desactivó la protección de la LSA en el anfitrión comprometido modificando una clave de registro. ¿Cuál es el camino completo de esa clave de registro?==**

**Respuesta correcta: La ruta de la calve de registro que se modificó fué: HKLM\System\CurrentControlSet\Control\Lsa**

``` bash
┌──(root㉿beginer)-[/home/…/blue/difr/operation_smoke_mirrors/eventos_json]
└─# cat windows_sysmon | jq '.[] | select(.Event.System.EventID == 13) | .Event.EventData.TargetObject' | sort -n | uniq | grep Lsa
"HKLM\\System\\CurrentControlSet\\Control\\Lsa\\LsaCfgFlagsDefault"
"HKLM\\System\\CurrentControlSet\\Control\\Lsa\\ProductType"
"HKLM\\System\\CurrentControlSet\\Control\\Lsa\\RunAsPPL"
"HKLM\\System\\CurrentControlSet\\Control\\Lsa\\RunAsPPLBoot"
```

**==2. ¿Qué comando de PowerShell ejecutó por primera vez el atacante para desactivar Windows Defender?==**

###### Comando utilizado para el filtrado

``` bash
┌──(root㉿beginer)-[/home/…/blue/difr/operation_smoke_mirrors/eventos_json]
└─# cat powershell_operational | jq '.[] | select(.Event.System.EventID == 4104) | .Event.EventData.ScriptBlockText' | uniq
```

Se encontró el comando utilizado

![[Pasted image 20251226151900.png]]

**Respuesta correcta: Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true**

###### ¿Cómo sabemos que es el primer comando?

Aparte que es uno de los primeros comandos en aparecer en el registro si se ordena de la forma correcta, se puede observar la siguiente información


- `Set-MpPreference` es el cmdlet official de Windows Defender
    
- **El atacante desactiva todas las protecciones principales:
    
    - Realtime Monitoring
        
    - Script Scanning
        
    - Behavior Monitoring
        
    - IOAV (descargas)
        
    - IPS



**==3. El atacante cargó un parche AMSI escrito en PowerShell. Qué función en el DLL está siendo parcheada por el script para desactivar de manera efectiva AMSI?==**

El atacante desactivó AMSI con la función:   IntPtr a = GetProcAddress(h, \"A\" + \"m\" + \"s\" + \"i\" + \"S\" + \"c\" + \"a\" + \"n\" + \"B\" + \"u\" + \"f\" + \"f\" + \"e\" + \"r\");

Concatenando los caracteres la función es: AmsiScanBuffer

###### Comando utilizado para la filtración

``` bash
┌──(root㉿beginer)-[/home/…/blue/difr/operation_smoke_mirrors/eventos_json]
└─# cat powershell_operational | jq '.[] | select(.Event.System.EventID == 4104) | .Event.EventData.ScriptBlockText' | uniq
```


![[Pasted image 20251226153252.png]]



**==4. ¿Qué comando usó el atacante para reiniciar la máquina en modo seguro?==**

El commando que utilizó el atacante para reiniciar la máquina en modo seguro es bcdedit /set safeboot network. (El registro de powershell puede omitir la extensión del ejecutable si este esta añadido correctamente al PATH)

**Respuesta correcta: bcdedit.exe /set safeboot network**

###### Comando utilizado:

``` bash
┌──(root㉿beginer)-[/home/…/blue/difr/operation_smoke_mirrors/eventos_json]
└─# cat powershell_operational | jq '.[] | select(.Event.System.EventID == 4104) | .Event.EventData.ScriptBlockText' | uniq
```

![[Pasted image 20251226153826.png]]

**==5. ¿Qué comando PowerShell usó el atacante para desactivar la tala de historia de comandos de PowerShell?==**

El comando que utilizó el atacante fue: Set-PSReadlineOption -HistorySaveStyle SaveNothing

**Respuesta correcta: Set-PSReadlineOption -HistorySaveStyle SaveNothing**

###### Comando utilizado

``` bash
┌──(root㉿beginer)-[/home/…/blue/difr/operation_smoke_mirrors/eventos_json]
└─# cat powershell_operational | jq '.[] | select(.Event.System.EventID == 4104) | .Event.EventData.ScriptBlockText' | uniq
```


![[Pasted image 20251226154155.png]]


### ¿Qué es `Set-PSReadLineOption`?

Es un cmdlet de PowerShell que **configura PSReadLine, el módulo que:

- maneja la **entrada de commandos**
    
- guarda el **historial**
    
- habilita autocompletado y edición tipo shell
    

PSReadLine es el responsible de guardar el historial en disco.

---

### ¿Qué es `-HistorySaveStyle`?

Es la opción que define **cómo se guarda el historial de commandos.

Valores posibles:

| Valor                             | Comportamiento                          |
| --------------------------------- | --------------------------------------- |
| `SaveIncrementally` (por defecto) | Guarda cada commando al ejecutarse       |
| `SaveAtExit`                      | Guarda el historial al cerrar la sesión |
| `SaveNothing`                     | ❌ **No guarda ningún commando          |

---

### ¿Qué have `SaveNothing` exactamente?

Cuando se usa:

`-HistorySaveStyle SaveNothing`

PowerShell:

- **deja de escribir commandos en el archivo de historial
    
- **no registra nuevos commandos**
    
- solo afecta a la **sesión actual**

# Resumen y conclusión