
## Enunciado

**Tu sistema SIEM generó múltiples alertas en menos de un minuto, indicando una posible comunicación de C2 (Command and Control) desde la estación de trabajo de Simón Stark. A pesar de que Simón no notó nada inusual, el equipo de TI le pidió que compartiera capturas de pantalla de su administrador de tareas para verificar si había procesos extraños. No se encontraron procesos sospechosos, pero las alertas sobre comunicaciones C2 persistían.**

**El responsable del SOC ordenó entonces la contención inmediata del equipo y la realización de un volcado de memoria para su análisis. Como experto en análisis forense de memoria, se te ha asignado la tarea de ayudar al equipo SOC de Forela a investigar y resolver este incidente urgente.**

# Preparación y análisis

En el apartado de preparación se debe investigar a cerca del archivo que nos proporciona el reto, su formato, y demás información.

#### Descompresión del archivo RogueOne

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# ls
'RogueOne(1).zip'
                                                                                                             
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# 7z x RogueOne\(1\).zip                      

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=es_ES.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 1368047191 bytes (1305 MiB)

Extracting archive: RogueOne(1).zip
--
Path = RogueOne(1).zip
Type = zip
Physical Size = 1368047191
64-bit = +
Characteristics = Zip64

    
Enter password (will not be echoed):
Everything is Ok   

Size:       5368709120
Compressed: 1368047191
                                                                                                             
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# ls
 20230810.mem  'RogueOne(1).zip'
                                                                                                             
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# file 20230810.mem 
20230810.mem: Windows Event Trace Log

```

Como se puede observar el archivo tiene la extensión '.mem', así que estamos ante un volcado de memoria

Podemos leer el archivo he investigarlo con Volatility 3 y Volatility 2. Vamos a utilizar Volatility3 ya que volatility2 tarda mucho, utilizaremos el siguiente comando para determinar las características de la imagen.

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# vol3 -f 20230810.mem windows.info 
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished                        
Variable        Value

Kernel Base     0xf80178400000
DTB     0x16a000
Symbols file:///home/beginer/apps/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/3789767E34B7A48A3FC80CE12DE18E65-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdVersionBlock  0xf8017900f398
Major/Minor     15.19041
MachineType     34404
KeNumberProcessors      8
SystemTime      2023-08-10 11:32:00+00:00
NtSystemRoot    C:\WINDOWS
NtProductType   NtProductWinNt
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Mon Nov 24 23:45:00 2070
```

**Podemos concluir en que el equipo es un Windows 10 versión 2004 / 20H1**
# Preguntas

**==1. Identifica el proceso malicioso y confirma el ID de proceso (PID) del proceso malicioso.==**

Para ello identificamos los procesos que han quedado registrados

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# vol3 -f memoria.mem windows.pslist
Volatility 3 Framework 2.28.0
usage: vol.py [-h] [-c CONFIG] [--parallelism [{processes,threads,off}]] [-e EXTEND] [-p PLUGIN_DIRS]
              [-s SYMBOL_DIRS] [-v] [-l LOG] [-o OUTPUT_DIR] [-q] [-f FILE] [--write-config]
              [--save-config SAVE_CONFIG] [--clear-cache] [--cache-path CACHE_PATH] [--offline | -u URL]
              [--filters FILTERS] [--hide-columns [HIDE_COLUMNS ...]] [-r RENDERER]
              [--single-location SINGLE_LOCATION] [--stackers [STACKERS ...]]
              [--single-swap-locations [SINGLE_SWAP_LOCATIONS ...]]
              PLUGIN ...
vol.py: error: File does not exist: /home/beginer/maquinas/blue/difr/rogueone/memoria.mem
                                                                                                              
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# vol3 -f 20230810.mem windows.pslist 
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime      File output

4       0       System  0x9e8b87680040  225     -       N/A     False   2023-08-10 11:13:38.000000 UTC  N/A  Disabled
140     4       Registry        0x9e8b876ce080  4       -       N/A     False   2023-08-10 11:13:32.000000 UTCN/A     Disabled
436     4       smss.exe        0x9e8b8843f040  2       -       N/A     False   2023-08-10 11:13:38.000000 UTCN/A     Disabled
564     548     csrss.exe       0x9e8b882f8140  13      -       0       False   2023-08-10 11:13:41.000000 UTCN/A     Disabled
644     636     csrss.exe       0x9e8b893eb140  14      -       1       False   2023-08-10 11:13:41.000000 UTCN/A     Disabled
656     548     wininit.exe     0x9e8b89416080  1       -       0       False   2023-08-10 11:13:41.000000 UTCN/A     Disabled
744     636     winlogon.exe    0x9e8b89441080  4       -       1       False   2023-08-10 11:13:42.000000 UTCN/A     Disabled
788     656     services.exe    0x9e8b8949e080  10      -       0       False   2023-08-10 11:13:42.000000 UTCN/A     Disabled
808     656     lsass.exe       0x9e8b894a2080  12      -       0       False   2023-08-10 11:13:42.000000 UTCN/A     Disabled
928     788     svchost.exe     0x9e8b89527240  13      -       0       False   2023-08-10 11:13:42.000000 UTCN/A     Disabled
956     744     fontdrvhost.ex  0x9e8b89530180  5       -       1       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
964     656     fontdrvhost.ex  0x9e8b8952e180  5       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
512     788     svchost.exe     0x9e8b895a72c0  11      -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
864     788     svchost.exe     0x9e8b895a9240  6       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1048    744     dwm.exe 0x9e8b89c520c0  14      -       1       False   2023-08-10 11:13:43.000000 UTC  N/A  Disabled
1148    788     svchost.exe     0x9e8b89c922c0  30      -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1272    788     svchost.exe     0x9e8b89cf4280  3       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1280    788     svchost.exe     0x9e8b89cf5080  4       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1288    788     svchost.exe     0x9e8b89cf71c0  3       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1296    788     svchost.exe     0x9e8b89cf91c0  4       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1304    788     svchost.exe     0x9e8b89cfb200  4       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1432    788     svchost.exe     0x9e8b89d121c0  5       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1472    788     svchost.exe     0x9e8b89d3e1c0  7       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1500    788     svchost.exe     0x9e8b89d412c0  10      -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1580    788     svchost.exe     0x9e8b89d900c0  7       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1588    788     svchost.exe     0x9e8b89d94080  6       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1712    788     svchost.exe     0x9e8b89dab1c0  2       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1748    788     svchost.exe     0x9e8b89e541c0  11      -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1756    788     svchost.exe     0x9e8b89e562c0  6       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1828    788     svchost.exe     0x9e8b89e70240  6       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1980    788     svchost.exe     0x9e8b89fbc240  3       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1988    788     svchost.exe     0x9e8b89fc1280  6       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
1996    788     svchost.exe     0x9e8b89fc4080  6       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
2044    788     svchost.exe     0x9e8b89fc2080  8       -       0       False   2023-08-10 11:13:43.000000 UTCN/A     Disabled
2140    788     svchost.exe     0x9e8b89f6f200  2       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2168    788     svchost.exe     0x9e8b8a039240  2       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2184    4       MemCompression  0x9e8b8a038040  22      -       N/A     False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2256    788     svchost.exe     0x9e8b8a09c240  21      -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2356    788     svchost.exe     0x9e8b8a106280  2       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2368    788     svchost.exe     0x9e8b8a108280  2       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2476    788     svchost.exe     0x9e8b8a131240  5       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2588    788     svchost.exe     0x9e8b8a18c240  4       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2704    788     svchost.exe     0x9e8b8a2581c0  1       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2740    788     svchost.exe     0x9e8b8a25b080  11      -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2816    788     svchost.exe     0x9e8b8a2ed300  5       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2936    788     svchost.exe     0x9e8b8a327240  5       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2948    788     svchost.exe     0x9e8b8a33b1c0  3       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2956    788     svchost.exe     0x9e8b8a33d1c0  4       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
2644    788     svchost.exe     0x9e8b8a3ea240  2       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3108    788     svchost.exe     0x9e8b8a42f240  3       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3204    788     spoolsv.exe     0x9e8b8a43f200  7       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3316    788     svchost.exe     0x9e8b8a510240  10      -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3324    788     svchost.exe     0x9e8b8a5652c0  7       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3352    788     svchost.exe     0x9e8b8a574080  1       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3368    788     svchost.exe     0x9e8b8a5631c0  16      -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3376    788     svchost.exe     0x9e8b8a575080  3       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3404    788     svchost.exe     0x9e8b8a562080  7       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3416    788     vmtoolsd.exe    0x9e8b8a57a280  11      -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3424    788     Sysmon64.exe    0x9e8b8a578200  13      -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3444    788     VGAuthService.  0x9e8b8a57c300  2       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3464    788     vm3dservice.ex  0x9e8b8a52d080  2       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3680    788     svchost.exe     0x9e8b8a60c2c0  3       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3756    788     svchost.exe     0x9e8b8a6a4240  6       -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3788    3464    vm3dservice.ex  0x9e8b8a71f200  2       -       1       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
3816    788     svchost.exe     0x9e8b8a761240  11      -       0       False   2023-08-10 11:13:44.000000 UTCN/A     Disabled
4132    928     unsecapp.exe    0x9e8b8a9b00c0  3       -       0       False   2023-08-10 11:13:45.000000 UTCN/A     Disabled
4416    928     WmiPrvSE.exe    0x9e8b8aac5280  15      -       0       False   2023-08-10 11:13:45.000000 UTCN/A     Disabled
4440    788     dllhost.exe     0x9e8b8aac8080  10      -       0       False   2023-08-10 11:13:45.000000 UTCN/A     Disabled
4744    788     svchost.exe     0x9e8b8946d1c0  1       -       0       False   2023-08-10 11:13:45.000000 UTCN/A     Disabled
4876    788     svchost.exe     0x9e8b8aedb1c0  4       -       0       False   2023-08-10 11:13:45.000000 UTCN/A     Disabled
4912    788     msdtc.exe       0x9e8b8a9b3300  9       -       0       False   2023-08-10 11:13:45.000000 UTCN/A     Disabled
4308    788     svchost.exe     0x9e8b8b19a1c0  6       -       0       False   2023-08-10 11:13:46.000000 UTCN/A     Disabled
4160    788     svchost.exe     0x9e8b8b1ef280  2       -       0       False   2023-08-10 11:13:46.000000 UTCN/A     Disabled
1792    788     svchost.exe     0x9e8b8b2561c0  5       -       0       False   2023-08-10 11:13:46.000000 UTCN/A     Disabled
5292    928     WmiPrvSE.exe    0x9e8b8b30a280  4       -       0       False   2023-08-10 11:13:47.000000 UTCN/A     Disabled
5452    788     svchost.exe     0x9e8b8b34b240  28      -       0       False   2023-08-10 11:13:51.000000 UTCN/A     Disabled
5796    788     svchost.exe     0x9e8b8b4b61c0  5       -       0       False   2023-08-10 11:13:51.000000 UTCN/A     Disabled
5972    788     svchost.exe     0x9e8b8b4cb240  18      -       0       False   2023-08-10 11:13:52.000000 UTCN/A     Disabled
6136    788     svchost.exe     0x9e8b8b34a080  11      -       0       False   2023-08-10 11:13:53.000000 UTCN/A     Disabled
5628    788     svchost.exe     0x9e8b8b77e080  4       -       0       False   2023-08-10 11:13:53.000000 UTCN/A     Disabled
7008    788     svchost.exe     0x9e8b8b5ea080  6       -       0       False   2023-08-10 11:14:05.000000 UTCN/A     Disabled
7072    788     svchost.exe     0x9e8b8b5f0240  9       -       0       False   2023-08-10 11:14:06.000000 UTCN/A     Disabled
7128    928     MoUsoCoreWorke  0x9e8b8b526280  10      -       0       False   2023-08-10 11:14:06.000000 UTCN/A     Disabled
4272    1828    sihost.exe      0x9e8b8b872280  8       -       1       False   2023-08-10 11:14:07.000000 UTCN/A     Disabled
4992    788     svchost.exe     0x9e8b8b9bd300  11      -       1       False   2023-08-10 11:14:07.000000 UTCN/A     Disabled
4372    788     svchost.exe     0x9e8b8b9ce300  5       -       1       False   2023-08-10 11:14:07.000000 UTCN/A     Disabled
6324    1580    taskhostw.exe   0x9e8b8c45a300  8       -       1       False   2023-08-10 11:14:07.000000 UTCN/A     Disabled
6692    788     svchost.exe     0x9e8b8c42c280  3       -       0       False   2023-08-10 11:14:07.000000 UTCN/A     Disabled
6768    6692    ctfmon.exe      0x9e8b8c452280  12      -       1       False   2023-08-10 11:14:07.000000 UTCN/A     Disabled
7400    744     userinit.exe    0x9e8b8c608340  0       -       1       False   2023-08-10 11:14:07.000000 UTC2023-08-10 11:14:34.000000 UTC  Disabled
7436    7400    explorer.exe    0x9e8b8c4d2080  75      -       1       False   2023-08-10 11:14:07.000000 UTCN/A     Disabled
8116    788     svchost.exe     0x9e8b8cc6e240  10      -       0       False   2023-08-10 11:14:11.000000 UTCN/A     Disabled
7236    788     svchost.exe     0x9e8b8c6b2080  7       -       1       False   2023-08-10 11:14:11.000000 UTCN/A     Disabled
7704    928     StartMenuExper  0x9e8b8cd9e080  8       -       1       False   2023-08-10 11:14:13.000000 UTCN/A     Disabled
652     788     svchost.exe     0x9e8b8cee2080  5       -       0       False   2023-08-10 11:14:13.000000 UTCN/A     Disabled
4380    928     RuntimeBroker.  0x9e8b8cf95080  3       -       1       False   2023-08-10 11:14:13.000000 UTCN/A     Disabled
8224    928     SearchApp.exe   0x9e8b89d92080  55      -       1       False   2023-08-10 11:14:14.000000 UTCN/A     Disabled
8488    928     RuntimeBroker.  0x9e8b8caa5080  8       -       1       False   2023-08-10 11:14:14.000000 UTCN/A     Disabled
8680    788     SearchIndexer.  0x9e8b9010c240  15      -       0       False   2023-08-10 11:14:15.000000 UTCN/A     Disabled
8828    928     smartscreen.ex  0x9e8b8cff5300  8       -       1       False   2023-08-10 11:14:15.000000 UTCN/A     Disabled
7756    928     RuntimeBroker.  0x9e8b89c39080  4       -       1       False   2023-08-10 11:14:16.000000 UTCN/A     Disabled
4200    788     svchost.exe     0x9e8b90554240  0       -       0       False   2023-08-10 11:14:19.000000 UTC2023-08-10 11:16:20.000000 UTC  Disabled
4664    928     dllhost.exe     0x9e8b907ef080  8       -       1       False   2023-08-10 11:14:21.000000 UTCN/A     Disabled
9580    7436    SecurityHealth  0x9e8b90135340  1       -       1       False   2023-08-10 11:14:25.000000 UTCN/A     Disabled
9612    788     SecurityHealth  0x9e8b8c7d6080  11      -       0       False   2023-08-10 11:14:25.000000 UTCN/A     Disabled
9712    7436    vmtoolsd.exe    0x9e8b8cbd5080  9       -       1       False   2023-08-10 11:14:26.000000 UTCN/A     Disabled
1564    788     svchost.exe     0x9e8b92bdf080  1       -       0       False   2023-08-10 11:14:54.000000 UTCN/A     Disabled
10044   9952    OneDrive.exe    0x9e8b90507080  0       -       1       True    2023-08-10 11:15:31.000000 UTC2023-08-10 11:15:37.000000 UTC  Disabled
10176   788     SgrmBroker.exe  0x9e8b911e5080  7       -       0       False   2023-08-10 11:15:45.000000 UTCN/A     Disabled
1396    788     uhssvc.exe      0x9e8b930402c0  3       -       0       False   2023-08-10 11:15:45.000000 UTCN/A     Disabled
10072   788     svchost.exe     0x9e8b92f1c340  9       -       0       False   2023-08-10 11:15:45.000000 UTCN/A     Disabled
7416    788     svchost.exe     0x9e8b92ddd340  1       -       1       False   2023-08-10 11:15:45.000000 UTCN/A     Disabled
3024    928     TextInputHost.  0x9e8b9050d080  9       -       1       False   2023-08-10 11:17:11.000000 UTCN/A     Disabled
4112    1580    GoogleUpdate.e  0x9e8b8c74c080  3       -       0       True    2023-08-10 11:20:19.000000 UTCN/A     Disabled
5864    7436    WinRAR.exe      0x9e8b92bdb0c0  5       -       1       False   2023-08-10 11:20:21.000000 UTCN/A     Disabled
1576    5864    msedgewebview2  0x9e8b8b4cc080  47      -       1       False   2023-08-10 11:20:21.000000 UTCN/A     Disabled
2728    1576    msedgewebview2  0x9e8b8cf97080  7       -       1       False   2023-08-10 11:20:21.000000 UTCN/A     Disabled
1616    1576    msedgewebview2  0x9e8b8a74f080  22      -       1       False   2023-08-10 11:20:25.000000 UTCN/A     Disabled
2284    1576    msedgewebview2  0x9e8b8b8dc080  14      -       1       False   2023-08-10 11:20:25.000000 UTCN/A     Disabled
1552    1576    msedgewebview2  0x9e8b8aa85080  8       -       1       False   2023-08-10 11:20:25.000000 UTCN/A     Disabled
6084    1576    msedgewebview2  0x9e8b8b0f1080  19      -       1       False   2023-08-10 11:20:25.000000 UTCN/A     Disabled
936     7436    svchost.exe     0x9e8b8cd89080  0       -       1       False   2023-08-10 11:22:31.000000 UTC2023-08-10 11:27:51.000000 UTC  Disabled
8560    788     svchost.exe     0x9e8b8c7430c0  7       -       0       False   2023-08-10 11:24:26.000000 UTCN/A     Disabled
3136    788     MsMpEng.exe     0x9e8b914f0300  10      -       0       False   2023-08-10 11:24:47.000000 UTCN/A     Disabled
9088    788     svchost.exe     0x9e8b8c4020c0  2       -       0       False   2023-08-10 11:26:32.000000 UTCN/A     Disabled
6344    788     svchost.exe     0x9e8b8a04f340  4       -       0       False   2023-08-10 11:26:32.000000 UTCN/A     Disabled
1244    788     svchost.exe     0x9e8b92987300  5       -       0       False   2023-08-10 11:26:35.000000 UTCN/A     Disabled
8260    936     cmd.exe 0x9e8b8afda300  2       -       1       False   2023-08-10 11:27:15.000000 UTC  N/A  Disabled
1668    8260    conhost.exe     0x9e8b92c65300  3       -       1       False   2023-08-10 11:27:15.000000 UTCN/A     Disabled
2240    928     ShellExperienc  0x9e8b8775c080  11      -       1       False   2023-08-10 11:27:30.000000 UTCN/A     Disabled
3616    928     RuntimeBroker.  0x9e8b8cb62080  6       -       1       False   2023-08-10 11:27:38.000000 UTCN/A     Disabled
1908    2740    audiodg.exe     0x9e8b90ec9080  5       -       0       False   2023-08-10 11:27:38.000000 UTCN/A     Disabled
5232    928     ApplicationFra  0x9e8b9a26d080  3       -       1       False   2023-08-10 11:27:42.000000 UTCN/A     Disabled
7904    788     svchost.exe     0x9e8b8cf91080  3       -       0       False   2023-08-10 11:27:43.000000 UTCN/A     Disabled
6000    788     svchost.exe     0x9e8b926e7300  2       -       0       False   2023-08-10 11:27:43.000000 UTCN/A     Disabled
5196    788     svchost.exe     0x9e8b8ca65300  3       -       0       False   2023-08-10 11:27:43.000000 UTCN/A     Disabled
9724    788     svchost.exe     0x9e8b911e3080  4       -       0       False   2023-08-10 11:28:20.000000 UTCN/A     Disabled
6224    788     svchost.exe     0x9e8b8a33e080  4       -       0       False   2023-08-10 11:28:46.000000 UTCN/A     Disabled
8428    8680    SearchProtocol  0x9e8b8b742080  7       -       0       False   2023-08-10 11:29:25.000000 UTCN/A     Disabled
6812    7436    svchost.exe     0x9e8b87762080  3       -       1       False   2023-08-10 11:30:03.000000 UTCN/A     Disabled
4364    6812    cmd.exe 0x9e8b8b6ef080  1       -       1       False   2023-08-10 11:30:57.000000 UTC  N/A  Disabled
9204    4364    conhost.exe     0x9e8b89ec7080  3       -       1       False   2023-08-10 11:30:57.000000 UTCN/A     Disabled
9784    8680    SearchFilterHo  0x9e8b92fda080  4       -       0       False   2023-08-10 11:31:32.000000 UTCN/A     Disabled
2776    7436    RamCapture64.e  0x9e8b8aa66080  5       -       1       False   2023-08-10 11:31:52.000000 UTCN/A     Disabled
9816    2776    conhost.exe     0x9e8b91cda080  6       -       1       False   2023-08-10 11:31:52.000000 UTCN/A     Disabled
```

No aparece ninguna proceso aparentemente malicioso, así que identificaremos los comandos que se han ejecutado en las consolas, para ello utilizaremos el complemento windows.cmdscan.

**Comandos en cmd:**

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# vol3 -f 20230810.mem windows.cmdscan
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished                        
PID     Process ConsoleInfo     Property        Address Data

1668    conhost.exe     0x18054aa5a10   _COMMAND_HISTORY        0x18054aa5a10   None
* 1668  conhost.exe     0x18054aa5a10   _COMMAND_HISTORY.Application    0x18054aa5a40   cmd.exe
* 1668  conhost.exe     0x18054aa5a10   _COMMAND_HISTORY.ProcessHandle  0x18052a36050   0x128
* 1668  conhost.exe     0x18054aa5a10   _COMMAND_HISTORY.CommandCount   N/A     0
* 1668  conhost.exe     0x18054aa5a10   _COMMAND_HISTORY.LastDisplayed  0x18054aa5a6c   -1
* 1668  conhost.exe     0x18054aa5a10   _COMMAND_HISTORY.CommandCountMax        0x18054aa5a38   50
* 1668  conhost.exe     0x18054aa5a10   _COMMAND_HISTORY.CommandBucket  0x18054aa5a20
9204    conhost.exe     0x1b53d4d66c0   _COMMAND_HISTORY        0x1b53d4d66c0   None
* 9204  conhost.exe     0x1b53d4d66c0   _COMMAND_HISTORY.Application    0x1b53d4d66f0   cmd.exe
* 9204  conhost.exe     0x1b53d4d66c0   _COMMAND_HISTORY.ProcessHandle  0x1b53b2d6840   0x128
* 9204  conhost.exe     0x1b53d4d66c0   _COMMAND_HISTORY.CommandCount   N/A     0
* 9204  conhost.exe     0x1b53d4d66c0   _COMMAND_HISTORY.LastDisplayed  0x1b53d4d671c   -1
* 9204  conhost.exe     0x1b53d4d66c0   _COMMAND_HISTORY.CommandCountMax        0x1b53d4d66e8   50
* 9204  conhost.exe     0x1b53d4d66c0   _COMMAND_HISTORY.CommandBucket  0x1b53d4d66d0
9816    conhost.exe     0x1b718fe9b40   _COMMAND_HISTORY        0x1b718fe9b40   None
* 9816  conhost.exe     0x1b718fe9b40   _COMMAND_HISTORY.Application    0x1b718fe9b70   RamCapture64.exe
* 9816  conhost.exe     0x1b718fe9b40   _COMMAND_HISTORY.ProcessHandle  0x1b716ec6560   0x108
* 9816  conhost.exe     0x1b718fe9b40   _COMMAND_HISTORY.CommandCount   N/A     0
* 9816  conhost.exe     0x1b718fe9b40   _COMMAND_HISTORY.LastDisplayed  0x1b718fe9b9c   -1
* 9816  conhost.exe     0x1b718fe9b40   _COMMAND_HISTORY.CommandCountMax        0x1b718fe9b68   50
* 9816  conhost.exe     0x1b718fe9b40   _COMMAND_HISTORY.CommandBucket  0x1b718fe9b50
```

No aparece ningún comando visible

**Comandos en Powershell:**

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# vol3 -f 20230810.mem windows.cmdline
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished                        
PID     Process Args

4       System  -
140     Registry        -
436     smss.exe        \SystemRoot\System32\smss.exe
564     csrss.exe       %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
644     csrss.exe       %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
656     wininit.exe     wininit.exe
744     winlogon.exe    winlogon.exe
788     services.exe    C:\WINDOWS\system32\services.exe
808     lsass.exe       C:\WINDOWS\system32\lsass.exe
928     svchost.exe     C:\WINDOWS\system32\svchost.exe -k DcomLaunch -p
956     fontdrvhost.ex  "fontdrvhost.exe"
964     fontdrvhost.ex  "fontdrvhost.exe"
512     svchost.exe     C:\WINDOWS\system32\svchost.exe -k RPCSS -p
864     svchost.exe     C:\WINDOWS\system32\svchost.exe -k DcomLaunch -p -s LSM
1048    dwm.exe "dwm.exe"
1148    svchost.exe     C:\WINDOWS\System32\svchost.exe -k NetworkService -s TermService
1272    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService
1280    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalService -s W32Time
1288    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s lmhosts
1296    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalService -p -s nsi
1304    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s TimeBrokerSvc
1432    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp
1472    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog
1500    svchost.exe     C:\WINDOWS\system32\svchost.exe -k NetworkService -p -s Dnscache
1580    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s Schedule
1588    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s ProfSvc
1712    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalServiceNoNetwork -p
1748    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p
1756    svchost.exe     C:\WINDOWS\System32\svchost.exe -k NetworkService -p -s NlaSvc
1828    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s UserManager
1980    svchost.exe     C:\WINDOWS\System32\svchost.exe -k netsvcs -p -s Themes
1988    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s SysMain
1996    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalService -p -s EventSystem
2044    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalService -p -s netprofm
2140    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s WinHttpAutoProxySvc
2168    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s SENS
2184    MemCompression  -
2256    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s Winmgmt
2356    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s AudioEndpointBuilder
2368    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s UmRdpService
2476    svchost.exe     C:\WINDOWS\System32\svchost.exe -k NetSvcs -p -s iphlpsvc
2588    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -s CertPropSvc
2704    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalService -p -s DispBrokerDesktopSvc
2740    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p
2816    svchost.exe     C:\WINDOWS\System32\svchost.exe -k NetworkService -p -s LanmanWorkstation
2936    svchost.exe     C:\WINDOWS\System32\svchost.exe -k netsvcs -p -s SessionEnv
2948    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p
2956    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p
2644    svchost.exe     C:\WINDOWS\System32\svchost.exe -k netsvcs -p -s ShellHWDetection
3108    svchost.exe     C:\WINDOWS\system32\svchost.exe -k appmodel -p -s StateRepository
3204    spoolsv.exe     C:\WINDOWS\System32\spoolsv.exe
3316    svchost.exe     C:\WINDOWS\System32\svchost.exe -k utcsvc -p
3324    svchost.exe     C:\WINDOWS\system32\svchost.exe -k NetworkService -p -s CryptSvc
3352    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalService -p -s SstpSvc
3368    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS
3376    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s TrkWks
3404    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s WpnService
3416    vmtoolsd.exe    "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
3424    Sysmon64.exe    C:\WINDOWS\Sysmon64.exe
3444    VGAuthService.  "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
3464    vm3dservice.ex  C:\WINDOWS\system32\vm3dservice.exe
3680    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalService -p -s WdiServiceHost
3756    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s LanmanServer
3788    vm3dservice.ex  vm3dservice.exe -n
3816    svchost.exe     C:\WINDOWS\System32\svchost.exe -k netsvcs
4132    unsecapp.exe    C:\WINDOWS\system32\wbem\unsecapp.exe -Embedding
4416    WmiPrvSE.exe    C:\WINDOWS\system32\wbem\wmiprvse.exe
4440    dllhost.exe     C:\WINDOWS\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}
4744    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalService -p -s fdPHost
4876    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalServiceAndNoImpersonation -p -s FDResPub
4912    msdtc.exe       C:\WINDOWS\System32\msdtc.exe
4308    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalServiceAndNoImpersonation -p -s SSDPSRV
4160    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s WdiSystemHost
1792    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -s RmSvc
5292    WmiPrvSE.exe    C:\WINDOWS\system32\wbem\wmiprvse.exe
5452    svchost.exe     C:\WINDOWS\system32\svchost.exe -k wsappx -p -s AppXSvc
5796    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalService -p -s LicenseManager
5972    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s wuauserv
6136    svchost.exe     C:\WINDOWS\System32\svchost.exe -k NetworkService -p -s DoSvc
5628    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s StorSvc
7008    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s TokenBroker
7072    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s UsoSvc
7128    MoUsoCoreWorke  C:\Windows\System32\mousocoreworker.exe -Embedding
4272    sihost.exe      sihost.exe
4992    svchost.exe     C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup -s CDPUserSvc
4372    svchost.exe     C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup -s WpnUserService
6324    taskhostw.exe   taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
6692    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s TabletInputService
6768    ctfmon.exe      "ctfmon.exe"
7400    userinit.exe    -
7436    explorer.exe    C:\WINDOWS\Explorer.EXE
8116    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc
7236    svchost.exe     C:\WINDOWS\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc
7704    StartMenuExper  "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca
652     svchost.exe     C:\WINDOWS\System32\svchost.exe -k netsvcs -p
4380    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
8224    SearchApp.exe   "C:\WINDOWS\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca
8488    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
8680    SearchIndexer.  C:\WINDOWS\system32\SearchIndexer.exe /Embedding
8828    smartscreen.ex  C:\Windows\System32\smartscreen.exe -Embedding
7756    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
4200    svchost.exe     -
4664    dllhost.exe     C:\WINDOWS\system32\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}
9580    SecurityHealth  "C:\Windows\System32\SecurityHealthSystray.exe" 
9612    SecurityHealth  C:\WINDOWS\system32\SecurityHealthService.exe
9712    vmtoolsd.exe    "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
1564    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s lfsvc
10044   OneDrive.exe    -
10176   SgrmBroker.exe  C:\WINDOWS\system32\SgrmBroker.exe
1396    uhssvc.exe      "C:\Program Files\Microsoft Update Health Tools\uhssvc.exe"
10072   svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s wscsvc
7416    svchost.exe     C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup
3024    TextInputHost.  "C:\WINDOWS\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe" -ServerName:InputApp.AppXjd5de1g66v206tj52m9d0dtpppx4cgpn.mca
4112    GoogleUpdate.e  "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /c
5864    WinRAR.exe      "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\simon.stark\Desktop\Aws hosts.zip"
1576    msedgewebview2  "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\115.0.1901.200\msedgewebview2.exe" --embedded-browser-webview=1 --webview-exe-name=WinRAR.exe --webview-exe-version=6.21.0 --user-data-dir="C:\Users\SIMON~1.STA\AppData\Local\Temp\WinRAR.exe.WebView2\EBWebView" --noerrdialogs --embedded-browser-webview-dpi-awareness=1 --enable-features=MojoIpcz --mojo-named-platform-channel-pipe=5864.6920.14039180623604215873
2728    msedgewebview2  "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\115.0.1901.200\msedgewebview2.exe" --type=crashpad-handler --user-data-dir=C:\Users\SIMON~1.STA\AppData\Local\Temp\WinRAR.exe.WebView2\EBWebView /prefetch:7 --monitor-self-annotation=ptype=crashpad-handler --database=C:\Users\SIMON~1.STA\AppData\Local\Temp\WinRAR.exe.WebView2\EBWebView\Crashpad --annotation=IsOfficialBuild=1 --annotation=channel= --annotation=chromium-version=115.0.5790.171 "--annotation=exe=C:\Program Files (x86)\Microsoft\EdgeWebView\Application\115.0.1901.200\msedgewebview2.exe" --annotation=plat=Win64 "--annotation=prod=Edge WebView2" --annotation=ver=115.0.1901.200 --initial-client-data=0x168,0x16c,0x170,0x144,0x178,0x7ffdad44d310,0x7ffdad44d320,0x7ffdad44d330
1616    msedgewebview2  "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\115.0.1901.200\msedgewebview2.exe" --type=gpu-process --noerrdialogs --user-data-dir="C:\Users\SIMON~1.STA\AppData\Local\Temp\WinRAR.exe.WebView2\EBWebView" --webview-exe-name=WinRAR.exe --webview-exe-version=6.21.0 --embedded-browser-webview=1 --embedded-browser-webview-dpi-awareness=1 --gpu-preferences=WAAAAAAAAADgAAAMAAAAAAAAAAAAAAAAAABgAAAAAAA4AAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAYAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --mojo-platform-channel-handle=1772 --field-trial-handle=1788,i,15027792176495759910,3450595540239995173,262144 --enable-features=MojoIpcz /prefetch:2
2284    msedgewebview2  "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\115.0.1901.200\msedgewebview2.exe" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --noerrdialogs --user-data-dir="C:\Users\SIMON~1.STA\AppData\Local\Temp\WinRAR.exe.WebView2\EBWebView" --webview-exe-name=WinRAR.exe --webview-exe-version=6.21.0 --embedded-browser-webview=1 --embedded-browser-webview-dpi-awareness=1 --mojo-platform-channel-handle=2024 --field-trial-handle=1788,i,15027792176495759910,3450595540239995173,262144 --enable-features=MojoIpcz /prefetch:3
1552    msedgewebview2  "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\115.0.1901.200\msedgewebview2.exe" --type=utility --utility-sub-type=storage.mojom.StorageService --lang=en-US --service-sandbox-type=service --noerrdialogs --user-data-dir="C:\Users\SIMON~1.STA\AppData\Local\Temp\WinRAR.exe.WebView2\EBWebView" --webview-exe-name=WinRAR.exe --webview-exe-version=6.21.0 --embedded-browser-webview=1 --embedded-browser-webview-dpi-awareness=1 --mojo-platform-channel-handle=2232 --field-trial-handle=1788,i,15027792176495759910,3450595540239995173,262144 --enable-features=MojoIpcz /prefetch:8
6084    msedgewebview2  "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\115.0.1901.200\msedgewebview2.exe" --type=renderer --noerrdialogs --user-data-dir="C:\Users\SIMON~1.STA\AppData\Local\Temp\WinRAR.exe.WebView2\EBWebView" --webview-exe-name=WinRAR.exe --webview-exe-version=6.21.0 --embedded-browser-webview=1 --embedded-browser-webview-dpi-awareness=1 --first-renderer-process --lang=en-US --device-scale-factor=1 --num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id=5 --js-flags="--harmony-weak-refs-with-cleanup-some --expose-gc --ms-user-locale=" --time-ticks-at-unix-epoch=-1691666011071154 --launch-time-ticks=414152570 --mojo-platform-channel-handle=3356 --field-trial-handle=1788,i,15027792176495759910,3450595540239995173,262144 --enable-features=MojoIpcz /prefetch:1
936     svchost.exe     -
8560    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s gpsvc
3136    MsMpEng.exe     "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.23070.1004-0\MsMpEng.exe"
9088    svchost.exe     C:\WINDOWS\System32\svchost.exe -k wsappx -p -s ClipSVC
6344    svchost.exe     C:\WINDOWS\system32\svchost.exe -k defragsvc
1244    svchost.exe     C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s DsSvc
8260    cmd.exe C:\WINDOWS\system32\cmd.exe
1668    conhost.exe     \??\C:\WINDOWS\system32\conhost.exe 0x4
2240    ShellExperienc  "C:\WINDOWS\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca
3616    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
1908    audiodg.exe     C:\WINDOWS\system32\AUDIODG.EXE 0x534
5232    ApplicationFra  C:\WINDOWS\system32\ApplicationFrameHost.exe -Embedding
7904    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalService -p -s BthAvctpSvc
6000    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s NgcCtnrSvc
5196    svchost.exe     C:\WINDOWS\system32\svchost.exe -k WbioSvcGroup -s WbioSrvc
9724    svchost.exe     C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s Appinfo
6224    svchost.exe     C:\WINDOWS\system32\svchost.exe -k appmodel -p -s camsvc
8428    SearchProtocol  "C:\WINDOWS\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe3_ Global\UsGthrCtrlFltPipeMssGthrPipe3 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon" 
6812    svchost.exe     "C:\Users\simon.stark\Downloads\svchost.exe" 
4364    cmd.exe C:\WINDOWS\system32\cmd.exe
9204    conhost.exe     \??\C:\WINDOWS\system32\conhost.exe 0x4
9784    SearchFilterHo  "C:\WINDOWS\system32\SearchFilterHost.exe" 0 764 820 828 8192 824 808 
2776    RamCapture64.e  "C:\Users\simon.stark\Desktop\BelkaSoft Live RAM Capturer\BelkaSoft Live RAM Capturer\RamCapture64.exe" 
9816    conhost.exe     \??\C:\WINDOWS\system32\conhost.exe 0x4
```

Podemos ver que la mayoría de procesos son procesos legítimos de windows.

El siguiente registro no es común ya que WebView2 está corriendo con un nombre WinRAR.exe en User - Data - Temp. Esto es típico de malware living-off-the-land o C2 que se camufla como proceso legítimo. No es un proceso normal de WinRAR ni de Edge; alguien podría estar ejecutando un payload a través de WebView2.

``` bash
1576    msedgewebview2  --webview-exe-name=WinRAR.exe --user-data-dir="...\Temp\WinRAR.exe.WebView2"
```

Se ha ejecutado el programa legítimo para capturar la memoria, puede haberse ejecutado por un trabajador de la empresa o porque esta programado así, no obstante, hay que tenerlo en cuanta.

``` bash
2776    RamCapture64.e  "C:\Users\simon.stark\Desktop\BelkaSoft Live RAM Capturer\BelkaSoft Live RAM Capturer\RamCapture64.exe"
```

El siguiente proceso es malicioso ya que `svchost.exe` ejecutándose desde `Downloads` es un indicador claro de malware. Normalmente `svchost.exe` solo se ejecuta desde `C:\Windows\System32`.

``` bash
6812    svchost.exe     "C:\Users\simon.stark\Downloads\svchost.exe"
```

Podemos observar el PID 6812, vamos a comprobar si el archivo es malicioso de la siguiente forma.

Obtenemos el hash del archivo, para ello volamos los archivos que tengan que ver con el PID 6812 en una carpeta.

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# vol3 -f 20230810.mem -o /root/dumps windows.dumpfiles --pid 6812
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished                        
Cache   FileObject      FileName        Result

DataSectionObject       0x9e8b894b5de0  SortDefault.nls Error dumping file
DataSectionObject       0x9e8b886f89d0  locale.nls      Error dumping file
DataSectionObject       0x9e8b91ec0140  svchost.exe     Error dumping file
ImageSectionObject      0x9e8b91ec0140  svchost.exe     file.0x9e8b91ec0140.0x9e8b957f24c0.ImageSectionObject.svchost.exe.img
ImageSectionObject      0x9e8b886c3d40  crypt32.dll     file.0x9e8b886c3d40.0x9e8b886726e0.ImageSectionObject.crypt32.dll.img
ImageSectionObject      0x9e8b894d2d00  mswsock.dll     file.0x9e8b894d2d00.0x9e8b8943da20.ImageSectionObject.mswsock.dll.img
ImageSectionObject      0x9e8b8a4e3460  winmm.dll       file.0x9e8b8a4e3460.0x9e8b8a60d920.ImageSectionObject.winmm.dll.img
ImageSectionObject      0x9e8b8b0708b0  wininet.dll     file.0x9e8b8b0708b0.0x9e8b8a2a3d20.ImageSectionObject.wininet.dll.img
ImageSectionObject      0x9e8b8a4e4270  mpr.dll file.0x9e8b8a4e4270.0x9e8b8a656d00.ImageSectionObject.mpr.dll.img
ImageSectionObject      0x9e8b8ae25140  cscapi.dll      file.0x9e8b8ae25140.0x9e8b8a7e5a20.ImageSectionObject.cscapi.dll.img
ImageSectionObject      0x9e8b894d69f0  rsaenh.dll      file.0x9e8b894d69f0.0x9e8b89492d20.ImageSectionObject.rsaenh.dll.img
ImageSectionObject      0x9e8b89f9e870  winhttp.dll     file.0x9e8b89f9e870.0x9e8b889f3a70.ImageSectionObject.winhttp.dll.img
ImageSectionObject      0x9e8b8a4de640  netapi32.dll    file.0x9e8b8a4de640.0x9e8b8a6062b0.ImageSectionObject.netapi32.dll.img
ImageSectionObject      0x9e8b89de26e0  dhcpcsvc6.dll   file.0x9e8b89de26e0.0x9e8b89e02050.ImageSectionObject.dhcpcsvc6.dll.img
ImageSectionObject      0x9e8b89de1740  dhcpcsvc.dll    file.0x9e8b89de1740.0x9e8b89daf7f0.ImageSectionObject.dhcpcsvc.dll.img
ImageSectionObject      0x9e8b894d2850  IPHLPAPI.DLL    file.0x9e8b894d2850.0x9e8b89442cf0.ImageSectionObject.IPHLPAPI.DLL.img
ImageSectionObject      0x9e8b894d50f0  wkscli.dll      file.0x9e8b894d50f0.0x9e8b89491a20.ImageSectionObject.wkscli.dll.img
ImageSectionObject      0x9e8b894d3980  dnsapi.dll      file.0x9e8b894d3980.0x9e8b89442a20.ImageSectionObject.dnsapi.dll.img
ImageSectionObject      0x9e8b886e03e0  ucrtbase.dll    file.0x9e8b886e03e0.0x9e8b88575990.ImageSectionObject.ucrtbase.dll.img
ImageSectionObject      0x9e8b89399400  sspicli.dll     file.0x9e8b89399400.0x9e8b88af3d30.ImageSectionObject.sspicli.dll.img
ImageSectionObject      0x9e8b894b4b20  cryptsp.dll     file.0x9e8b894b4b20.0x9e8b8941bcc0.ImageSectionObject.cryptsp.dll.img
ImageSectionObject      0x9e8b894b4cb0  cryptbase.dll   file.0x9e8b894b4cb0.0x9e8b8943ba20.ImageSectionObject.cryptbase.dll.img
ImageSectionObject      0x9e8b894b3860  msasn1.dll      file.0x9e8b894b3860.0x9e8b88a9ad80.ImageSectionObject.msasn1.dll.img
ImageSectionObject      0x9e8b893998b0  userenv.dll     file.0x9e8b893998b0.0x9e8b88ac1d30.ImageSectionObject.userenv.dll.img
ImageSectionObject      0x9e8b893990e0  profapi.dll     file.0x9e8b893990e0.0x9e8b882f9d30.ImageSectionObject.profapi.dll.img
ImageSectionObject      0x9e8b886c4830  msvcp_win.dll   file.0x9e8b886c4830.0x9e8b88680d20.ImageSectionObject.msvcp_win.dll.img
ImageSectionObject      0x9e8b886c4b50  KernelBase.dll  file.0x9e8b886c4b50.0x9e8b88677b20.ImageSectionObject.KernelBase.dll.img
ImageSectionObject      0x9e8b878da700  kernel32.dll    file.0x9e8b878da700.0x9e8b88562c20.ImageSectionObject.kernel32.dll.img
ImageSectionObject      0x9e8b885f5b50  advapi32.dll    file.0x9e8b885f5b50.0x9e8b881a9c00.ImageSectionObject.advapi32.dll.img
ImageSectionObject      0x9e8b885f4570  bcrypt.dll      file.0x9e8b885f4570.0x9e8b87cbe3b0.ImageSectionObject.bcrypt.dll.img
ImageSectionObject      0x9e8b885f5510  gdi32full.dll   file.0x9e8b885f5510.0x9e8b885c4ce0.ImageSectionObject.gdi32full.dll.img
ImageSectionObject      0x9e8b885f4d40  bcryptprimitives.dll    file.0x9e8b885f4d40.0x9e8b885764d0.ImageSectionObject.bcryptprimitives.dll.img
ImageSectionObject      0x9e8b885f56a0  win32u.dll      file.0x9e8b885f56a0.0x9e8b88576010.ImageSectionObject.win32u.dll.img
ImageSectionObject      0x9e8b885f4250  psapi.dll       file.0x9e8b885f4250.0x9e8b88576990.ImageSectionObject.psapi.dll.img
ImageSectionObject      0x9e8b878daed0  sechost.dll     file.0x9e8b878daed0.0x9e8b878d7ca0.ImageSectionObject.sechost.dll.img
ImageSectionObject      0x9e8b878da890  shlwapi.dll     file.0x9e8b878da890.0x9e8b885b7bf0.ImageSectionObject.shlwapi.dll.img
ImageSectionObject      0x9e8b878db1f0  gdi32.dll       file.0x9e8b878db1f0.0x9e8b878d6920.ImageSectionObject.gdi32.dll.img
ImageSectionObject      0x9e8b878da570  nsi.dll file.0x9e8b878da570.0x9e8b88576bf0.ImageSectionObject.nsi.dll.img
ImageSectionObject      0x9e8b884f7570  user32.dll      file.0x9e8b884f7570.0x9e8b884bacc0.ImageSectionObject.user32.dll.img
ImageSectionObject      0x9e8b885206a0  ws2_32.dll      file.0x9e8b885206a0.0x9e8b8855fd00.ImageSectionObject.ws2_32.dll.img
DataSectionObject       0x9e8b8851f890  ole32.dll       Error dumping file
ImageSectionObject      0x9e8b8851f890  ole32.dll       file.0x9e8b8851f890.0x9e8b88560d00.ImageSectionObject.ole32.dll.img
ImageSectionObject      0x9e8b88520830  combase.dll     file.0x9e8b88520830.0x9e8b8855bc10.ImageSectionObject.combase.dll.img
ImageSectionObject      0x9e8b885201f0  msvcrt.dll      file.0x9e8b885201f0.0x9e8b88164d40.ImageSectionObject.msvcrt.dll.img
DataSectionObject       0x9e8b88520380  oleaut32.dll    Error dumping file
ImageSectionObject      0x9e8b88520380  oleaut32.dll    file.0x9e8b88520380.0x9e8b8853ebb0.ImageSectionObject.oleaut32.dll.img
ImageSectionObject      0x9e8b884f70c0  rpcrt4.dll      file.0x9e8b884f70c0.0x9e8b884b3a20.ImageSectionObject.rpcrt4.dll.img
DataSectionObject       0x9e8b884f8ce0  imm32.dll       Error dumping file
ImageSectionObject      0x9e8b884f8ce0  imm32.dll       file.0x9e8b884f8ce0.0x9e8b884baa20.ImageSectionObject.imm32.dll.img
ImageSectionObject      0x9e8b882ca920  ntdll.dll       file.0x9e8b882ca920.0x9e8b882e4010.ImageSectionObject.ntdll.dll.img
```

**Después obtenemos su hash**

``` bash
┌──(root㉿beginer)-[/home/beginer/Escritorio/Dumps]
└─# sha256sum file.0x9e8b91ec0140.0x9e8b957f24c0.ImageSectionObject.svchost.exe.img
eaf09578d6eca82501aa2b3fcef473c3795ea365a9b33a252e5dc712c62981ea  file.0x9e8b91ec0140.0x9e8b957f24c0.ImageSectionObject.svchost.exe.img
```

Aparece el hash eaf09578d6eca82501aa2b3fcef473c3795ea365a9b33a252e5dc712c62981ea  

Vamos a copiarlo en VirusTotal y ver si se ha registrado como malicioso. Al pegar el hash podemos ver que casi todos los archivos que contiene son detectados como maliciosos

![[Pasted image 20260327235245.png]]

Estamos ante el troyano rozena usado en metasploit.

**Respuesta correcta: 6812**

**==2. El equipo SOC cree que el proceso malicioso pudo haber generado otro proceso que permitió al atacante ejecutar commandos. ¿Cuál es el ID de proceso de ese proceso hijo?==**

Para ello utilizaremos el complemento de pslist, el cual lista los procesos, sus PID y sus procesos hijos creados.

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# vol3 -f 20230810.mem windows.pslist
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime      File output

4       0       System  0x9e8b87680040  225     -       N/A     False   2023-08-10 11:13:38.000000 UTC  N/A     Disabled
140     4       Registry        0x9e8b876ce080  4       -       N/A     False   2023-08-10 11:13:32.000000 UTC  N/A   Disabled
436     4       smss.exe        0x9e8b8843f040  2       -       N/A     False   2023-08-10 11:13:38.000000 UTC  N/A   Disabled
564     548     csrss.exe       0x9e8b882f8140  13      -       0       False   2023-08-10 11:13:41.000000 UTC  N/A   Disabled
644     636     csrss.exe       0x9e8b893eb140  14      -       1       False   2023-08-10 11:13:41.000000 UTC  N/A   Disabled
656     548     wininit.exe     0x9e8b89416080  1       -       0       False   2023-08-10 11:13:41.000000 UTC  N/A   Disabled
744     636     winlogon.exe    0x9e8b89441080  4       -       1       False   2023-08-10 11:13:42.000000 UTC  N/A   Disabled
788     656     services.exe    0x9e8b8949e080  10      -       0       False   2023-08-10 11:13:42.000000 UTC  N/A   Disabled
808     656     lsass.exe       0x9e8b894a2080  12      -       0       False   2023-08-10 11:13:42.000000 UTC  N/A   Disabled
928     788     svchost.exe     0x9e8b89527240  13      -       0       False   2023-08-10 11:13:42.000000 UTC  N/A   Disabled
956     744     fontdrvhost.ex  0x9e8b89530180  5       -       1       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
964     656     fontdrvhost.ex  0x9e8b8952e180  5       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
512     788     svchost.exe     0x9e8b895a72c0  11      -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
864     788     svchost.exe     0x9e8b895a9240  6       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1048    744     dwm.exe 0x9e8b89c520c0  14      -       1       False   2023-08-10 11:13:43.000000 UTC  N/A     Disabled
1148    788     svchost.exe     0x9e8b89c922c0  30      -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1272    788     svchost.exe     0x9e8b89cf4280  3       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1280    788     svchost.exe     0x9e8b89cf5080  4       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1288    788     svchost.exe     0x9e8b89cf71c0  3       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1296    788     svchost.exe     0x9e8b89cf91c0  4       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1304    788     svchost.exe     0x9e8b89cfb200  4       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1432    788     svchost.exe     0x9e8b89d121c0  5       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1472    788     svchost.exe     0x9e8b89d3e1c0  7       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1500    788     svchost.exe     0x9e8b89d412c0  10      -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1580    788     svchost.exe     0x9e8b89d900c0  7       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1588    788     svchost.exe     0x9e8b89d94080  6       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1712    788     svchost.exe     0x9e8b89dab1c0  2       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1748    788     svchost.exe     0x9e8b89e541c0  11      -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1756    788     svchost.exe     0x9e8b89e562c0  6       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1828    788     svchost.exe     0x9e8b89e70240  6       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1980    788     svchost.exe     0x9e8b89fbc240  3       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1988    788     svchost.exe     0x9e8b89fc1280  6       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
1996    788     svchost.exe     0x9e8b89fc4080  6       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
2044    788     svchost.exe     0x9e8b89fc2080  8       -       0       False   2023-08-10 11:13:43.000000 UTC  N/A   Disabled
2140    788     svchost.exe     0x9e8b89f6f200  2       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2168    788     svchost.exe     0x9e8b8a039240  2       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2184    4       MemCompression  0x9e8b8a038040  22      -       N/A     False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2256    788     svchost.exe     0x9e8b8a09c240  21      -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2356    788     svchost.exe     0x9e8b8a106280  2       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2368    788     svchost.exe     0x9e8b8a108280  2       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2476    788     svchost.exe     0x9e8b8a131240  5       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2588    788     svchost.exe     0x9e8b8a18c240  4       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2704    788     svchost.exe     0x9e8b8a2581c0  1       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2740    788     svchost.exe     0x9e8b8a25b080  11      -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2816    788     svchost.exe     0x9e8b8a2ed300  5       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2936    788     svchost.exe     0x9e8b8a327240  5       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2948    788     svchost.exe     0x9e8b8a33b1c0  3       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2956    788     svchost.exe     0x9e8b8a33d1c0  4       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
2644    788     svchost.exe     0x9e8b8a3ea240  2       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3108    788     svchost.exe     0x9e8b8a42f240  3       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3204    788     spoolsv.exe     0x9e8b8a43f200  7       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3316    788     svchost.exe     0x9e8b8a510240  10      -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3324    788     svchost.exe     0x9e8b8a5652c0  7       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3352    788     svchost.exe     0x9e8b8a574080  1       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3368    788     svchost.exe     0x9e8b8a5631c0  16      -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3376    788     svchost.exe     0x9e8b8a575080  3       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3404    788     svchost.exe     0x9e8b8a562080  7       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3416    788     vmtoolsd.exe    0x9e8b8a57a280  11      -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3424    788     Sysmon64.exe    0x9e8b8a578200  13      -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3444    788     VGAuthService.  0x9e8b8a57c300  2       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3464    788     vm3dservice.ex  0x9e8b8a52d080  2       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3680    788     svchost.exe     0x9e8b8a60c2c0  3       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3756    788     svchost.exe     0x9e8b8a6a4240  6       -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3788    3464    vm3dservice.ex  0x9e8b8a71f200  2       -       1       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
3816    788     svchost.exe     0x9e8b8a761240  11      -       0       False   2023-08-10 11:13:44.000000 UTC  N/A   Disabled
4132    928     unsecapp.exe    0x9e8b8a9b00c0  3       -       0       False   2023-08-10 11:13:45.000000 UTC  N/A   Disabled
4416    928     WmiPrvSE.exe    0x9e8b8aac5280  15      -       0       False   2023-08-10 11:13:45.000000 UTC  N/A   Disabled
4440    788     dllhost.exe     0x9e8b8aac8080  10      -       0       False   2023-08-10 11:13:45.000000 UTC  N/A   Disabled
4744    788     svchost.exe     0x9e8b8946d1c0  1       -       0       False   2023-08-10 11:13:45.000000 UTC  N/A   Disabled
4876    788     svchost.exe     0x9e8b8aedb1c0  4       -       0       False   2023-08-10 11:13:45.000000 UTC  N/A   Disabled
4912    788     msdtc.exe       0x9e8b8a9b3300  9       -       0       False   2023-08-10 11:13:45.000000 UTC  N/A   Disabled
4308    788     svchost.exe     0x9e8b8b19a1c0  6       -       0       False   2023-08-10 11:13:46.000000 UTC  N/A   Disabled
4160    788     svchost.exe     0x9e8b8b1ef280  2       -       0       False   2023-08-10 11:13:46.000000 UTC  N/A   Disabled
1792    788     svchost.exe     0x9e8b8b2561c0  5       -       0       False   2023-08-10 11:13:46.000000 UTC  N/A   Disabled
5292    928     WmiPrvSE.exe    0x9e8b8b30a280  4       -       0       False   2023-08-10 11:13:47.000000 UTC  N/A   Disabled
5452    788     svchost.exe     0x9e8b8b34b240  28      -       0       False   2023-08-10 11:13:51.000000 UTC  N/A   Disabled
5796    788     svchost.exe     0x9e8b8b4b61c0  5       -       0       False   2023-08-10 11:13:51.000000 UTC  N/A   Disabled
5972    788     svchost.exe     0x9e8b8b4cb240  18      -       0       False   2023-08-10 11:13:52.000000 UTC  N/A   Disabled
6136    788     svchost.exe     0x9e8b8b34a080  11      -       0       False   2023-08-10 11:13:53.000000 UTC  N/A   Disabled
5628    788     svchost.exe     0x9e8b8b77e080  4       -       0       False   2023-08-10 11:13:53.000000 UTC  N/A   Disabled
7008    788     svchost.exe     0x9e8b8b5ea080  6       -       0       False   2023-08-10 11:14:05.000000 UTC  N/A   Disabled
7072    788     svchost.exe     0x9e8b8b5f0240  9       -       0       False   2023-08-10 11:14:06.000000 UTC  N/A   Disabled
7128    928     MoUsoCoreWorke  0x9e8b8b526280  10      -       0       False   2023-08-10 11:14:06.000000 UTC  N/A   Disabled
4272    1828    sihost.exe      0x9e8b8b872280  8       -       1       False   2023-08-10 11:14:07.000000 UTC  N/A   Disabled
4992    788     svchost.exe     0x9e8b8b9bd300  11      -       1       False   2023-08-10 11:14:07.000000 UTC  N/A   Disabled
4372    788     svchost.exe     0x9e8b8b9ce300  5       -       1       False   2023-08-10 11:14:07.000000 UTC  N/A   Disabled
6324    1580    taskhostw.exe   0x9e8b8c45a300  8       -       1       False   2023-08-10 11:14:07.000000 UTC  N/A   Disabled
6692    788     svchost.exe     0x9e8b8c42c280  3       -       0       False   2023-08-10 11:14:07.000000 UTC  N/A   Disabled
6768    6692    ctfmon.exe      0x9e8b8c452280  12      -       1       False   2023-08-10 11:14:07.000000 UTC  N/A   Disabled
7400    744     userinit.exe    0x9e8b8c608340  0       -       1       False   2023-08-10 11:14:07.000000 UTC  2023-08-10 11:14:34.000000 UTC Disabled
7436    7400    explorer.exe    0x9e8b8c4d2080  75      -       1       False   2023-08-10 11:14:07.000000 UTC  N/A   Disabled
8116    788     svchost.exe     0x9e8b8cc6e240  10      -       0       False   2023-08-10 11:14:11.000000 UTC  N/A   Disabled
7236    788     svchost.exe     0x9e8b8c6b2080  7       -       1       False   2023-08-10 11:14:11.000000 UTC  N/A   Disabled
7704    928     StartMenuExper  0x9e8b8cd9e080  8       -       1       False   2023-08-10 11:14:13.000000 UTC  N/A   Disabled
652     788     svchost.exe     0x9e8b8cee2080  5       -       0       False   2023-08-10 11:14:13.000000 UTC  N/A   Disabled
4380    928     RuntimeBroker.  0x9e8b8cf95080  3       -       1       False   2023-08-10 11:14:13.000000 UTC  N/A   Disabled
8224    928     SearchApp.exe   0x9e8b89d92080  55      -       1       False   2023-08-10 11:14:14.000000 UTC  N/A   Disabled
8488    928     RuntimeBroker.  0x9e8b8caa5080  8       -       1       False   2023-08-10 11:14:14.000000 UTC  N/A   Disabled
8680    788     SearchIndexer.  0x9e8b9010c240  15      -       0       False   2023-08-10 11:14:15.000000 UTC  N/A   Disabled
8828    928     smartscreen.ex  0x9e8b8cff5300  8       -       1       False   2023-08-10 11:14:15.000000 UTC  N/A   Disabled
7756    928     RuntimeBroker.  0x9e8b89c39080  4       -       1       False   2023-08-10 11:14:16.000000 UTC  N/A   Disabled
4200    788     svchost.exe     0x9e8b90554240  0       -       0       False   2023-08-10 11:14:19.000000 UTC  2023-08-10 11:16:20.000000 UTC Disabled
4664    928     dllhost.exe     0x9e8b907ef080  8       -       1       False   2023-08-10 11:14:21.000000 UTC  N/A   Disabled
9580    7436    SecurityHealth  0x9e8b90135340  1       -       1       False   2023-08-10 11:14:25.000000 UTC  N/A   Disabled
9612    788     SecurityHealth  0x9e8b8c7d6080  11      -       0       False   2023-08-10 11:14:25.000000 UTC  N/A   Disabled
9712    7436    vmtoolsd.exe    0x9e8b8cbd5080  9       -       1       False   2023-08-10 11:14:26.000000 UTC  N/A   Disabled
1564    788     svchost.exe     0x9e8b92bdf080  1       -       0       False   2023-08-10 11:14:54.000000 UTC  N/A   Disabled
10044   9952    OneDrive.exe    0x9e8b90507080  0       -       1       True    2023-08-10 11:15:31.000000 UTC  2023-08-10 11:15:37.000000 UTC Disabled
10176   788     SgrmBroker.exe  0x9e8b911e5080  7       -       0       False   2023-08-10 11:15:45.000000 UTC  N/A   Disabled
1396    788     uhssvc.exe      0x9e8b930402c0  3       -       0       False   2023-08-10 11:15:45.000000 UTC  N/A   Disabled
10072   788     svchost.exe     0x9e8b92f1c340  9       -       0       False   2023-08-10 11:15:45.000000 UTC  N/A   Disabled
7416    788     svchost.exe     0x9e8b92ddd340  1       -       1       False   2023-08-10 11:15:45.000000 UTC  N/A   Disabled
3024    928     TextInputHost.  0x9e8b9050d080  9       -       1       False   2023-08-10 11:17:11.000000 UTC  N/A   Disabled
4112    1580    GoogleUpdate.e  0x9e8b8c74c080  3       -       0       True    2023-08-10 11:20:19.000000 UTC  N/A   Disabled
5864    7436    WinRAR.exe      0x9e8b92bdb0c0  5       -       1       False   2023-08-10 11:20:21.000000 UTC  N/A   Disabled
1576    5864    msedgewebview2  0x9e8b8b4cc080  47      -       1       False   2023-08-10 11:20:21.000000 UTC  N/A   Disabled
2728    1576    msedgewebview2  0x9e8b8cf97080  7       -       1       False   2023-08-10 11:20:21.000000 UTC  N/A   Disabled
1616    1576    msedgewebview2  0x9e8b8a74f080  22      -       1       False   2023-08-10 11:20:25.000000 UTC  N/A   Disabled
2284    1576    msedgewebview2  0x9e8b8b8dc080  14      -       1       False   2023-08-10 11:20:25.000000 UTC  N/A   Disabled
1552    1576    msedgewebview2  0x9e8b8aa85080  8       -       1       False   2023-08-10 11:20:25.000000 UTC  N/A   Disabled
6084    1576    msedgewebview2  0x9e8b8b0f1080  19      -       1       False   2023-08-10 11:20:25.000000 UTC  N/A   Disabled
936     7436    svchost.exe     0x9e8b8cd89080  0       -       1       False   2023-08-10 11:22:31.000000 UTC  2023-08-10 11:27:51.000000 UTC Disabled
8560    788     svchost.exe     0x9e8b8c7430c0  7       -       0       False   2023-08-10 11:24:26.000000 UTC  N/A   Disabled
3136    788     MsMpEng.exe     0x9e8b914f0300  10      -       0       False   2023-08-10 11:24:47.000000 UTC  N/A   Disabled
9088    788     svchost.exe     0x9e8b8c4020c0  2       -       0       False   2023-08-10 11:26:32.000000 UTC  N/A   Disabled
6344    788     svchost.exe     0x9e8b8a04f340  4       -       0       False   2023-08-10 11:26:32.000000 UTC  N/A   Disabled
1244    788     svchost.exe     0x9e8b92987300  5       -       0       False   2023-08-10 11:26:35.000000 UTC  N/A   Disabled
8260    936     cmd.exe 0x9e8b8afda300  2       -       1       False   2023-08-10 11:27:15.000000 UTC  N/A     Disabled
1668    8260    conhost.exe     0x9e8b92c65300  3       -       1       False   2023-08-10 11:27:15.000000 UTC  N/A   Disabled
2240    928     ShellExperienc  0x9e8b8775c080  11      -       1       False   2023-08-10 11:27:30.000000 UTC  N/A   Disabled
3616    928     RuntimeBroker.  0x9e8b8cb62080  6       -       1       False   2023-08-10 11:27:38.000000 UTC  N/A   Disabled
1908    2740    audiodg.exe     0x9e8b90ec9080  5       -       0       False   2023-08-10 11:27:38.000000 UTC  N/A   Disabled
5232    928     ApplicationFra  0x9e8b9a26d080  3       -       1       False   2023-08-10 11:27:42.000000 UTC  N/A   Disabled
7904    788     svchost.exe     0x9e8b8cf91080  3       -       0       False   2023-08-10 11:27:43.000000 UTC  N/A   Disabled
6000    788     svchost.exe     0x9e8b926e7300  2       -       0       False   2023-08-10 11:27:43.000000 UTC  N/A   Disabled
5196    788     svchost.exe     0x9e8b8ca65300  3       -       0       False   2023-08-10 11:27:43.000000 UTC  N/A   Disabled
9724    788     svchost.exe     0x9e8b911e3080  4       -       0       False   2023-08-10 11:28:20.000000 UTC  N/A   Disabled
6224    788     svchost.exe     0x9e8b8a33e080  4       -       0       False   2023-08-10 11:28:46.000000 UTC  N/A   Disabled
8428    8680    SearchProtocol  0x9e8b8b742080  7       -       0       False   2023-08-10 11:29:25.000000 UTC  N/A   Disabled
6812    7436    svchost.exe     0x9e8b87762080  3       -       1       False   2023-08-10 11:30:03.000000 UTC  N/A   Disabled
4364    6812    cmd.exe 0x9e8b8b6ef080  1       -       1       False   2023-08-10 11:30:57.000000 UTC  N/A     Disabled
9204    4364    conhost.exe     0x9e8b89ec7080  3       -       1       False   2023-08-10 11:30:57.000000 UTC  N/A   Disabled
9784    8680    SearchFilterHo  0x9e8b92fda080  4       -       0       False   2023-08-10 11:31:32.000000 UTC  N/A   Disabled
2776    7436    RamCapture64.e  0x9e8b8aa66080  5       -       1       False   2023-08-10 11:31:52.000000 UTC  N/A   Disabled
9816    2776    conhost.exe     0x9e8b91cda080  6       -       1       False   2023-08-10 11:31:52.000000 UTC  N/A   Disabled
```

Podemos observar que el proceso malicioso tiene el PID 6812

``` bash
6812    7436    svchost.exe     0x9e8b87762080  3       -       1       False   2023-08-10 11:30:03.000000 UTC  N/A   Disabled
```

El proceso 6812 ha creado el proceso hijo cmd.exe con PID 4364

``` bash
4364    6812    cmd.exe 0x9e8b8b6ef080  1       -       1       False   2023-08-10 11:30:57.000000 UTC  N/A     Disabled
```

El proceso 4364 es conhost.exe, el cual ha creado el proceso con PID 9204

``` bash
9204    4364    conhost.exe     0x9e8b89ec7080  3       -       1       False   2023-08-10 11:30:57.000000 UTC  N/A   Disabled
```

El proceso 9204 no se encuentra en el sistema, solo se encuentra el proceso anterior que ha creado el proceso con PID 9204

``` bash
9204    4364    conhost.exe     0x9e8b89ec7080  3       -       1       False   2023-08-10 11:30:57.000000 UTC  N/A   Disabled
```


**==3. El equipo de ingeniería inversa necesita la muestra del archivo malicioso para analizarla. Tu responsible del SOC te ha indicado que encuentres el hash del archivo y luego envíes la muestra al equipo de ingeniería inversa. ¿Cuál es el hash MD5 del archivo malicioso?==**

Podemos extraer el hash MD5 utilizando la herramienta de md5sum. El volcado de archivos del proceso malicioso 6812 ya lo hicimos anteriormente.

``` bash
┌──(root㉿beginer)-[/home/beginer/Escritorio/Dumps2]
└─# md5sum /home/beginer/Escritorio/Dumps/file.0x9e8b91ec0140.0x9e8b957f24c0.ImageSectionObject.svchost.exe.img 
5bd547c6f5bfc4858fe62c8867acfbb5  /home/beginer/Escritorio/Dumps/file.0x9e8b91ec0140.0x9e8b957f24c0.ImageSectionObject.svchost.exe.img
```

El hash MD5 del archivo malicioso o proceso llamado svchost.exe es 5bd547c6f5bfc4858fe62c8867acfbb5.

**Respuesta correcta: 5bd547c6f5bfc4858fe62c8867acfbb5  **


**==4. Para determinar el alcance del incidente, el responsible del SOC ha desplegado un equipo de threat hunting para buscar indicadores de compromiso en todo el entorno. Sería de gran ayuda para el equipo si puedes confirmar la dirección IP de C2 y los puertos, para que puedan utilizarlos en su investigación.==**

Podemos utilizar el complemento de netscan y filtrar por el PID del proceso malicioso.

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# vol3 -f 20230810.mem windows.netscan | grep '6812'
0x9e8b8cb58010.0TCPv4   172.17.79.131can64254fin13.127.155.166  8888    ESTABLISHED     6812    svchost.exe     2023-08-10 11:30:03.000000 UTC
```

Podemos observar que el proceso malicioso opera desde la IP víctima 172.17.79.131 mediante el puerto 8888 a la IP del atacante 13.127.155.166.

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# vol3 -f 20230810.mem windows.netscan | grep '6812'
0x9e8b8cb58010.0TCPv4   172.17.79.131can64254fin13.127.155.166  8888    ESTABLISHED     6812    svchost.exe     2023-08-10 11:30:03.000000 UTC
```

**Respuesta correcta: 13.127.155.166:8888**


**==5. Necesitamos una línea temporal para ayudar a delimitar el incidente y permitir al equipo DFIR realizar un análisis de causa raíz. ¿Puedes confirmar el memento en que el proceso fue ejecutado y cuando se estableció el canal de C2?==**

Podemos observarlo en la evidencia anterior.

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# vol3 -f 20230810.mem windows.netscan | grep '6812'
0x9e8b8cb58010.0TCPv4   172.17.79.131can64254fin13.127.155.166  8888    ESTABLISHED     6812    svchost.exe     2023-08-10 11:30:03.000000 UTC
```

En la evidencia podemos observar la fecha de la ejecución del proceso 2023-08-10 11:30:03.000000 UTC.

**Respuesta correcta: 10/08/2023 11:30:03**

**==6. ¿Cuál es el offset de memoria del proceso malicioso?==**

En Volatility 3, cada plugin puede mostrar distintos offsets, el complemento de windows.pslist muestra el offset del proceso.

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/rogueone]
└─# vol3 -f 20230810.mem windows.pslist | grep '6812'
6812    7436    svchost.exe     0x9e8b87762080  3       -       1       False   2023-08-10 11:30:03.000000 UTC  N/A   Disabled
4364    6812    cmd.exe 0x9e8b8b6ef080  1       -       1       False   2023-08-10 11:30:57.000000 UTC  N/A     Disabled
```

Podemos observar que el offset del proceso svchost.exe es el siguiente 0x9e8b87762080.

**Respuesta correcta: 0x9e8b87762080** 

**==7. Has analizado con éxito un volcado de memoria y has recibido elogios de tu responsible. Al día siguiente, tu responsible te pide una actualización sobre el archivo malicioso. Revisas VirusTotal y descubres que el archivo ya ha sido subido, probablemente por el equipo de ingeniería inversa. Tu tarea es determinar cuándo se envió por primera vez la muestra a VirusTotal.==**

Anteriormente analizamos el proceso y los pasos que se deben seguir para buscar el archivo maliciosos en virustotal.

Una vez subido a virustotal, en el apartado de detalles podemos observar el campo de 'First Submission', alojado en el apartado de 'History'.

![[Pasted image 20260328005324.png]]

**Respuesta correcta: 10/08/2023 11:58:10**
# Conclusión

El análisis forense de memoria realizado sobre el sistema comprometido permitie confirmar la existencia de actividad sospechosa asociada a comunicaciones de tipo C2, a pesar de que no se identificaron procesos maliciosos evidentes en la lista de procesos activa. Esto sugiere el uso de técnicas de evasión, como procesos legítimos comprometidos o ejecución en memoria sin persistencia visible.

Mediante el uso de herramientas como Volatility, se logró caracterizar el entorno (Windows 10) y examinar tanto procesos como posibles artefactos en consola, sin encontrar commandos explícitos que evidencien la actividad maliciosa. Esto refuerza la hipótesis de un ataque sigiloso, posiblemente basado en técnicas fileless.

Finalmente se observa el proceso llamado svchost.exe con PID 6812, un proceso legítimo que normalmente se ejecuta y se encuentra en la ruta `C:\Windows\System32`, en este caso el archivo se encontraba en la ruta `C:\Users\simon.stark\Downloads\svchost.exe`, por lo que se procedió a investigar dicho archivo y los procesos en los que interfiere. Tras la investigación se extrae su hash MD5 (5bd547c6f5bfc4858fe62c8867acfbb5) y su hash SHA256 (eaf09578d6eca82501aa2b3fcef473c3795ea365a9b33a252e5dc712c62981ea) analiza que el proceso y el archivo es malicioso, conocido comúnmente como el troyano rozena, utilizado en metasploit. El archivo actuaba sobre la consola cmd.exe, que a su vez, esta consola controlada por el archivo malicioso actuaba sobre el archivo y proceso conhost.exe. El memento en el que el proceso svchost.exe fue ejecutado por primera vez es en fecha y hora 10/08/2023 11:30:03, actuando desde la IP víctima '172.17.79.131', mediante el puerto 8888 hasta la IP enemiga '13.127.155.166'.

