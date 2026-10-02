# Enunciado

Torrin es sospechoso de set una amenaza interna en Forela. Se cree que filtró algunos datos y eliminó ciertas aplicaciones de su estación de trabajo. Logró evadir algunos controles e instaló software no autorizado.

A pesar de los esfuerzos del equipo forense, no se encontró evidencia de filtración de datos.

Como analista senior de respuesta a incidentes, se te ha asignado la tarea de investigar el incidente para determinar la conversación entre las dos partes involucradas.

# Preparación y visualización de los archivos del reto

#### Análisis principal

En esta sección analizaremos los archivos del reto, su formato o extensión e identificaremos que herramientas y apps usaremos para su posterior analysis.

Primero descomprimiremos el archivo que nos proporciona el reto y analizaremos los archivos resultantes


``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/soc/jinglebell]
└─# 7z x jinglebell.zip 

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=es_ES.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 478652 bytes (468 KiB)

Extracting archive: jinglebell.zip
--
Path = jinglebell.zip
Type = zip
Physical Size = 478652

    
Enter password (will not be echoed):
Everything is Ok                                                                            

Folders: 9
Files: 3
Size:       2589296
Compressed: 478652
                                                                                                              
┌──(root㉿beginer)-[/home/…/maquinas/blue/soc/jinglebell]
└─# ls
jinglebell.zip  Torrincase
                                                                                                              
┌──(root㉿beginer)-[/home/…/maquinas/blue/soc/jinglebell]
└─# cd Torrincase                                
                                                                                                              
┌──(root㉿beginer)-[/home/…/blue/soc/jinglebell/Torrincase]
└─# ls
C
                                                                                                              
┌──(root㉿beginer)-[/home/…/blue/soc/jinglebell/Torrincase]
└─# cd C         
                                                                                                              
┌──(root㉿beginer)-[/home/…/soc/jinglebell/Torrincase/C]
└─# ls
Users
                                                                                                              
┌──(root㉿beginer)-[/home/…/soc/jinglebell/Torrincase/C]
└─# cd Users 
                                                                                                              
┌──(root㉿beginer)-[/home/…/jinglebell/Torrincase/C/Users]
└─# ls
Appdata
                                                                                                              
┌──(root㉿beginer)-[/home/…/jinglebell/Torrincase/C/Users]
└─# cd Appdata 
                                                                                                              
┌──(root㉿beginer)-[/home/…/Torrincase/C/Users/Appdata]
└─# ls
Local
                                                                                                              
┌──(root㉿beginer)-[/home/…/Torrincase/C/Users/Appdata]
└─# cd Local   
                                                                                                              
┌──(root㉿beginer)-[/home/…/C/Users/Appdata/Local]
└─# ls
Microsoft
                                                                                                              
┌──(root㉿beginer)-[/home/…/C/Users/Appdata/Local]
└─# cd Microsoft 
                                                                                                              
┌──(root㉿beginer)-[/home/…/Users/Appdata/Local/Microsoft]
└─# ls
Windows
                                                                                                              
┌──(root㉿beginer)-[/home/…/Users/Appdata/Local/Microsoft]
└─# cd Windows  
                                                                                                              
┌──(root㉿beginer)-[/home/…/Appdata/Local/Microsoft/Windows]
└─# ls
Notifications
                                                                                                              
┌──(root㉿beginer)-[/home/…/Appdata/Local/Microsoft/Windows]
└─# cd Notifications 
                                                                                                              
┌──(root㉿beginer)-[/home/…/Local/Microsoft/Windows/Notifications]
└─# ls
wpndatabase.db  wpndatabase.db-shm  wpndatabase.db-wal  wpnidm
                                                                                                              
┌──(root㉿beginer)-[/home/…/Local/Microsoft/Windows/Notifications]
└─# cd wpnidm       
                                                                                                              
┌──(root㉿beginer)-[/home/…/Microsoft/Windows/Notifications/wpnidm]
└─# ls
           
```

Podemos observar los archivos wpndatabase.db, wpndatabase.db-shm y wpndatabase.db-wal. Estos tipos de archivos tienen formato SQLite, ya que forman parte de bases de datos.

Para analizar los archivos utilizaremos principalmente la herramienta SQLite3 como pipeline y DB Browser from SQLite como complemento visual.

###### Contenido de la base de datos

Vamos a proceder a analizar el contenido de cada tabla de la base de datos, estas son las tablas que existen en el primer archivo.

``` bash
┌──(root㉿beginer)-[/home/…/Local/Microsoft/Windows/Notifications]
└─# sqlite3 wpndatabase.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
HandlerAssets        Notification         TransientTable     
HandlerSettings      NotificationData     WNSPushChannel     
Metadata             NotificationHandler
sqlite> 

```

Podemos observar el contenido de alguna de las tablas. Como se ve en la imagen, la tabla HandlerAssets no contiene datos, la tabla HandlerSettings sí contiene datos. Vamos a proceder a ver que columnas contiene

![[Pasted image 20260218140253.png]]

Datos de la estructura de una tabla.

``` bash
sqlite> .schema HandlerSettings
CREATE TABLE [HandlerSettings]( [HandlerId] INTEGER CONSTRAINT[SettingsToHandler] REFERENCES[NotificationHandler]([RecordId]) ON DELETE CASCADE ON UPDATE CASCADE, [SettingKey] TEXT NOT NULL, [Value] INT, CONSTRAINT[] PRIMARY KEY([SettingKey], [HandlerId]) ON CONFLICT REPLACE);
CREATE INDEX [bySetting] ON[HandlerSettings] ([SettingKey], [Value]);
```

Ordenado

``` bash
CREATE TABLE HandlerSettings (
    HandlerId INTEGER 
        CONSTRAINT SettingsToHandler 
        REFERENCES NotificationHandler(RecordId) 
        ON DELETE CASCADE 
        ON UPDATE CASCADE,
    SettingKey TEXT NOT NULL,
    Value INT,
    CONSTRAINT pk_HandlerSettings 
        PRIMARY KEY(SettingKey, HandlerId) 
        ON CONFLICT REPLACE
);

CREATE INDEX bySetting 
    ON HandlerSettings (SettingKey, Value);

```

Identificación de cada columna

``` bash
sqlite> PRAGMA table_info(HandlerSettings);
0|HandlerId|INTEGER|0||2
1|SettingKey|TEXT|1||1
2|Value|INT|0||0
```

Explicación

|Columna|Tipo|Not Null|PK|Descripción / Significado|Valores posibles / Ejemplo|
|---|---|---|---|---|---|
|**HandlerId**|INTEGER|No|Sí|Identificador del handler/notificación. Sirve para vincular esta configuración con un registro en `NotificationHandler`. Permite saber **a qué canal o tipo de notificación pertenece cada setting.|166 (ejemplo del reto)|
|**SettingKey**|TEXT|Sí|Sí|Nombre de la configuración o ajuste de la notificación. Indica **qué aspecto del handler está siendo configurado.|`s:toast`, `r:tile`, `s:badge`, `s:audio`, `s:voip`, `s:listenerEnabled`, `c:cloud`, `c:ringing`|
|**Value**|INT|No|No|Valor de la configuración. En algunos diseños de base de datos puede estar **en otra tabla o set un valor asociado al SettingKey, indicando si el ajuste está habilitado o deshabilitado.|`1` → activado, `0` → desactivado|

Vamos a proceder a ver el contenido de otras tablas, tabla de Metadata:

``` bash
sqlite> select * from Metadata;
tile:maxCount|5
toast:maxCount|20
badge:maxCount|1
toastCondensed:maxCount|80
DB_INTIIALIZED|1
OutlookQuirkEnabled|1
TilesBandwidthTotal|0
CurrentNotificationId|282
```

Parte del contenido de la tabla de Notification (parece set que almacena notificaciones del sistema).

``` bash
sqlite> select * from Notification;
26|31|121||tile|<tile>
  <visual hint-overlay="0">
    <binding template="TileMedium" branding="name">
      <image id="1" src="ms-appx:///Assets/GamesXboxHubMedTile.png" placement="Background"/>
    </binding>
    <binding template="TileWide" branding="name" hint-overlay="0">
      <image id="1" src="ms-appx:///Assets/GamesXboxHubWideTile.png" placement="Background"/>
    </binding>
    <binding template="TileLarge" branding="name" hint-overlay="0">
      <image id="1" src="ms-appx:///Assets/GamesXboxHubLargeTile.png" placement="Background"/>
    </binding>
  </visual>
</tile>|Logo||0|133221326847389066|0|Xml|133221286845000000|0
27|32|121||tile|<tile>
  <visual>
    <binding template="TileMedium" hint-overlay="0" branding="nameAndLogo">
      <image src="ms-appx:///Assets/LiveTiles/avatar150x150.png" placement="peek"/>
      <text hint-maxLines="3" hint-wrap="true" hint-style="Body">More ways to play. Join us!</text>
    </binding>
    <binding template="TileWide" hint-overlay="0" branding="nameAndLogo">
      <image src="ms-appx:///Assets/LiveTiles/avatar310x150.png" placement="peek"/>
      <text hint-maxLines="3" hint-wrap="true" hint-style="Body">More ways to play. Join us!</text>
    </binding>
    <binding template="TileLarge" hint-overlay="0" branding="nameAndLogo">
      <image src="ms-appx:///Assets/LiveTiles/avatar310x310.png" placement="peek"/>
      <text hint-maxLines="3" hint-wrap="true" hint-style="Subtitle">More ways to play. Join us!</text>
    </binding>
  </visual>
</tile>|Community||0|133221326847389066|0|Xml|133221286845000000|0
42|203|75||tile|<tile>
        <visual>
                <binding template="TileMedium" branding="nameAndLogo" hint-textStacking="center">
                        <text hint-style="caption" hint-align="center" hint-wrap="true">ms-resource://microsoft.windowscommunicationsapps/hxcommintl/MAIL_NOTIFICATION_LIVETILE_PROMOTIONAL_GMAIL</text>
                </binding>
                <binding template="TileWide" branding="nameAndLogo">
                        <group>
                                <subgroup>
                                        <text hint-align="center">ms-resource://microsoft.windowscommunicationsapps/hxcommintl/MAIL_NOTIFICATION_LIVETILE_PROMOTIONAL_MULTIENDPOINT</text>
                                </subgroup>
                        </group>
                        <group>
                                <subgroup>
                                        <text></text>
                                </subgroup>
                        </group>
                        <group>
                                <subgroup hint-weight="1">
                                </subgroup>
                                <subgroup hint-weight="1">
                                        <image src="ms-appx:///images/GooglePromoTile.png" hint-removeMargin="true" hint-align="center"/>
                                </subgroup>
                                <subgroup hint-weight="1">
                                        <image src="ms-appx:///images/OutlookPromoTile.png" hint-removeMargin="true" hint-align="center"/>
                                </subgroup>
                                <subgroup hint-weight="1">
                                        <image src="ms-appx:///images/YahooPromoTile.png" hint-removeMargin="true" hint-align="center"/>
                                </subgroup>
                                <subgroup hint-weight="1">
                                </subgroup>
                        </group>
                        <group>
                                <subgroup>
                                        <text hint-align="center">ms-resource://microsoft.windowscommunicationsapps/hxcommintl/MAIL_WIDETILE_PROMO_FOOTER</text>
                                </subgroup>
                        </group>
                </binding>
                <binding template="TileLarge" branding="nameAndLogo" hint-textStacking="center">
                        <text hint-style="subtitle" hint-align="center" hint-wrap="true">ms-resource://microsoft.windowscommunicationsapps/hxcommintl/MAIL_NOTIFICATION_LIVETILE_PROMOTIONAL_GMAIL</text>
                </binding>

```

Contenido de la tabla NotificationHandler, parecen set manejadores de notificaciones, es decir, programas o software que han creado notificaciones o tienen permiso para crearlas.

``` bash
sqlite> select * from NotificationHandler;
1|FamilySafety_Settings|windows.familysafety_cw5n1h2txyewy|app:system|4725692431943338101||2023-02-01 00:43:03|2023-02-01 00:43:03||
2|Microsoft.Windows.InputSwitchToastHandler|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
3|Microsoft.Windows.LanguageComponentsInstaller|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
4|Microsoft.Windows.ParentalControls|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
5|Windows.Defender|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
6|Windows.System.AppInitiatedDownload|System|app:system|||2023-02-01 00:43:03|2023-04-20 10:14:00||
7|Windows.System.Audio|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
8|Windows.System.Continuum|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
9|Windows.System.MiracastReceiver|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
10|Windows.System.NearShareExperienceReceive|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
11|Windows.System.ShareExperience|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
12|Windows.SystemToast.AudioTroubleshooter|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
13|Windows.SystemToast.AutoPlay|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
14|Windows.SystemToast.BackgroundAccess|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
15|Windows.SystemToast.BackupReminder|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
16|Windows.SystemToast.BdeUnlock|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
17|Windows.SystemToast.BitLockerPolicyRefresh|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
18|Windows.SystemToast.Bthprops|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
19|Windows.SystemToast.BthQuickPair|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
20|Windows.SystemToast.Calling|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
21|Windows.SystemToast.Calling.SystemAlertNotification|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
22|Windows.SystemToast.Compat|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
23|Windows.SystemToast.DeviceConsent|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
24|Windows.SystemToast.DeviceEnrollmentActivity|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
25|Windows.SystemToast.DeviceManagement|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
26|Windows.SystemToast.Devices|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
27|Windows.SystemToast.EnterpriseDataProtection|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
28|Windows.SystemToast.Explorer|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
29|Windows.SystemToast.HelloFace|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
30|Windows.SystemToast.LocationManager|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
31|Windows.SystemToast.LowDisk|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
32|Windows.SystemToast.NfpAppAcquire|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
33|Windows.SystemToast.NfpAppLaunch|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
34|Windows.SystemToast.NfpDevicePairing|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
35|Windows.SystemToast.NfpReceiveContent|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
36|Windows.SystemToast.Print.Notification|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
37|Windows.SystemToast.RasToastNotifier|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
38|Windows.SystemToast.SecurityAndMaintenance|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
39|Windows.SystemToast.SecurityCenter|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
40|Windows.SystemToast.ServiceInitiatedHealing.Notification|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
41|Windows.SystemToast.Share|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
42|Windows.SystemToast.SoftLanding|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
43|Windows.SystemToast.SpeechServices|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
44|Windows.SystemToast.StorSvc|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
45|Windows.SystemToast.Usb.Notification|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
46|Windows.SystemToast.WiFiNetworkManager|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
47|Windows.SystemToast.WindowsUpdate.Notification|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
48|Windows.SystemToast.Wwansvc|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
49|Windows.SystemToast.CloudExperienceHostLauncher|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
50|Windows.SystemToast.CloudExperienceHostLauncherCustom|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
51|Windows.SystemToast.DisplaySettings|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
52|Windows.SystemToast.FodHelper|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
53|Windows.SystemToast.MobilityExperience|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
54|Windows.SystemToast.Suggested|System|app:system|||2023-02-01 00:43:03|2023-02-01 00:43:03||
55|Windows.SystemToast.WindowsTip|System|app:system|||2023-02-01 00:43:03|2023-04-20 10:14:03||
56|Microsoft.BioEnrollment_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:43:03|2023-02-01 00:43:03||
57|Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:43:03|2023-02-01 00:43:03||
58|Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:43:03|2023-02-01 00:43:03||
59|Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:43:03|2023-02-01 00:43:03||
60|Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:43:04|2023-02-01 00:43:04||
61|MicrosoftWindows.Client.CBS_cw5n1h2txyewy!PackageMetadata||app:immersive|||2023-02-01 00:43:04|2023-03-22 08:23:39||
62|MicrosoftWindows.Client.CBS_cw5n1h2txyewy!InputApp||app:immersive|||2023-02-01 00:43:04|2023-03-22 08:23:39||
63|MicrosoftWindows.Client.CBS_cw5n1h2txyewy!Global.IrisService||app:immersive|||2023-02-01 00:43:04|2023-03-22 08:23:39||
64|MicrosoftWindows.Client.CBS_cw5n1h2txyewy!ScreenClipping||app:immersive|||2023-02-01 00:43:04|2023-03-22 08:23:39||
65|MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:43:04|2023-02-01 00:43:04||
66|Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:43:04|2023-02-01 00:43:04||
67|windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel||app:immersive|||2023-02-01 00:43:04|2023-04-20 10:13:59||
68|Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:43:04|2023-03-22 08:23:08||
69|Microsoft.549981C3F5F10_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:43:05|2023-03-01 08:24:33||
70|Microsoft.Windows.Search_cw5n1h2txyewy!CortanaUI||app:immersive|||2023-02-01 00:43:05|2023-04-12 16:19:30||
71|Microsoft.Windows.Search_cw5n1h2txyewy!ShellFeedsUI||app:immersive|||2023-02-01 00:43:05|2023-04-12 16:19:30||
72|Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge||app:immersive|||2023-02-01 00:43:05|2023-02-01 00:43:05||
73|Microsoft.MicrosoftEdge_8wekyb3d8bbwe!PdfReader||app:immersive|||2023-02-01 00:43:05|2023-02-01 00:43:05||
74|Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:43:05|2023-02-01 00:43:05||
75|microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.mail||app:immersive|||2023-02-01 00:43:06|2023-03-22 08:36:22||
76|microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.calendar||app:immersive|||2023-02-01 00:43:06|2023-03-22 08:36:22||
77|microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.manageaccounts||app:immersive|||2023-02-01 00:43:06|2023-03-22 08:36:22||
78|Microsoft.Windows.Photos_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:43:06|2023-03-27 10:06:13||
79|Microsoft.WindowsCamera_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:43:06|2023-03-01 08:46:18||
80|Microsoft.XboxIdentityProvider_8wekyb3d8bbwe!Microsoft.XboxIdentityProvider||app:immersive|||2023-02-01 00:43:06|2023-03-01 08:38:03||
81|Microsoft.WindowsStore_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:43:06|2023-03-27 10:05:25||
82|Microsoft.DesktopAppInstaller_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:43:06|2023-03-01 08:46:59||
83|Microsoft.DesktopAppInstaller_8wekyb3d8bbwe!PythonRedirector||app:immersive|||2023-02-01 00:43:06|2023-03-01 08:46:59||
84|Microsoft.MicrosoftEdge_8wekyb3d8bbwe!26310719480||app:immersive|||2023-02-01 00:43:07|2023-02-01 00:43:07|Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge|
85|Microsoft.MicrosoftEdge_8wekyb3d8bbwe!38975140460||app:immersive|||2023-02-01 00:43:07|2023-02-01 00:43:07|Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge|
86|Microsoft.MicrosoftEdge_8wekyb3d8bbwe!7603651830||app:immersive|||2023-02-01 00:43:07|2023-02-01 00:43:07|Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge|
87|Microsoft.MicrosoftEdge_8wekyb3d8bbwe!6501008900||app:immersive|||2023-02-01 00:43:07|2023-02-01 00:43:07|Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge|
88|Windows.Defender.SecurityCenter|System|app:system|||2023-02-01 00:44:18|2023-02-01 00:44:18||
90|Microsoft.XboxGameCallableUI_cw5n1h2txyewy!Microsoft.XboxGameCallableUI||app:immersive|||2023-02-01 00:59:07|2023-02-01 00:59:07||
91|NcsiUwpApp_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:07|2023-02-01 00:59:07||
92|Windows.CBSPreview_cw5n1h2txyewy!Microsoft.Windows.CBSPreview||app:immersive|||2023-02-01 00:59:07|2023-02-01 00:59:07||
93|Microsoft.AsyncTextService_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:07|2023-02-01 00:59:07||
94|Microsoft.CredDialogHost_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:59:07|2023-02-01 00:59:07||
95|Microsoft.ECApp_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:08|2023-02-01 00:59:08||
96|Microsoft.LockApp_cw5n1h2txyewy!WindowsDefaultLockScreen||app:immersive|||2023-02-01 00:59:08|2023-02-01 00:59:08||
97|Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:08|2023-02-01 00:59:08||
98|1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy!Microsoft.Windows.FilePicker||app:immersive|||2023-02-01 00:59:08|2023-02-01 00:59:08||
99|c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:59:08|2023-03-22 08:23:40||
100|E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy!Microsoft.Windows.AppResolverUX||app:immersive|||2023-02-01 00:59:08|2023-02-01 00:59:08||
101|F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:59:08|2023-02-01 00:59:08||
102|Microsoft.AccountsControl_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:59:09|2023-02-01 00:59:09||
103|Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.PerMonitorAware||app:immersive|||2023-02-01 00:59:09|2023-02-01 00:59:09||
104|Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.SystemAware||app:immersive|||2023-02-01 00:59:09|2023-02-01 00:59:09||
105|Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.Unaware||app:immersive|||2023-02-01 00:59:09|2023-02-01 00:59:09||
106|Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:59:09|2023-02-01 00:59:09||
107|Microsoft.Windows.AssignedAccessLockApp_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:59:09|2023-02-01 00:59:09||
108|Microsoft.Windows.CallingShellApp_cw5n1h2txyewy!Microsoft.Windows.CallingShellApp||app:immersive|||2023-02-01 00:59:09|2023-02-01 00:59:09||
109|Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy!Microsoft.Windows.XGpuEjectDialog||app:immersive|||2023-02-01 00:59:10|2023-02-01 00:59:10||
110|Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:59:10|2023-03-22 08:23:39||
111|Microsoft.Windows.SecHealthUI_cw5n1h2txyewy!SecHealthUI||app:immersive|||2023-02-01 00:59:10|2023-03-22 08:23:40||
112|Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:59:10|2023-02-01 00:59:10||
113|Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:59:10|2023-02-01 00:59:10||
114|Microsoft.Windows.ParentalControls_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:59:10|2023-02-01 00:59:10||
115|Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:11|2023-02-01 00:59:11||
116|Microsoft.Windows.CapturePicker_cw5n1h2txyewy!App||app:immersive|||2023-02-01 00:59:11|2023-02-01 00:59:11||
117|Microsoft.WindowsAlarms_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:11|2023-03-27 10:05:18||
118|Microsoft.YourPhone_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:11|2023-04-12 06:41:58||
119|Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:11|2023-03-01 08:23:49||
120|Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:12|2023-03-01 08:23:37||
121|Microsoft.XboxApp_8wekyb3d8bbwe!Microsoft.XboxApp||app:immersive|||2023-02-01 00:59:12|2023-03-01 08:24:44||
122|Microsoft.WindowsMaps_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:12|2023-03-27 10:05:45||
123|Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:13|2023-03-22 08:36:02||
124|Microsoft.WindowsCalculator_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:13|2023-03-01 08:55:51||
125|Microsoft.Wallet_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:13|2023-02-01 00:59:13||
126|Microsoft.StorePurchaseApp_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:14|2023-03-22 08:35:41||
127|Microsoft.ScreenSketch_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:14|2023-03-27 10:04:56||
128|Microsoft.People_8wekyb3d8bbwe!x4c7a3b7dy2188y46d4ya362y19ac5a5805e5x||app:immersive|||2023-02-01 00:59:14|2023-03-27 10:05:58||
129|Microsoft.Office.OneNote_8wekyb3d8bbwe!microsoft.onenoteim||app:immersive|||2023-02-01 00:59:15|2023-04-14 10:29:28||
130|Microsoft.MSPaint_8wekyb3d8bbwe!Microsoft.MSPaint||app:immersive|||2023-02-01 00:59:15|2023-03-22 08:35:22||
131|Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:15|2023-03-01 08:46:55||
132|Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:16|2023-03-22 08:36:28||
133|Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe!Microsoft.MicrosoftOfficeHub||app:immersive|||2023-02-01 00:59:16|2023-03-01 08:46:42||
134|Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe!LocalBridge||app:immersive|||2023-02-01 00:59:16|2023-03-01 08:46:42||
135|Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:16|2023-04-14 10:30:18||
136|Microsoft.Microsoft3DViewer_8wekyb3d8bbwe!Microsoft.Microsoft3DViewer||app:immersive|||2023-02-01 00:59:17|2023-03-01 08:47:02||
137|Microsoft.Getstarted_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:17|2023-03-01 08:46:01||
138|Microsoft.GetHelp_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:17|2023-03-27 10:05:01||
139|Microsoft.BingWeather_8wekyb3d8bbwe!App||app:immersive|||2023-02-01 00:59:18|2023-03-22 08:35:55||
142|Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe!OfficeHubHWA||app:immersive|||2023-03-01 08:46:42|2023-03-01 08:46:42||
143|Microsoft.DesktopAppInstaller_8wekyb3d8bbwe!winget||app:immersive|||2023-03-01 08:46:59|2023-03-01 08:46:59||
144|Microsoft.DesktopAppInstaller_8wekyb3d8bbwe!WinGetComServer||app:immersive|||2023-03-01 08:46:59|2023-03-01 08:46:59||
145|Microsoft.Windows.Photos_8wekyb3d8bbwe!SecondaryEntry||app:immersive|||2023-03-01 08:56:39|2023-03-27 10:06:13||
147|MicrosoftWindows.Client.CBS_cw5n1h2txyewy!Global.AppListBackup||app:immersive|||2023-03-22 08:23:39|2023-03-22 08:23:39||
149|PythonSoftwareFoundation.Python.3.10_qbz5n2kfra8p0!Python||app:immersive|||2023-03-23 18:51:13|2023-03-27 10:06:30||
150|PythonSoftwareFoundation.Python.3.10_qbz5n2kfra8p0!PythonW||app:immersive|||2023-03-23 18:51:13|2023-03-27 10:06:30||
151|PythonSoftwareFoundation.Python.3.10_qbz5n2kfra8p0!Pip||app:immersive|||2023-03-23 18:51:13|2023-03-27 10:06:30||
152|PythonSoftwareFoundation.Python.3.10_qbz5n2kfra8p0!Idle||app:immersive|||2023-03-23 18:51:13|2023-03-27 10:06:30||
164|com.squirrel.slack.slack|NonImmersivePackage|app:desktop|||2023-04-20 10:09:09|2023-04-20 10:09:09||
165|Windows.Defender.MpUxDlp|System|app:system|||2023-04-20 10:14:00|2023-04-20 10:14:00||
166|Microsoft.SkyDrive.Desktop|Microsoft.SkyDrive.Desktop|app:desktop|||2023-04-20 10:14:16|2023-04-20 10:14:16||

```


### RESÚMEN

Las únicas tablas en las que se han encontrado datos son las siguientes:

|Nombre de la Tabla|Descripción del Contenido|
|---|---|
|**HandlerSettings|Configuraciones de cada handler de notificaciones, indicando qué funciones están activadas o desactivadas.|
|**Metadata|Información general del sistema de notificaciones, como límites de tiles, toasts y IDs actuales.|
|**Notification|Notificaciones registradas, con su contenido visual o textual (tiles, toasts, badges).|
|**NotificationHandler|Manejadores de notificaciones: apps o servicios que pueden generar notificaciones, con sus identificadores y metadatos.|


# Preguntas

**==1. ¿Qué software o aplicación utilizó Torrin para filtrar los secretos de Forela?**

Al abrir la base de datos con la herramienta DB Browser From SQLite o SQLite Studio podemos agilizar el flujo de trabajo y ver el contenido ordenado de cada tabla

Al navegar a la tabla de Notification podemos observar lo siguiente

![[Pasted image 20260218143435.png]]

El payload de las notificaciones aparece el protocolo `slack://` para lanzar canales, lo que confirma que Slack es la app relacionada con esas notificaciones.

*Slack es una aplicación de mensajería y colaboración enfocada principalmente en el entorno laboral y professional. Permite a equipos comunicarse mediante canales organizados por temas, enviar mensajes directos, compartir archivos, realizar videollamadas y conectar con otras herramientas y servicios para facilitar el trabajo en equipo.

Respuesta correcta: Slack

**==2. ¿Cuál es el nombre de la empresa rival a la que Torrin filtró los datos?**

Al observar el contenido del primer evento de Notificaciones de la app Slack podemos observar lo siguiente (En el título aparece el nombre de la empresa).

![[Pasted image 20260218143838.png]]

Respuesta correcta: PrimeTech Innovations

**==3. ¿Cuál es el nombre de usuario de la persona de la organización competidora con la que Torrin compartió información?**

Si observamos la anterior imagen podemos concluir lo siguiente:

El mensaje de la notificación refería a que el usuario Cyberjunkie-PrimeTechDev acepto la invitación para unirse a Slack

![[Pasted image 20260218144102.png]]

Respuesta correcta: Cyberjunkie-PrimeTechDev


**==4. ¿Cuál es el nombre del canal en el que conversaron entre ellos?**

En la siguiente evidencia aparece en texto New message in forela-secrets-leak, esto indica el canal por el que ambos usuarios conversaron.

![[Pasted image 20260218144914.png]]

Respuesta correcta: forela-secrets-leak

**==5. ¿Cuál era la contraseña del servidor de archivos?**

En la evidencia anterior aparece Password for archive server is: ...

![[Pasted image 20260218145039.png]]

Respuesta correcta: Tobdaf8Qip$re@1

**==6. ¿Cuál fue la URL proporcionada a Torrin para subir los datos robados?**

Si analizamos la cronología de los hechos, el usuario atacante invita al usuario Cyberjunkie-PrimeTechDev a unirse a Slack, el usuario víctima (Cyberjunkie) acepta la invitación. Posteriormente Cyberjunkie pregunta al usuario torrin lo siguiente 'Hola Torrin, ¿lograste encontrar los archivos relacionados con el plan de extracción de petróleo de Forela en Angola?'

![[Pasted image 20260218145429.png]]

Posteriormente intercambian mensajes que no se han registrado y aparece lo siguiente, Cyberjunkie le da la contraseña del servidor de archivos, acompañado de un mensaje que dice 'Solo para confirmar, ya que no queremos que el equipo de TI de Forela se ponga sospechoso.'

![[Pasted image 20260218145637.png]]

Posteriormente Cyberjunkie le pregunta al usuario atacante lo siguiente 'Confirma que la contraseña es "Tobdaf8Qip$re@1"'

![[Pasted image 20260218145739.png]]

Posteriormente el usuario de Cyberjunkie mensajea lo siguiente 'Está bien, te estoy enviando un enlace de Google Drive donde puedes subir toda la otra información que hayas recopilado hasta ahora.'

![[Pasted image 20260218145850.png]]

Posteriormente en otro mensaje le envía la url y mensajea lo siguiente 'Recuerda subir también los documentos y los PDFs.'

![[Pasted image 20260218150005.png]]

Posteriormente Cyberjunkie mensajea lo siguiente 'Número de cuenta bancaria: 03135905179789. Envié 10.000 £ a la cuenta anterior como prometí, saludos'.

![[Pasted image 20260218150044.png]]

Respuesta correcta: https://drive.google.com/drive/folders/1vW97VBmxDZUIEuEUG64g5DLZvFP-Pdll?usp=sharing

==7. ¿Cuándo se compartió el enlace anterior con Torrin?

El enlace se compartió en Time 1681986889.660179, esta marca de tiempo es en formato Unix y hay que convertirla

![[Pasted image 20260218150713.png]]

Podemos utilizar un conversor online de forma segura y rápida

![[Pasted image 20260218150856.png]]

Respuesta correcta: 2023-04-20 10:34:49 

Conviene realizar la conversión en código Python

==8. ¿Por cuánto dinero Torrin filtró los secretos de Forela?

Aparece en la última evidencia de la pregunta 6, al analizar la cronología de los echos

![[Pasted image 20260218150044.png]]

Mensaje traducido: Número de cuenta bancaria: 03135905179789. Envié 10.000 £ a la cuenta anterior como prometí, saludos.

Repuesta correcta: £10000