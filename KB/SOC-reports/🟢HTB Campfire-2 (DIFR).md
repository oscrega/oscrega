
# Enunciado

**La red de Forela está constantemente bajo ataque. El sistema de seguridad ha generado una alerta sobre una cuenta de administrador antigua que está solicitando un ticket del KDC en un controlador de dominio. El inventario muestra que esta cuenta de usuario no está siendo utilizada en la actualidad, por lo que se te ha asignado la tarea de investigar este caso. Esto podría tratarse de un ataque de AsREP roasting, ya que cualquiera puede solicitar el ticket de cualquier usuario cuya preautenticación esté deshabilitada.**
# Preparación

**Vamos a proceder a descomprimir el archivo que nos proporciona el reto, leer el archivo que nos proporciona al realizar la compresión y convertirlo a formato json para obtener una lectura fácil y un filtrado óptimo**

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/campfire2]
└─# 7z x campfire-2.zip                

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=es_ES.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 25037 bytes (25 KiB)

Extracting archive: campfire-2.zip
--
Path = campfire-2.zip
Type = zip
Physical Size = 25037

    
Enter password (will not be echoed):
Everything is Ok    

Size:       1118208
Compressed: 25037
                                                                                                             
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/campfire2]
└─# ls
campfire-2.zip  Security.evtx
```

**Para leerlo y convertirlo a formato json usaremos la herramienta Chainsaw de la siguiente forma**

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/campfire2]
└─# chainsaw dump Security.evtx --json >> security.json

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Security.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (1.1 MiB)
[+] Done
```


**Ahora filtraremos todos los ID de eventos que se encuentran en el archivo y estudiaremos cada ID para obtener una visión general y una guía sobre los tipos de eventos que sucedieron en el sistema.**

``` bash
                                                                                                             
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/campfire2]
└─# cat security.json | jq '.[] | .Event.System.EventID' | sort -n | uniq >> id_security.txt
                                                                                                             
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/campfire2]
└─# cat id_security.txt                                                                     
1100
4688
4696
4698
4699
4702
4768
4769
4771
4799
4826
5140
5142
5379
```


**Ahora podemos estudiar cada evento**

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/campfire2]
└─# cat id_security.txt 
1100            La política de auditoría del sistema ha cambiado.
4688            Un nuevo proceso ha sido creado.
4696            Un archivo ha sido eliminado de un sistema.
4698            Se ha establecido una tarea programada.
4699            Se ha eliminado una tarea programada.
4702            Se ha actualizado una tarea programada.
4768            Un inicio de sesión Kerberos ha tenido éxito.
4769            El servicio de tickets de autenticación Kerberos ha emitido un ticket.
4771            El intento de autenticación Kerberos ha fallado.
4799            Un usuario ha intentado cambiar su contraseña pero ha fallado.
4826            Un archivo de registro ha sido sobreescrito.
5140            Un recurso compartido de archivos ha sido accesado.
5142            Se ha modificado la configuración de un recurso compartido.
5379            El intento de autenticación de un proveedor de autenticación ha fallado.
```

# Preguntas

**==1. ¿En qué memento ocurrió el ataque ASREP Roasting, y cuándo solicitó el atacante el ticket Kerberos para el usuario vulnerable?==**

**Respuesta correcta: 2024-05-29 06:36:40**

**El ataque ASREP Roasting es una técnica utilizada por atacantes en redes de Windows que explotan vulnerabilidades en el protocolo de autenticación Kerberos para obtener credenciales de usuario en texto claro.**

**El primero paso de este ataque es la solicitud de un ticket de servicio (TGS) pero, al compararlo con el inicio de sesión exitoso no cuadran los datos.**

**Hay un único inicio de sesión exitoso para el usuario arthur.kyle, los demás inicios de sesión fueron por los siguientes usuarios.**

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/campfire2]
└─# cat security.json | jq '.[] | select(.Event.System.EventID == 4768) | .Event.EventData.TargetUserName' | sort -n | uniq

"Administrator" 
"arthur.kyle"
"DC01$"
```

**El inicio de sesión de Administrador y de DC01$ se realizó desde la misma IP (::1), lo cual deja constancia de que fueron servicios o trabajadores de la organización.**

- **`::1`** es la **dirección IPv6 de loopback**, que es el equivalente a **`127.0.0.1` en IPv4.
    
- Esta dirección es utilizada para **referirse a la propia máquina. En otras palabras, cuando se usa `::1`, significa que el tráfico de red está destinado al propio sistema que lo está generando, no a una red externa.

**Esta es la evidencia del inicio de sesión por el servicio de kerberos para el usuario arthur.kyle.**

![[Pasted image 20260102150930.png]]



**==2. Por favor, confirma la cuenta de usuario que fue objetivo del atacante.==**

**Esta pregunta la respondimos en la pregunta anterior**

**Respuesta correcta: arthur.kyle**


**==3. ¿Cuál era el SID de la cuenta?==**

**El SID de la cuenta sale en la evidencia anterior**

**Respuesta correcta: S-1-5-21-3239415629-1862073780-2394361899-1601**

![[Pasted image 20260102151639.png]]

**==4. Es crucial identificar la cuenta de usuario comprometida y la estación de trabajo responsible de este ataque. Por favor, proporciona la dirección IP interna del activo comprometido para ayudar a nuestro equipo de investigación de amenazas.==**

**La dirección IP desde la que se realizó el ataque sale en la misma evidencia. Respuesta correcta: 172.17.79.129**

![[Pasted image 20260102151830.png]]

**5. Aún no tenemos artefactos de la máquina de origen. Usando los mismos registros de seguridad del controlador de dominio (DC), ¿puedes confirmar la cuenta de usuario utilizada para realizar el ataque ASREP Roasting para que podamos container la/s cuenta/s comprometida/s?**

**Respuesta correcta: happy.grunwald@FORELA.LOCAL**

**Se realizaron múltiples intentos de cambios de contraseñas relacionados con el usuario Administrator**

![[Pasted image 20260102152132.png]]

**También se intentó iniciar sesión sin éxito con la cuenta Administrator**

![[Pasted image 20260102152213.png]]

**Se obtenieron dos inicios de sesión con la cuenta Administrator**

![[Pasted image 20260102152427.png]]

**No obstante la cuenta comprometida con es esta ya que la IP registrada en cada intento es la interna de la corporación**

**Decidí filtrar por todas las cuentas de todos los eventos registrados y encontré una cuenta sospechosa**

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/campfire2]
└─# cat security.json | jq '.[] | .Event.EventData.TargetUserName' | sort -n | uniq 
 
"-"
"Administrator"
"Administrator@FORELA.LOCAL"
"Administrators"
"arthur.kyle"
"Backup Operators"
"DC01$"
"DC01$@FORELA.LOCAL"
"happy.grunwald@FORELA.LOCAL"
null
```

**Filtramos por la cuenta para obtener los eventos en los que quedó registrada**

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/campfire2]
└─# cat security.json | jq '.[] | select(.Event.EventData.TargetUserName == "happy.grunwald@FORELA.LOCAL")' 
{
  "Event_attributes": {
    "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
  },
  "Event": {
    "System": {
      "Provider_attributes": {
        "Name": "Microsoft-Windows-Security-Auditing",
        "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D"
      },
      "EventID": 4769,
      "Version": 0,
      "Level": 0,
      "Task": 14337,
      "Opcode": 0,
      "Keywords": "0x8020000000000000",
      "TimeCreated_attributes": {
        "SystemTime": "2024-05-29T06:37:49.227372Z"
      },
      "EventRecordID": 6242,
      "Correlation": null,
      "Execution_attributes": {
        "ProcessID": 752,
        "ThreadID": 3188
      },
      "Channel": "Security",
      "Computer": "DC01.forela.local",
      "Security": null
    },
    "EventData": {
      "TargetUserName": "happy.grunwald@FORELA.LOCAL",
      "TargetDomainName": "FORELA.LOCAL",
      "ServiceName": "DC01$",
      "ServiceSid": "S-1-5-21-3239415629-1862073780-2394361899-1000",
      "TicketOptions": "0x40810000",
      "TicketEncryptionType": "0x12",
      "IpAddress": "::ffff:172.17.79.129",
      "IpPort": "61975",
      "Status": "0x0",
      "LogonGuid": "543ACECF-87DD-45D9-CF0D-6C1F28070DC3",
      "TransmittedServices": "-"
    }
  }
}
```


**En esta evidencia se puede comprobar un evento de emisión de ticket de kerberos con la cuenta `happy.grunwald@FORELA.LOCAL` con la misma IP del atacante (172.17.79.129)**
# Conclusión

**El atacante obtuvo acceso primero a la cuenta de arthur.kyle y después, desde esta misma cuenta intentó obtener un ticket de kerberos para la cuenta happy.grunwald, esto da como resultado que el atacante escaló privilegios de una cuenta a otra o pidió un ticket para otro usuario modificando permisos de grupos o haciendose miembro de estos pero tras investigar se llegó a la conclusión que los registros eran procesos que se ejecutaban propios de la corporación o de windows, como por ejemplo svchost.exe**

**Solo se registraron los eventos de las cuentas comprometidas con la IP del atacante lo cual confirma que lo demás es ruido o falsos positivos**

``` bash
┌──(root㉿beginer)-[/home/…/maquinas/blue/difr/campfire2]
└─# cat security.json | jq '.[] | select(.Event.EventData.IpAddress == "::ffff:172.17.79.129")'
{
  "Event_attributes": {
    "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
  },
  "Event": {
    "System": {
      "Provider_attributes": {
        "Name": "Microsoft-Windows-Security-Auditing",
        "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D"
      },
      "EventID": 4768,
      "Version": 0,
      "Level": 0,
      "Task": 14339,
      "Opcode": 0,
      "Keywords": "0x8020000000000000",
      "TimeCreated_attributes": {
        "SystemTime": "2024-05-29T06:36:40.246362Z"
      },
      "EventRecordID": 6241,
      "Correlation": null,
      "Execution_attributes": {
        "ProcessID": 752,
        "ThreadID": 3188
      },
      "Channel": "Security",
      "Computer": "DC01.forela.local",
      "Security": null
    },
    "EventData": {
      "TargetUserName": "arthur.kyle",
      "TargetDomainName": "forela.local",
      "TargetSid": "S-1-5-21-3239415629-1862073780-2394361899-1601",
      "ServiceName": "krbtgt",
      "ServiceSid": "S-1-5-21-3239415629-1862073780-2394361899-502",
      "TicketOptions": "0x40800010",
      "Status": "0x0",
      "TicketEncryptionType": "0x17",
      "PreAuthType": "0",
      "IpAddress": "::ffff:172.17.79.129",
      "IpPort": "61965",
      "CertIssuerName": "",
      "CertSerialNumber": "",
      "CertThumbprint": ""
    }
  }
}
{
  "Event_attributes": {
    "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
  },
  "Event": {
    "System": {
      "Provider_attributes": {
        "Name": "Microsoft-Windows-Security-Auditing",
        "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D"
      },
      "EventID": 4769,
      "Version": 0,
      "Level": 0,
      "Task": 14337,
      "Opcode": 0,
      "Keywords": "0x8020000000000000",
      "TimeCreated_attributes": {
        "SystemTime": "2024-05-29T06:37:49.227372Z"
      },
      "EventRecordID": 6242,
      "Correlation": null,
      "Execution_attributes": {
        "ProcessID": 752,
        "ThreadID": 3188
      },
      "Channel": "Security",
      "Computer": "DC01.forela.local",
      "Security": null
    },
    "EventData": {
      "TargetUserName": "happy.grunwald@FORELA.LOCAL",
      "TargetDomainName": "FORELA.LOCAL",
      "ServiceName": "DC01$",
      "ServiceSid": "S-1-5-21-3239415629-1862073780-2394361899-1000",
      "TicketOptions": "0x40810000",
      "TicketEncryptionType": "0x12",
      "IpAddress": "::ffff:172.17.79.129",
      "IpPort": "61975",
      "Status": "0x0",
      "LogonGuid": "543ACECF-87DD-45D9-CF0D-6C1F28070DC3",
      "TransmittedServices": "-"
    }
  }
}

```


