### [HTB-CAMPFIRE2: ACTIVE DIRECTORY AS-REP ROASTING INCIDENT REPORT]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Active Directory / Windows Server 2019 Domain Controller / HTB Sherlock  
**Objetivo:** Controlador de Dominio DC01.forela.local

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó una alerta de seguridad emitida por la infraestructura del dominio FORELA.LOCAL concerniente a la solicitud de tickets de autenticación Kerberos (AS-REQ / AS-REP) asociados a una cuenta de usuario administrativa en desuso (arthur.kyle). El análisis forense de los registros de auditoría de seguridad (Security.evtx) confirmó un ataque de **AS-REP Roasting**. El actor de amenaza explotó la falta de preautenticación Kerberos (DONT_REQ_PREAUTH) en dicha cuenta para solicitar un Ticket Granting Ticket (TGT) cifrado en RC4-HMAC (0x17), permitiendo la extracción offline del material criptográfico para ataques de fuerza bruta/diccionario. La telemetría posterior revela el uso simultáneo de una cuenta de usuario adicional (happy.grunwald@FORELA.LOCAL) originada desde la misma estación de trabajo comprometida (172.17.79.129), lo que denota persistencia y escalada de privilegios dentro del perímetro interno.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - Security.evtx de DC01.forela.local volcado y normalizado a formato JSON estructurado mediante la utilidad forense Chainsaw.
        
    - Correlación de eventos de auditoría Kerberos: Event ID 4768 (A Kerberos authentication ticket (TGT) was requested) y Event ID 4769 (A Kerberos service ticket was requested).
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Credential Access**|T1558.004|Steal or Forge Kerberos Tickets: AS-REP Roasting|Solicitud exitosa de TGT sin preautenticación (PreAuthType: 0) para el usuario arthur.kyle negociando cifrado débil RC4 (0x17). Event ID 4768.|
|**Initial Access / Discovery**|T1087.002|Account Discovery: Domain Account|Peticiones deliberadas contra cuentas con el flag DONT_REQ_PREAUTH activo en el atributo userAccountControl.|
|**Lateral Movement**|T1558.003|Steal or Forge Kerberos Tickets: Kerberoasting / Service Requests|Solicitud de Ticket Granting Service (TGS) para el SPN DC01$ bajo el contexto de happy.grunwald@FORELA.LOCAL desde la IP de origen hostil. Event ID 4769.|

#### 3. Cadena de Infección y Análisis Forense Detallado

1. **Identificación de la Cuenta Vulnerable:** La cuenta de usuario identificada como objetivo es arthur.kyle, con identificador de seguridad relativo (RID) 1601 (TargetSid: S-1-5-21-3239415629-1862073780-2394361899-1601).
    
2. **Explotación AS-REP Roasting (Event ID 4768):**
    
    - **Timestamp UTC:** 2024-05-29 06:36:40.246362Z
        
    - **Registro de Evento:** Record ID 6241
        
    - **Host Origen / Dirección IP:** ::ffff:172.17.79.129 (IPv4 mapeada en IPv6)
        
    - **Puerto Efímero Origen:** 61965
        
    - **Nombre de Servicio:** krbtgt (SID S-1-5-21-3239415629-1862073780-2394361899-502)
        
    - **PreAuthType:** 0 (Indica que la preautenticación Kerberos no fue requerida ni provista, confirmando la activación previa del flag DONT_REQ_PREAUTH).
        
    - **TicketEncryptionType:** 0x17 (KERB_ETYPE_RC4_HMAC_MD5). El adversario fuerza deliberadamente este tipo de cifrado para simplificar el ataque offline de recuperación de contraseña con Hashcat (modo 18200: Kerberos 5 AS-REP etype 23).
        
    - **TicketOptions:** 0x40800010 (Forwardable, Renewable, Canonicalize).
        
    - **Status:** 0x0 (Operación completada con éxito por el KDC).
        

Aproximadamente 69 segundos después del ataque AS-REP Roasting, a las 2024-05-29 06:37:49.227372Z (Record ID 6242), se identificó una solicitud de TGS (EventID: 4769) originada desde la misma dirección IP hostil (172.17.79.129, puerto 61975):

- **TargetUserName:** happy.grunwald@FORELA.LOCAL
    
- **ServiceName:** DC01$
    
- **ServiceSid:** S-1-5-21-3239415629-1862073780-2394361899-1000
    
- **TicketEncryptionType:** 0x12 (AES256-CTS-HMAC-SHA1-96)
    
- **TicketOptions:** 0x40810000
    
- **LogonGuid:** 543ACECF-87DD-45D9-CF0D-6C1F28070DC3
    

Este hallazgo confirma que el atacante ya poseía credenciales válidas o una sesión activa bajo el contexto de happy.grunwald en la estación de trabajo 172.17.79.129 desde la cual ejecutó el reconocimiento y solicitud del AS-REP de arthur.kyle.


``` bash
# Invocación de extracción y filtrado en Chainsaw/jq para aislar la actividad del atacante
cat security.json | jq -r '.[] | select(.Event.System.EventID == 4768 and .Event.EventData.PreAuthType == "0") | 
{
  Timestamp: .Event.System.TimeCreated_attributes.SystemTime,
  User: .Event.EventData.TargetUserName,
  SID: .Event.EventData.TargetSid,
  ClientIP: .Event.EventData.IpAddress,
  ClientPort: .Event.EventData.IpPort,
  Encryption: .Event.EventData.TicketEncryptionType,
  Status: .Event.EventData.Status
}'
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yaml
title: Deteccion de Ataque AS-REP Roasting en Active Directory
id: a7d398f1-e3d8-4f81-9b16-4768asreproast
status: production
description: Detecta eventos de solicitud de TGT (Event ID 4768) donde la preautenticacion esta deshabilitada (PreAuthType 0) y se utiliza cifrado debil RC4 (0x17).
references:
  - https://attack.mitre.org/techniques/T1558/004/
author: Senior DFIR Specialist
date: 2024-05-30
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
    Status: '0x0'
  filter_machine_accounts:
    TargetUserName|endswith: '$'
  condition: selection and not filter_machine_accounts
falsepositives:
  - Cuentas legacy que explícitamente requieran compatibilidad con sistemas operativos desactualizados (deben mitigarse).
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```


``` SPL
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0" NOT TargetUserName="*$"
| eval ClientIP=replace(IpAddress, "::ffff:", "")
| stats count, min(_time) as Primer_Intento, max(_time) as Ultimo_Intento by ClientIP, TargetUserName, TargetSid, TicketOptions
| convert ctime(Primer_Intento) ctime(Ultimo_Intento)
| table Primer_Intento, Ultimo_Intento, ClientIP, TargetUserName, TargetSid, TicketOptions, count
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Aislamiento de Red:** Desconectar y poner en cuarentena estricta la estación de trabajo con dirección IP 172.17.79.129 mediante políticas de Firewall perimetral y aislamiento a nivel de agente EDR.
    
2. **Bloqueo y Restablecimiento de Credenciales:**
    
    - Deshabilitar de forma inmediata la cuenta comprometida arthur.kyle (S-1-5-21-3239415629-1862073780-2394361899-1601).
        
    - Forzar el reseteo de credenciales de la cuenta happy.grunwald@FORELA.LOCAL, invalidando todas las sesiones Kerberos activas mediante la revocación de tokens.
        
3. **Auditoría de Sesiones Activas:** Verificar las sesiones remotas y conexiones SMB/WMI abiertas desde 172.17.79.129 hacia otros activos de la red.
    

4. **Eliminación del Flag DONT_REQ_PREAUTH:**
    
    - Auditar mediante PowerShell todas las cuentas del dominio que tengan deshabilitada la preautenticación Kerberos:
        
        
        
        ``` Powershell
        Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth | Select-Object SamAccountName, DistinguishedName, Enabled
        ```
        
    - Forzar la preautenticación en todos los objetos identificados:
        
        
        
        ``` Powershell
        Set-ADAccountControl -Identity "arthur.kyle" -DoesNotRequirePreAuth $False
        ```
        
5. **Deshabilitación de Cifrado RC4 en Kerberos:**
    
    - Configurar directiva de grupo (GPO) para restringir los tipos de cifrado permitidos en Kerberos exclusivamente a AES (AES128_HMAC_SHA1 y AES256_HMAC_SHA1) bajo la ruta:  
        Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Network security: Configure encryption types allowed for Kerberos.
        
6. **Gestión del Ciclo de Vida de Cuentas:** Implementar revisiones automáticas para deshabilitar o purgar cuentas inactivas o en desuso que conserven privilegios administrativos.