### [HTB-CAMPFIRE1: ACTIVE DIRECTORY KERBEROASTING INCIDENT]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Active Directory / Windows Enterprise / HTB Sherlock  
**Objetivo:** Workstation Alonzo (172.17.79.129) / Dominio FORELA.LOCAL

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó una incursión adversaria en la estación de trabajo asignada al usuario Alonzo (172.17.79.129). El actor de amenaza obtuvo ejecución interactiva de comandos, evadió la directiva de ejecución local de PowerShell (-ep bypass) y ejecutó en memoria el framework de auditoría PowerView para realizar reconocimiento de objetos de dominio con atributos ServicePrincipalName (SPN). Posteriormente, desplegó la utilidad ofensiva compilada Rubeus.exe en el perfil de descargas del usuario para ejecutar un ataque de **Kerberoasting**, solicitando un Ticket Granting Service (TGS) negociado en cifrado débil RC4-HMAC (0x17) contra la cuenta de servicio MSSQLService para su descifrado offline.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - SECURITY-DC.evtx: Registro de Seguridad del KDC (Event ID 4769).
        
    - Microsoft-Windows-PowerShell%4Operational.evtx: Registro de Script Block Logging del endpoint (Event ID 4104).
        
    - C:\Windows\Prefetch\RUBEUS.EXE-B488C951.pf: Artefacto de ejecución analizado mediante PECmd.
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Execution**|T1059.001|Command and Scripting Interpreter: PowerShell|Invocación interactiva de powershell.exe -ep bypass y carga de módulos PowerView en memoria (Event ID 4104).|
|**Defense Evasion**|T1562.001|Impair Defenses: Disable or Modify Tools|Omitir la directiva de firma de scripts locales mediante -ExecutionPolicy Bypass.|
|**Discovery**|T1087.002|Account Discovery: Domain Account|Ejecución de funciones de PowerView: Convert-NameToSid, ConvertFrom-UACValue, Export-PowerViewCSV.|
|**Credential Access**|T1558.003|Steal or Forge Kerberos Tickets: Kerberoasting|Solicitud forzada de un ticket TGS con cifrado RC4 (0x17) para MSSQLService utilizando Rubeus.exe.|

#### 3. Cadena de Infección y Análisis Forense Detallado

En Microsoft-Windows-PowerShell%4Operational.evtx, a las **2024-05-21 03:16:29 UTC**, se registró un Event ID 4104 (Script Block Logging) de nivel Information que documenta la definición en memoria de funciones de reconocimiento Active Directory de la suite **PowerView**:

- **Firmas Identificadas:** Export-PowerViewCSV, Set-MacAttribute, Convert-NameToSid y ConvertFrom-UACValue.
    
- **Propósito Táctico:** Enumerar en el KDC todas las cuentas de usuario con el atributo servicePrincipalName poblado, descartando cuentas de máquina (*$) y cuentas de infraestructura (krbtgt).
    

El procesado pericial del archivo Prefetch en el endpoint de Alonzo certificó la actividad del binario compilado:

- **Archivo Analizado:** C:\Windows\Prefetch\RUBEUS.EXE-B488C951.pf
    
- **Ruta del Ejecutable:** **C:\Users\Alonzo\Downloads\Rubeus.exe**
    
- **Primer Registro en Sistema de Archivos:** 2024-05-21 03:16:32 UTC.
    
- **Timestamp de Última Ejecución (Run Time UTC):** **2024-05-21 03:18:08 UTC**.
    
- **Run Count:** 1.
    
- **Dependencias Cargadas en Runtime:** NTDLL.DLL, KERNEL32.DLL, MSCOREE.DLL, CLR.DLL (confirmando una aplicación standalone escrita en C#/.NET Framework).
    

Exactamente un segundo después de la ejecución en Prefetch, a las **2024-05-21 03:18:09 UTC**, el Controlador de Dominio registró la emisión del ticket TGS:

- **Event ID:** **4769** (A Kerberos service ticket was requested).
    
- **TargetUserName:** **MSSQLService@FORELA.LOCAL**
    
- **ServiceName:** MSSQLService
    
- **ServiceSid:** **S-1-5-21-3814545217-1834241598-1324545322-1108**
    
- **TicketOptions:** 0x40810000 (Forwardable, Renewable, Canonicalize).
    
- **TicketEncryptionType:** **0x17** (KERB_ETYPE_RC4_HMAC_MD5).
    
- **Client IP Address:** ::ffff:172.17.79.129 (Estación de Alonzo).
    
- **Client Port:** 49832.
    
- Conclusión pericial: La solicitud de cifrado 0x17 confirma un downgrade forzado para facilitar el descifrado offline mediante suites como Hashcat (modo 13100).
    


``` bash
# Invocación pericial de PECmd sobre el artefacto Prefetch de Rubeus
PECmd.exe -f "C:\Windows\Prefetch\RUBEUS.EXE-B488C951.pf" --json "C:\Analysis\Output"
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yaml
title: Deteccion de Kerberoasting por Downgrade de Cifrado RC4
id: 593b4a22-3ceb-4d43-9828-98e204769kerb
status: production
description: Identifica solicitudes de tickets Kerberos TGS (Event ID 4769) emitidas contra cuentas de servicio que fuerzan cifrado RC4 (0x17).
references:
  - https://attack.mitre.org/techniques/T1558/003/
author: Senior DFIR Specialist
date: 2024-05-22
logsource:
  product: windows
  service: security
detection:
  selection_tgs:
    EventID: 4769
    TicketEncryptionType: '0x17'
    Status: '0x0'
  filter_machine:
    ServiceName|endswith: '$'
  filter_krbtgt:
    ServiceName: 'krbtgt'
  condition: selection_tgs and not filter_machine and not filter_krbtgt
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```


``` Spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17" ServiceName!="*$" ServiceName!="krbtgt" Status="0x0"
| eval ClientIP=replace(IpAddress, "::ffff:", "")
| stats count, values(ServiceName) as Servicios_Solicitados by ClientIP, TargetUserName, _time
| sort - _time
| table _time, ClientIP, TargetUserName, Servicios_Solicitados, count
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Aislamiento del Endpoint:** Aislar de la red la estación 172.17.79.129 mediante agente EDR.
    
2. **Restablecimiento de Credenciales del Servicio:** Cambiar de forma inmediata la contraseña de la cuenta MSSQLService (S-1-5-21-3814545217-1834241598-1324545322-1108), estableciendo una clave compleja de al menos 32 caracteres con alta entropía.
    

3. **Transición a Cuentas Administradas de Servicio de Grupo (gMSA):** Migrar MSSQLService a una cuenta gMSA, eliminando el uso de contraseñas estáticas legadas y permitiendo que Active Directory gestione la rotación criptográfica automática con claves de 128 caracteres.
    
4. **Deshabilitación de Cifrado Débil (RC4) en Active Directory:**
    
    - Forzar exclusivamente suites de cifrado modernas mediante GPO:  
        Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Network security: Configure encryption types allowed for Kerberos.
        
    - Seleccionar únicamente: AES128_HMAC_SHA1, AES256_HMAC_SHA1 y Future encryption types.
        
5. **Restricción de Ejecución (AppLocker / WDAC):** Bloquear la ejecución de binarios ejecutables o scripts ubicados en carpetas de usuario no privilegiadas (C:\Users\*\Downloads\*, C:\Users\*\AppData\*).