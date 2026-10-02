### [HTB-REAPER: ACTIVE DIRECTORY NTLM RELAY ATTACK REPORT]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Active Directory / Windows Enterprise Workstations / HTB Sherlock  
**Objetivo:** Forela-Wkstn001.forela.local / Tráfico de Red y Autenticación NTLM

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó una alerta de SIEM originada por una anomalía de autenticación de red: una discrepancia directa entre la dirección IP de origen y el nombre de equipo (Workstation Name) reportado durante el inicio de sesión. La correlación forense entre el tráfico de red (ntlmrelay.pcapng) y los registros de auditoría (Security.evtx) demostró un ataque de **NTLM Relay**. El adversario operó desde un dispositivo hostil no autorizado (172.17.79.135) interceptando solicitudes de red generadas por la víctima (arthur.kyle) en Forela-Wkstn002 tras inducirla a acceder a un recurso compartido inexistente (\\DC01\Trip). El atacante reenvió los desafíos/respuestas criptográficas NTLMv2 contra Forela-Wkstn001 (172.17.79.129), logrando autenticarse exitosamente y accediendo al recurso IPC$.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - ntlmrelay.pcapng: Captura de paquetes analizada con Wireshark/tshark (protocolos NBNS, SMB, SMB2, KRB5).
        
    - Security.evtx de Forela-Wkstn001: Event ID 4624 (Network Logon - Type 3) y Event ID 5140 (Network Share Access).
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Credential Access**|T1557.001|Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and Relay|Envenenamiento de resolución local y retransmisión de hashes NTLMv2 desde 172.17.79.135.|
|**Lateral Movement**|T1212|Exploitation of Remote Services (NTLM Relay)|Uso de tokens de autenticación retransmitidos para autenticarse como arthur.kyle en Forela-Wkstn001.|
|**Discovery**|T1135|Network Share Discovery|Inducción y exploración del recurso compartido \\DC01\Trip que retornó STATUS_BAD_NETWORK_NAME.|

#### 3. Cadena de Infección y Análisis Forense Detallado

- **Forela-Wkstn001 (Objetivo del Relay):** **172.17.79.129** (Identificada por volumen masivo de tráfico entrante y registros NetBIOS/SMB).
    
- **Forela-Wkstn002 (Equipo Origen Legítimo):** **172.17.79.136** (Identificada mediante peticiones broadcast NBNS).
    
- **Dispositivo Hostil del Atacante (Rogue Asset):** **172.17.79.135** (Dispositivo intermediario donde corría la suite de relay, ej. ntlmrelayx).
    

1. **Generación de Tráfico SMB:** La cuenta de usuario víctima arthur.kyle navegó hacia el recurso de red **\\DC01\Trip**.
    
2. En la captura de red, las peticiones fallaron sistemáticamente con el error **STATUS_BAD_NETWORK_NAME**, demostrando que el atacante o un enlace malicioso indujo a la estación a buscar un recurso inaccesible para forzar el fallback de autenticación y retransmitir los desafíos NTLMv2.
    

En Forela-Wkstn001, se detectó la materialización del acceso mediante un Event ID 4624:

- **Timestamp UTC:** **2024-07-31 04:55:16.240589Z** (Record ID 14610).
    
- **TargetUserName:** **arthur.kyle** (SID S-1-5-21-3239415629-1862073780-2394361899-1601).
    
- **LogonType:** 3 (Network Logon).
    
- **AuthenticationPackageName:** NTLM (LmPackageName: NTLM V2).
    
- **Discrepancia Forense Crítica:**
    
    - **WorkstationName:** **FORELA-WKSTN002**
        
    - **IpAddress (Origen Real del Tráfico):** **172.17.79.135**
        
    - Esta discrepancia entre el hostname declarado en la negociación NTLMSSP y la dirección IP que estableció el socket TCP demuestra de forma concluyente que la sesión fue retransmitida por un tercero (172.17.79.135).
        
- **Puerto de Origen:** **40252**.
    
- **LogonId Asignado:** **0x64a799**.
    
- **Recurso Compartido Consultado (Event ID 5140):** El atacante interactuó inmediatamente con el recurso IPC
    
    `**), mecanismo estándar utilizado por herramientas de ejecución remota basadas en SMB (como Impacket) para enumerar Named Pipes antes de desplegar servicios o tareas remotas.
    


``` bash
# Extracción en Chainsaw del inicio de sesión malicioso con discrepancia IP-Hostname
cat security.json | jq '.[] | select(.Event.System.EventID == 4624) | 
select(.Event.EventData.TargetUserName == "arthur.kyle") | 
{
  Timestamp: .Event.System.TimeCreated_attributes.SystemTime,
  User: .Event.EventData.TargetUserName,
  Workstation: .Event.EventData.WorkstationName,
  AttackerIP: .Event.EventData.IpAddress,
  SourcePort: .Event.EventData.IpPort,
  LogonID: .Event.EventData.TargetLogonId,
  AuthPackage: .Event.EventData.AuthenticationPackageName
}'
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yaml
title: Posible NTLM Relay por Discrepancia entre WorkstationName e IpAddress
id: c4a82190-7d81-4233-a128-ntlmrelaydiscrepancy
status: production
description: Identifica inicios de sesion NTLM (Logon Type 3) donde el nombre de estacion de trabajo reportado no pertenece al rango DHCP/IP asignado.
references:
  - https://attack.mitre.org/techniques/T1557/001/
author: Senior DFIR Specialist
date: 2024-08-01
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: '3'
    AuthenticationPackageName: 'NTLM'
  filter_local:
    IpAddress:
      - '127.0.0.1'
      - '::1'
      - '-'
  condition: selection and not filter_local
level: medium
tags:
  - attack.credential_access
  - attack.t1557.001
```


``` SPL
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
| eval SessionID=TargetLogonId
| join type=inner SessionID [
    search index=wineventlog EventCode=5140 ShareName="*IPC$"
    | eval SessionID=SubjectLogonId
]
| where IpAddress != "127.0.0.1" AND isnotnull(WorkstationName)
| table _time, TargetUserName, WorkstationName, IpAddress, IpPort, ShareName, SessionID
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Aislamiento de Puerto en Switch:** Localizar la boca física del switch o la dirección MAC asociada a la IP hostil 172.17.79.135 y revocar su acceso a la red (bloqueo 802.1X).
    
2. **Invalidación de Sesión:** Terminar la sesión de red 0x64a799 en Forela-Wkstn001 y resetear la contraseña del usuario arthur.kyle.
    

3. **Firma Obligatoria de SMB (SMB Signing):**
    
    - Habilitar la firma digital en todos los clientes y servidores mediante GPO:  
        Microsoft network server: Digitally sign communications (always) = Enabled.  
        Microsoft network client: Digitally sign communications (always) = Enabled.  
        (Esto neutraliza completamente los ataques de NTLM Relay hacia SMB).
        
4. **Protección Extendida para Autenticación (EPA):** Habilitar EPA en servicios web e interfaces de gestión interna para prevenir relay hacia HTTP/HTTPS/LDAP.
    
5. **Deprecación de NTLMv1 y Restricción de NTLMv2:** Migrar la infraestructura hacia autenticación exclusiva mediante Kerberos y deshabilitar fallback NTLM donde sea viable.