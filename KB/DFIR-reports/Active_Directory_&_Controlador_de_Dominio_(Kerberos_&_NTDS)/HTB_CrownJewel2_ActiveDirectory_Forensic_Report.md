### [HTB-CROWNJEWEL2: ACTIVE DIRECTORY PERSISTENCE & NTDSUTIL EXFILTRATION]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Active Directory / Windows Server 2019 / HTB Sherlock  
**Objetivo:** Controlador de Dominio DC01.forela.local

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Tras la contención inicial del incidente anterior, el actor de amenaza recuperó acceso administrativo sobre el Controlador de Dominio mediante mecanismos de persistencia no erradicados. En esta segunda incursión, el atacante abusó de la utilidad legítima de administración de Active Directory **ntdsutil.exe**, empleando la directiva de volcado IFM (Install From Media). Esta técnica invoca directamente al motor de base de datos **ESENT** (Extensible Storage Engine) para realizar un volcado consistente de NTDS.dit en una ruta temporal (C:\Windows\Temp\dump_tmp\Active Directory\), intentando camuflar la extracción bajo operaciones de mantenimiento estándar de Windows.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - APPLICATION.evtx: Registros del motor transaccional ESENT (Event IDs 325, 327).
        
    - SYSTEM.evtx: Monitorización del estado de servicios del sistema (Event ID 7036).
        
    - SECURITY.evtx: Auditoría de autenticación y sesiones Kerberos (Event IDs 4768, 4769, 4799, 5379).
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Credential Access**|T1003.003|OS Credential Dumping: NTDS|Volcado completo de la base de datos de AD utilizando ntdsutil.exe con salida en C:\Windows\Temp\dump_tmp\Active Directory\ntds.dit.|
|**Defense Evasion**|T1036.005|Masquerading: Device / Utility Masquerading|Uso de utilidades administrativas nativas (ntdsutil) para evadir alertas de inyección de memoria directa en lsass.exe.|
|**Discovery**|T1069.002|Permission Groups Discovery: Domain Groups|Validación automática de pertenencia a grupos privileged: Administrators y Backup Operators (Event ID 4799).|
|**Credential Access**|T1555.004|Credentials from Password Stores: Windows Credential Manager|Acceso a credenciales almacenadas en el Credential Manager inmediatamente antes del dumping (Event ID 5379).|

#### 3. Cadena de Infección y Análisis Forense Detallado

1. **Activación del Servicio Shadow Copy para Soporte de IFM (System Log - Event ID 7036):**
    
    - Para generar un snapshot consistente sin desconectar Active Directory, ntdsutil.exe llama al servicio VSS.
        
    - Último timestamp en que el servicio entró en estado running: **2024-05-15 05:39:55 UTC**.
        
2. **Actividad del Motor de Base de Datos ESENT (Application Log):**
    
    - **Fuente del Evento:** **ESENT** (Extensible Storage Engine / JET Blue Engine).
        
    - **Creación / Inicialización de la Base de Datos (Event ID 325):**
        
        - Registrado a las **2024-05-15 05:39:56 UTC**.
            
        - Documenta la creación del archivo de volcado en la ruta física:  
            **C:\Windows\Temp\dump_tmp\Active Directory\ntds.dit**
            
    - **Finalización y Desacople de la Base de Datos (Event ID 327):**
        
        - Registrado a las **2024-05-15 05:39:58 UTC**.
            
        - El evento certifica que la base de datos fue detachada de forma limpia, consistente y quedó lista para su copia/exfiltración por parte del atacante.
            
3. **Validación de Privilegios de Cuenta (Security Log - Event ID 4799):**
    
    - Exactamente dos segundos antes de que la base de datos estuviera lista, el proceso ntdsutil.exe ejecutó consultas de enumeración de miembros sobre dos grupos de seguridad: **Administrators** y **Backup Operators**.
        

La correlación de eventos en Security.evtx determinó el momento exacto en que la sesión comprometida inició su actividad:

- **Timestamp de la Sesión:** **2024-05-15 05:36:31 UTC**.
    
- **Cadena de Eventos Concurrente:**
    
    1. Event ID 4768: Solicitud exitosa de TGT de Kerberos para la cuenta Administrator.
        
    2. Event ID 4769: Solicitud de ticket TGS para servicios locales del DC.
        
    3. Event ID 5379: Lectura de credenciales protegidas desde el Administrador de Credenciales de Windows (Credential Manager), operación típica previa al despliegue de comandos de volcado interactivos.
        


``` bash
# Filtrado de eventos ESENT para certificar la ruta del volcado NTDS
cat application.json | jq '.[] | select(.Event.System.Provider_attributes.Name == "ESENT") | 
select(.Event.System.EventID == 325 or .Event.System.EventID == 327) | 
{
  Time: .Event.System.TimeCreated_attributes.SystemTime,
  EventID: .Event.System.EventID,
  Description: .Event.EventData
}'
```

#### 4. Reglas de Detección e Ingeniería de Seguridad


``` Yaml
title: Volcado de NTDS.dit Mediante Ntdsutil (IFM)
id: 1198c4d2-f472-4d1a-8219-ntdsutilifmdump
status: production
description: Detecta el uso de ntdsutil.exe con parametros diseñados para volcar la base de datos de Active Directory en disco.
references:
  - https://attack.mitre.org/techniques/T1003/003/
author: Senior DFIR Specialist
date: 2024-05-16
logsource:
  product: windows
  service: security
detection:
  selection_ntdsutil:
    EventID: 4688
    NewProcessName|endswith: '\ntdsutil.exe'
    CommandLine|contains|all:
      - 'ac'
      - 'i'
      - 'ntds'
  selection_ifm:
    CommandLine|contains|any:
      - 'create full'
      - 'ifm'
  condition: selection_ntdsutil and selection_ifm
level: critical
tags:
  - attack.credential_access
  - attack.t1003.003
```


``` Spl
index=wineventlog (source="*Application" SourceName="ESENT" (EventCode=325 OR EventCode=327)) OR (source="*Security" EventCode=4688 NewProcessName="*\\ntdsutil.exe")
| transaction host maxspan=30s
| search CommandLine="*ifm*" OR CommandLine="*create full*"
| table _time, host, SubjectUserName, CommandLine, Message
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Aislamiento Total del DC Afectado:** Aislar DC01 de la red corporativa manteniendo únicamente conectividad forense controlada.
    
2. **Reconstrucción de Confianza del Dominio:** Ante dos compromisos consecutivos de NTDS.dit, el bosque de Active Directory debe considerarse completamente comprometido. Se debe planificar la rebuild completa del KDC y los controladores de dominio primarios desde imágenes verificadas.
    
3. **Bloqueo y Re-rotación de Claves:** Nueva rotación de la cuenta krbtgt y revocación de certificados emitidos por los Active Directory Certificate Services (AD CS).
    

4. **Auditoría Estricta sobre Creación de Procesos (CommandLine Auditing):** Forzar mediante GPO la directiva Include command line in process creation events (Event ID 4688) para garantizar trazabilidad sobre los argumentos pasados a ntdsutil.exe.
    
5. **Restricción de Privilegios Administrativos:** Implementar un modelo de administración por niveles (Tier Model / Enterprise Access Model) que impida el inicio de sesión de Domain Admins en cualquier sistema que no sea un Controlador de Dominio dedicado.