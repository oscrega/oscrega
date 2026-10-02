### [HTB-BRUTUS: LINUX AUTH.LOG & WTMP FORENSICS REPORT]

**Clasificación:** TLP:AMBER  
**Entorno / Plataforma:** Linux Enterprise / Debian/Ubuntu Auth Telemetry / HTB Sherlock  
**Objetivo:** Servidor SSH Corporativo comprometido

#### 1. Escenario, Contexto e Identificación del Incidente

- **Resumen Ejecutivo:** Se investigó un servidor corporativo Linux tras registrarse una intrusión mediante un ataque de fuerza bruta exitoso contra el servicio OpenSSH. El análisis de los registros de autenticación (/var/log/auth.log) y de sesiones históricas binarias (/var/log/wtmp) reveló que el actor de amenaza operó desde la dirección IP **65.2.161.68**. Tras vulnerar la cuenta root, el adversario desplegó una estrategia de persistencia creando una cuenta de usuario local denominada **cyberjunkie** y asignándole privilegios de administración en el grupo sudo. Posteriormente, utilizó esta cuenta para acceder al archivo de hashes del sistema (/etc/shadow), cerrando la sesión tras completar el robo de credenciales.
    
- **Fuentes de Telemetría y Evidencias:**
    
    - /var/log/auth.log: Registro de eventos de PAM, SSH y ejecuciones de sudo.
        
    - /var/log/wtmp: Registro de sesiones del sistema parseado mediante utmpdump y scripts en Python (utmp.py).
        

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de Técnica|Evidencia Específica Hallada|
|**Credential Access**|T1110.001|Brute Force: Password Guessing|Ataque de fuerza bruta SSH contra la cuenta root desde la IP 65.2.161.68.|
|**Persistence**|T1136.001|Create Account: Local Account|Creación de la cuenta de usuario local cyberjunkie a las 06:34:18 UTC.|
|**Privilege Escalation**|T1548.003|Abuse Elevation Control Mechanism: Sudo and Sudoers|Adición del usuario cyberjunkie al grupo sudo para permitir ejecución de comandos como root.|
|**Credential Access**|T1003.008|OS Credential Dumping: /etc/passwd and /etc/shadow|Ejecución del comando sudo cat /etc/shadow a las 06:37:57 UTC.|

#### 3. Cadena de Infección y Análisis Forense Detallado

1. **Dirección IP del Adversario:** **65.2.161.68** (Registró más de 170 intentos fallidos de autenticación en ráfaga).
    
2. **Materialización del Acceso (Root Login):**
    
    - El envío de la petición de autenticación válida se produjo a las 06:32:44 UTC.
        
    - **Timestamp de Inicio de Sesión Aceptado:** **06:32:45 UTC** (6 de marzo).
        
    - Entrada en auth.log: Accepted password for root from 65.2.161.68 port ... ssh2.
        
    - **Identificador de Sesión (wtmp):** Registrado bajo el identificador **411** (sesión pts/0).
        
3. **Cierre de la Primera Sesión de Root:**
    
    - La primera sesión del atacante finalizó a las **06:37:24 UTC**.
        

A fin de asegurar el acceso ante posibles rotaciones de credenciales de root, el atacante creó una cuenta de respaldo:

- **Timestamp de Creación:** **06:34:18 UTC**.
    
- **Cuenta Creada:** **cyberjunkie** (new user: name=cyberjunkie, UID=1001, GID=1001).
    
- **Escalada y Asignación de Grupo:** Inmediatamente después de la creación, la cuenta fue agregada al grupo con privilegios de ejecución delegada:
    
    
    
    ``` bash
    usermod -aG sudo cyberjunkie
    ```
    

1. **Inicio de Sesión vía SSH:**
    
    - A las **06:37:34 UTC**, el atacante inició una nueva sesión SSH autenticándose como cyberjunkie desde la misma IP (65.2.161.68).
        
    - El sistema registró la sesión activa formalmente en wtmp a las **06:37:35 UTC**.
        
2. **Acceso a Credenciales del Sistema (/etc/shadow):**
    
    - A las **06:37:57 UTC**, el usuario ejecutó:
        
        
        
        ``` bash
        sudo cat /etc/shadow
        ```
        
    - En el mismo segundo (06:37:57 UTC), se cerró la sesión sudo (session closed for user root), confirmando que la elevación de privilegios se utilizó exclusivamente para extraer los hashes de contraseñas de todos los usuarios locales.
        



``` bash
# Comandos de auditoría pericial utilizados en Linux
utmpdump -f wtmp -o tsv
TZ=UTC last -f wtmp -F
grep -E "(Accepted|session opened|sudo)" /var/log/auth.log | grep -E "(cyberjunkie|root)"
```

#### 4. Reglas de Detección e Ingeniería de Seguridad



``` Yaml
- rule: Acceso No Estandar a Fichero Shadow
  desc: Detecta cualquier lectura sobre /etc/shadow ejecutada por utilidades de lectura directa
  condition: >
    spawned_process and proc.name in (cat, head, tail, more, less) 
    and fd.name = "/etc/shadow" and not user.name = "root"
  output: "Alerta DFIR: Intento de lectura de /etc/shadow por usuario no-root (usuario=%user.name comando=%proc.cmdline)"
  priority: CRITICAL
  tags: [credential_access, T1003.008]
```



``` SPL
index=linux_auth sourcetype=syslog ("Failed password" OR "Accepted password")
| stats count(eval(searchmatch("Failed password"))) as Fallidos, 
        count(eval(searchmatch("Accepted password"))) as Exitosos, 
        latest(_time) as Ultimo_Login by src_ip, user
| where Fallidos > 15 AND Exitosos >= 1
| convert ctime(Ultimo_Login)
| table Ultimo_Login, src_ip, user, Fallidos, Exitosos
```

#### 5. Plan de Contención, Erradicación y Hardening

1. **Bloqueo IP en Host y Perímetro:** Aplicar regla en iptables / nftables bloqueando la IP 65.2.161.68.
    
2. **Eliminación de Cuentas Hostiles:**
    
   
    
    ``` bash
    pkill -u cyberjunkie
    userdel -r -f cyberjunkie
    ```
    
3. **Restablecimiento Inmediato de Contraseñas:** Rotar la contraseña de root y de todas las cuentas listadas en /etc/shadow.
    

4. **Deshabilitar Acceso Directo de Root vía SSH:**
    
    - Configurar en /etc/ssh/sshd_config:
        
        
        
        ``` TEXT
        PermitRootLogin no
        PasswordAuthentication no
        ```
        
5. **Implementar Autenticación Exclusiva por Llaves Criptográficas:** Requerir llaves ED25519 o RSA-4096 junto con autenticación multifactor (MFA/2FA) para el acceso SSH.
    
6. **Despliegue de Fail2ban / CrowdSec:** Instalar mecanismos automáticos de baneo ante intentos reiterados de autenticación fallida.