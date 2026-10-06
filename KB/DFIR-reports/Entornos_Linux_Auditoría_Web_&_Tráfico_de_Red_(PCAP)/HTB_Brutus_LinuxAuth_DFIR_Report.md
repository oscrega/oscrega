**Classification:** TLP:AMBER  
**Environment / Platform:** Linux Enterprise / Debian/Ubuntu Auth Telemetry / HTB Sherlock  
**Target:** Compromised Corporate SSH Server  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** A Linux server was investigated following an unauthorized intrusion resulting from a successful brute-force attack against OpenSSH. Analysis of authentication logs (/var/log/auth.log) and binary session histories (/var/log/wtmp) revealed the threat actor operated from IP address **65.2.161.68**. After compromising the root account, the adversary established persistence by creating a local user account named **cyberjunkie** and assigning it to the sudo group. The attacker subsequently used this account to access system password hashes (/etc/shadow) before terminating the session.
    
- **Telemetry Sources and Evidence:**
    
    - /var/log/auth.log: PAM, SSH, and sudo authentication logs.
        
    - /var/log/wtmp: Historical binary login records parsed using utmpdump and Python scripts (utmp.py).
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Credential Access** | T1110.001 | Brute Force: Password Guessing | SSH password brute-force attack against the root account from 65.2.161.68. |
| **Persistence** | T1136.001 | Create Account: Local Account | Creation of local user account cyberjunkie at 06:34:18 UTC. |
| **Privilege Escalation** | T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudoers | Addition of cyberjunkie to the sudo group for root privilege escalation. |
| **Credential Access** | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | Execution of command sudo cat /etc/shadow at 06:37:57 UTC. |

#### 3. Infection Chain and Detailed Forensic Analysis

1. **Adversary IP Address:** **65.2.161.68** (Recorded over 170 rapid failed authentication attempts).
    
2. **Access Compromise (Root Login):**
    
    - The valid authentication request was received at 06:32:44 UTC.
        
    - **Successful Authentication Timestamp:** **06:32:45 UTC** (March 6).
        
    - auth.log entry: Accepted password for root from 65.2.161.68 port ... ssh2.
        
    - **wtmp Session ID:** Recorded under session identifier **411** (pts/0).
        
3. **Initial Root Session Termination:**
    
    - The initial root session was terminated at **06:37:24 UTC**.
        

To ensure persistence against root password rotation, the adversary created a secondary local account:

- **Creation Timestamp:** **06:34:18 UTC**.
    
- **Account Created:** **cyberjunkie** (new user: name=cyberjunkie, UID=1001, GID=1001).
    
- **Privilege Delegation:** The account was added to the privileged execution group:
    
    ``` bash
    usermod -aG sudo cyberjunkie
    ```
    

1. **Secondary SSH Session:**
    
    - At **06:37:34 UTC**, the attacker authenticated via SSH as cyberjunkie from the same IP (65.2.161.68).
        
    - The active session was logged in wtmp at **06:37:35 UTC**.
        
2. **Credential Access (/etc/shadow):**
    
    - At **06:37:57 UTC**, the user executed:
        
        ``` bash
        sudo cat /etc/shadow
        ```
        
    - At the exact same second (06:37:57 UTC), the sudo session closed (session closed for user root), confirming that privilege escalation was executed exclusively to extract system password hashes.

``` bash
# Comandos de auditoría pericial utilizados en Linux
utmpdump -f wtmp -o tsv
TZ=UTC last -f wtmp -F
grep -E "(Accepted|session opened|sudo)" /var/log/auth.log | grep -E "(cyberjunkie|root)"
```

#### 4. Detection Rules and Security Engineering

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

#### 5. Containment, Eradication, and Hardening Plan

1. **Host and Perimeter Firewall Block:** Add blocking rules in iptables / nftables for IP 65.2.161.68.
    
2. **Account Removal:**
    
    ``` bash
    pkill -u cyberjunkie
    userdel -r -f cyberjunkie
    ```
    
3. **Immediate Credential Reset:** Change passwords for root and all user accounts listed in /etc/shadow.
    
4. **Disable Direct SSH Root Login:**
    
    - Modify /etc/ssh/sshd_config:
        
        ``` TEXT
        PermitRootLogin no
        PasswordAuthentication no
        ```
        
5. **Enforce Public Key Authentication:** Require ED25519 or RSA-4096 cryptographic keys and implement MFA for SSH administration.
    
6. **Implement Fail2ban / CrowdSec:** Deploy automated intrusion prevention tools to drop brute-force connection attempts.