**Classification:** TLP:AMBER (Internal Use — SOC / Incident Response)  
**Platform / Environment:** Wireshark / Tshark / PCAP Network Forensics / Splunk Enterprise ES  
**Target / Infrastructure:** Internal Test Host (192.168.157.144) / Attacker DNS C2 Server (192.168.157.145)  

#### 1. Threat Scenario and Context

- **Executive Summary:** An intrusion against an internal test workstation managed by user Khalid (192.168.157.144) was investigated. The target host, located in a test environment with internal network access, was compromised by an adversary operating from IP 192.168.157.145. The threat actor deployed a custom **DNS Tunneling** utility (version 0.07), renamed on disk to win_installer.exe to blend in with legitimate system operations. Through this covert channel, the adversary issued interactive reconnaissance commands (whoami), traversed local and cloud directories (OneDrive), and located an unprotected customer repository (C:\Users\test\Documents\client data optimisation\user details.csv). The attacker exfiltrated **721 Personally Identifiable Information (PII) records** encoded within DNS lookups directed to fraudulent domain microsoft360.com.
    
- **Telemetry Sources and Dataset Contents:** Network packet capture suspicious_traffic.pcap (42.3 MB). Protocols examined: DNS (queries and responses with anomalous label lengths), TCP (port scanning activity), and ARP traffic.

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence / Log Found |
|---|---|---|---|
| **Command and Control** | T1071.004 | Application Layer Protocol: DNS | Bidirectional C2 channel established using DNS Tunneling over microsoft360.com. |
| **Defense Evasion** | T1036.005 | Masquerading: Match Legitimate Name | Binary renamed on target host to win_installer.exe. |
| **Discovery** | T1033 | System Owner/User Discovery | Interactive execution of whoami transmitted inside the DNS tunnel. |
| **Discovery** | T1083 | File and Directory Discovery | Enumeration of local OneDrive storage directories and folder path client data optimisation. |
| **Collection** | T1005 | Data from Local System | Cleartext retrieval of user details.csv utilizing the native type command. |
| **Exfiltration** | T1048.003 | Exfiltration Over Alternative Protocol: DNS | Exfiltration of 721 PII records chunked and encoded within DNS subdomains. |

#### 3. Forensic Investigation Chain and Telemetry Analysis

- **Hunting Hypothesis:** Isolate protocols displaying anomalous transmission volumes, request frequencies, and unusual packet lengths.
    
- **Operational Queries and Commands:**

``` bash
tshark -r suspicious_traffic.pcap -q -z io,phs
tshark -r suspicious_traffic.pcap -Y "dns" -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -nr
```

- **Technical Breakdown of Evidence:**
    
    - The **DNS** protocol accounted for the primary anomaly, characterized by high-frequency query bursts with variable-length subdomains targeting **microsoft360.com**.
        
    - **Victim IP Address:** **192.168.157.144**.
        
    - **Adversary DNS C2 Server IP Address:** **192.168.157.145**.

---

- **Hunting Hypothesis:** Extract client DNS query names and decode hexadecimal/Base32 payload strings to reconstruct the attacker's interactive shell session.
    
- **Operational Queries and Commands:**

``` bash
tshark -r suspicious_traffic.pcap -Y "dns && ip.src == 192.168.157.145" -T fields -e dns.qry.name | xxd -r -p > exfil.txt
strings exfil.txt | head -n 30
```

- **Technical Breakdown of Evidence:**
    
    - **Initial Command Executed:** The adversary initiated access with reconnaissance command **whoami**.
        
    - **Tunneling Utility Version:** Initial handshake parameters identified the client tool version: **0.07**.
        
    - **Evasion Masquerading:** The attacker renamed the staging binary deployed to the endpoint to: **win_installer.exe**.

---

- **Hunting Hypothesis:** Parse directory traversal and file inspection commands issued across the decoded session stream.
    
- **Operational Queries and Commands:**

``` bash
strings exfil.txt | grep -i -C 5 "onedrive"
strings exfil.txt | grep -i -C 5 "type "
```

- **Technical Breakdown of Evidence:**
    
    - **Cloud Storage Discovery:** The attacker executed directory listing commands against the user's local OneDrive folder, returning **0 bytes** (indicating no files were synchronized at that time).
        
    - **PII Data Access:** At line 651 of the parsed output, the attacker executed:

``` Cmd
type "C:\Users\test\Documents\client data optimisation\user details.csv"
```

- **Full File Path:** **C:\Users\test\Documents\client data optimisation\user details.csv**.

---

- **Hunting Hypothesis:** Reconstruct the structured data stream to determine the exact volume of compromised records.
    
- **Operational Queries and Commands:**

``` Bash
strings exfil.txt | sed -n '650,5180p' > stolen.txt
head -n 5 stolen.txt
tail -n 5 stolen.txt
```

- **Technical Breakdown of Evidence:**
    
    - The extracted file contained sequentially indexed customer data.
        
    - Record indices began at ID 0 and concluded at ID 720.
        
    - **Total Compromised PII Records:** Exactly **721 customer entries** (encompassing full names, email addresses, and corporate metadata).

#### 4. Detection Engineering (Alert & Correlation Rules)

``` Suricata
alert dns $HOME_NET any -> any 53 (msg:"SOC - Sospecha de DNS Tunneling / Exfiltracion (microsoft360.com)"; dns.query; content:".microsoft360.com"; isdataat:30,relative; pcre:"/^[a-f0-9]{20,}\.microsoft360\.com$/i"; classtype:bad-unknown; sid:20260410; rev:1;)
```

- **False Positive Considerations:** None; domain microsoft360.com is an unapproved lookalike domain that does not belong to Microsoft.
    
- **Tuning:** Deploy frequency thresholds to trigger on more than 100 queries per minute matching high-entropy regex patterns.

``` SPL
index=network sourcetype="stream:dns" query_type="A" OR query_type="TXT"
| eval query_len=len(query)
| where query_len > 50
| stats count, dc(query) as subdominios_unicos, values(query) as muestras by src, dest
| where subdominios_unicos > 50
| table src, dest, subdominios_unicos, count, muestras
```

- **False Positive Considerations:** Security software lookups (e.g., DNSBL/RBL spam blacklists) and dynamic CDN queries.
    
- **Tuning:** Exclude approved enterprise recursive DNS resolvers and allowlist reputable CDN endpoints (e.g., Akamai, Cloudflare).

#### 5. Containment, Remediation, and Hardening Recommendations

1. **Host Isolation:** Immediately disconnect internal test workstation 192.168.157.144 from the network.
    
2. **DNS & Network Blocking:**
    
    - Implement firewall and DNS sinkhole drop rules for domain **microsoft360.com**.
        
    - Isolate internal host **192.168.157.145** at the switch/access layer.
        
3. **Data Breach Incident Response:** Initiate data breach notification workflows regarding the 721 impacted individuals in compliance with applicable regulatory frameworks (GDPR, national data privacy laws).
    
4. **Enforce Recursive DNS Routing:** Mandate that all endpoints query internal enterprise DNS servers exclusively; block outbound UDP/TCP port 53 traffic to external destinations at the network boundary.
    
5. **Next-Generation DNS Protection:** Implement automated DNS tunneling and domain reputation inspection engines on all perimeter DNS gateways (e.g., Cisco Umbrella, Infoblox BloxOne).