**Classification:** TLP:AMBER  
**Environment / Platform:** Linux Enterprise / Network Traffic Analysis (PCAP) / HTB Sherlock  
**Target:** Corporate FTP Server (172.31.45.144:21) / Exfiltration toward AWS S3  

#### 1. Incident Scenario, Context, and Identification

- **Executive Summary:** A critical intrusion against an Internet-facing FTP server (172.31.45.144) was investigated. The attacker, operating from an AWS EC2 instance in India (15.206.185.207), conducted a successful brute-force attack against the **vsFTPd 3.0.5** service, gaining access through weak credentials (forela-ftp:ftprocks69$). Once authenticated, the adversary utilized Extended Passive Mode (EPSV) and the RETR command to exfiltrate sensitive internal files. The downloaded data included maintenance notices containing cleartext credentials for backup SSH servers (B@ckup2024!) and Amazon S3 bucket inventories later leveraged for data extortion involving approximately 20 GB of corporate data.
    
- **Telemetry Sources and Evidence:**
    
    - Network packet capture: ftp.pcap (microsecond timestamps, little-endian).
        
    - Analysis tools: Wireshark, tshark, and NetworkMiner for TCP stream reconstruction and transmitted file carving.
        
    - IP geolocation enrichment (IP-API).
        

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence Found |
|---|---|---|---|
| **Credential Access** | T1110.001 | Brute Force: Password Guessing | Sequential FTP authentication attempts originating from 15.206.185.207 against TCP port 21. |
| **Initial Access** | T1078.003 | Valid Accounts: Local Accounts | Successful authentication to the FTP service utilizing account forela-ftp. |
| **Collection** | T1005 | Data from Local System | Retrieval of sensitive documentation (Maintenance-Notice.pdf and s3_buckets.txt). |
| **Exfiltration** | T1048.003 | Exfiltration Over Alternative Protocol: FTP | Remote file extraction through the execution of the FTP RETR command. |
| **Credential Access** | T1552.001 | Credentials In Files | Extraction of backup SSH server passwords embedded in a PDF document. |

#### 3. Infection Chain and Detailed Forensic Analysis

- **Attacker IP Address:** **15.206.185.207**.
    
- **Target Server IP Address:** **172.31.45.144** (TCP port 21).
    
- **Geographic Attribution (GeoIP):**
    
    - City: **Mumbai**
        
    - Country: **India**
        
    - ASN / ISP: AS16509 Amazon.com, Inc. (AWS EC2 instance, region ap-south-1).
        

1. **Service Fingerprinting:**  
    The initial TCP connection exposed service details:
    
    - **Software / Version:** **vsFTPd 3.0.5** (Very Secure FTP Daemon).
        
2. **Brute-Force Activity:**  
    The first burst of authentication failure responses (530 Login incorrect) occurred at:  
    **2024-05-03 04:12:54 UTC**.
        
3. **Compromised Credentials:**  
    Following multiple failures, a packet containing USER forela-ftp followed by PASS ftprocks69$ was processed with code 230 Login successful:
    
    - **Credentials:** **forela-ftp:ftprocks69$**
        

- **Extraction Mechanism:** The adversary initiated extended passive mode via the EPSV command and retrieved files using:
    
    - **FTP Command:** **RETR**
        
- **Exfiltrated Artifacts Carved (NetworkMiner):**
    
    1. Maintenance-Notice.pdf:
        
        - Document inspection recovered privileged infrastructure credentials:
            
        - **Backup SSH Server Password:** **B@ckup2024!**
            
    2. s3_buckets.txt:
        
        - The file detailed internal corporate cloud infrastructure:
            
        - **2023 Cold Storage S3 Bucket URL:** **https://2023-coldstorage.s3.amazonaws.com**
            
        - **Internal Email Address (Phishing/Social Engineering Context):** **archivebackups@forela.co.uk**  
            (Reference: "[https://2022-warmstor.s3.amazonaws.com](https://www.google.com/url?sa=E&q=https%3A%2F%2F2022-warmstor.s3.amazonaws.com) audit pending, send an email to alonzo at [archivebackups@forela.co.uk](https://www.google.com/url?sa=E&q=mailto%3Aarchivebackups%40forela.co.uk) for any authorization").

``` bash
# Filtrado de credenciales y comandos RETR en tshark
tshark -r ftp.pcap -Y "ftp.request.command in {\"USER\",\"PASS\",\"RETR\",\"EPSV\"}" -T fields -e frame.time_epoch -e ip.src -e ftp.request.command -e ftp.request.arg
```

#### 4. Detection Rules and Security Engineering

``` Snort
alert tcp any any -> 172.31.45.144 21 (msg:"ALERTA CTI - Posible Fuerza Bruta FTP (vsFTPd)"; flow:to_server,established; content:"USER"; nocase; threshold:type threshold, track by_src, count 10, seconds 60; sid:1000941; rev:1;)
```

``` SPL
index=network sourcetype="pcap:ftp" dest_port=21
| stats count(eval(searchmatch("530 Login incorrect"))) as Fallidos, 
        count(eval(searchmatch("230 Login successful"))) as Exitosos,
        values(ftp_user) as Usuarios_Probados by src_ip
| where Fallidos > 10 AND Exitosos >= 1
| table src_ip, Usuarios_Probados, Fallidos, Exitosos
```

#### 5. Containment, Eradication, and Hardening Plan

1. **Perimeter Containment:** Implement firewall blocks for the AWS source subnet 15.206.185.0/24.
    
2. **Credential Rotation:**
    
    - Reset the password for account forela-ftp.
        
    - Rotate the backup SSH server credentials (B@ckup2024!).
        
    - Audit IAM policies and rotate access keys associated with buckets 2023-coldstorage and 2022-warmstor.
        
3. **Decommission Cleartext Protocols:** Replace unencrypted FTP with SFTP (SSH File Transfer Protocol) or FTPS (FTP over explicit TLS).
    
4. **Administrative Access Control:** Configure access control lists (ACLs) to ensure file transfer services are accessible only from authorized internal corporate ranges or corporate VPN gateways.