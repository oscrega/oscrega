**Classification:** TLP:AMBER (Internal Use — SOC / Incident Response)  
**Platform / Environment:** Wireshark / Tshark / Network Analysis / Splunk Enterprise ES  
**Target / Infrastructure:** Internal Host 172.16.1.191 / External C2 162.252.172.54 & steasteel.net  

#### 1. Threat Scenario and Context

- **Executive Summary:** A network packet capture (capture.pcap) was analyzed following detection of anomalous outbound traffic from host 172.16.1.191. Forensic analysis determined initial access occurred on **May 17, 2023**, when the host retrieved an executable payload via an HTTP GET request targeting external IP **162.252.172.54**. The artifact was identified as a loader from the **Pikabot** malware family (SHA256: 9b8ffdc8ba2b2caa485cca56a82b2dcbd251f65fb30bc88f0ac3da6704e4d3c6). Following execution, the malware established encrypted C2 channels over non-standard HTTPS ports (2078, 2222, 32999) using self-signed digital certificates containing synthetic metadata (Pyopneumopericardium), alongside a fallback DNS Tunneling channel targeting **steasteel.net**.
    
- **Telemetry Sources and Dataset Contents:** Packet capture capture.pcap (11.7 MB). Inspected protocols: HTTP (payload delivery), TLS/SSL (self-signed certificates over high ports), TCP (SYN/RST flag analysis), and DNS (tunneling traffic).

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence / Log Found |
|---|---|---|---|
| **Initial Access / Execution** | T1204.002 | User Execution: Malicious File | Retrieval and execution of Pikabot loader from 162.252.172.54/9GQ5A8/6ctf5JL. |
| **Command and Control** | T1573.002 | Encrypted Channel: Asymmetric Cryptography | Self-signed SSL certificates utilized over HTTPS to evade traffic monitoring. |
| **Command and Control** | T1571 | Non-Standard Port | C2 communications initiated over TCP ports 2078, 2222, and 32999. |
| **Command and Control** | T1071.004 | Application Layer Protocol: DNS | DNS Tunneling channel implemented targeting infrastructure at steasteel.net. |

#### 3. Forensic Investigation Chain and Telemetry Analysis

- **Hunting Hypothesis:** Locate the initial outbound connection to an external address involving binary file transfers or abnormal TCP tear-downs.
    
- **Operational Queries and Commands:**

``` bash
tshark -r capture.pcap -Y "http.request" -T fields -e frame.time -e ip.src -e ip.dst -e http.request.method -e http.request.uri
tshark -r capture.pcap -Y "ip.addr == 162.252.172.54 && tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e frame.time -e ip.src -e ip.dst
```

- **Technical Breakdown of Evidence:**
    
    - Internal host **172.16.1.191** initiated outbound communication via a TCP SYN packet at **15:32:45 UTC** on **2023-05-17**.
        
    - **Initial Access Server IP:** **162.252.172.54**.
        
    - The client requested `GET /9GQ5A8/6ctf5JL`, receiving an HTTP 200 OK response returning a payload disguised under an image/gif content header.
        
    - The TCP session terminated with an abrupt **RST/ACK** flag exchange at 15:32:50 UTC, typical of first-stage loaders dropping payloads and rapidly closing connections.

---

- **Hunting Hypothesis:** Carve the transferred HTTP payload and compute cryptographic hashes for threat intelligence matching.
    
- **Operational Queries and Commands:**

``` bash
tshark -r capture.pcap --export-objects "http,./extracted_pikabot"
sha256sum extracted_pikabot/*
```

- **Technical Breakdown of Evidence:**
    
    - **Payload SHA-256 Hash:**  
        **9b8ffdc8ba2b2caa485cca56a82b2dcbd251f65fb30bc88f0ac3da6704e4d3c6**.
        
    - **Malware Classification:** **pikabot** (initial access loader commonly delivering Cobalt Strike or ransomware).
        
    - **First Seen In The Wild:** **2023-05-19 14:01:21 UTC**.

---

- **Hunting Hypothesis:** Analyze TLS handshakes established over non-standard destination ports and extract X.509 certificate metadata.
    
- **Operational Queries and Commands:**

``` bash
tshark -r capture.pcap -Y "tls.handshake.type == 11" -T fields -e ip.src -e tcp.srcport -e x509sat.printableString
```

- **Technical Breakdown of Evidence:**
    
    - Outbound HTTPS connections were established toward malicious hosts (including 45.85.235.39 and 193.122.200.171) on high ports:
        
        - **Target Ports (Ascending):** **2078, 2222, 32999**.
            
    - **Certificate Metadata (45.85.235.39 / Port 2078):**
        
        - Locality Attribute (id-at-localityName): **Pyopneumopericardium**.
            
        - Certificate Validity (notBefore UTC): **2023-05-14 08:36:52 UTC**.

---

- **Hunting Hypothesis:** Identify DNS queries used as an alternative covert communication tunnel.
    
- **Operational Queries and Commands:**

``` bash
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | grep -v "in-addr.arpa" | sort -u | head -n 10
```

- **Technical Breakdown of Evidence:**
    
    - Outbound queries to high-entropy subdomains resolved via nameserver 78.141.214.249:

``` TEXT
ridoj4.26fa3eb6.dns.steasteel.net
```

- **Tunneling Domain Identified:** **steasteel.net**.

#### 4. Detection Engineering (Alert & Correlation Rules)

``` Suricata
alert tls $HOME_NET any -> $EXTERNAL_NET [2078,2222,32999] (msg:"SOC - Deteccion de Trafico C2 Pikabot / Puertos No Estandar"; flow:to_server,established; tls.cert_subject; content:"Pyopneumopericardium"; fast_pattern; classtype:trojan-activity; sid:20260411; rev:1;)
```

- **False Positive Considerations:** None in standard production; coupling high-port TLS traffic with anomalous subject strings is indicative of Pikabot C2 activity.
    
- **Tuning:** Monitor outbound client traffic initiating TLS sessions to ports above TCP 1024.

``` SPL
index=network sourcetype="stream:dns" (query="*.steasteel.net" OR query="*steasteel.net*")
| stats count, dc(query) as subdominios, values(query) as muestras by src, dest
| table _time, src, dest, subdominios, count, muestras
```

- **False Positive Considerations:** Zero expected; steasteel.net is confirmed malicious infrastructure.
    
- **Tuning:** Ingest CTI indicators to maintain up-to-date lists of dynamic domains linked to Pikabot and QakBot campaigns.

#### 5. Containment, Remediation, and Hardening Recommendations

1. **Immediate Host Quarantine:** Isolate endpoint 172.16.1.191 via EDR to prevent the execution of secondary modules.
    
2. **Perimeter C2 Infrastructure Blocking:**
    
    - Block traffic to IPs 162.252.172.54, 45.85.235.39, and 193.122.200.171.
        
    - Drop outbound traffic to TCP ports 2078, 2222, and 32999.
        
    - Add steasteel.net to the internal DNS sinkhole.
        
3. **Payload Remediation:** Remove on-disk artifacts matching hash 9b8ffdc8ba2b2caa485cca56a82b2dcbd251f65fb30bc88f0ac3da6704e4d3c6 from user profile directories.
    
4. **Strict Egress Filtering:** Restrict internal endpoints from establishing outbound connections over ports other than standard approved destinations (TCP 80, 443).
    
5. **SSL/TLS Inspection (Deep Packet Inspection):** Enable SSL decryption on web proxies to detect executable files disguised under spoofed MIME types (e.g., binaries delivered as image/gif).