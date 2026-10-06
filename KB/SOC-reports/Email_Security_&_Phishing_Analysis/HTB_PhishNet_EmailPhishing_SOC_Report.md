**Classification:** TLP:AMBER (Internal Use — SOC / Incident Response)  
**Platform / Environment:** Email Gateway Analysis / EML Forensics / Linux CLI (ripmime)  
**Target / Infrastructure:** Accounting Department (accounts@globalaccounting.com)  

#### 1. Threat Scenario and Context

- **Executive Summary:** A financial spearphishing campaign targeting the organization's accounting department was investigated. The attack vector involved a fraudulent email (email.eml) designed to simulate an urgent overdue invoice notification from a known supplier (**Business Finance Ltd.**). The threat actor forged message headers, transmitting from source IP 45.67.89.10 and setting the return address to support@business-finance.com. The message implemented a dual-infection vector: a hyperlink pointing to phishing infrastructure (secure.business-finance.com) and an attached compressed archive named Invoice_2025_Payment.zip. Analysis of the extracted payload revealed a malicious script employing a double file extension (invoice_document.pdf.bat), structured to induce the recipient into immediate execution.
    
- **Telemetry Sources and Dataset Contents:** RFC 5322 email file (email.eml, 3.5 KiB). Inspection of SMTP routing hops (Received hops, SPF, DKIM, DMARC), multipart/mixed HTML message body, and a Base64-encoded ZIP container extracted via ripmime.

#### 2. MITRE ATT&CK® Tactical Mapping

| Tactic | Technique / Sub-technique ID | Technique Name | Specific Evidence / Log Found |
|---|---|---|---|
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment | Delivery of attached compressed archive Invoice_2025_Payment.zip containing an executable script. |
| **Initial Access** | T1566.002 | Phishing: Spearphishing Link | Embedded hyperlink pointing to fraudulent invoice portal: https://secure.business-finance.com/.../payment. |
| **Defense Evasion** | T1036.007 | Masquerading: Double File Extension | Malicious payload utilizing simulated PDF extension: invoice_document.pdf.bat. |

#### 3. Forensic Investigation Chain and Telemetry Analysis

- **Hunting Hypothesis:** Reconstruct SMTP routing hops to pinpoint the true originating IP address and assess the alignment of SPF/DKIM/DMARC mechanisms.
    
- **Operational Queries and Commands:**

``` bash
grep -E "(X-Originating-IP|X-Sender-IP|Received:|Return-Path:|Reply-To:|From:)" email.eml
grep -i "Authentication-Results" -A 3 email.eml
```

- **Technical Breakdown of Evidence:**
    
    - **Sender Originating IP Address:** **45.67.89.10** (identified in X-Originating-IP and X-Sender-IP).
        
    - **Final Relay Server:** **203.0.113.25** (mail.business-finance.com), which transferred the email to the corporate MTA mail.target.com.
        
    - **Sender Address (From):** finance@business-finance.com.
        
    - **Reply-To Address:** **support@business-finance.com**.
        
    - **SPF Validation Assessment:** **Pass** (protection.outlook.com: domain of business-finance.com designates 45.67.89.10 as permitted sender).

---

- **Hunting Hypothesis:** Extract embedded redirection links and analyze the impersonated corporate identity within the message body.
    
- **Technical Breakdown of Evidence:**
    
    - **Impersonated Corporate Entity:** **Business Finance Ltd.**.
        
    - The message demanded an immediate settlement of $4,750.00 for invoice #INV-2025-0012 prior to February 28, 2025.
        
    - **Phishing URL Domain:** **secure.business-finance.com**.  
        Full URL: https://secure.business-finance.com/invoice/details/view/INV2025-0987/payment.

---

- **Hunting Hypothesis:** Extract the attached Base64-encoded container, generate cryptographic hashes, and unpack the internal payload.
    
- **Operational Queries and Commands:**

``` bash
ripmime -i email.eml -d ./extracted_attachment
sha256sum extracted_attachment/Invoice_2025_Payment.zip
7z l extracted_attachment/Invoice_2025_Payment.zip
```

- **Technical Breakdown of Evidence:**
    
    - **Attachment Filename:** **Invoice_2025_Payment.zip**.
        
    - **ZIP File SHA-256 Hash:**  
        **8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a**.
        
    - **Concealed Payload:** Inside the ZIP container, an executable script utilizing a double extension was identified:  
        **invoice_document.pdf.bat**.

#### 4. Detection Engineering (Alert & Correlation Rules)

``` Yara
rule Phish_Invoice_Zip_Batch_Attachment {
    meta:
        description = "Detecta contenedores ZIP que ocultan scripts batch con extension doble simulando ser facturas PDF"
        author = "Senior Threat Hunter"
        date = "2026-04-02"
        hash = "8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a"
    strings:
        $zip_magic = { 50 4B 03 04 }
        $payload_name = "invoice_document.pdf.bat" ascii nocase
    condition:
        $zip_magic at 0 and $payload_name
}
```

- **False Positive Considerations:** None; .pdf.bat extensions are unambiguous indicators of malicious staging.
    
- **Tuning:** Expand rule syntax to match regex patterns such as `\.[a-z]{3,4}\.bat$` within the central directory header of the ZIP.

``` SPL
index=email_gateway sourcetype="ms:exchange:tracking" (file_name="*.bat" OR file_name="*.vbs" OR file_name="*.pdf.bat")
| stats count values(sender) as remitentes values(recipient) as destinatarios values(file_name) as adjuntos by src_ip, subject
| table _time, src_ip, remitentes, destinatarios, subject, adjuntos, count
```

- **False Positive Considerations:** Zero in standard corporate environments enforcing policies prohibiting executable files via email.
    
- **Tuning:** Enforce automated drops at the gateway boundary prior to reaching the recipient mailbox.

#### 5. Containment, Remediation, and Hardening Recommendations

1. **Mailbox Purge:** Remove the identified message across all accounting department mailboxes via compliance search-and-purge actions in Microsoft 365 / Google Workspace.
    
2. **IOC Blocking:**
    
    - Block IP **45.67.89.10** and relay host **203.0.113.25** on the Secure Email Gateway (SEG).
        
    - Add domain **secure.business-finance.com** to the enterprise perimeter web proxy blocklist.
        
    - Ingest the SHA-256 hash into the corporate EDR blocklist.
        
3. **Mail Gateway File Inspection Policies:** Enforce strict SEG inspection rules to block or quarantine compressed archives (.zip, .rar, .7z) containing executable files or script extensions (.bat, .cmd, .ps1, .vbs, .js).
    
4. **Execution Prevention for Double Extensions:** Enforce Windows policies to disable the hiding of known file extensions and block execution of .bat scripts launched from standard user Downloads or Outlook Temporary folders.

---

# HTB_Cuidado — SOC & Threat Hunting Technical Report



---

# HTB_Interceptor — SOC & Threat Hunting Technical Report



---

# HTB_Litter — SOC & Threat Hunting Technical Report



---

# HTB_Takedown — SOC & Threat Hunting Technical Report


---

# HTB_Compromised — SOC & Threat Hunting Technical Report



---

# HTB_Meerkat — SOC & Threat Hunting Technical Report



---

# HTB_JingleBell — SOC & Threat Hunting Technical Report

