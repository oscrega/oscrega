## 📄 Featured Reports (TOP 8 PDF Audits)

> *Note: Comprehensive technical audits structured in corporate PDF format. They include an Executive Summary (targeted at C-Level / Management), CVSS v3.1 Findings Matrix, detailed Proofs of Concept (PoC), MITRE ATT&CK alignment, and a remediation roadmap.*

### A. Active Directory & Enterprise Infrastructure
| Project / Target | Key Vectors & TTPs (MITRE ATT&CK) | Full Report |
| :--- | :--- | :--- |
| **HTB EscapeTwo** | AD CS Exploitation (ESC4 to ESC1), WriteOwner in DACL, MSSQL `xp_cmdshell` | 📄 [View PDF](./Reports-pdf/HTB_EscapeTwo_Windows_ActiveDirectory_Pentest_Report.pdf) |
| **HTB Fluffy** | NTLMv2 Coercion (CVE-2025-24071), Shadow Credentials (`msDS-KeyCredentialLink` / ESC16), PKINIT | 📄 [View PDF](./Reports-pdf/HTB_Fluffy_Windows_ActiveDirectory_Pentest_Report.pdf) |
| **HTB Voleur** | Targeted Kerberoasting, object restoration with `bloodyAD`, DPAPI, and WSL pivoting | 📄 [View PDF](./Reports-pdf/HTB_Voleur_Windows_ActiveDirectory_Pentest_Report.pdf) |
| **HTB Administrator** | GenericAll permissions in RPC, malicious SPN injection (`GenericWrite`), and DCSync | 📄 [View PDF](./Reports-pdf/HTB_Administrator_Windows_ActiveDirectory_Pentest_Report.pdf) |

### B. Linux, Web Applications & Modern Stacks
| Project / Target | Key Vectors & TTPs (MITRE ATT&CK) | Full Report |
| :--- | :--- | :--- |
| **HTB DevHub** | MCP Protocol RCE (CVE-2026-23744), Chisel Tunneling, Flask Endpoints | 📄 [View PDF](./Reports-pdf/HTB_DevHub_Linux_Web_AI_Pentest_Report.pdf) |
| **HTB Conversor** | XSLT Injection to RCE, Privilege Escalation via `needrestart` (CVE-2024-48990 / `PYTHONPATH`) | 📄 [View PDF](./Reports-pdf/HTB_Conversor_Linux_Web_PrivilegeEscalation_Pentest_Report.pdf) |
| **HTB Outbound** | Roundcube RCE (CVE-2025-49113), 3DES session decryption, escalation in `Below` (CVE-2025-27591) | 📄 [View PDF](./Reports-pdf/HTB_Outbound_Linux_Web_MailServer_Pentest_Report.pdf) |
| **HTB Lock** | ASPX WebShell via Gitea, mRemoteNG decryption, OpLock / MSI Race Condition (CVE-2023-49147) | 📄 [View PDF](./Reports-pdf/HTB_Lock_Windows_Web_PrivilegeEscalation_Pentest_Report.pdf) |


## 📚 Knowledge Base (KB) - Audits and Analysis (.md)

Full access to the knowledge base (`./KB/`) in native Markdown syntax for command inspection, code, forensic artifacts, and SPL queries:

* ⚔️ **[Pentesting, Red Team & Offensive Security (`./KB/PENTEST-reports/`)](./KB/PENTEST-reports/)**

  * **[Active Directory & Enterprise Identity](./KB/PENTEST-reports/Active-Directory-and-Enterprise-Identity/):** LDAP enumeration, Kerberos exploitation, lateral movement, persistence, and Active Directory infrastructure auditing.
  * **[Binary Exploitation & Host Hardening](./KB/PENTEST-reports/Binary-Exploitation-and-Host-Hardening/):** Binary exploitation, buffer overflow analysis, privilege escalation, and system hardening.
  * **[Emerging Tech, AI & CI/CD Security](./KB/PENTEST-reports/Emerging-Tech-AI-and-CICD-Security/):** CI/CD pipeline audits, security in AI models/applications, and emerging technology assessment.
  * **[Perimeter Network & Remote Access](./KB/PENTEST-reports/Perimeter-Network-and-Remote-Access/):** Perimeter pentesting, remote access services (VPN, SSH, RDP), and exposed infrastructure audits.
  * **[Web Application Penetration Testing](./KB/PENTEST-reports/Web-Application-Penetration-Testing/):** NoSQL/SQL injections, control evasion, web privilege escalation, and application auditing.

* 🔍 **[DFIR & Host Forensics (`./KB/DFIR-reports/`)](./KB/DFIR-reports/)**

  * **[Active Directory & Domain Controller](./KB/DFIR-reports/Active_Directory_%26_Controlador_de_Dominio_(Kerberos_%26_NTDS)/):** Authentication artifacts, NTDS.dit database extraction/analysis, and Kerberos dumps.
  * **[RAM Memory Forensic Analysis](./KB/DFIR-reports/An%C3%A1lisis_Forense_de_Memoria_RAM_(Volatility)/):** Extraction of artifacts in RAM volumes using Volatility, identification of injected malware, and Imphash.
  * **[File System Forensics & Disk Triage](./KB/DFIR-reports/An%C3%A1lisis_Forense_de_Sistema_de_Archivos_%26_Triaje_de_Disco_(MFT_%26_USN_%26_Prefetch)/):** Disk triage, MFT registry analysis, USN Journal, and execution evidence in Prefetch.
  * **[Linux Environments, Web Auditing & Network Traffic](./KB/DFIR-reports/Entornos_Linux_Auditor%C3%ADa_Web_%26_Tr%C3%A1fico_de_Red_(PCAP)/):** PCAP traffic captures, web access analysis, and forensic artifacts on Linux systems.
  * **[Windows Endpoint Security & Defense Evasion](./KB/DFIR-reports/Seguridad_de_Endpoints_Windows_%26_Evasi%C3%B3n_de_Defensas_(EVTX_%26_Sysmon)/):** EVTX/Sysmon event correlation, evasion technique detection, and Indicators of Compromise (IOCs).

* 🚨 **[SOC, Threat Hunting & Network Analysis (`./KB/SOC-reports/`)](./KB/SOC-reports/)**

  * **[Email Security & Phishing Analysis](./KB/SOC-reports/Email_Security_%26_Phishing_Analysis/):** Email header analysis, SMTP header traceability, attachment extraction, and phishing triage.
  * **[Network Traffic & C2 Analysis](./KB/SOC-reports/Network_Traffic_%26_C2_Analysis/):** Anomalous network traffic detection, C2 beacon identification, and data exfiltration.
  * **[Web Security & NIDS Alert Triage](./KB/SOC-reports/Web_Security_%26_NIDS_Alert_Triage/):** NIDS alert triage (Suricata/Snort), exposed web vulnerabilities, and network request inspection.
  * **[Windows Endpoint & Database Artifacts](./KB/SOC-reports/Windows_Endpoint_%26_Database_Artifacts/):** Endpoint persistence detection, database analysis, and anomalous process behavior.

* 📊 **[Detection, SIEM & Log Analysis with Splunk (`./KB/SPLUNK-reports/Dataset_Botv2/`)](./KB/SPLUNK-reports/Dataset_Botv2/)**

  * Threat Hunting through advanced SPL queries, correlation rule development, and analysis of large security event datasets.

## 🎓 Academic Projects & Artificial Intelligence (`Academic_projects/`)

Access to academic projects, source code, test scripts, and developed technical documentation (`Academic_projects/`):

* 🤖 **[Artificial Intelligence & Intelligent Systems](Academic_projects/Artificial%20Intelligence%20%26%20Intelligent%20Systems/)**

  * **[Documentation & Analysis (`Ejercicio_Embalses_IA_ÓOR.pdf`)](Academic_projects/Artificial%20Intelligence%20%26%20Intelligent%20Systems/Ejercicio_Embalses_IA_%C3%93OR.pdf):** Technical report on the study and implementation of Artificial Intelligence models applied to reservoir prediction and analysis.
  * **[Code Notebook (`Ejercicio.ipynb`)](Academic_projects/Artificial%20Intelligence%20%26%20Intelligent%20Systems/Ejercicio.ipynb):** Interactive Jupyter Notebook featuring algorithm execution, data preprocessing, and performance graphs.

* 🗄️ **[Dataset Design & Development (ST)](Academic_projects/Dataset%20Design%20%26%20Development%20%28ST%29/)**

  * **[Design Documentation (`Trabajo_DataBase_Óscar_Ortega_Rueda_1.pdf`)](Academic_projects/Dataset%20Design%20%26%20Development%20%28ST%29/Trabajo_DataBase_%C3%93scar_Ortega_Rueda_1.pdf):** Comprehensive project covering conceptual, logical, and physical modeling for database management.
  * **[Schematics & Diagrams](Academic_projects/Dataset%20Design%20%26%20Development%20%28ST%29/):** Physical Diagram (`Aceites_Tardudo_Diagrama_Físico.drawio`), Conceptual Diagram (`Aceites_Tardudo_Diagrama_Conceptual.drawio`), and Relational Diagram (`Aceites_Tardudo_Diagrama_Relacional.drawio`).
  * **[Implemented SQL Scripts](Academic_projects/Dataset%20Design%20%26%20Development%20%28ST%29/):** DDL/DML files and queries grouped in subfolders (`aceites_tarudo.sql/` and `querry_aceites_tarudo.sql/`).

* 📋 **[Planning a Computing Project](Academic_projects/Planning%20a%20Computing%20Project/)**

  * **[Project Proposal (`E-volution Óscar Ortega Rueda.pdf`)](Academic_projects/Planning%20a%20Computing%20Project/E-volution%20%C3%93scar%20Ortega%20Rueda.pdf):** Strategic planning, resource management, and methodology for software development (*E-volution* Project).

* 💻 **[Programming & Coding (Python & Development)](Academic_projects/Programming%20%26%20Coding/)**

  * **[Technical Report (`Oscar Ortega Trabajo.pdf`)](Academic_projects/Programming%20%26%20Coding/PDF%20Completo/Oscar%20Ortega%20Trabajo.pdf):** Complete software development project documentation and logical architecture.
  * **[Executive Presentation (`PPT Trabajo Oscar Ortega.pptx`)](Academic_projects/Programming%20%26%20Coding/PPT%20Oscar%20Ortega%20Rueda/PPT%20Trabajo%20Oscar%20Ortega.pptx):** Slide deck for the programming project defense.
  * **[Python Code Files](Academic_projects/Programming%20%26%20Coding/Python%20archivos/):** Python implementations grouped by activities (`AB2/` with `main.py`, `numeros.py`, and `AB3/`).

---

## 📜 Professional Certifications (`Certifications/`)

Cybersecurity and industry accreditations and certifications:

* 🛡️ **[INE - eJPTv2 (eLearnSecurity Junior Penetration Tester v2)](Certifications/INE_eJPTv2.pdf)**

  * Practical certification in ethical hacking, offensive network auditing, vulnerability assessment, web application exploitation, and post-exploitation.
