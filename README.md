## 📄 Informes Destacados (TOP 8 Entregables VIP en PDF)

> *Nota: Auditorías técnicas completas maquetadas en formato corporativo PDF. Incluyen Resumen Ejecutivo (dirigido a C-Level / Dirección), Matriz de Hallazgos CVSS v3.1, Pruebas de Concepto (PoC) detalladas, alineación con MITRE ATT&CK y plan de remediación.*

### A. Active Directory & Enterprise Infrastructure
| Proyecto / Target | Vectores & TTPs Clave (MITRE ATT&CK) | Reporte Completo |
| :--- | :--- | :--- |
| **HTB EscapeTwo** | Explotación AD CS (ESC4 a ESC1), WriteOwner en DACL, MSSQL `xp_cmdshell` | 📄 [Ver PDF](./Reports-pdf/HTB_EscapeTwo_Windows_ActiveDirectory_Pentest_Report.pdf) |
| **HTB Fluffy** | Coerción NTLMv2 (CVE-2025-24071), Shadow Credentials (`msDS-KeyCredentialLink` / ESC16), PKINIT | 📄 [Ver PDF](./Reports-pdf/HTB_Fluffy_Windows_ActiveDirectory_Pentest_Report.pdf) |
| **HTB Voleur** | Targeted Kerberoasting, restauración de objetos con `bloodyAD`, DPAPI y pivotaje WSL | 📄 [Ver PDF](./Reports-pdf/HTB_Voleur_Windows_ActiveDirectory_Pentest_Report.pdf) |
| **HTB Administrator** | Permisos GenericAll en RPC, inyección de SPN malicioso (`GenericWrite`) y DCSync | 📄 [Ver PDF](./Reports-pdf/HTB_Administrator_Windows_ActiveDirectory_Pentest_Report.pdf) |

### B. Linux, Web Applications & Modern Stacks
| Proyecto / Target | Vectores & TTPs Clave (MITRE ATT&CK) | Reporte Completo |
| :--- | :--- | :--- |
| **HTB DevHub** | RCE en protocolo MCP (CVE-2026-23744), Tunneling con Chisel, Endpoints Flask | 📄 [Ver PDF](./Reports-pdf/HTB_DevHub_Linux_Web_AI_Pentest_Report.pdf) |
| **HTB Conversor** | Inyección XSLT a RCE, Escalada vía `needrestart` (CVE-2024-48990 / `PYTHONPATH`) | 📄 [Ver PDF](./Reports-pdf/HTB_Conversor_Linux_Web_PrivilegeEscalation_Pentest_Report.pdf) |
| **HTB Outbound** | RCE en Roundcube (CVE-2025-49113), descifrado 3DES de sesión, escalada en `Below` (CVE-2025-27591) | 📄 [Ver PDF](./Reports-pdf/HTB_Outbound_Linux_Web_MailServer_Pentest_Report.pdf) |
| **HTB Lock** | WebShell ASPX vía Gitea, descifrado mRemoteNG, OpLock / MSI Race Condition (CVE-2023-49147) | 📄 [Ver PDF](./Reports-pdf/HTB_Lock_Windows_Web_PrivilegeEscalation_Pentest_Report.pdf) |


## 📚 Base de Conocimiento (KB) - Auditorías y Análisis (.md)

Acceso completo a la base de conocimiento (`./KB/`) en sintaxis Markdown nativa para inspección de comandos, código, artefactos forenses y queries SPL:

* ⚔️ **[Pentesting, Red Team & Offensive Security (`./KB/PENTEST-reports/`)](./KB/PENTEST-reports/)**
  * **[Active Directory & Enterprise Identity](./KB/PENTEST-reports/Active-Directory-and-Enterprise-Identity/):** *HTB Cascade* (LDAP Custom, DES VNC) y auditorías de infraestructura Active Directory.
  * **[Binary Exploitation & Host Hardening](./KB/PENTEST-reports/Binary-Exploitation-and-Host-Hardening/):** Explotación de binarios, análisis de buffer overflows, elevación de privilegios y hardening.
  * **[Emerging Tech, AI & CI/CD Security](./KB/PENTEST-reports/Emerging-Tech-AI-and-CICD-Security/):** Auditorías de pipelines CI/CD y seguridad en modelos/aplicaciones con IA.
  * **[Perimeter Network & Remote Access](./KB/PENTEST-reports/Perimeter-Network-and-Remote-Access/):** Pentesting perimetral, VPN, SSH, RDP y auditorías de servicios expuestos.
  * **[Web Application Penetration Testing](./KB/PENTEST-reports/Web-Application-Penetration-Testing/):** *HTB Mango* (Blind NoSQLi `$regex`, `jjs` SUID) y auditorías de aplicaciones web.
* 🔍 **[DFIR & Forense de Host (`./KB/DFIR-reports/`)](./KB/DFIR-reports/)**
  * **[Active Directory & Controlador de Dominio](./KB/DFIR-reports/Active_Directory_&_Controlador_de_Dominio_(Kerberos_&_NTDS)/):** Kerberos, NTDS.
  * **[Análisis Forense de Memoria RAM](./KB/DFIR-reports/Análisis_Forense_de_Memoria_RAM_(Volatility)/):** Volatility 3, Imphash en RAM (*HTB Recollection*).
  * **[Análisis Forense de Sistema de Archivos & Triage](./KB/DFIR-reports/Análisis_Forense_de_Sistema_de_Archivos_&_Triage_de_Disco_(MFT_&_USN_&_Prefetch)/):** MFT, USN Journal, Prefetch (*HTB Tracer*).
  * **[Entornos Linux, Auditoría Web & Tráfico de Red](./KB/DFIR-reports/Entornos_Linux_Auditoría_Web_&_Tráfico_de_Red_(PCAP)/):** PCAP, logs web (*HTB RogueOne*, *HTB BFT*, *HTB CrownJewel-1*, *HTB Operation Blackout*).
  * **[Seguridad de Endpoints Windows & Evasión de Defensas](./KB/DFIR-reports/Seguridad_de_Endpoints_Windows_&_Evasión_de_Defensas_(EVTX_&_Sysmon)/):** EVTX, Sysmon.
* 🚨 **[SOC, Threat Hunting & Análisis de Red (`./KB/SOC-reports/`)](./KB/SOC-reports/)**
  * **[Email Security & Phishing Analysis](./KB/SOC-reports/Email_Security_&_Phishing_Analysis/):** Cabeceras, artefactos de correo y adjuntos maliciosos.
  * **[Network Traffic & C2 Analysis](./KB/SOC-reports/Network_Traffic_&_C2_Analysis/):** Tráfico de red, beacons y comunicación C2 (*HTB Interceptor*).
  * **[Web Security & NIDS Alert Triage](./KB/SOC-reports/Web_Security_&_NIDS_Alert_Triage/):** Suricata IDS, alertas NIDS, vulnerabilidades web (*HTB Meerkat* - CVE-2022-25237).
  * **[Windows Endpoint & Database Artifacts](./KB/SOC-reports/Windows_Endpoint_&_Database_Artifacts/):** Eventos de endpoint, bases de datos y persistencia (*HTB Takedown*, *HTB Jingle Bell*, *HTB Campfire-2*).
* 📊 **[Detección, SIEM & Análisis de Logs con Splunk (`./KB/SPLUNK-reports/Dataset_Botv2/`)](./KB/SPLUNK-reports/Dataset_Botv2/)**
  * Threat Hunting con consultas SPL, reglas de correlación y análisis de datasets BOTv2 / EVTX.

