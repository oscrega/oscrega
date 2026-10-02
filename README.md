## 📄 Informes Destacados (TOP 8 Entregables VIP en PDF)

> *Nota: Auditorías técnicas completas maquetadas en formato corporativo PDF. Incluyen Resumen Ejecutivo (dirigido a C-Level / Dirección), Matriz de Hallazgos CVSS v3.1, Pruebas de Concepto (PoC) detalladas, alineación con MITRE ATT&CK y plan de remediación.*

### A. Active Directory & Enterprise Infrastructure
| Proyecto / Target | Vectores & TTPs Clave (MITRE ATT&CK) | Reporte Completo |
| :--- | :--- | :--- |
| **HTB EscapeTwo** | Explotación AD CS (ESC4 a ESC1), WriteOwner en DACL, MSSQL `xp_cmdshell` | 📄 [Ver PDF](./Reports-pdf/HTB_EscapeTwo_Windows_ActiveDirectory_Pentest_Report.pdf) |
| **HTB Fluffy** | Coerción NTLMv2 (CVE-2025-24071), Shadow Credentials (`msDS-KeyCredentialLink` / ESC16), PKINIT | 📄 [Ver PDF](./reports-pdf/HTB_Fluffy_Pentest_Report.pdf) |
| **HTB Voleur** | Targeted Kerberoasting, restauración de objetos con `bloodyAD`, DPAPI y pivotaje WSL | 📄 [Ver PDF](./reports-pdf/HTB_Voleur_Pentest_Report.pdf) |
| **HTB Administrator** | Permisos GenericAll en RPC, inyección de SPN malicioso (`GenericWrite`) y DCSync | 📄 [Ver PDF](./reports-pdf/HTB_Administrator_Pentest_Report.pdf) |

### B. Linux, Web Applications & Modern Stacks
| Proyecto / Target | Vectores & TTPs Clave (MITRE ATT&CK) | Reporte Completo |
| :--- | :--- | :--- |
| **HTB DevHub** | RCE en protocolo MCP (CVE-2026-23744), Tunneling con Chisel, Endpoints Flask | 📄 [Ver PDF](./reports-pdf/HTB_DevHub_Pentest_Report.pdf) |
| **HTB Conversor** | Inyección XSLT a RCE, Escalada vía `needrestart` (CVE-2024-48990 / `PYTHONPATH`) | 📄 [Ver PDF](./reports-pdf/HTB_Conversor_Pentest_Report.pdf) |
| **HTB Outbound** | RCE en Roundcube (CVE-2025-49113), descifrado 3DES de sesión, escalada en `Below` (CVE-2025-27591) | 📄 [Ver PDF](./reports-pdf/HTB_Outbound_Pentest_Report.pdf) |
| **HTB Lock** | WebShell ASPX vía Gitea, descifrado mRemoteNG, OpLock / MSI Race Condition (CVE-2023-49147) | 📄 [Ver PDF](./reports-pdf/HTB_Lock_Pentest_Report.pdf) |


## 📚 Base de Conocimiento (KB) - Auditorías y Análisis (.md)

Acceso completo a la base de conocimiento (`/kb/pentest-reports/`) en sintaxis Markdown nativa para inspección de comandos, código, artefactos forenses y queries SPL:

* 🪟 **[Active Directory & Windows Infrastructure (`/kb/pentest-reports/active-directory/`)](./kb/pentest-reports/active-directory/)**
  * *HTB Cascade* (LDAP Custom, DES VNC) y auditorías adicionales.
* 🐧 **[Linux & Web Applications (`/kb/pentest-reports/linux-web/`)](./kb/pentest-reports/linux-web/)**
  * *HTB Mango* (Blind NoSQLi `$regex`, `jjs` SUID) y auditorías adicionales.
* 🔍 **[DFIR & Forense de Host (`/kb/pentest-reports/dfir-forensics/`)](./kb/pentest-reports/dfir-forensics/)**
  * *HTB Recollection* (Volatility 3, Imphash en RAM), *HTB Tracer* (Prefetch, USN Journal, Sysmon), *HTB RogueOne*, *HTB BFT*, *HTB CrownJewel-1*, *HTB Operation Blackout*.
* 🚨 **[SOC, Threat Hunting & Análisis de Red (`/kb/pentest-reports/soc-threat-hunting/`)](./kb/pentest-reports/soc-threat-hunting/)**
  * *HTB Meerkat* (Suricata IDS, CVE-2022-25237), *HTB Interceptor* (Malware SSLoad, DLL Side-Loading), *HTB Takedown*, *HTB Jingle Bell*, *HTB Campfire-2*.
