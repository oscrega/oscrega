## 📄 Informes Destacados (TOP 8 Auditorias en PDF)

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

  * **[Active Directory & Enterprise Identity](./KB/PENTEST-reports/Active-Directory-and-Enterprise-Identity/):** Enumeración LDAP, explotación de Kerberos, movimiento lateral, persistencia y auditoría de infraestructuras Active Directory.
  * **[Binary Exploitation & Host Hardening](./KB/PENTEST-reports/Binary-Exploitation-and-Host-Hardening/):** Explotación de binarios, análisis de buffer overflows, elevación de privilegios y hardening de sistemas.
  * **[Emerging Tech, AI & CI/CD Security](./KB/PENTEST-reports/Emerging-Tech-AI-and-CICD-Security/):** Auditorías de pipelines CI/CD, seguridad en modelos/aplicaciones con IA y evaluación de tecnologías emergentes.
  * **[Perimeter Network & Remote Access](./KB/PENTEST-reports/Perimeter-Network-and-Remote-Access/):** Pentesting perimetral, servicios de acceso remoto (VPN, SSH, RDP) y auditorías de infraestructura expuesta.
  * **[Web Application Penetration Testing](./KB/PENTEST-reports/Web-Application-Penetration-Testing/):** Inyecciones NoSQL/SQL, evasión de controles, escalada de privilegios web y auditorías de aplicaciones.

* 🔍 **[DFIR & Forense de Host (`./KB/DFIR-reports/`)](./KB/DFIR-reports/)**

  * **[Active Directory & Controlador de Dominio](./KB/DFIR-reports/Active_Directory_&_Controlador_de_Dominio_(Kerberos_&_NTDS)/):** Artefactos de autenticación, extracción/análisis de bases de datos NTDS.dit y dumps de Kerberos.
  * **[Análisis Forense de Memoria RAM](./KB/DFIR-reports/Análisis_Forense_de_Memoria_RAM_(Volatility)/):** Extracción de artefactos en volúmenes de RAM con Volatility, identificación de malware inyectado e Imphash.
  * **[Análisis Forense de Sistema de Archivos & Triage](./KB/DFIR-reports/Análisis_Forense_de_Sistema_de_Archivos_&_Triaje_de_Disco_(MFT_&_USN_&_Prefetch)/):** Triage de disco, análisis de registros MFT, USN Journal y evidencias de ejecución en Prefetch.
  * **[Entornos Linux, Auditoría Web & Tráfico de Red](./KB/DFIR-reports/Entornos_Linux_Auditoría_Web_&_Tráfico_de_Red_(PCAP)/):** Capturas de tráfico PCAP, análisis de accesos web y artefactos forenses en sistemas Linux.
  * **[Seguridad de Endpoints Windows & Evasión de Defensas](./KB/DFIR-reports/Seguridad_de_Endpoints_Windows_&_Evasión_de_Defensas_(EVTX_&_Sysmon)/):** Correlación de eventos EVTX/Sysmon, detección de técnicas de evasión e indicadores de compromiso (IOCs).

* 🚨 **[SOC, Threat Hunting & Análisis de Red (`./KB/SOC-reports/`)](./KB/SOC-reports/)**

  * **[Email Security & Phishing Analysis](./KB/SOC-reports/Email_Security_&_Phishing_Analysis/):** Análisis de cabeceras de correo, trazabilidad de cabeceras SMTP, extracción de adjuntos y triage de phishing.
  * **[Network Traffic & C2 Analysis](./KB/SOC-reports/Network_Traffic_&_C2_Analysis/):** Detección de tráfico de red anómalo, identificación de beacons C2 y exfiltración de datos.
  * **[Web Security & NIDS Alert Triage](./KB/SOC-reports/Web_Security_&_NIDS_Alert_Triage/):** Triage de alertas NIDS (Suricata/Snort), vulnerabilidades web expuestas e inspección de peticiones de red.
  * **[Windows Endpoint & Database Artifacts](./KB/SOC-reports/Windows_Endpoint_&_Database_Artifacts/):** Detección de persistencia en endpoints, análisis de bases de datos y comportamiento anómalo de procesos.

* 📊 **[Detección, SIEM & Análisis de Logs con Splunk (`./KB/SPLUNK-reports/Dataset_Botv2/`)](./KB/SPLUNK-reports/Dataset_Botv2/)**

  * Threat Hunting mediante consultas SPL avanzadas, desarrollo de reglas de correlación y análisis de grandes datasets de eventos de seguridad.

## 🎓 Proyectos Académicos & Inteligencia Artificial (`Academic_projects/`)

Acceso a proyectos académicos, código fuente, scripts de prueba y documentación técnica desarrollada (`Academic_projects/`):

* 🤖 **[Artificial Intelligence & Intelligent Systems](Academic_projects/Artificial%20Intelligence%20%26%20Intelligent%20Systems/)**

  * **[Documentación & Análisis (`Ejercicio_Embalses_IA_ÓOR.pdf`)](Academic_projects/Artificial%20Intelligence%20%26%20Intelligent%20Systems/Ejercicio_Embalses_IA_%C3%93OR.pdf):** Memoria técnica del estudio e implementación de modelos de Inteligencia Artificial aplicados a la predicción y análisis de embalses.
  * **[Cuaderno de Código (`Ejercicio.ipynb`)](Academic_projects/Artificial%20Intelligence%20%26%20Intelligent%20Systems/Ejercicio.ipynb):** Jupyter Notebook interactivo con la ejecución de algoritmos, preprocesamiento de datos y gráficos de rendimiento.

* 🗄️ **[Dataset Design & Development (ST)](Academic_projects/Dataset%20Design%20%26%20Development%20%28ST%29/)**

  * **[Documentación de Diseño (`Trabajo_DataBase_Óscar_Ortega_Rueda_1.pdf`)](Academic_projects/Dataset%20Design%20%26%20Development%20%28ST%29/Trabajo_DataBase_%C3%93scar_Ortega_Rueda_1.pdf):** Proyecto completo sobre el modelado conceptual, lógico y físico para la gestión de bases de datos.
  * **[Esquemas & Diagramas](Academic_projects/Dataset%20Design%20%26%20Development%20%28ST%29/):** Diagrama Físico (`Aceites_Tardudo_Diagrama_Físico.drawio`), Diagrama Conceptual (`Aceites_Tardudo_Diagrama_Conceptual.drawio`) y Diagrama Relacional (`Aceites_Tardudo_Diagrama_Relacional.drawio`).
  * **[Scripts SQL Implementados](Academic_projects/Dataset%20Design%20%26%20Development%20%28ST%29/):** Ficheros DDL/DML y consultas agrupadas en subcarpetas (`aceites_tarudo.sql/` y `querry_aceites_tarudo.sql/`).

* 📋 **[Planning a Computing Project](Academic_projects/Planning%20a%20Computing%20Project/)**

  * **[Propuesta de Proyecto (`E-volution Óscar Ortega Rueda.pdf`)](Academic_projects/Planning%20a%20Computing%20Project/E-volution%20%C3%93scar%20Ortega%20Rueda.pdf):** Planificación estratégica, gestión de recursos y metodología para el desarrollo de software (Proyecto *E-volution*).

* 💻 **[Programming & Coding (Python & Desarrollo)](Academic_projects/Programming%20%26%20Coding/)**

  * **[Memoria Técnica (`Oscar Ortega Trabajo.pdf`)](Academic_projects/Programming%20%26%20Coding/PDF%20Completo/Oscar%20Ortega%20Trabajo.pdf):** Documentación completa del proyecto de desarrollo de software y arquitectura lógica.
  * **[Presentación Ejecutiva (`PPT Trabajo Oscar Ortega.pptx`)](Academic_projects/Programming%20%26%20Coding/PPT%20Oscar%20Ortega%20Rueda/PPT%20Trabajo%20Oscar%20Ortega.pptx):** Diapositivas de defensa del proyecto de programación.
  * **[Archivos de Código Python](Academic_projects/Programming%20%26%20Coding/Python%20archivos/):** Implementaciones en Python agrupadas por actividades (`AB2/` con `main.py`, `numeros.py` y `AB3/`).

---

## 📜 Certificaciones Profesionales (`Certifications/`)

Acreditaciones y certificaciones de ciberseguridad e industria:

* 🛡️ **[INE - eJPTv2 (eLearnSecurity Junior Penetration Tester v2)](Certifications/INE_eJPTv2.pdf)**

  * Certificación práctica de hacking ético y auditoría ofensiva de redes, evaluación de vulnerabilidades, explotación de aplicaciones web y post-explotación.
