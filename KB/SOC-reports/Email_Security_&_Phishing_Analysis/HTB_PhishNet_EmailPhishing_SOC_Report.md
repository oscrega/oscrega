### [HTB_PHISHNET] — Informe Técnico de SOC & Threat Hunting

**Clasificación:** TLP:AMBER (Uso Interno — SOC / Incident Response)  
**Plataforma / Entorno:** Email Gateway Analysis / EML Forensics / Linux CLI (ripmime)  
**Objetivo / Infraestructura:** Departamento de Contabilidad (accounts@globalaccounting.com)

#### 1. Escenario y Contexto de la Amenaza

- **Resumen Ejecutivo:** Se investigó una campaña de spearphishing financiero dirigida contra el departamento de contabilidad de la organización. El vector consistió en un correo electrónico fraudulento (email.eml) diseñado para simular una notificación urgente de factura vencida de un proveedor conocido (**Business Finance Ltd.**). El atacante manipuló las cabeceras del mensaje transmitiéndolo desde la IP de origen 45.67.89.10 y forzando la dirección de respuesta a support@business-finance.com. El mensaje incorporó un vector dual de infección: un hipervínculo que apuntaba a una infraestructura de phishing (secure.business-finance.com) y un archivo comprimido adjunto denominado Invoice_2025_Payment.zip. El análisis de la carga útil extraída reveló un script malicioso con doble extensión (invoice_document.pdf.bat), diseñado para inducir al receptor a su ejecución inmediata.
    
- **Fuentes de Telemetría y Contenido del Dataset:** Archivo de correo en formato RFC 5322 (email.eml, 3.5 KiB). Análisis de cabeceras de tránsito SMTP (Received hops, SPF, DKIM, DMARC), cuerpo HTML multipart/mixed y contenedor ZIP codificado en Base64 extraído mediante ripmime.
    

#### 2. Mapeo Táctico MITRE ATT&CK®

|   |   |   |   |
|---|---|---|---|
|Táctica|ID Técnica / Subtécnica|Nombre de la Técnica|Evidencia / Log Específico Hallado|
|**Initial Access**|T1566.001|Phishing: Spearphishing Attachment|Envío del archivo comprimido adjunto Invoice_2025_Payment.zip conteniendo un script ejecutable.|
|**Initial Access**|T1566.002|Phishing: Spearphishing Link|Enlace a portal de facturas fraudulento: https://secure.business-finance.com/.../payment.|
|**Defense Evasion**|T1036.007|Masquerading: Double File Extension|Carga maliciosa con extensión simulada: invoice_document.pdf.bat.|

#### 3. Cadena de Investigación Forense y Análisis de Telemetría

- **Hipótesis de Búsqueda:** Reconstruir los saltos de enrutamiento SMTP para identificar la IP de origen real y evaluar la autenticidad de los mecanismos SPF/DKIM/DMARC.
    
- **Consultas y Comandos Operativos:**
    


``` bash
grep -E "(X-Originating-IP|X-Sender-IP|Received:|Return-Path:|Reply-To:|From:)" email.eml
grep -i "Authentication-Results" -A 3 email.eml
```

- **Desglose Técnico de Evidencias:**
    
    - **Dirección IP de Origen del Remitente:** **45.67.89.10** (reportada en X-Originating-IP y X-Sender-IP).
        
    - **Último Servidor Relay de Retransmisión:** **203.0.113.25** (mail.business-finance.com), el cual entregó el correo al MTA corporativo mail.target.com.
        
    - **Dirección de Correo del Remitente:** finance@business-finance.com.
        
    - **Dirección de Respuesta (Reply-To):** **support@business-finance.com**.
        
    - **Resultado de la Validación SPF:** **Pass** (protection.outlook.com: domain of business-finance.com designates 45.67.89.10 as permitted sender).
        

- **Hipótesis de Búsqueda:** Extraer los enlaces de redirección y evaluar la identidad corporativa suplantada en el cuerpo del correo.
    
- **Desglose Técnico de Evidencias:**
    
    - **Nombre de la Empresa Falsa:** **Business Finance Ltd.**.
        
    - El mensaje exigía el pago inmediato de $4,750.00 bajo la factura #INV-2025-0012 antes del 28 de febrero de 2025.
        
    - **Dominio de la URL de Phishing:** **secure.business-finance.com**.  
        URL Completa: https://secure.business-finance.com/invoice/details/view/INV2025-0987/payment.
        

- **Hipótesis de Búsqueda:** Extraer el contenedor Base64 adjunto, calcular sus firmas criptográficas y desempaquetar la carga interna.
    
- **Consultas y Comandos Operativos:**
    


``` bash
ripmime -i email.eml -d ./extracted_attachment
sha256sum extracted_attachment/Invoice_2025_Payment.zip
7z l extracted_attachment/Invoice_2025_Payment.zip
```

- **Desglose Técnico de Evidencias:**
    
    - **Nombre del Archivo Adjunto:** **Invoice_2025_Payment.zip**.
        
    - **Hash SHA-256 del Archivo ZIP:**  
        **8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a**.
        
    - **Carga Útil Oculta:** Dentro del ZIP se localizó un archivo ejecutable que utilizaba una técnica de extensión doble para simular un documento PDF legítimo:  
        **invoice_document.pdf.bat**.
        

#### 4. Ingeniería de Detección (Reglas de Alerta & Correlación)


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

- **Consideraciones de Falso Positivo:** Nulas; las extensiones .pdf.bat son un indicador unívoco de actividad maliciosa.
    
- **Tuning:** Extender la regla para buscar patrones regex como \.[a-z]{3,4}\.bat$ en el índice del ZIP.
    


``` SPL
index=email_gateway sourcetype="ms:exchange:tracking" (file_name="*.bat" OR file_name="*.vbs" OR file_name="*.pdf.bat")
| stats count values(sender) as remitentes values(recipient) as destinatarios values(file_name) as adjuntos by src_ip, subject
| table _time, src_ip, remitentes, destinatarios, subject, adjuntos, count
```

- **Consideraciones de Falso Positivo:** Ninguna en entornos corporativos estándar donde las directivas prohíben archivos ejecutables en el correo.
    
- **Tuning:** Bloquear la recepción a nivel de gateway antes de que el mensaje alcance la bandeja del usuario.
    

#### 5. Recomendaciones de Contención, Remedición y Hardening

1. **Purgado de Buzones de Correo:** Eliminar el correo identificado de todas las bandejas del departamento de contabilidad mediante búsqueda y purga administrativa en Microsoft 365 / Google Workspace.
    
2. **Bloqueo de IOCs:**
    
    - Bloquear la IP **45.67.89.10** y el servidor relay **203.0.113.25** en el Secure Email Gateway (SEG).
        
    - Incorporar a la lista de bloqueo web el dominio **secure.business-finance.com**.
        
    - Registrar el hash SHA-256 en la lista de exclusión del EDR.
        

3. **Reglas de Inspección de Archivos en Pasarela de Correo:** Configurar el Secure Email Gateway para bloquear o poner en cuarentena estricta cualquier archivo comprimido (.zip, .rar, .7z) que contenga binarios o scripts (.bat, .cmd, .ps1, .vbs, .js).
    
4. **Restricción de Ejecución por Doble Extensión:** Desplegar directivas de Windows que impidan la ocultación de extensiones de archivo y bloqueen la ejecución de scripts .bat desde el directorio de descargas o carpetas temporales de Outlook.