# Certificate Trust Validation Feature

Certificate Guardian nu validerar certifikat mot systemets CA store och detekterar self-signed certifikat!

## 🔐 Vad detekteras?

### 1. Self-Signed Certifikat
Certifikat där Subject == Issuer, dvs certifikatet är signerat av sig själv.

**Varning:** ⛔ SELF-SIGNED CERTIFICATE

**Risker:**
- Kan inte verifieras mot trusted CA
- Ingen chain of trust
- Kan vara tecken på man-in-the-middle attack
- Acceptabelt för development/testing men ALDRIG i production

### 2. Untrusted CA
Certifikat signerade av en CA som inte finns i systemets trust store.

**Varning:** ❌ UNTRUSTED CA

**Risker:**
- CA är inte godkänd av systemet
- Kan vara privat/internal CA
- Kan vara komprometterad eller fake CA
- Browsern kommer visa varningar

### 3. Validation Errors
Specifika fel vid certifikat-validering:
- Certificate has expired
- Hostname mismatch
- Certificate chain incomplete
- Certificate revoked
- Weak signature algorithm

## 📊 Databas Schema

Nya kolumner i `certificates` tabellen:

```sql
is_self_signed INTEGER DEFAULT 0      -- 1 om certifikatet är self-signed
is_trusted_ca INTEGER DEFAULT 0       -- 1 om CA är trusted
validation_error TEXT                 -- Beskrivning av valideringsfel
chain_length INTEGER DEFAULT 0        -- Längd på cert chain
```

## 🚨 Notifieringar

### Expiry Alert med Trust Status

Alla expiry alerts visar nu även trust status:

```
⚠️ **CRITICAL: Certificate Issue Detected**

┌─────────────────────────────────────────┐
│ Security Issues:                        │
│ 🔴 SELF-SIGNED CERTIFICATE             │
├─────────────────────────────────────────┤
│ Endpoint: internal-api.company.com:443  │
│ Days Until Expiry: 7 days              │
│                                         │
│ Subject: CN=internal-api.company.com    │
│ Issuer: CN=internal-api.company.com     │
│ Expires: 2025-02-09 14:30 UTC          │
│                                         │
│ Trust Status: ⛔ Self-Signed           │
│ Validation Error: `Self-signed cert`   │
│ Chain Length: 1                         │
└─────────────────────────────────────────┘
```

### Security Summary Alert

Ny kommando för att få sammanfattning av alla untrusted certs:

```bash
python src/main.py --security
```

Skickar alert som:

```
🔐 **Security Alert: Certificate Trust Issues Detected**

🔴 **3 SELF-SIGNED certificates detected**
⚠️ **2 certificates from UNTRUSTED CAs**

Affected Endpoints:

api.internal.com:443 (CRITICAL)
  Status: ⛔ SELF-SIGNED
  Subject: CN=api.internal.com
  Issuer: CN=api.internal.com
  Error: `Self-signed certificate`

legacy-app.company.com:8443 (HIGH)
  Status: ❌ UNTRUSTED CA
  Subject: CN=legacy-app.company.com
  Issuer: CN=Internal Corporate CA
  Error: `certificate verify failed: unable to get local issuer certificate`
```

## 💻 Användning

### Kör Security Check

```bash
# Kör en scan med CA validation
python src/main.py --once

# Skicka security summary
python src/main.py --security
```

### Query Database

```sql
-- Visa alla self-signed certifikat
SELECT host, port, subject, issuer 
FROM certificates c
JOIN certificate_scans cs ON c.id = cs.certificate_id
JOIN endpoints e ON cs.endpoint_id = e.id
WHERE c.is_self_signed = 1;

-- Visa alla untrusted certifikat
SELECT host, port, subject, validation_error
FROM certificates c
JOIN certificate_scans cs ON c.id = cs.certificate_id
JOIN endpoints e ON cs.endpoint_id = e.id
WHERE c.is_trusted_ca = 0;

-- Visa trust statistics
SELECT 
    COUNT(*) as total,
    SUM(is_self_signed) as self_signed,
    SUM(is_trusted_ca) as trusted,
    AVG(chain_length) as avg_chain_length
FROM certificates;
```

## 🔧 Konfiguration

### Trusted CA Store

Certificate Guardian använder `certifi` paketet som innehåller Mozilla's CA bundle:

```python
import certifi

# Visa path till CA bundle
print(certifi.where())
# Output: /path/to/certifi/cacert.pem
```

### Custom CA Store (för internal CAs)

Om du har interna CAs kan du lägga till dem i systemets trust store:

**Linux:**
```bash
# Kopiera CA cert
sudo cp internal-ca.crt /usr/local/share/ca-certificates/

# Uppdatera trust store
sudo update-ca-certificates
```

**Python (temporary):**
```python
import ssl
import certifi

# Load default context with custom CA
context = ssl.create_default_context(cafile='/path/to/custom-ca-bundle.pem')
```

## 📋 Best Practices

### 1. Self-Signed Certs i Development

**Acceptabelt:**
- Local development (localhost)
- Test miljöer
- Internal tools med begränsad access

**Använd istället:**
- Let's Encrypt för publika endpoints
- Internal PKI för företagsmiljö
- mkcert för local development

### 2. Untrusted CA Hantering

**Om du har internal CA:**
1. Lägg till CA cert i OS trust store
2. Distribuera till alla maskiner
3. Övervaka att CA cert inte går ut!

**Om det är extern untrusted CA:**
1. Undersök varför CA inte är trusted
2. Kontakta certificate provider
3. Byt till trusted CA (Let's Encrypt, DigiCert, etc.)

### 3. Monitoring Strategy

**Daglig check:**
```bash
# I cron: Kör security summary varje dag kl 08:00
0 8 * * * /usr/bin/python3 /opt/cert-guardian/src/main.py --security
```

**Immediate alerts:**
När ny endpoint läggs till eller cert byts:
- Security alert skickas direkt om cert är untrusted
- Alert skickas max en gång per vecka per cert
- Kan konfigureras i koden (se `_send_security_alert_for_cert`)

## 🎯 Use Cases

### Use Case 1: Development Team Alert

**Scenario:** Development team använder self-signed cert i staging

**Alert:**
```
🔴 SELF-SIGNED CERTIFICATE detected
Endpoint: staging-api.company.com:443
Owner: DevOps Team
Criticality: MEDIUM

Action Required: Replace with Let's Encrypt cert
```

### Use Case 2: Expired Internal CA

**Scenario:** Internal CA cert har gått ut

**Alert:**
```
❌ UNTRUSTED CA
Validation Error: certificate verify failed: certificate has expired
Issuer: CN=Company Internal Root CA

CRITICAL: Internal CA has expired!
All internal services will show security warnings.
```

### Use Case 3: Unauthorized Certificate

**Scenario:** Någon har satt upp en tjänst med self-signed cert

**Alert:**
```
⛔ SELF-SIGNED CERTIFICATE
Endpoint: unknown-service.company.com:8443
Owner: Unassigned
Criticality: HIGH

WARNING: Unauthorized service detected!
This may be a rogue application or security incident.
```

## 🔍 Troubleshooting

### Problem: All Certs Show as Untrusted

**Orsak:** CA bundle inte uppdaterad eller custom CA saknas

**Lösning:**
```bash
# Uppdatera certifi
pip install --upgrade certifi

# Verifiera CA bundle
python -c "import certifi; print(certifi.where())"
```

### Problem: Internal Certs Flaggas som Untrusted

**Orsak:** Internal CA inte i trust store

**Lösning:**
1. Exportera CA cert från din PKI
2. Lägg till i system trust store (se ovan)
3. Restarta Certificate Guardian

### Problem: För Många Security Alerts

**Orsak:** Många interna self-signed certs i development

**Lösning:**
```yaml
# config.yaml - Lägg till exclude för dev miljöer
endpoints:
  - host: "staging.internal"
    port: 443
    owner: "Dev Team"
    criticality: "low"
    # Eller helt enkelt ta bort dev endpoints från monitoring
```

## 📈 Metrics & Reporting

### Trust Statistics Query

```sql
-- Weekly trust report
SELECT 
    DATE(updated_at) as date,
    COUNT(*) as total_certs,
    SUM(CASE WHEN is_self_signed = 1 THEN 1 ELSE 0 END) as self_signed,
    SUM(CASE WHEN is_trusted_ca = 1 THEN 1 ELSE 0 END) as trusted,
    ROUND(AVG(chain_length), 2) as avg_chain_length
FROM certificates
WHERE updated_at >= date('now', '-7 days')
GROUP BY DATE(updated_at)
ORDER BY date DESC;
```

### Most Common Validation Errors

```sql
SELECT 
    validation_error,
    COUNT(*) as count,
    GROUP_CONCAT(DISTINCT host) as affected_hosts
FROM certificates c
JOIN certificate_scans cs ON c.id = cs.certificate_id
JOIN endpoints e ON cs.endpoint_id = e.id
WHERE validation_error IS NOT NULL
GROUP BY validation_error
ORDER BY count DESC;
```

## 🚀 Future Enhancements

- [ ] Support för CRL (Certificate Revocation Lists)
- [ ] OCSP (Online Certificate Status Protocol) checking
- [ ] Certificate Transparency log monitoring
- [ ] Integration med SIEM för security events
- [ ] Custom CA bundle support via config
- [ ] Whitelisting för known self-signed certs

## 📚 References

- [Mozilla CA Certificate Program](https://wiki.mozilla.org/CA)
- [certifi Python package](https://github.com/certifi/python-certifi)
- [RFC 5280 - X.509 Certificate](https://tools.ietf.org/html/rfc5280)
- [NIST Guidelines on TLS](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
