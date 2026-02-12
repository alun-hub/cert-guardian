# Mattermost Notification Examples

Exempel på hur olika typer av notifieringar ser ut i Mattermost.

## 1. Standard Expiry Warning (Trusted Certificate)

```
ℹ️ **INFO: Certificate Expiring Soon**

┌─────────────────────────────────┐
│ Endpoint: api.example.com:443   │
│ Days Until Expiry: 60 days      │
├─────────────────────────────────┤
│ Subject: CN=api.example.com     │
│ Issuer: CN=Let's Encrypt Auth   │
│ Expires: 2025-04-03 14:30 UTC   │
├─────────────────────────────────┤
│ Owner: DevOps Team              │
│ Criticality: HIGH               │
│ Trust Status: ✅ Trusted CA     │
│ Chain Length: 3                 │
│ Fingerprint: `a1b2c3d4e5f6...`  │
└─────────────────────────────────┘
```
**Color:** Green (good)

---

## 2. Critical Expiry Warning (Trusted Certificate)

```
⚠️ **CRITICAL: Certificate Expiring Soon**

┌─────────────────────────────────┐
│ Endpoint: www.company.com:443   │
│ Days Until Expiry: 5 days       │
├─────────────────────────────────┤
│ Subject: CN=www.company.com     │
│ Issuer: CN=DigiCert TLS RSA     │
│ Expires: 2025-02-07 14:30 UTC   │
├─────────────────────────────────┤
│ Owner: IT Security              │
│ Criticality: CRITICAL           │
│ Trust Status: ✅ Trusted CA     │
│ Chain Length: 2                 │
│ Fingerprint: `f6e5d4c3b2a1...`  │
└─────────────────────────────────┘
```
**Color:** Red (danger)

---

## 3. Self-Signed Certificate Warning

```
⚠️ **WARNING: Certificate Issue Detected**

┌──────────────────────────────────────┐
│ Security Issues:                     │
│ 🔴 SELF-SIGNED CERTIFICATE          │
├──────────────────────────────────────┤
│ Endpoint: dev-api.internal:443       │
│ Days Until Expiry: 30 days          │
├──────────────────────────────────────┤
│ Validation Error:                    │
│ `Self-signed certificate`            │
├──────────────────────────────────────┤
│ Subject: CN=dev-api.internal         │
│ Issuer: CN=dev-api.internal          │
│ Expires: 2025-03-04 14:30 UTC       │
├──────────────────────────────────────┤
│ Owner: Development Team              │
│ Criticality: LOW                     │
│ Trust Status: ⛔ Self-Signed        │
│ Chain Length: 1                      │
│ Fingerprint: `123abc456def...`       │
└──────────────────────────────────────┘
```
**Color:** Red (danger)

---

## 4. Untrusted CA Warning

```
⚠️ **CRITICAL: Certificate Issue Detected**

┌─────────────────────────────────────────────┐
│ Security Issues:                            │
│ ⚠️ UNTRUSTED CA                            │
├─────────────────────────────────────────────┤
│ Endpoint: legacy.company.com:8443           │
│ Days Until Expiry: 7 days                  │
├─────────────────────────────────────────────┤
│ Validation Error:                           │
│ `certificate verify failed: unable to get`  │
│ `local issuer certificate`                  │
├─────────────────────────────────────────────┤
│ Subject: CN=legacy.company.com              │
│ Issuer: CN=Company Internal Root CA        │
│ Expires: 2025-02-09 14:30 UTC              │
├─────────────────────────────────────────────┤
│ Owner: Legacy Systems Team                  │
│ Criticality: HIGH                           │
│ Trust Status: ❌ Untrusted                 │
│ Chain Length: 2                             │
│ Fingerprint: `789ghi012jkl...`              │
└─────────────────────────────────────────────┘
```
**Color:** Red (danger)

---

## 5. Security Summary Alert

```
🔐 **Security Alert: Certificate Trust Issues Detected**

🔴 **3 SELF-SIGNED certificates detected**
⚠️ **2 certificates from UNTRUSTED CAs**

┌─────────────────────────────────────────┐
│ Affected Endpoints                      │
├─────────────────────────────────────────┤
│ dev-api.internal:443 (LOW)              │
│   Status: ⛔ SELF-SIGNED                │
│   Subject: CN=dev-api.internal          │
│   Issuer: CN=dev-api.internal           │
│   Error: `Self-signed certificate`      │
├─────────────────────────────────────────┤
│ test.staging.com:443 (MEDIUM)           │
│   Status: ⛔ SELF-SIGNED                │
│   Subject: CN=test.staging.com          │
│   Issuer: CN=test.staging.com           │
│   Error: `Self-signed certificate`      │
├─────────────────────────────────────────┤
│ legacy.company.com:8443 (HIGH)          │
│   Status: ❌ UNTRUSTED CA               │
│   Subject: CN=legacy.company.com        │
│   Issuer: CN=Company Internal Root CA   │
│   Error: `unable to get local issuer`   │
├─────────────────────────────────────────┤
│ internal-app.corp:9443 (CRITICAL)       │
│   Status: ❌ UNTRUSTED CA               │
│   Subject: CN=internal-app.corp         │
│   Issuer: CN=Corp Private CA 2020       │
│   Error: `certificate has expired`      │
├─────────────────────────────────────────┤
│ docker-registry.local:5000 (MEDIUM)     │
│   Status: ⛔ SELF-SIGNED                │
│   Subject: CN=docker-registry.local     │
│   Issuer: CN=docker-registry.local      │
│   Error: `Self-signed certificate`      │
└─────────────────────────────────────────┘

🔒 Certificate Guardian - Security Check
```
**Color:** Red (danger)

---

## 6. Daily Summary (Mixed Trust Status)

```
📊 **Daily Certificate Expiry Summary**

🚨 **1 certificate expiring within 24 hours!**
⚠️ **2 certificates expiring within 7 days**
⚠️ 5 certificates expiring within 30 days
ℹ️ 12 certificates expiring within 90 days

┌─────────────────────────────────────────┐
│ Top 10 Most Urgent Certificates         │
├─────────────────────────────────────────┤
│ emergency.example.com:443               │
│ Expires in **0 days** - CN=emergency... │
│ 🔴 SELF-SIGNED                          │
├─────────────────────────────────────────┤
│ api.production.com:443                  │
│ Expires in **5 days** - CN=api.prod...  │
│ ✅ Trusted                              │
├─────────────────────────────────────────┤
│ www.company.com:443                     │
│ Expires in **7 days** - CN=www.comp...  │
│ ✅ Trusted                              │
├─────────────────────────────────────────┤
│ internal.corp:8443                      │
│ Expires in **14 days** - CN=internal... │
│ ❌ Untrusted CA                         │
├─────────────────────────────────────────┤
│ mail.company.com:443                    │
│ Expires in **21 days** - CN=mail.com... │
│ ✅ Trusted                              │
└─────────────────────────────────────────┘

Certificate Guardian - Daily Summary
```
**Color:** Yellow (warning) om emergency eller critical finns, annars Green

---

## 7. Emergency Alert (Expiring Today + Self-Signed)

```
🚨 **EMERGENCY: Certificate Issue Detected**

┌──────────────────────────────────────────┐
│ Security Issues:                         │
│ 🔴 SELF-SIGNED CERTIFICATE              │
├──────────────────────────────────────────┤
│ Endpoint: critical-api.prod:443          │
│ Days Until Expiry: 0 days               │
├──────────────────────────────────────────┤
│ ⚠️ CERTIFICATE EXPIRES TODAY! ⚠️        │
├──────────────────────────────────────────┤
│ Validation Error:                        │
│ `Self-signed certificate`                │
├──────────────────────────────────────────┤
│ Subject: CN=critical-api.prod            │
│ Issuer: CN=critical-api.prod             │
│ Expires: 2025-02-02 23:59 UTC           │
├──────────────────────────────────────────┤
│ Owner: Platform Team                     │
│ Criticality: CRITICAL                    │
│ Trust Status: ⛔ Self-Signed            │
│ Chain Length: 1                          │
│ Fingerprint: `abc123def456...`           │
└──────────────────────────────────────────┘

🚨 IMMEDIATE ACTION REQUIRED! 🚨
```
**Color:** Red (danger)

---

## Notification Frequency

### Expiry Notifications

Varje certifikat får **max en notifiering per threshold-nivå** under hela sin livscykel (totalt max 7 notifieringar). Systemet väljer alltid den lägsta matchande nivån:

- **90 days:** Info (en gång, när cert passerar 90-dagarsgränsen)
- **60 days:** Warning (en gång)
- **30 days:** Warning (en gång)
- **14 days:** Critical (en gång)
- **7 days:** Critical (en gång)
- **3 days:** Critical (en gång)
- **1 day:** Emergency (en gång)

Ett cert som går ut om 5 dagar genererar **en** notifiering (vid 7-dagars threshold), inte fem.

### Per-Endpoint Webhooks

Endpoints kan ha individuella webhook-URL:er. Notifieringar skickas till endpoint-specifik webhook om konfigurerad, annars till global Mattermost-webhook.

### Security Notifications
- **Self-signed/Untrusted:** När först detekterad (en gång per cert)
- **Security Summary:** Manuellt via `--security` kommando, rekommenderat dagligen

### Daily Summary
- **Frekvens:** Manuellt via `--summary` kommando eller via cron
- **Innehåll:** Alla certs som går ut inom 90 dagar, grupperade efter urgency

---

## Color Coding Guide

- **Green (good):** 30+ dagar kvar, Trusted CA
- **Yellow (warning):** 7-30 dagar kvar, Trusted CA
- **Red (danger):** 
  - <7 dagar kvar
  - Self-signed certificate
  - Untrusted CA
  - Validation error

---

## Emojis Reference

- ℹ️ - Information
- ⚠️ - Warning
- 🚨 - Emergency
- 🔐 - Security
- 🔴 - Critical Security Issue (Self-signed)
- ❌ - Security Warning (Untrusted)
- ✅ - Verified/Trusted
- ⛔ - Blocked/Rejected

---

## Testing Notifications

För att testa notifications:

```bash
# Test connection
python src/main.py --once

# Test security alerts (om du har self-signed certs)
python src/main.py --security

# Test daily summary
python src/main.py --summary
```
