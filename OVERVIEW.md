# Certificate Guardian - Projekt Översikt

## 📦 Vad är det här?

Ett säkerhetsverktyg som automatiskt övervakar TLS-certifikat på dina endpoints och skickar varningar till Mattermost innan de går ut. Perfekt för att undvika den klassiska "shit, certifikatet gick ut och nu är allt nere!"-situationen.

## 🎯 Kärnfunktioner

✅ **Automatisk Scanning**
- Scannar TLS endpoints varje timme (konfigurerbart)
- Hämtar cert metadata (subject, issuer, expiry date, fingerprint)
- Stödjer SNI (Server Name Indication)
- **Validerar mot system CA store**
- **Detekterar self-signed certifikat**

✅ **Intelligent Notifiering**
- Skickar varningar vid 90, 60, 30, 14, 7, 3, 1 dagar före expiry
- Färgkodade meddelanden i Mattermost (grön → gul → röd)
- Undviker spam - samma varning skickas max en gång per 24h
- Daglig sammanfattning av alla expiring certs
- **Security alerts för self-signed och untrusted CA**

✅ **Persistent Storage**
- SQLite databas spårar alla certs över tid
- Historik över scanningar och notifications
- Kan se när ett cert senast sågs och vilka endpoints som använder det
- **Lagrar CA validation status**

✅ **Flexible Deployment**
- Native Python (systemd service)
- Podman/Docker containers
- Kubernetes deployment
- Alla varianter inkluderade!

## 📁 Projektstruktur

```
cert-guardian/
├── src/
│   ├── main.py          # Huvudapplikation
│   ├── scanner.py       # TLS scanner
│   ├── notifier.py      # Mattermost integration
│   └── database.py      # SQLite database layer
├── config/
│   ├── config.yaml      # Din konfiguration
│   └── config.yaml.example
├── data/
│   └── certificates.db  # SQLite databas (skapas automatiskt)
├── kubernetes/
│   └── deployment.yaml  # K8s manifests
├── Dockerfile
├── docker-compose.yaml
├── requirements.txt
├── test.py              # Test suite
├── README.md            # Användardokumentation
├── INSTALL.md           # Installation guide
└── ENHANCEMENTS.md      # Framtida features

Systemd services:
├── cert-guardian.service           # Main service
├── cert-guardian-summary.service   # Daily summary
└── cert-guardian-summary.timer     # Cron-like timer
```

## 🚀 Snabbstart

### 1. Konfigurera Mattermost
```yaml
# config/config.yaml
mattermost:
  webhook_url: "https://your-mattermost.com/hooks/YOUR_TOKEN"
```

### 2. Lägg till endpoints
```yaml
endpoints:
  - host: "api.example.com"
    port: 443
    owner: "DevOps Team"
    criticality: "high"
```

### 3. Kör
```bash
# Test
python3 src/main.py --once

# Production (välj en):
# A) Systemd
sudo systemctl start cert-guardian

# B) Podman
podman-compose up -d

# C) Kubernetes
kubectl apply -f kubernetes/deployment.yaml
```

## 📊 Exempel Mattermost-meddelande

**Standard Expiry Alert:**
```
⚠️ **CRITICAL: Certificate Expiring Soon**

┌─────────────────────────────────────┐
│ Endpoint: api.example.com:443       │
│ Days Until Expiry: 7 days           │
├─────────────────────────────────────┤
│ Subject: CN=api.example.com         │
│ Issuer: CN=Let's Encrypt Authority  │
│ Expires: 2025-02-09 14:30 UTC      │
├─────────────────────────────────────┤
│ Owner: DevOps Team                  │
│ Criticality: HIGH                   │
│ Trust Status: ✅ Trusted CA         │
│ Fingerprint: a1b2c3d4e5f6...        │
└─────────────────────────────────────┘
```

**Security Alert (Self-Signed):**
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
│ Trust Status: ⛔ Self-Signed        │
└──────────────────────────────────────┘
```

Se [NOTIFICATION_EXAMPLES.md](NOTIFICATION_EXAMPLES.md) för fler exempel!

## 🔧 Teknisk Stack

- **Python 3.11+** - Huvudspråk
- **SQLite** - Persistent storage
- **PyYAML** - Config parsing
- **Requests** - HTTP client för Mattermost
- **SSL/Socket** - TLS scanning (builtin Python)

## 🎨 Arkitektur

```
┌─────────────┐
│   Config    │
│ (YAML file) │
└──────┬──────┘
       │
       v
┌─────────────────────────────────────┐
│         Main Application            │
│  (Scheduler + Orchestrator)         │
└─────┬───────────────────────┬───────┘
      │                       │
      v                       v
┌──────────┐          ┌──────────────┐
│  Scanner │          │   Notifier   │
│  (TLS)   │          │ (Mattermost) │
└────┬─────┘          └──────────────┘
     │
     v
┌──────────────┐
│   Database   │
│  (SQLite)    │
└──────────────┘
```

## 🔐 Säkerhetsaspekter

**✅ Bra:**
- Lagrar ALDRIG private keys
- Read-only scanning (ingen write access till targets)
- Använder TLS för all kommunikation
- Kan köras som unprivileged user
- Webhook URL är den enda sensitiva datan

**⚠️ Överväg:**
- Skydda config.yaml (innehåller webhook URL)
- Begränsa network access (endast HTTPS outbound)
- Backup databas regelbundet
- Logrotation för cert-guardian.log

## 🎯 Use Cases

**1. Produktionsmiljöer**
```yaml
endpoints:
  - host: "api.company.com"
    port: 443
    criticality: "critical"
  - host: "www.company.com"
    port: 443
    criticality: "critical"
```

**2. Internal Services**
```yaml
endpoints:
  - host: "gitlab.internal"
    port: 443
    criticality: "high"
  - host: "jenkins.internal"
    port: 8443
    criticality: "medium"
```

**3. Testing/Development**
```yaml
endpoints:
  - host: "dev-api.company.com"
    port: 443
    criticality: "low"
```

## 📈 Monitoring Certificate Guardian

Själva monitoring-verktyget behöver också övervakas!

```bash
# Check att servicen körs
systemctl is-active cert-guardian

# Check senaste scan
sqlite3 data/certificates.db \
  "SELECT MAX(scanned_at) FROM certificate_scans"

# Check antal övervakade certs
sqlite3 data/certificates.db \
  "SELECT COUNT(*) FROM certificates"
```

## 🚀 Framtida Förbättringar

Se ENHANCEMENTS.md för detaljerad lista, men här är highlights:

- **Filesystem scanning** - scanna .pem/.crt filer på disk
- **LDAP/AD integration** - user certificates i Active Directory  
- **Auto-renewal** - Let's Encrypt integration
- **REST API** - exponera data för andra system
- **Web Dashboard** - visualisering och control panel
- **Multi-channel** - Email, Slack, Teams notifications
- **Chain validation** - hela cert chain, inte bara leaf

## 💡 Tips & Tricks

**Frequent scanning för kritiska certs:**
```yaml
scanner:
  interval_seconds: 1800  # 30 minuter istället för 1h
```

**Färre notifications:**
```yaml
notifications:
  warning_days: [30, 7, 1]  # Bara 3 varningar istället för 7
```

**Debug mode:**
```bash
# Kör med verbose logging
python3 src/main.py --once 2>&1 | tee debug.log
```

## 📚 Dokumentation

- **README.md** - Användardokumentation, features, användning
- **INSTALL.md** - Detaljerade installationsinstruktioner för alla platforms
- **ENHANCEMENTS.md** - Framtida features med implementation guides
- **config.yaml.example** - Exempel-konfiguration med alla options

## 🤝 Support

För frågor:
1. Kolla README.md och INSTALL.md
2. Kör test suite: `python3 test.py`
3. Kolla logs: `journalctl -u cert-guardian -f`
4. Kontakta IT Security team

## 📝 License

MIT License - använd fritt i din organisation.

---

**Skapad av:** AI/Security Team  
**Version:** 1.0.0  
**Datum:** 2025-02-02
