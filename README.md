# Certificate Guardian 🔒

Ett säkerhetsverktyg för att övervaka TLS-certifikat och skicka varningar till Mattermost innan de går ut.

## Funktioner

- 📡 **Automatisk scanning** av TLS endpoints
- 🌐 **Network Sweeps** - Skanna IP-ranges för att upptäcka TLS-tjänster (CIDR/range notation)
- 💾 **SQLite databas** för att spåra certifikat över tid
- 📨 **Mattermost notifieringar** vid olika varningsnivåer:
  - 90, 60, 30, 14, 7, 3, 1 dagar innan expiry
  - Färgkodade meddelanden (grön → gul → röd)
  - Dagliga sammanfattningar
  - Per-endpoint webhooks för teamspecifika notifieringar
- 🔍 **Spårar certifikathistorik** - ser när cert senast scannades
- 🚫 **Undviker spam** - skickar inte samma varning flera gånger inom 24h
- 🐳 **Containerized** - lätt att deploya med Podman/Docker

## Snabbstart

### 1. Konfigurera Mattermost Webhook

Skapa en incoming webhook i Mattermost:
1. Gå till **System Console → Integrations → Incoming Webhooks**
2. Klicka **Add Incoming Webhook**
3. Välj kanal och kopiera webhook URL

### 2. Redigera config/config.yaml

```yaml
mattermost:
  webhook_url: "https://your-mattermost.com/hooks/YOUR_WEBHOOK_TOKEN"
  channel: "#security-alerts"

endpoints:
  - host: "example.com"
    port: 443
    owner: "IT Team"
    criticality: "high"
  
  - host: "internal-api.company.com"
    port: 8443
    owner: "DevOps"
    criticality: "critical"
```

### 3. Kör med Podman/Docker

```bash
# Bygg imagen
podman build -t cert-guardian .

# Kör en gång för att testa
podman run --rm -v ./config:/app/config:ro -v ./data:/app/data cert-guardian \
  python /app/src/main.py --config /app/config/config.yaml --once

# Kör kontinuerligt med compose
podman-compose up -d
```

### 4. Eller kör nativt med Python

```bash
# Installera dependencies
pip install -r requirements.txt

# Setup endpoints från config
python src/main.py --setup

# Kör en scan
python src/main.py --once

# Kör kontinuerlig monitoring
python src/main.py
```

## Användning

### Kommandon

```bash
# Kör en scan och avsluta
python src/main.py --once

# Kör kontinuerlig monitoring (default)
python src/main.py

# Skicka daglig sammanfattning
python src/main.py --summary

# Setup endpoints från config
python src/main.py --setup
```

### Konfigurations-exempel

```yaml
database:
  path: "data/certificates.db"

mattermost:
  webhook_url: "https://mattermost.example.com/hooks/xxxxx"
  username: "Certificate Guardian"
  icon_emoji: ":lock:"

endpoints:
  - host: "google.com"
    port: 443
    owner: "External Test"
    criticality: "low"

notifications:
  warning_days: [90, 60, 30, 14, 7, 3, 1]
  critical_days: 7
  emergency_days: 1

scanner:
  interval_seconds: 3600  # Scanna varje timme
  timeout_seconds: 10
  max_concurrent: 10
```

## Notifieringsnivåer

| Dagar kvar | Nivå | Färg | Emoji |
|-----------|------|------|-------|
| 90+ | INFO | Grön | ℹ️ |
| 30-89 | WARNING | Gul | ⚠️ |
| 7-29 | CRITICAL | Röd | ⚠️ |
| 0-6 | EMERGENCY | Röd | 🚨 |

## Databas-schema

### Tabeller

- **certificates** - Lagrar certifikat metadata
- **endpoints** - Konfigurerade endpoints att scanna
- **certificate_scans** - Historik över scanningar
- **notifications** - Spårar skickade notifieringar

## Säkerhetsöverväganden

✅ **Bra:**
- Lagrar ALDRIG private keys
- Read-only access till endpoints
- Använder TLS för all kommunikation
- Loggar alla aktiviteter
- Ingen persistent connection till scannede system

⚠️ **Tänk på:**
- Webhook URL innehåller secrets - skydda config-filen
- Database innehåller cert fingerprints - kan vara känsligt
- Scanning kan trigga IDS/IPS - whitelist scanner IP

## Webbgränssnitt

Certificate Guardian inkluderar ett komplett webbgränssnitt. Se [WEBAPP_README.md](WEBAPP_README.md) för detaljer.

```bash
# Starta med webbgränssnitt
podman-compose -f docker-compose-webapp.yaml up -d

# Frontend: http://localhost:3000
# API Docs: http://localhost:8000/docs
```

## Framtida förbättringar

- [x] ~~REST API för externa integrations~~
- [x] ~~Web dashboard för överblick~~
- [x] ~~Network Sweeps för IP-range scanning~~
- [x] ~~Per-endpoint webhooks~~
- [ ] Support för client certificate authentication
- [ ] Filesystem scanning för .pem/.crt filer
- [ ] LDAP/AD integration för user certificates
- [ ] Automatisk renewal för Let's Encrypt certs
- [ ] Support för flera notification channels (email, Slack, etc.)
- [ ] Kubernetes CRD för native k8s integration

## Exempel Mattermost-meddelande

```
⚠️ **CRITICAL: Certificate Expiring Soon**

Endpoint: api.example.com:443
Days Until Expiry: 7 days

Subject: CN=api.example.com
Issuer: CN=Let's Encrypt Authority X3
Expires: 2025-02-09 14:30 UTC
Owner: DevOps Team
Criticality: HIGH
Fingerprint: a1b2c3d4e5f6...

Certificate Guardian
```

## Felsökning

### Ingen Mattermost-notifiering

```bash
# Testa webhook manuellt
curl -X POST -H 'Content-Type: application/json' \
  -d '{"text":"Test"}' \
  https://your-mattermost.com/hooks/xxxxx
```

### Connection timeout

Öka timeout i config:
```yaml
scanner:
  timeout_seconds: 30
```

### För många notifieringar

Justera varningströsklar:
```yaml
notifications:
  warning_days: [30, 7, 1]  # Färre notifieringar
```

## Licens

MIT License - använd fritt i din organisation.

## Support

För frågor eller buggrapporter, kontakta IT Security team.
