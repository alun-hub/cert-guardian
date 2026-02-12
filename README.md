# Certificate Guardian

Ett säkerhetsverktyg för att övervaka TLS-certifikat och skicka varningar till Mattermost innan de går ut.

## Funktioner

- **Automatisk scanning** av TLS endpoints
- **Network Sweeps** - Skanna IP-ranges för att upptäcka TLS-tjänster (CIDR/range notation)
- **SQLite databas** för att spåra certifikat över tid
- **Mattermost notifieringar** vid olika varningsnivåer:
  - 90, 60, 30, 14, 7, 3, 1 dagar innan expiry
  - Färgkodade meddelanden (grön -> gul -> röd)
  - Dagliga sammanfattningar
  - Per-endpoint webhooks för teamspecifika notifieringar
- **Spårar certifikathistorik** - ser när cert senast scannades
- **Undviker spam** - max en notifiering per threshold-nivå per certifikat (totalt 7 under hela livscykeln)
- **Containerized** - lätt att deploya med Podman/Docker
- **Detaljerad certifikatvy** - klicka för att se SAN, key size, signature, TLS version/cipher m.m.
- **Säkerhetskontroller** - hostname match, OCSP/CRL, EKU/Key Usage, weak signatures, expiring chain
- **UI-badges** - snabba varningsflaggor i certifikatlistan
- **Endpoint-trend** - mini-graf över senaste scanningsstatus per endpoint
- **Audit logs** - adminvy med filter och historik över användaråtgärder

### Nya funktioner

- **Multi-mode autentisering** - Stöd för:
  - Local auth (användarnamn/lösenord med JWT)
  - Pomerium proxy auth (SSO via headers)
  - OIDC/Keycloak (OpenID Connect)
- **Rollbaserad åtkomstkontroll (RBAC)**:
  - **Viewer** - Kan se certifikat, endpoints och dashboard
  - **Editor** - Kan skapa, redigera och ta bort endpoints, sweeps, CAs
  - **Admin** - Full åtkomst, användarhantering, audit logs
- **Audit logging** - Spårar alla ändringar:
  - Vem loggar in/ut
  - Vem skapar/ändrar/tar bort resurser
  - IP-adresser loggas
- **Custom CA Management** - Lägg till egna root-certifikat för intern PKI
- **Scanner settings i UI** - ändra scan-intervall direkt i Settings (admin)
- **Database Health panel** - storlek, antal rader och scan-volym
- **SIEM-forwarding** - Stdout, Syslog eller Beats med TLS (testknapp i UI)
- **Rescan i sweeps** - starta om befintliga nätverkssvep
- **Ägarskap för endpoints/sweeps** - bara skaparen/admin kan ändra/ta bort
- **Prometheus metrics** - `/metrics` endpoint för Grafana dashboards och alerting
- **Helm chart** - Kubernetes-deployment med konfigurerbara values, Ingress och ServiceMonitor

## Snabbstart

### 1. Konfigurera

```bash
cp config/config.yaml.example config/config.yaml
nano config/config.yaml
```

### 2. Sätt autentiseringsläge

```yaml
auth:
  mode: "local"  # eller "proxy" för Pomerium, "oidc" för Keycloak

  local:
    access_token_expire_minutes: 15
    refresh_token_expire_days: 30
```

### 3. Kör med Podman/Docker

```bash
# Bygg och starta med webbgränssnitt
podman-compose -f docker-compose-webapp.yaml up -d

# Frontend: http://localhost:3000
# API Docs: http://localhost:8000/docs
```

Default admin-konto (local mode):
- Användarnamn: `admin`
- Lösenord: `admin` (ändra omedelbart!)

### 4. HTTPS (valfritt)

Aktivera inbyggd TLS genom att lägga certifikat i `certs/`:

```bash
mkdir -p certs/
cp /path/to/cert.pem certs/tls.crt
cp /path/to/key.pem certs/tls.key

# Starta om frontend
podman restart cert-guardian-frontend
# HTTPS: https://localhost:3443
```

Utan certifikat fungerar allt som vanligt via HTTP.

### 5. Kubernetes med Helm

```bash
helm install cert-guardian helm/cert-guardian/ \
  --set config.mattermost.webhookUrl="https://mattermost.example.com/hooks/xxx" \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=certguardian.example.com \
  -n cert-guardian --create-namespace
```

### Prometheus Metrics

Tillgängligt på `http://localhost:8000/metrics` (ingen auth):

```bash
curl http://localhost:8000/metrics | grep cert_guardian
# cert_guardian_certificates_total 25.0
# cert_guardian_certificates_expiring{window="7d"} 2.0
# cert_guardian_certificates_expired 0.0
# cert_guardian_http_requests_total{...} 150.0
```

## Dokumentation

| Dokument | Beskrivning |
|----------|-------------|
| [INSTALL.md](INSTALL.md) | Installationsguide för olika miljöer |
| [WEBAPP_README.md](WEBAPP_README.md) | Webbgränssnitt och funktioner |
| [API.md](API.md) | Komplett API-referens |
| [AUTHENTICATION.md](AUTHENTICATION.md) | Autentisering med Keycloak/Pomerium |
| [CA_VALIDATION.md](CA_VALIDATION.md) | Custom CA och certifikatvalidering |

## Roller och behörigheter

| Funktion | Viewer | Editor | Admin |
|----------|--------|--------|-------|
| Visa dashboard | ✅ | ✅ | ✅ |
| Visa certifikat | ✅ | ✅ | ✅ |
| Visa endpoints | ✅ | ✅ | ✅ |
| Skapa/ändra endpoints | ❌ | ✅ | ✅ |
| Trigga scan | ❌ | ✅ | ✅ |
| Network sweeps | ❌ | ✅ | ✅ |
| Hantera trusted CAs | ❌ | ✅ | ✅ |
| Användarhantering | ❌ | ❌ | ✅ |
| Visa audit logs | ❌ | ❌ | ✅ |
| Konfigurera SIEM | ❌ | ❌ | ✅ |

## Konfigurationsexempel

```yaml
database:
  path: "data/certificates.db"

mattermost:
  webhook_url: "https://mattermost.example.com/hooks/xxxxx"
  username: "Certificate Guardian"
  icon_emoji: ":lock:"

endpoints:
  - host: "example.com"
    port: 443
    owner: "IT Team"
    criticality: "high"

notifications:
  warning_days: [90, 60, 30, 14, 7, 3, 1]
  critical_days: 7
  emergency_days: 1

scanner:
  interval_seconds: 3600
  timeout_seconds: 10
  max_concurrent: 10

server:
  cors_origins:
    - "*"  # Ange din frontend-URL i produktion, t.ex. ["https://certs.example.com"]

siem:
  mode: "disabled"  # disabled | stdout | syslog | beats
  host: "siem.example.com"
  port: 6514
  tls_enabled: true
  tls_verify: true
  ca_pem: ""
  client_cert_pem: ""
  client_key_pem: ""

auth:
  mode: "local"
  local:
    access_token_expire_minutes: 15
    refresh_token_expire_days: 30
```

## Schemalagda rapporter

Utöver realtidsvarningar kan Certificate Guardian skicka sammanfattningar till Mattermost via `docker-compose.yaml`:

```bash
# Daglig sammanfattning — certifikat som löper ut inom 90 dagar
podman-compose -f docker-compose.yaml --profile summary run --rm cert-guardian-summary

# Säkerhetsrapport — self-signed och untrusted certifikat
podman-compose -f docker-compose.yaml run --rm cert-guardian python /app/src/main.py --config /app/config/config.yaml --security
```

Kör via cron eller systemd timer för dagliga rapporter, t.ex.:
```bash
# Varje morgon kl 08:00
0 8 * * * podman-compose -f /path/to/docker-compose.yaml --profile summary run --rm cert-guardian-summary
```

## Notifieringsnivåer

| Dagar kvar | Nivå | Färg |
|-----------|------|------|
| 90+ | INFO | Grön |
| 30-89 | WARNING | Gul |
| 7-29 | CRITICAL | Röd |
| 0-6 | EMERGENCY | Röd |

## Databas-schema

### Tabeller

- **certificates** - Certifikat metadata
- **endpoints** - Konfigurerade endpoints att scanna
- **certificate_scans** - Historik över scanningar
- **notifications** - Spårar skickade notifieringar
- **sweeps** - Network sweep-konfigurationer
- **sweep_results** - Resultat från sweeps
- **users** - Användarkonton (local mode)
- **refresh_tokens** - JWT refresh tokens
- **trusted_cas** - Custom root-certifikat
- **audit_log** - Spårning av användaraktiviteter

## Säkerhetsöverväganden

**Bra:**
- Lagrar ALDRIG private keys
- Read-only access till endpoints
- Använder TLS för all kommunikation
- Loggar alla aktiviteter (audit log)
- Rollbaserad åtkomstkontroll
- JWT tokens med kort livslängd

**Tänk på:**
- Webhook URL innehåller secrets - skydda config-filen (per-endpoint webhooks maskeras i API-svar)
- Ändra default admin-lösenord omedelbart
- Använd HTTPS i produktion
- Konfigurera `server.cors_origins` i config.yaml med din frontend-URL i produktion
- Alla data-endpoints kräver autentisering (JWT token)

## Felsökning

### Ingen Mattermost-notifiering

```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"text":"Test"}' \
  https://your-mattermost.com/hooks/xxxxx
```

### Connection timeout

```yaml
scanner:
  timeout_seconds: 30
```

### Database read-only (Podman rootless)

Använd `:U` suffix på volume mounts:
```yaml
volumes:
  - ./data:/app/data:U
```

## Licens

MIT License - använd fritt i din organisation.
