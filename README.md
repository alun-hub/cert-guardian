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
- **Undviker spam** - skickar inte samma varning flera gånger inom 24h
- **Containerized** - lätt att deploya med Podman/Docker

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

auth:
  mode: "local"
  local:
    access_token_expire_minutes: 15
    refresh_token_expire_days: 30
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
- Webhook URL innehåller secrets - skydda config-filen
- Ändra default admin-lösenord omedelbart
- Använd HTTPS i produktion
- Konfigurera CORS korrekt för din domän

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
