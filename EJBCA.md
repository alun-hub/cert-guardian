# EJBCA / PrimeKey Integration

Certificate Guardian kan hämta certifikat direkt från en EJBCA-server via REST API. Det ger fullständig täckning — inklusive interna tjänster utan publik port, certifikat som utfärdats men ännu inte deployats, och certifikat som aldrig syns i nätverksskanningar.

## Varför EJBCA-integration?

| Nätverksskanning | EJBCA-synk |
|-----------------|------------|
| Kräver att tjänsten är nåbar på nätverket | Hämtar direkt från CA:n |
| Hittar bara deployade certifikat | Hittar även ej-deployade certifikat |
| Kräver konfigurerade endpoints | Täcker automatiskt alla utfärdade certifikat |
| Hittar inte interna tjänster utan publik port | Komplett täckning oavsett port/IP |

## Förutsättningar

- EJBCA med REST API aktiverat (`ejbca-rest-api`)
- Autentisering: klientcertifikat (mTLS) för Community och Enterprise; API-nyckel (Bearer token) **endast Enterprise**
- EJBCA Community 8.2+ eller Enterprise (rekommenderas för full sökning och paginering)

## Community vs Enterprise — API-skillnader

| Funktion | Community | Enterprise |
|----------|-----------|------------|
| `GET /v1/ca` | ✅ (sedan 8.2) | ✅ |
| `POST /v1/certificate/search` | ⚠️ Kan finnas, ej garanterat | ✅ |
| `POST /v2/certificate/search` (paginerat) | ❌ | ✅ |
| mTLS-autentisering | ✅ | ✅ |
| API-nyckel (Bearer token) | ❌ | ✅ |

**Klienten auto-detekterar** vilken endpoint som finns:
1. Probar `/v2/certificate/search` (Enterprise) — stödjer paginering med `current_page` (1-indexerat)
2. Faller tillbaka på `/v1/certificate/search` (Community) — en enda sida med `max_number_of_results`

> **Notera:** PrimeKey förvärvades av Keyfactor 2021. EJBCA heter nu officiellt "Keyfactor EJBCA". API:et är identiskt — samma kodbas, samma endpoints.

## Konfiguration via UI

1. Logga in som **admin**
2. Gå till **Settings** → avsnittet **EJBCA / PrimeKey Sync**
3. Fyll i fälten (se nedan) och klicka **Save settings**
4. Klicka **Test connection** för att verifiera
5. Klicka **Sync now** för att köra en första synk

## Konfiguration via config.yaml

```yaml
ejbca:
  enabled: false                              # true för att aktivera
  base_url: "https://ejbca.example.com/ejbca-rest-api"
  auth_method: "client_cert"                  # "client_cert" | "api_key"

  # --- Klientcertifikat-autentisering (mTLS) ---
  client_cert_pem: |
    -----BEGIN CERTIFICATE-----
    MIIBxxx...
    -----END CERTIFICATE-----
  client_key_pem: |
    -----BEGIN PRIVATE KEY-----
    MIIExxx...
    -----END PRIVATE KEY-----
  ca_pem: |                                   # Valfritt: CA för att verifiera EJBCA:s cert
    -----BEGIN CERTIFICATE-----
    MIIByyy...
    -----END CERTIFICATE-----
  verify_tls: true                            # false = skippa TLS-verifiering (ej rekommenderat)

  # --- API-nyckel-autentisering (alternativ) ---
  api_key: ""                                 # Sätts som Bearer-token i Authorization-headern

  # --- Filter och synkinställningar ---
  ca_dn_filter: ""                            # Kommaseparerat, t.ex. "CN=MyCA,O=Acme" — tomt = alla CA:er
  sync_interval_hours: 6                      # Automatisk synk var 6:e timme; 0 = manuellt
  max_results_per_page: 1000                  # Antal certifikat per API-sida (max 1000)
```

### Konfigurationsparametrar

| Parameter | Typ | Beskrivning |
|-----------|-----|-------------|
| `enabled` | bool | Aktiverar EJBCA-integrationen |
| `base_url` | string | Bas-URL till EJBCA REST API |
| `auth_method` | string | `client_cert` (mTLS) eller `api_key` |
| `client_cert_pem` | string | PEM-kodat klientcertifikat (mTLS) |
| `client_key_pem` | string | PEM-kodad privat nyckel (mTLS) |
| `ca_pem` | string | CA-certifikat för att verifiera EJBCA:s TLS-certifikat (valfritt) |
| `verify_tls` | bool | Verifiera EJBCA:s TLS-certifikat (`true` rekommenderat) |
| `api_key` | string | API-nyckel (används som Bearer-token) |
| `ca_dn_filter` | string | Kommaseparerade CA-DN:er att filtrera på, tomt = alla |
| `sync_interval_hours` | int | Timmar mellan automatiska synkar; `0` = manuellt |
| `max_results_per_page` | int | Sidstorlek för paginering mot EJBCA API (max 1000) |

## Autentiseringsmetoder

### Klientcertifikat (mTLS) — rekommenderat

EJBCA stöder mTLS nativt. Skapa ett klientcertifikat i EJBCA med rätt behörigheter:

```bash
# Skapa nycklar och CSR
openssl req -newkey rsa:2048 -nodes \
  -keyout client.key \
  -out client.csr \
  -subj "/CN=cert-guardian-client/O=MyOrg"

# Signera med EJBCA (via EJBCA UI eller CLI)
# Exportera certifikat som PEM

# Testa anslutning manuellt
curl --cert client.crt --key client.key \
  https://ejbca.example.com/ejbca-rest-api/v1/ca
```

Klistra sedan in innehållet i `client.crt` och `client.key` i Settings-UI:t eller direkt i `config.yaml`.

### API-nyckel

Om EJBCA är konfigurerat med API-nyckelautentisering:

```yaml
ejbca:
  auth_method: "api_key"
  api_key: "din-api-nyckel-här"
```

API-nyckeln skickas som `Authorization: Bearer <api_key>` i varje anrop.

## Synkbeteende

### Automatisk synk (schemalagd)

Scannern (`src/main.py`) kontrollerar efter varje nätverksskanning om det är dags att synka med EJBCA:

```
run_once()
  → scan_all_endpoints()
  → cleanup_orphaned_certificates()
  → _maybe_sync_ejbca()  ← körs om intervallet har förlutet
```

`sync_interval_hours: 0` inaktiverar automatisk synk — använd då **Sync now** i UI:t eller API-anropet.

### API-version och endpoint-detektion

Klienten väljer API-version via **lazy fallback** — ingen separat sondering görs:

1. Första anropet görs alltid mot **`POST /v2/certificate/search`** (Enterprise, paginerat, `current_page` 1-indexerat).
2. Om EJBCA svarar `404`, `405` eller `501` faller klienten automatiskt tillbaka till **`POST /v1/certificate/search`** (Community/äldre Enterprise, enkel sida med `max_number_of_results`). En `INFO`-loggpost skrivs.
3. Alla andra HTTP-fel (t.ex. `401`, `403`) ger ett åtgärdsbart felmeddelande — se [Felsökning](#felsökning) nedan.

För Community-installationer med många certifikat: sätt `max_results_per_page: 1000` (max som EJBCA tillåter per sida). Alla certifikat över 1000 kommer **inte** att hämtas om v2 inte finns.

### Manuell synk via API

```bash
# Trigga synk (editor+)
curl -X POST http://localhost:8000/api/ejbca/sync \
  -H "Authorization: Bearer $TOKEN"

# Kontrollera status
curl http://localhost:8000/api/ejbca/sync/status \
  -H "Authorization: Bearer $TOKEN"
```

### Vad synkas?

Endast aktiva certifikat (`STATUS = CERT_ACTIVE`) hämtas. Återkallade och utgångna certifikat synkas inte.

För varje certifikat:
1. DER-kodat certifikat avkodas och parsas (subject, issuer, SAN, nyckelinfo, etc.)
2. SHA-256-fingeravtryck beräknas
3. Om certifikatet redan finns i databasen → uppdateras med ny EJBCA-metadata
4. Om certifikatet är nytt → läggs till med `source = 'ejbca'`
5. EJBCA-specifik metadata lagras i `ejbca_certificates`-tabellen

### Kolisjon med nätverksskanning

Om samma certifikat hittas av både EJBCA-synk och nätverksskanning:
- Certifikatposten i `certificates` bevaras med sin ursprungliga `source`-flagga
- Scanningsposten i `certificate_scans` kopplas till endpoint-ID som vanligt
- I UI:t visas certifikatet med **både** EJBCA-badge och endpoint-information

### Rensning av orphaned certifikat

`cleanup_orphaned_certificates()` tar **inte** bort EJBCA-synkade certifikat — de har inga scanningsposter och skulle annars raderas vid varje cycle. Certifikat med `source = 'ejbca'` behålls tills de tas bort manuellt eller ersätts vid nästa synk.

## UI-indikatorer

### Certifikatlistan

EJBCA-synkade certifikat visas med en indigo **EJBCA**-badge bredvid subject-namnet.

För certifikat utan konfigurerade endpoints visas CA DN i endpoints-kolumnen:
```
CN=MyCA  (extraherat ur ca_dn)
```

### Detaljvy

Expandera ett certifikat för att se EJBCA-sektionen:

| Fält | Beskrivning |
|------|-------------|
| CA DN | Distinguished Name för utfärdande CA |
| Användarnamn | End entity-användarnamn i EJBCA |
| End Entity Profile | Profil som användes vid utfärdande |
| Certificate Profile | Certifikatprofil |
| Status | `CERT_ACTIVE`, `CERT_REVOKED`, etc. |
| Senast synkad | Tidsstämpel för senaste EJBCA-synk |

## Databastabeller

### `ejbca_certificates`

Lagrar EJBCA-specifik metadata per certifikat:

```sql
CREATE TABLE ejbca_certificates (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id       INTEGER NOT NULL UNIQUE,   -- FK → certificates.id
    ejbca_url            TEXT NOT NULL,             -- EJBCA base URL
    ca_dn                TEXT NOT NULL,             -- Utfärdande CA:ns DN
    username             TEXT,                      -- End entity-användarnamn
    end_entity_profile   TEXT,                      -- End entity-profil
    certificate_profile  TEXT,                      -- Certifikatprofil
    ejbca_status         TEXT NOT NULL DEFAULT 'CERT_ACTIVE',
    last_synced_at       TEXT NOT NULL              -- ISO8601 tidsstämpel
)
```

### `ejbca_sync_log`

Historik per synkkörning:

```sql
CREATE TABLE ejbca_sync_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    synced_at      TEXT NOT NULL,       -- ISO8601
    certs_found    INTEGER DEFAULT 0,   -- Totalt hittade
    certs_new      INTEGER DEFAULT 0,   -- Nytillagda
    certs_updated  INTEGER DEFAULT 0,   -- Uppdaterade
    status         TEXT NOT NULL,       -- 'success' | 'failed'
    error_message  TEXT                 -- Felmeddelande om status = 'failed'
)
```

### `certificates.source`

Ny kolumn som anger var certifikatet först hittades:

| Värde | Beskrivning |
|-------|-------------|
| `scan` | Funnet via nätverksskanning (default) |
| `ejbca` | Hämtat från EJBCA |

## API-endpoints

| Metod | Endpoint | Auth | Beskrivning |
|-------|----------|------|-------------|
| `GET` | `/api/settings/ejbca` | Admin | Läs EJBCA-konfiguration |
| `PUT` | `/api/settings/ejbca` | Admin | Spara EJBCA-konfiguration |
| `POST` | `/api/settings/ejbca/test` | Admin | Testa anslutning mot EJBCA |
| `POST` | `/api/ejbca/sync` | Editor+ | Trigga manuell synk (bakgrundstask) |
| `GET` | `/api/ejbca/sync/status` | Any auth | Status för senaste synk |

### Exempelsvar — `/api/ejbca/sync/status`

```json
{
  "last_sync": {
    "id": 42,
    "synced_at": "2026-02-23T20:14:07",
    "certs_found": 142,
    "certs_new": 3,
    "certs_updated": 1,
    "status": "success",
    "error_message": null
  }
}
```

### Exempelsvar — `/api/settings/ejbca/test`

```json
{ "ok": true, "message": "3 CAs found" }
```

eller vid fel:

```json
{ "ok": false, "message": "TLS error: certificate verify failed" }
```

## Felsökning

Klienten returnerar åtgärdbara felmeddelanden för de vanligaste problemen. Nedan beskrivs vad varje fel betyder och hur du löser det.

### "Connection failed — check host, port and firewall rules"

```bash
# Kontrollera att EJBCA REST API är aktiverat och nåbart
curl -k https://ejbca.example.com/ejbca-rest-api/v1/ca

# Kontrollera att rätt port används (vanligtvis 8443 eller 443)
curl -v https://ejbca.example.com:8443/ejbca-rest-api/v1/ca
```

### "TLS error — provide ca_pem or set verify_tls: false"

Antingen:
- Ange EJBCA:s CA-certifikat i `ca_pem`-fältet (rekommenderat)
- Eller sätt `verify_tls: false` (ej rekommenderat i produktion)

### "401 Unauthorized — verify that the client certificate or API key is valid"

- Kontrollera att klientcertifikatet är giltigt och inte utgånget
- Verifiera att `auth_method` matchar EJBCA:s konfiguration
- **API-nyckel fungerar bara på Enterprise** — använd mTLS för Community
- För API-nyckel: kontrollera att nyckeln är giltig och inte återkallad

### "403 Forbidden — ensure the client has the 'REST Certificate Management' role"

Klientcertifikatet saknar behörighet i EJBCA:
1. Logga in i EJBCA Admin UI
2. Gå till **Roller och åtkomstregler** → hitta eller skapa en roll
3. Lägg till åtkomstregel **`/rest/v1/certificate`** (läs) och **`/rest/v2/certificate`** (läs)
4. Lägg till klientens slutentitet i rollen

### "404 Not Found — verify base_url points to the EJBCA REST API root"

Kontrollera att `base_url` slutar på REST API-rotkatalogen, t.ex.:
```
https://ejbca.example.com/ejbca/ejbca-rest-api
https://ejbca.example.com:8443/ejbca-rest-api
```
Testa manuellt:
```bash
curl -k https://ejbca.example.com/ejbca/ejbca-rest-api/v1/ca
```

### "405 Method Not Allowed — check that ejbca-rest-api module is installed"

REST API-modulen är inte aktiverad i EJBCA. I Enterprise: kontrollera att `ejbca-rest-api` är installerat och aktiverat i `web.xml` eller motsvarande konfiguration.

### Färre certifikat än förväntat (Community)

Community stödjer bara `/v1/certificate/search` utan paginering. Max antal certifikat som returneras styrs av `max_results_per_page` (max 1000). Om du har fler certifikat behöver du uppgradera till Enterprise för att få full täckning, eller använda `ca_dn_filter` för att dela upp hämtningen per CA.

### Inga certifikat returneras

- Kontrollera `ca_dn_filter` — ett felaktigt DN filtrerar bort allt
- Verifiera att det finns certifikat med status `CERT_ACTIVE` i EJBCA
- Öka `max_results_per_page` om du har fler än 1000 certifikat per sida

### Certifikat försvinner efter cleanup

EJBCA-certifikat ska **inte** rensas av cleanup-funktionen. Om det ändå händer, kontrollera att `source`-kolumnen har värdet `ejbca` för berörda rader:

```bash
sqlite3 data/certificates.db \
  "SELECT fingerprint, source FROM certificates WHERE source = 'ejbca' LIMIT 5"
```

### Loggar

```bash
# Scannerlogs (visar EJBCA-synkstatus)
podman logs cert-guardian-scanner | grep -i ejbca

# Backend-logs
podman logs cert-guardian-backend | grep -i ejbca
```
