# Certificate Guardian - API Reference

Komplett API-dokumentation för Certificate Guardian REST API.

**Base URL:** `http://localhost:8000`
**Interactive Docs:** `http://localhost:8000/docs` (Swagger UI)

## Autentisering

API:t stöder tre autentiseringslägen:

| Läge | Beskrivning | Header |
|------|-------------|--------|
| `local` | JWT Bearer tokens | `Authorization: Bearer <token>` |
| `proxy` | Pomerium headers | `X-Pomerium-Jwt-Assertion` |
| `oidc` | Keycloak/OIDC tokens | `Authorization: Bearer <token>` |

### Roller

- **viewer** - Läsbehörighet
- **editor** - Läs + skriv (skapa, ändra, ta bort resurser)
- **admin** - Full åtkomst (inkl. användarhantering, audit logs)

---

## Auth Endpoints

### GET /api/auth/mode

Returnerar aktuellt autentiseringsläge.

**Response:**
```json
{
  "mode": "local"
}
```

---

### POST /api/auth/login

Logga in (endast local mode).

**Request Body:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 900,
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@local",
    "role": "admin",
    "groups": []
  }
}
```

**Cookies:** Sätter `refresh_token` som httpOnly cookie.

---

### POST /api/auth/refresh

Förnya access token med refresh token.

**Request:** Skicka refresh token via cookie eller body:
```json
{
  "refresh_token": "abc123..."
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 900
}
```

---

### POST /api/auth/logout

Logga ut och revokera refresh token.

**Headers:** `Authorization: Bearer <token>` (valfritt)

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

---

### GET /api/auth/me

Hämta info om inloggad användare.

**Headers:** `Authorization: Bearer <token>` (krävs)

**Response:**
```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@local",
  "role": "admin",
  "groups": []
}
```

---

## User Management (Admin only)

### GET /api/users

Lista alla användare.

**Headers:** `Authorization: Bearer <token>` (admin krävs)

**Response:**
```json
{
  "users": [
    {
      "id": 1,
      "username": "admin",
      "email": "admin@local",
      "role": "admin",
      "is_active": 1,
      "created_at": "2025-01-15T10:30:00"
    }
  ],
  "total": 1
}
```

---

### POST /api/users

Skapa ny användare.

**Headers:** `Authorization: Bearer <token>` (admin krävs)

**Request Body:**
```json
{
  "username": "newuser",
  "password": "securepassword",
  "email": "user@example.com",
  "role": "editor"
}
```

**Response:**
```json
{
  "id": 2,
  "message": "User created successfully"
}
```

---

### GET /api/users/{user_id}

Hämta specifik användare.

**Headers:** `Authorization: Bearer <token>` (admin krävs)

---

### PUT /api/users/{user_id}

Uppdatera användare.

**Headers:** `Authorization: Bearer <token>` (admin krävs)

**Request Body:**
```json
{
  "email": "newemail@example.com",
  "role": "admin",
  "is_active": true
}
```

---

### DELETE /api/users/{user_id}

Ta bort användare.

**Headers:** `Authorization: Bearer <token>` (admin krävs)

---

### POST /api/users/{user_id}/password

Återställ användares lösenord (admin).

**Headers:** `Authorization: Bearer <token>` (admin krävs)

**Request Body:**
```json
{
  "new_password": "newsecurepassword"
}
```

---

### POST /api/auth/change-password

Ändra eget lösenord.

**Headers:** `Authorization: Bearer <token>` (krävs)

**Request Body:**
```json
{
  "current_password": "oldpassword",
  "new_password": "newpassword"
}
```

---

## Dashboard

### GET /api/dashboard/stats

Hämta dashboard-statistik.

**Response:**
```json
{
  "total_certificates": 25,
  "total_endpoints": 15,
  "expiring_soon": 3,
  "expired": 1,
  "self_signed": 2,
  "untrusted": 1
}
```

---

### GET /api/timeline

Hämta certifikat-expiry timeline.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| months | int | 12 | Antal månader framåt |

**Response:**
```json
{
  "timeline": [
    {"month": "2025-02", "label": "Feb", "count": 2},
    {"month": "2025-03", "label": "Mar", "count": 5}
  ]
}
```

---

## Certificates

### GET /api/certificates

Lista certifikat med filtrering.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| expiring_days | int | Filtrera på dagar till expiry |
| self_signed | bool | Filtrera self-signed |
| untrusted | bool | Filtrera untrusted CA |
| search | string | Sök i subject/issuer |
| limit | int | Max antal (default 100) |
| offset | int | Pagination offset |

**Response:**
```json
{
  "certificates": [
    {
      "id": 1,
      "fingerprint": "SHA256:abc123...",
      "subject": "CN=example.com",
      "issuer": "CN=Let's Encrypt",
      "not_before": "2024-01-01T00:00:00",
      "not_after": "2025-04-01T00:00:00",
      "days_until_expiry": 45.5,
      "is_self_signed": false,
      "is_trusted_ca": true,
      "validation_error": null,
      "endpoints": [
        {"id": 1, "host": "example.com", "port": 443}
      ]
    }
  ],
  "total": 1
}
```

---

### GET /api/certificates/{cert_id}

Hämta certifikatdetaljer.

---

## Endpoints

### GET /api/endpoints

Lista alla endpoints.

**Response:**
```json
{
  "endpoints": [
    {
      "id": 1,
      "host": "example.com",
      "port": 443,
      "owner": "IT Team",
      "criticality": "high",
      "webhook_url": null,
      "last_scan": "2025-01-15T10:00:00",
      "certificate": {
        "subject": "CN=example.com",
        "days_until_expiry": 45,
        "is_self_signed": false
      }
    }
  ]
}
```

---

### POST /api/endpoints

Skapa ny endpoint.

**Headers:** `Authorization: Bearer <token>` (editor+ krävs)
**Notering:** Endpoints kan endast ändras/raderas av skaparen eller admin.

**Request Body:**
```json
{
  "host": "api.example.com",
  "port": 443,
  "owner": "DevOps",
  "criticality": "critical"
}
```

**Response:**
```json
{
  "id": 2,
  "message": "Endpoint created successfully"
}
```

---

### PUT /api/endpoints/{endpoint_id}

Uppdatera endpoint.

**Headers:** `Authorization: Bearer <token>` (editor+ krävs)
**Notering:** Endpoints kan endast ändras/raderas av skaparen eller admin.

**Request Body:**
```json
{
  "owner": "New Owner",
  "criticality": "high",
  "webhook_url": "https://mattermost.example.com/hooks/xxx"
}
```

---

### DELETE /api/endpoints/{endpoint_id}

Ta bort endpoint.

**Headers:** `Authorization: Bearer <token>` (editor+ krävs)
**Notering:** Endpoints kan endast ändras/raderas av skaparen eller admin.

---

## Scanning

### POST /api/scan

Trigga certifikat-scan.

**Headers:** `Authorization: Bearer <token>` (editor+ krävs)

**Request Body:**
```json
{
  "endpoint_id": 1
}
```

Använd `null` för att scanna alla endpoints:
```json
{
  "endpoint_id": null
}
```

**Response:**
```json
{
  "message": "Scan completed",
  "results": [
    {
      "endpoint_id": 1,
      "host": "example.com",
      "port": 443,
      "success": true,
      "certificate_id": 5
    }
  ]
}
```

---

## Network Sweeps

### POST /api/sweeps/validate

Validera sweep-target och få antal IP-adresser.

**Request Body:**
```json
{
  "target": "192.168.1.0/24"
}
```

**Response:**
```json
{
  "valid": true,
  "ip_count": 254,
  "target_type": "cidr"
}
```

---

### POST /api/sweeps

Skapa och starta network sweep.

**Headers:** `Authorization: Bearer <token>` (editor+ krävs)
**Notering:** Sweeps kan endast ändras/raderas av skaparen eller admin.

**Request Body:**
```json
{
  "name": "Office Network",
  "target": "192.168.1.0/24",
  "ports": [443, 8443],
  "owner": "IT",
  "criticality": "medium",
  "webhook_url": "https://mattermost.example.com/hooks/xxx"
}
```

**Response:**
```json
{
  "id": 1,
  "message": "Sweep started",
  "total_scans": 508
}
```

---

### GET /api/sweeps

Lista alla sweeps.

**Response:**
```json
{
  "sweeps": [
    {
      "id": 1,
      "name": "Office Network",
      "target": "192.168.1.0/24",
      "status": "completed",
      "progress_total": 508,
      "progress_scanned": 508,
      "progress_found": 12,
      "created_at": "2025-01-15T10:00:00"
    }
  ]
}
```

---

### GET /api/sweeps/{sweep_id}

Hämta sweep med resultat.

**Response:**
```json
{
  "sweep": {
    "id": 1,
    "name": "Office Network",
    "target": "192.168.1.0/24",
    "status": "completed"
  },
  "results": [
    {
      "ip_address": "192.168.1.10",
      "port": 443,
      "status": "open",
      "endpoint_id": 15
    }
  ]
}
```

---

### DELETE /api/sweeps/{sweep_id}

Ta bort sweep.

**Headers:** `Authorization: Bearer <token>` (editor+ krävs)
**Notering:** Sweeps kan endast ändras/raderas av skaparen eller admin.

---

### POST /api/sweeps/{sweep_id}/restart

Starta om befintlig sweep.

**Headers:** `Authorization: Bearer <token>` (editor+ krävs)

---

## Trusted CAs

### GET /api/trusted-cas

Lista custom trusted CAs.

**Response:**
```json
{
  "trusted_cas": [
    {
      "id": 1,
      "name": "Internal Root CA",
      "subject": "CN=Internal CA",
      "fingerprint": "SHA256:abc123...",
      "not_after": "2030-01-01T00:00:00"
    }
  ]
}
```

---

### POST /api/trusted-cas

Lägg till trusted CA.

**Headers:** `Authorization: Bearer <token>` (editor+ krävs)

**Request Body:**
```json
{
  "name": "My Internal CA",
  "pem_data": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

---

### DELETE /api/trusted-cas/{ca_id}

Ta bort trusted CA.

**Headers:** `Authorization: Bearer <token>` (editor+ krävs)

---

### GET /api/trusted-cas/{ca_id}/pem

Ladda ner CA-certifikat som PEM.

---

## Security

### GET /api/security/issues

Lista säkerhetsproblem.

**Response:**
```json
{
  "issues": [
    {
      "type": "self_signed",
      "certificate_id": 3,
      "subject": "CN=internal.local",
      "endpoints": ["internal.local:443"]
    }
  ],
  "total": 1
}
```

---

## Webhooks & Notifications

### POST /api/webhooks/test

Testa webhook URL.

**Headers:** `Authorization: Bearer <token>` (editor+ krävs)

**Request Body:**
```json
{
  "webhook_url": "https://mattermost.example.com/hooks/xxx",
  "message": "Test message"
}
```

---

### POST /api/notifications/test

Testa global Mattermost-webhook.

**Headers:** `Authorization: Bearer <token>` (editor+ krävs)

---

## Settings (Admin)

### GET /api/settings/scanner

Hämta scanner-inställningar.

**Headers:** `Authorization: Bearer <token>` (krävs)

---

### PUT /api/settings/scanner

Uppdatera scan-intervall (sekunder).

**Headers:** `Authorization: Bearer <token>` (admin krävs)

**Request Body:**
```json
{
  "interval_seconds": 3600
}
```

---

### GET /api/settings/db-health

Hämta DB-hälsa (storlek, rader, scans 30 dagar).

**Headers:** `Authorization: Bearer <token>` (admin krävs)

---

### GET /api/settings/siem

Hämta SIEM-konfiguration.

**Headers:** `Authorization: Bearer <token>` (admin krävs)

---

### PUT /api/settings/siem

Uppdatera SIEM-konfiguration (syslog/beats med TLS).

**Headers:** `Authorization: Bearer <token>` (admin krävs)

**Request Body:**
```json
{
  "mode": "syslog",
  "host": "siem.example.com",
  "port": 6514,
  "tls_enabled": true,
  "tls_verify": true,
  "ca_pem": "",
  "client_cert_pem": "",
  "client_key_pem": ""
}
```

---

### POST /api/settings/siem/test

Skicka test-event till SIEM.

**Headers:** `Authorization: Bearer <token>` (admin krävs)

**Request Body:**
```json
{
  "message": "Test event"
}
```

---

## Audit Logs (Admin only)

### GET /api/audit-logs

Hämta audit-loggar.

**Headers:** `Authorization: Bearer <token>` (admin krävs)

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| limit | int | Max antal (default 100) |
| offset | int | Pagination offset |
| user_email | string | Filtrera på användare |
| action | string | Filtrera på action |

**Response:**
```json
{
  "logs": [
    {
      "id": 1,
      "user_email": "admin@local",
      "action": "login",
      "resource_type": null,
      "resource_id": null,
      "details": "User logged in successfully",
      "ip_address": "192.168.1.100",
      "created_at": "2025-01-15T10:30:00"
    },
    {
      "id": 2,
      "user_email": "admin@local",
      "action": "endpoint_create",
      "resource_type": "endpoint",
      "resource_id": 5,
      "details": "Created endpoint api.example.com:443",
      "ip_address": "192.168.1.100",
      "created_at": "2025-01-15T10:35:00"
    }
  ],
  "total": 2,
  "limit": 100,
  "offset": 0
}
```

**Audit Actions:**
| Action | Description |
|--------|-------------|
| `login` | Lyckad inloggning |
| `login_failed` | Misslyckad inloggning |
| `logout` | Utloggning |
| `user_create` | Användare skapad |
| `user_update` | Användare uppdaterad |
| `user_delete` | Användare borttagen |
| `endpoint_create` | Endpoint skapad |
| `endpoint_update` | Endpoint uppdaterad |
| `endpoint_delete` | Endpoint borttagen |
| `sweep_create` | Network sweep startad |
| `sweep_delete` | Network sweep borttagen |
| `ca_create` | Trusted CA tillagd |
| `ca_delete` | Trusted CA borttagen |
| `scan_trigger` | Manuell scan triggad |

---

## Health

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "auth_mode": "local"
}
```

---

## Felkoder

| Kod | Beskrivning |
|-----|-------------|
| 400 | Bad Request - Ogiltig input |
| 401 | Unauthorized - Autentisering krävs |
| 403 | Forbidden - Otillräcklig behörighet |
| 404 | Not Found - Resursen finns inte |
| 500 | Internal Server Error |

**Felformat:**
```json
{
  "detail": "Error message here"
}
```

---

## Exempel med cURL

### Login och hämta certifikat

```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')

# Hämta certifikat
curl -s http://localhost:8000/api/certificates \
  -H "Authorization: Bearer $TOKEN" | jq

# Skapa endpoint
curl -s -X POST http://localhost:8000/api/endpoints \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host":"example.com","port":443,"owner":"IT"}' | jq

# Trigga scan
curl -s -X POST http://localhost:8000/api/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"endpoint_id":null}' | jq
```

---

## Rate Limiting

API:t har ingen inbyggd rate limiting. I produktion rekommenderas:
- Använd reverse proxy (nginx, Traefik) med rate limiting
- Konfigurera max connections per IP
- Övervaka API-användning via audit logs
