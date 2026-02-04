# Certificate Guardian - Authentication Guide

Guide för att konfigurera autentisering med Keycloak (OIDC) eller Pomerium (Proxy).

## Autentiseringslägen

Certificate Guardian stöder tre autentiseringslägen:

| Läge | Beskrivning | Användningsfall |
|------|-------------|-----------------|
| `local` | Inbyggd användarhantering med JWT | Enkel setup, små team |
| `proxy` | Pomerium/OAuth2 Proxy headers | Befintlig SSO-infrastruktur |
| `oidc` | OpenID Connect (Keycloak, Azure AD) | Enterprise SSO |

---

## Local Mode (Default)

Enklaste läget med inbyggd användarhantering.

### Konfiguration

```yaml
auth:
  mode: "local"
  local:
    # JWT secret - genereras automatiskt om ej satt
    # jwt_secret: "your-secret-key-here"
    access_token_expire_minutes: 15
    refresh_token_expire_days: 30
```

### Första start

Vid första start skapas automatiskt en admin-användare:
- **Användarnamn:** `admin`
- **Lösenord:** `admin`

Ändra lösenordet omedelbart!

```bash
# Via miljövariabel före första start
export CERT_GUARDIAN_ADMIN_PASSWORD="securepassword"
podman-compose up -d
```

### Användarhantering

Admins kan hantera användare via UI eller API:

```bash
# Lista användare
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/users

# Skapa användare
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"editor1","password":"pass123","role":"editor"}' \
  http://localhost:8000/api/users
```

---

## Keycloak (OIDC)

Enterprise-ready SSO med Keycloak.

### Förberedelser i Keycloak

#### 1. Skapa Client

1. Gå till **Clients** -> **Create client**
2. Fyll i:
   - **Client ID:** `cert-guardian`
   - **Client type:** OpenID Connect
   - **Client authentication:** On
3. Under **Settings**:
   - **Valid redirect URIs:** `https://certguardian.example.com/*`
   - **Web origins:** `https://certguardian.example.com`
4. Under **Credentials**, kopiera **Client secret**

#### 2. Skapa Roller

1. Gå till **Realm roles** -> **Create role**
2. Skapa roller:
   - `cert-admin`
   - `cert-editor`
   - `cert-viewer` (valfritt)

#### 3. Tilldela Roller till Användare

1. Gå till **Users** -> Välj användare
2. Under **Role mapping** -> **Assign role**
3. Tilldela `cert-admin` eller `cert-editor`

#### 4. Lägg till Groups Claim (Valfritt)

För gruppbaserad rollhantering:

1. Gå till **Client scopes** -> **Create client scope**
   - **Name:** `groups`
   - **Type:** Default
2. Under **Mappers** -> **Create mapper**:
   - **Name:** `groups`
   - **Mapper type:** Group Membership
   - **Token claim name:** `groups`
   - **Add to ID token:** On
   - **Add to access token:** On
3. Gå till **Clients** -> `cert-guardian` -> **Client scopes**
4. Lägg till `groups` scope

### Certificate Guardian Konfiguration

```yaml
auth:
  mode: "oidc"
  oidc:
    # Keycloak realm URL
    issuer: "https://keycloak.example.com/realms/myrealm"

    # Client credentials
    client_id: "cert-guardian"
    client_secret: "your-client-secret-from-keycloak"

    # Rollmappning - använd Keycloak realm roles eller groups
    admin_groups: ["cert-admin", "/Admin"]
    editor_groups: ["cert-editor", "/Editors"]
```

### Frontend Konfiguration

Frontend behöver konfigureras för Keycloak login:

```javascript
// .env eller vite config
VITE_AUTH_MODE=oidc
VITE_KEYCLOAK_URL=https://keycloak.example.com
VITE_KEYCLOAK_REALM=myrealm
VITE_KEYCLOAK_CLIENT_ID=cert-guardian
```

### Flöde

```
┌─────────┐     ┌──────────┐     ┌──────────────────┐
│ Browser │────>│ Frontend │────>│ Keycloak Login   │
└─────────┘     └──────────┘     └──────────────────┘
                                         │
                                         v
                              ┌──────────────────────┐
                              │ JWT Token med roller │
                              └──────────────────────┘
                                         │
                                         v
┌─────────┐     ┌──────────┐     ┌──────────────────┐
│ Browser │<────│ Frontend │<────│ Backend validerar│
│         │     │  (token) │     │ JWT via JWKS     │
└─────────┘     └──────────┘     └──────────────────┘
```

### Test

```bash
# Hämta token från Keycloak
TOKEN=$(curl -s -X POST \
  "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=cert-guardian" \
  -d "client_secret=your-secret" \
  -d "username=testuser" \
  -d "password=testpass" \
  -d "grant_type=password" | jq -r '.access_token')

# Använd token mot API
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/auth/me
```

---

## Pomerium (Proxy Auth)

Använd Pomerium som identity-aware proxy framför Certificate Guardian.

### Förberedelser

1. Installera och konfigurera Pomerium
2. Konfigurera identity provider (Google, Azure AD, Okta, etc.)
3. Skapa policy för Certificate Guardian

### Pomerium Policy

```yaml
# pomerium-config.yaml
routes:
  - from: https://certguardian.example.com
    to: http://cert-guardian-frontend:80
    policy:
      - allow:
          or:
            - domain:
                is: example.com
    pass_identity_headers: true

  - from: https://certguardian.example.com
    to: http://cert-guardian-backend:8000
    prefix: /api
    policy:
      - allow:
          or:
            - domain:
                is: example.com
    pass_identity_headers: true
```

### Certificate Guardian Konfiguration

```yaml
auth:
  mode: "proxy"
  proxy:
    # Pomerium JWKS endpoint för JWT-validering
    jwt_issuer: "https://authenticate.example.com"
    jwks_url: "https://authenticate.example.com/.well-known/pomerium/jwks.json"

    # Headers som Pomerium sätter
    email_header: "X-Pomerium-Claim-Email"
    groups_header: "X-Pomerium-Claim-Groups"
    jwt_header: "X-Pomerium-Jwt-Assertion"

    # Rollmappning baserat på grupper
    admin_groups: ["cert-admins@example.com", "security-team@example.com"]
    editor_groups: ["cert-editors@example.com", "devops@example.com"]
```

### Gruppkonfiguration i Identity Provider

#### Google Workspace

1. Skapa grupper i Google Admin:
   - `cert-admins@example.com`
   - `cert-editors@example.com`
2. Lägg till användare i grupperna
3. Konfigurera Pomerium att inkludera grupper i claims

#### Azure AD

1. Skapa grupper i Azure AD
2. Konfigurera Pomerium Azure AD connector med group claims
3. Mappa grupp-ID eller namn i config

### Flöde

```
┌─────────┐     ┌──────────┐     ┌──────────────────┐
│ Browser │────>│ Pomerium │────>│ Identity Provider│
└─────────┘     └──────────┘     │ (Google/Azure)   │
                                 └──────────────────┘
                                         │
                                         v
                              ┌──────────────────────┐
                              │ Authenticated user   │
                              │ + groups/claims      │
                              └──────────────────────┘
                                         │
                                         v
┌─────────┐     ┌──────────┐     ┌──────────────────┐
│ Browser │<────│ Pomerium │<────│ Backend          │
│         │     │ (headers)│     │ (läser headers)  │
└─────────┘     └──────────┘     └──────────────────┘
```

### Headers som Pomerium skickar

| Header | Innehåll |
|--------|----------|
| `X-Pomerium-Claim-Email` | user@example.com |
| `X-Pomerium-Claim-Groups` | ["group1", "group2"] |
| `X-Pomerium-Jwt-Assertion` | Signerad JWT |

### Test

```bash
# Simulera Pomerium headers (för test)
curl -H "X-Pomerium-Claim-Email: admin@example.com" \
     -H 'X-Pomerium-Claim-Groups: ["cert-admins@example.com"]' \
     http://localhost:8000/api/auth/me
```

---

## Rollmappning

Roller bestäms baserat på gruppmedlemskap.

### Hierarki

```
admin > editor > viewer
```

En användare med `admin`-roll har automatiskt `editor` och `viewer` behörigheter.

### Konfiguration

```yaml
auth:
  # Fungerar för både oidc och proxy mode
  oidc:  # eller proxy:
    # Användare i dessa grupper blir admins
    admin_groups:
      - "cert-admins"
      - "/Admin"
      - "security-team@example.com"

    # Användare i dessa grupper blir editors
    editor_groups:
      - "cert-editors"
      - "/Editors"
      - "devops@example.com"

    # Alla andra autentiserade användare blir viewers
```

### Prioritet

1. Om användaren är i någon `admin_groups` -> `admin`
2. Om användaren är i någon `editor_groups` -> `editor`
3. Annars -> `viewer`

---

## Säkerhetsrekommendationer

### HTTPS

Använd alltid HTTPS i produktion:

```yaml
# Nginx reverse proxy
server {
    listen 443 ssl;
    server_name certguardian.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### JWT Secret (Local Mode)

Sätt ett starkt JWT secret:

```yaml
auth:
  local:
    jwt_secret: "min-32-tecken-langa-hemliga-nyckel-har"
```

Eller via miljövariabel:
```bash
export CERT_GUARDIAN_JWT_SECRET="your-secret-key"
```

### CORS

Begränsa CORS i produktion:

```python
# backend/api.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://certguardian.example.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Cookie Security

I produktion, aktivera secure cookies:

```python
response.set_cookie(
    key="refresh_token",
    value=token,
    httponly=True,
    secure=True,  # Kräver HTTPS
    samesite="strict",
    max_age=30 * 24 * 60 * 60
)
```

---

## Felsökning

### Token expired

```
{"detail": "Token has expired"}
```

- Access tokens är kortlivade (default 15 min)
- Frontend bör automatiskt refresha token
- Kontrollera klockor är synkade (NTP)

### Invalid token

```
{"detail": "Invalid token"}
```

- Kontrollera JWT secret/JWKS URL
- Verifiera issuer matchar
- Kontrollera client_id/audience

### Forbidden (403)

```
{"detail": "Editor role required"}
```

- Användaren har inte rätt roll
- Kontrollera gruppmedlemskap i IdP
- Verifiera rollmappning i config

### Keycloak: Can't find signing key

- Kontrollera att issuer URL är korrekt
- Verifiera att Keycloak är nåbar från backend
- Kontrollera JWKS endpoint: `curl https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs`

### Pomerium: Headers not received

- Kontrollera att `pass_identity_headers: true` är satt
- Verifiera att backend tar emot rätt headers
- Logga inkommande headers för debug

```python
# Temporär debug i api.py
@app.middleware("http")
async def log_headers(request, call_next):
    print(dict(request.headers))
    return await call_next(request)
```

---

## Migration mellan lägen

### Local -> OIDC

1. Skapa användare i Keycloak med samma email
2. Tilldela roller i Keycloak
3. Uppdatera config till `mode: "oidc"`
4. Starta om backend

Lokala användare blir kvar i databasen men används inte.

### OIDC -> Local

1. Skapa lokala användare via API eller direkt i databas
2. Uppdatera config till `mode: "local"`
3. Starta om backend

---

## Exempel: Komplett Keycloak Setup

### 1. docker-compose med Keycloak

```yaml
version: '3.8'
services:
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    environment:
      - KEYCLOAK_ADMIN=admin
      - KEYCLOAK_ADMIN_PASSWORD=admin
    command: start-dev
    ports:
      - "8080:8080"

  cert-guardian-backend:
    build:
      context: .
      dockerfile: Dockerfile.backend
    volumes:
      - ./config:/app/config:ro
      - ./data:/app/data:U
    ports:
      - "8000:8000"

  cert-guardian-frontend:
    build:
      context: ./frontend
    ports:
      - "3000:80"
```

### 2. config.yaml

```yaml
database:
  path: "data/certificates.db"

auth:
  mode: "oidc"
  oidc:
    issuer: "http://localhost:8080/realms/master"
    client_id: "cert-guardian"
    client_secret: "your-keycloak-client-secret"
    admin_groups: ["cert-admin"]
    editor_groups: ["cert-editor"]
```

### 3. Starta

```bash
podman-compose up -d
# Konfigurera Keycloak client via admin UI på http://localhost:8080
```
