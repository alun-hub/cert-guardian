# Certificate Guardian - Installation Guide

## Projektstruktur

```
cert-guardian/
├── src/                  # Core Python (scanner, database, notifier, auth)
├── backend/              # FastAPI REST API
├── frontend/             # React webbgränssnitt
│   └── src/pages/        # Dashboard, Certificates, Endpoints, Security, Users
├── config/               # Konfigurationsfiler
├── kubernetes/           # K8s/OpenShift manifests
├── helm/cert-guardian/   # Helm chart
├── data/                 # SQLite databas (gitignored)
└── tests/                # Tester
```

---

## Option 1: Podman Installation (Rekommenderad)

### Scanner endast (utan webbgränssnitt)

```bash
# 1. Klona projektet
git clone <repo> cert-guardian && cd cert-guardian

# 2. Konfigurera
cp config/config.yaml.example config/config.yaml
nano config/config.yaml  # Sätt webhook URL och endpoints

# 3. Bygg image
podman build -t cert-guardian .

# 4. Kör med podman-compose
podman-compose up -d

# 5. Verifiera
podman logs -f cert-guardian
```

### Med webbgränssnitt (Frontend + Backend + Scanner)

```bash
# 1. Konfigurera
cp config/config.yaml.example config/config.yaml
nano config/config.yaml

# 2. Bygg och starta alla tjänster
podman-compose -f docker-compose-webapp.yaml up -d

# 3. Åtkomst
# Frontend:  http://localhost:3000
# API:       http://localhost:8000
# API Docs:  http://localhost:8000/docs

# 4. Login (local mode)
# Användarnamn: admin
# Lösenord: admin (ÄNDRA OMEDELBART!)

# 5. Verifiera
podman logs -f cert-guardian-backend
podman logs -f cert-guardian-frontend
podman logs -f cert-guardian-scanner
```

### Podman med systemd (rootless)

```bash
# Generera systemd-filer
podman generate systemd --new --name cert-guardian > ~/.config/systemd/user/cert-guardian.service

# Aktivera
systemctl --user daemon-reload
systemctl --user enable --now cert-guardian

# Autostart vid boot (utan inloggning)
loginctl enable-linger $USER
```

---

## Option 2: OpenShift/Kubernetes

```bash
# Logga in (OpenShift)
oc login https://api.cluster.example.com:6443

# Skapa projekt/namespace
oc new-project cert-guardian
# eller: kubectl create namespace cert-guardian

# Skapa secret med config
oc create secret generic cert-guardian-config \
  --from-file=config.yaml=config/config.yaml

# Applicera deployment
oc apply -f deployment.yaml

# Verifiera
oc get pods
oc logs -f deployment/cert-guardian

# Exponera webbgränssnitt (OpenShift)
oc expose service cert-guardian-frontend
oc get route
```

### Helm Chart (rekommenderat för Kubernetes)

```bash
# Grundinstallation
helm install cert-guardian helm/cert-guardian/ \
  --set config.mattermost.webhookUrl="https://mattermost.example.com/hooks/xxx" \
  -n cert-guardian --create-namespace

# Med Ingress, TLS och Prometheus
helm install cert-guardian helm/cert-guardian/ \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=certguardian.example.com \
  --set ingress.tls[0].secretName=cert-guardian-tls \
  --set ingress.tls[0].hosts[0]=certguardian.example.com \
  --set metrics.serviceMonitor.enabled=true \
  -n cert-guardian --create-namespace

# Avinstallera
helm uninstall cert-guardian -n cert-guardian
```

Se `helm/cert-guardian/values.yaml` för alla inställningar.

---

## Option 3: Native Installation (systemd)

```bash
# 1. Skapa användare
sudo useradd -r -s /bin/false certguardian

# 2. Skapa installation
sudo mkdir -p /opt/cert-guardian/{src,config,data}
sudo cp src/*.py /opt/cert-guardian/src/
sudo cp config/config.yaml.example /opt/cert-guardian/config/config.yaml
sudo cp requirements.txt /opt/cert-guardian/

# 3. Installera dependencies
sudo pip3 install -r /opt/cert-guardian/requirements.txt

# 4. Konfigurera
sudo nano /opt/cert-guardian/config/config.yaml

# 5. Sätt permissions
sudo chown -R certguardian:certguardian /opt/cert-guardian

# 6. Test
sudo -u certguardian python3 /opt/cert-guardian/src/main.py --once

# 7. Installera services
sudo cp cert-guardian*.service cert-guardian*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cert-guardian
sudo systemctl enable --now cert-guardian-summary.timer

# 8. Verifiera
sudo systemctl status cert-guardian
sudo journalctl -u cert-guardian -f
```

---

## Autentiseringskonfiguration

### Local Mode (Default)

Enklaste setup med inbyggd användarhantering:

```yaml
auth:
  mode: "local"
  local:
    access_token_expire_minutes: 15
    refresh_token_expire_days: 30
```

**Första start:** Admin-konto skapas automatiskt
- Användarnamn: `admin`
- Lösenord: `admin`

Ändra lösenord via miljövariabel före start:
```bash
export CERT_GUARDIAN_ADMIN_PASSWORD="securepassword"
```

### Keycloak (OIDC)

Enterprise SSO med Keycloak:

```yaml
auth:
  mode: "oidc"
  oidc:
    issuer: "https://keycloak.example.com/realms/myrealm"
    client_id: "cert-guardian"
    client_secret: "your-client-secret"
    admin_groups: ["cert-admin"]
    editor_groups: ["cert-editor"]
```

**Keycloak setup:**
1. Skapa client `cert-guardian` med Client authentication ON
2. Sätt Valid redirect URIs: `https://certguardian.example.com/*`
3. Skapa realm roles: `cert-admin`, `cert-editor`
4. Tilldela roller till användare

Se [AUTHENTICATION.md](AUTHENTICATION.md) för detaljerad guide.

### Pomerium (Proxy Auth)

SSO via Pomerium proxy:

```yaml
auth:
  mode: "proxy"
  proxy:
    jwt_issuer: "https://authenticate.example.com"
    jwks_url: "https://authenticate.example.com/.well-known/pomerium/jwks.json"
    email_header: "X-Pomerium-Claim-Email"
    groups_header: "X-Pomerium-Claim-Groups"
    jwt_header: "X-Pomerium-Jwt-Assertion"
    admin_groups: ["cert-admins@example.com"]
    editor_groups: ["cert-editors@example.com"]
```

Se [AUTHENTICATION.md](AUTHENTICATION.md) för detaljerad guide.

---

## Post-Installation

### Verifiera scanning

```bash
# Podman
podman exec cert-guardian python /app/src/main.py --once

# Native
python3 /opt/cert-guardian/src/main.py --once
```

### Testa Mattermost

```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"text":"Certificate Guardian aktiv!"}' \
  YOUR_WEBHOOK_URL
```

### Testa autentisering

```bash
# Check auth mode
curl http://localhost:8000/api/auth/mode

# Login (local mode)
curl -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'

# Health check
curl http://localhost:8000/health
```

### Lägg till endpoints

**Via webbgränssnitt:** Gå till Endpoints -> Add Endpoint (kräver editor-roll)

**Via API:**
```bash
TOKEN="your-jwt-token"
curl -X POST http://localhost:8000/api/endpoints \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"host":"example.com","port":443,"owner":"IT"}'
```

**Via config:**
1. Redigera `config/config.yaml`
2. Restarta: `podman-compose restart scanner`

### Skapa användare (local mode)

```bash
TOKEN="admin-jwt-token"
curl -X POST http://localhost:8000/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"editor1","password":"pass123","role":"editor"}'
```

### Visa audit logs

```bash
TOKEN="admin-jwt-token"
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/audit-logs
```

### HTTPS (valfritt)

Aktivera inbyggd TLS genom att montera certifikat:

```bash
mkdir -p certs/
# Kopiera certifikat (från cert-manager, Let's Encrypt, eller self-signed)
cp cert.pem certs/tls.crt
cp key.pem certs/tls.key

# Starta om frontend -- HTTPS aktiveras automatiskt
podman restart cert-guardian-frontend

# HTTPS: https://localhost:3443
# HTTP omdirigeras automatiskt till HTTPS
```

Self-signed cert för test:
```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/tls.key -out certs/tls.crt \
  -days 365 -subj '/CN=localhost'
```

Utan certifikat fungerar allt som vanligt via HTTP på port 3000.

### CORS-konfiguration (produktion)

CORS-origins konfigureras i `config/config.yaml`. Default `["*"]` tillåter alla origins (lämpligt för utveckling):

```yaml
server:
  cors_origins:
    - "https://certs.example.com"  # Din frontend-URL i produktion
```

### SIEM-forwarding (valfritt)

Konfigurera i `config/config.yaml` eller via Settings (admin):

```yaml
siem:
  mode: "syslog"   # disabled | stdout | syslog | beats
  host: "siem.example.com"
  port: 6514
  tls_enabled: true
  tls_verify: true
  ca_pem: ""
  client_cert_pem: ""
  client_key_pem: ""
```

Testa via UI eller API:

```bash
TOKEN="admin-jwt-token"
curl -X POST http://localhost:8000/api/settings/siem/test \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"message":"Test event"}'
```

---

## Troubleshooting

### Inga notifieringar

1. Verifiera webhook URL: `grep webhook config/config.yaml`
2. Testa webhook: `curl -X POST -d '{"text":"test"}' YOUR_URL`
3. Kolla logs: `podman logs cert-guardian-scanner`

### Connection timeouts

1. Öka timeout: `scanner.timeout_seconds: 30`
2. Testa från container: `podman exec cert-guardian-scanner openssl s_client -connect HOST:PORT`

### Database locked

```bash
podman-compose down
rm data/certificates.db-journal
podman-compose up -d
```

### Database read-only (Podman rootless)

Använd `:U` suffix på volume mounts i docker-compose:

```yaml
volumes:
  - ./data:/app/data:U
```

### Authentication issues

```bash
# Check mode
curl http://localhost:8000/api/auth/mode

# Test login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Check JWT token
curl http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### OIDC/Keycloak issues

```bash
# Verifiera issuer är nåbar
curl https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration

# Verifiera JWKS
curl https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs
```

### Frontend kan inte nå backend

1. Kolla `server.cors_origins` i config.yaml (default `["*"]` för utveckling)
2. Verifiera backend: `curl http://localhost:8000/health`
3. Kolla network: `podman network ls`

### Container startar inte

```bash
# Kolla build-fel
podman build -t cert-guardian . 2>&1 | tail -20

# Kolla permissions
ls -la data/ config/
```

---

## Säkerhet

### 1. Skydda config

```bash
chmod 600 config/config.yaml
```

### 2. Rootless Podman

```bash
podman-compose up -d  # körs som din användare
```

### 3. HTTPS för webbgränssnitt

```nginx
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
    }
}
```

### 4. Autentisering

- Ändra default admin-lösenord omedelbart
- Använd SSO (Keycloak/Pomerium) i produktion
- Begränsa editor/admin-roller

### 5. Audit logging

Alla ändringar loggas automatiskt:
- Login/logout
- CRUD-operationer
- IP-adresser

Visa med: `GET /api/audit-logs` (admin only)

### 6. Backup

```bash
cp data/certificates.db backup/cert-guardian-$(date +%Y%m%d).db
```

---

## Uppgradering

### Podman

```bash
git pull
podman-compose -f docker-compose-webapp.yaml down
podman-compose -f docker-compose-webapp.yaml up -d --build
```

### OpenShift

```bash
git pull
podman build -t cert-guardian .
podman push <registry>/cert-guardian:latest
oc rollout restart deployment/cert-guardian
```

---

## Monitoring

```bash
# Health endpoint (ingen auth)
curl http://localhost:8000/health

# Dashboard stats (kräver auth)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/dashboard/stats

# Container status
podman ps --filter name=cert-guardian

# Audit logs (admin)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/audit-logs
```

---

## Relaterad dokumentation

| Dokument | Beskrivning |
|----------|-------------|
| [README.md](README.md) | Projektöversikt |
| [WEBAPP_README.md](WEBAPP_README.md) | Webbgränssnitt |
| [API.md](API.md) | Komplett API-referens |
| [AUTHENTICATION.md](AUTHENTICATION.md) | Keycloak/Pomerium setup |
| [CA_VALIDATION.md](CA_VALIDATION.md) | Custom CA management |

---

## Support

Kontakta IT Security team eller öppna ärende i ticketsystemet.
