# Certificate Guardian - Web Application

Full-featured web application for monitoring TLS certificate expiry with a modern React frontend and FastAPI backend.

## Features

### Dashboard
- **Real-time Statistics** - Total certificates, expiring 7/30/90 dagar, self-signed, untrusted
- **Expiry Timeline Chart** - Visualize when certificates expire over time
- **Urgent Alerts** - Quick view of certificates expiring soon
- **One-Click Scanning** - Trigger manual scans from the UI (editor+)
- **TLS hygiene** - Indikatorer för weak keys, legacy TLS, senaste certförändring

### Certificates View
- **Comprehensive List** - All monitored certificates with status
- **Advanced Filtering** - Search, filter by expiry, trust status
- **Statusfilter** - Expired/Urgent/Warning/Valid
- **Sortable Columns** - Sort by certificate, endpoints, expiry, trust status
- **Color-Coded Status** - Easy visual identification of issues
- **Trust Validation** - See which certs are self-signed or untrusted
- **Detaljvy på klick** - SAN, key size, signature, TLS/cipher, scan history
- **Badges** - Snabba varningsflaggor (hostname mismatch, weak signature, OCSP/CRL saknas, m.m.)

### Endpoints Management
- **Add/Remove Endpoints** - Full CRUD operations (editor+)
- **Per-Endpoint Scanning** - Scan individual endpoints on demand
- **Criticality Levels** - Mark endpoints as low/medium/high/critical
- **Owner Assignment** - Track responsibility for each endpoint
- **Recent Scan Trend** - Mini-graf med senaste scanningsstatus
- **Per-Endpoint Webhooks** - Configure specific Mattermost webhook per endpoint
- **Search & Filter** - Search by host/owner, filter by criticality, expiry, webhook status
- **Sortable Columns** - Sort by any column
- **Ägarskap** - Endpoints kan endast ändras/raderas av skaparen eller admin

### Network Sweeps
- **IP Range Scanning** - Discover TLS endpoints in your network (editor+)
- **CIDR Support** - Use notation like `192.168.1.0/24`
- **Range Support** - Use notation like `10.0.0.1-50`
- **Custom Ports** - Scan port 443 and additional ports
- **Auto-Create Endpoints** - Discovered services added automatically
- **Progress Tracking** - Real-time progress during sweep
- **Batch Configuration** - Set owner, criticality, webhook for all discovered endpoints
- **Rescan** - Starta om befintliga sweeps
- **Ägarskap** - Sweeps kan endast ändras/raderas av skaparen eller admin

### Settings
- **Custom CA Management** - Add trusted root CAs for internal PKI (editor+)
- **CA Upload** - Upload PEM files or paste certificate data
- **Trust Verification** - Certificates signed by custom CAs show as trusted
- **Scanner Interval** - Ändra scan-intervall i UI (admin)
- **Database Health** - Storlek, tabellräkningar och scan-volym (admin)
- **SIEM Forwarding** - Syslog/Beats med TLS + test-event (admin)

### About
- **Feature Overview** - Beskrivning av vad appen gör och vilka signaler som spåras

### User Management (Admin)
- **User List** - View all users with roles
- **Create Users** - Add new users with role assignment
- **Edit Users** - Change roles, deactivate accounts

### Audit Logs (Admin)
- **Dedicated Page** - Filter på användare/action
- **Audit trail** - Inloggning, ändringar och administrativa handlingar

## Role-Based Access Control

| Feature | Viewer | Editor | Admin |
|---------|--------|--------|-------|
| View dashboard & stats | Yes | Yes | Yes |
| View certificates | Yes | Yes | Yes |
| View endpoints | Yes | Yes | Yes |
| Create/edit endpoints | No | Yes | Yes |
| Trigger scans | No | Yes | Yes |
| Run network sweeps | No | Yes | Yes |
| Manage trusted CAs | No | Yes | Yes |
| Manage users | No | No | Yes |
| View audit logs | No | No | Yes |
| Configure SIEM | No | No | Yes |

**Notering:** Endpoints och sweeps kan endast ändras/raderas av skaparen eller admin.

## Architecture

```
+-----------------------------------------------------+
|              React Frontend (Vite)                  |
|  +----------+ +----------+ +----------------+       |
|  |Dashboard | |  Certs   | |   Endpoints    |       |
|  +----------+ +----------+ +----------------+       |
|  +----------+ +----------+ +----------------+       |
|  | Security | | Settings | |     Users      |       |
|  +----------+ +----------+ +----------------+       |
|  +--------------------------------------------+    |
|  |     AuthContext + API Service Layer        |    |
|  +--------------------------------------------+    |
+-------------------------+---------------------------+
                          | HTTP/REST + JWT
+-------------------------+---------------------------+
|            FastAPI Backend (Python)                 |
|  +----------------------------------------------+  |
|  |  Auth (Local/Pomerium/Keycloak)              |  |
|  +----------------------------------------------+  |
|  |  REST API Endpoints                          |  |
|  +----------------------------------------------+  |
|  |  Database Layer (SQLite)                     |  |
|  +----------------------------------------------+  |
|  |  TLS Scanner + Notifier                      |  |
|  +----------------------------------------------+  |
+-----------------------------------------------------+
```

## Quick Start

### Option 1: Podman Compose (Recommended)

```bash
# Configure
cp config/config.yaml.example config/config.yaml
nano config/config.yaml

# Build and start
podman-compose -f docker-compose-webapp.yaml up -d

# Access:
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs

# Default login (local mode):
# Username: admin
# Password: admin
```

### Option 2: Development Mode

**Backend:**
```bash
pip install -r requirements.txt
pip install -r backend/requirements.txt

cd backend
uvicorn api:app --reload --host 0.0.0.0 --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
# http://localhost:3000
```

## Authentication

Certificate Guardian supports three authentication modes:

### Local Mode (Default)
Built-in user management with JWT tokens.

```yaml
auth:
  mode: "local"
  local:
    access_token_expire_minutes: 15
    refresh_token_expire_days: 30
```

### Pomerium (Proxy Auth)
Use Pomerium as identity-aware proxy.

```yaml
auth:
  mode: "proxy"
  proxy:
    jwks_url: "https://authenticate.example.com/.well-known/pomerium/jwks.json"
    admin_groups: ["cert-admins@example.com"]
    editor_groups: ["cert-editors@example.com"]
```

### Keycloak (OIDC)
Enterprise SSO with Keycloak or other OIDC providers.

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

See [AUTHENTICATION.md](AUTHENTICATION.md) for detailed setup instructions.

## API Documentation

Full API reference available at:
- Interactive docs: `http://localhost:8000/docs`
- Documentation: [API.md](API.md)

### Key Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | /api/dashboard/stats | Any | Dashboard statistics |
| GET | /api/certificates | Any | List certificates |
| GET | /api/endpoints | Any | List endpoints |
| POST | /api/endpoints | Editor+ | Create endpoint |
| POST | /api/scan | Editor+ | Trigger scan |
| POST | /api/sweeps | Editor+ | Start network sweep |
| POST | /api/sweeps/{id}/restart | Editor+ | Restart sweep |
| GET | /api/users | Admin | List users |
| GET | /api/audit-logs | Admin | View audit logs |
| GET | /api/settings/scanner | Any | Read scanner settings |
| PUT | /api/settings/scanner | Admin | Update scan interval |
| GET | /api/settings/db-health | Admin | DB health stats |
| GET | /api/settings/siem | Admin | Read SIEM settings |
| PUT | /api/settings/siem | Admin | Update SIEM settings |
| POST | /api/settings/siem/test | Admin | Send SIEM test event |

## Configuration

### Backend Configuration

Edit `config/config.yaml`:

```yaml
database:
  path: "data/certificates.db"

mattermost:
  webhook_url: "https://your-mattermost.com/hooks/xxxxx"
  username: "Certificate Guardian"
  icon_emoji: ":lock:"

scanner:
  interval_seconds: 3600
  timeout_seconds: 10

siem:
  mode: "disabled"  # disabled | syslog | beats
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

### Frontend Configuration

For production, set environment variable:

```bash
VITE_API_URL=https://your-api-domain.com
```

## Deployment

### Docker Compose

```bash
# Production deployment
docker-compose -f docker-compose-webapp.yaml up -d

# View logs
docker-compose -f docker-compose-webapp.yaml logs -f

# Stop services
docker-compose -f docker-compose-webapp.yaml down
```

### Reverse Proxy (Nginx)

```nginx
server {
    listen 443 ssl;
    server_name certguardian.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Frontend
    location / {
        proxy_pass http://localhost:3000;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security Considerations

### HTTPS
Always use HTTPS in production. Configure via:
- Reverse proxy (nginx, Traefik)
- Cloud load balancer
- Let's Encrypt

### CORS
Update backend for production:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-domain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Audit Logging
All modifications are logged:
- Who performed the action
- What was changed
- When it happened
- Client IP address

View audit logs via Admin -> Audit Logs or API:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/audit-logs
```

## Tech Stack

### Frontend
- **React 18** - UI framework
- **React Router** - Client-side routing
- **Axios** - HTTP client
- **Recharts** - Charts and data visualization
- **Tailwind CSS** - Styling
- **Lucide React** - Icons
- **Vite** - Build tool

### Backend
- **FastAPI** - Modern Python web framework
- **Uvicorn** - ASGI server
- **Pydantic** - Data validation
- **SQLite** - Database
- **PyJWT** - JWT handling
- **bcrypt** - Password hashing
- **httpx** - Async HTTP client

## Troubleshooting

### Backend won't start

```bash
# Check logs
docker logs cert-guardian-backend

# Common issues:
# 1. Database path incorrect
# 2. Config file not found
# 3. Port 8000 already in use
```

### Authentication issues

```bash
# Check auth mode
curl http://localhost:8000/api/auth/mode

# Test login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

### Database locked error

```bash
# Stop all services
docker-compose -f docker-compose-webapp.yaml down

# Remove lock file
rm data/certificates.db-journal

# Restart
docker-compose -f docker-compose-webapp.yaml up -d
```

### Database read-only (Podman rootless)

Use `:U` suffix on volume mounts:
```yaml
volumes:
  - ./data:/app/data:U
```

## Updates and Maintenance

### Updating the Application

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose -f docker-compose-webapp.yaml up -d --build
```

### Database Backup

```bash
# Backup database
cp data/certificates.db backups/certificates-$(date +%Y%m%d).db

# Automate with cron
0 2 * * * cp /path/to/data/certificates.db /backup/cert-guardian-$(date +\%Y\%m\%d).db
```

## Related Documentation

- [README.md](README.md) - Project overview
- [INSTALL.md](INSTALL.md) - Installation guide
- [API.md](API.md) - Complete API reference
- [AUTHENTICATION.md](AUTHENTICATION.md) - Auth setup (Keycloak/Pomerium)
- [CA_VALIDATION.md](CA_VALIDATION.md) - Custom CA management

## License

MIT License - Use freely in your organization.
