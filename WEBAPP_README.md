# Certificate Guardian - Web Application

Full-featured web application for monitoring TLS certificate expiry with a modern React frontend and FastAPI backend.

## 🎨 Features

### Dashboard
- **Real-time Statistics** - Total certificates, expiring soon, self-signed, untrusted
- **Expiry Timeline Chart** - Visualize when certificates expire over time
- **Urgent Alerts** - Quick view of certificates expiring soon
- **One-Click Scanning** - Trigger manual scans from the UI

### Certificates View
- **Comprehensive List** - All monitored certificates with status
- **Advanced Filtering** - Search, filter by expiry, trust status
- **Sortable Columns** - Sort by certificate, endpoints, expiry, trust status
- **Color-Coded Status** - Easy visual identification of issues
- **Trust Validation** - See which certs are self-signed or untrusted

### Endpoints Management
- **Add/Remove Endpoints** - Full CRUD operations
- **Per-Endpoint Scanning** - Scan individual endpoints on demand
- **Criticality Levels** - Mark endpoints as low/medium/high/critical
- **Owner Assignment** - Track responsibility for each endpoint
- **Per-Endpoint Webhooks** - Configure specific Mattermost webhook per endpoint
- **Search & Filter** - Search by host/owner, filter by criticality, expiry, webhook status
- **Sortable Columns** - Sort by any column

### Network Sweeps
- **IP Range Scanning** - Discover TLS endpoints in your network
- **CIDR Support** - Use notation like `192.168.1.0/24`
- **Range Support** - Use notation like `10.0.0.1-50`
- **Custom Ports** - Scan port 443 and additional ports
- **Auto-Create Endpoints** - Discovered services added automatically
- **Progress Tracking** - Real-time progress during sweep
- **Batch Configuration** - Set owner, criticality, webhook for all discovered endpoints

### Security Dashboard
- **Security Issues Overview** - Self-signed and untrusted certificates
- **Detailed Recommendations** - Action items for each issue
- **Validation Errors** - See exactly what's wrong with each cert

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│              React Frontend (Vite)              │
│  ┌──────────┐ ┌──────────┐ ┌────────────────┐ │
│  │Dashboard │ │  Certs   │ │   Endpoints    │ │
│  └──────────┘ └──────────┘ └────────────────┘ │
│  ┌──────────┐ ┌──────────────────────────────┐ │
│  │ Security │ │     API Service Layer        │ │
│  └──────────┘ └──────────────────────────────┘ │
└────────────────────┬────────────────────────────┘
                     │ HTTP/REST
┌────────────────────┴────────────────────────────┐
│            FastAPI Backend (Python)             │
│  ┌──────────────────────────────────────────┐  │
│  │  REST API Endpoints                      │  │
│  ├──────────────────────────────────────────┤  │
│  │  Database Layer (SQLite)                 │  │
│  ├──────────────────────────────────────────┤  │
│  │  TLS Scanner + Notifier                  │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## Quick Start

### Option 1: Podman Compose (Rekommenderad)

```bash
# Konfigurera
cp config/config.yaml.example config/config.yaml
nano config/config.yaml

# Bygg och starta
podman-compose -f docker-compose-webapp.yaml up -d

# Åtkomst:
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
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

## 📡 API Documentation

### Endpoints

**Dashboard:**
- `GET /api/dashboard/stats` - Get dashboard statistics
- `GET /api/timeline?months=12` - Get expiry timeline

**Certificates:**
- `GET /api/certificates` - List all certificates
  - Query params: `expiring_days`, `self_signed`, `untrusted`, `limit`, `offset`
- `GET /api/certificates/{id}` - Get certificate details

**Endpoints:**
- `GET /api/endpoints` - List all endpoints
- `POST /api/endpoints` - Create new endpoint
- `PUT /api/endpoints/{id}` - Update endpoint
- `DELETE /api/endpoints/{id}` - Delete endpoint

**Scanning:**
- `POST /api/scan` - Trigger scan
  - Body: `{"endpoint_id": 1}` or `{"endpoint_id": null}` for all

**Network Sweeps:**
- `GET /api/sweeps` - List all sweeps
- `POST /api/sweeps` - Create and start a new sweep
  - Body: `{"name": "Office Network", "target": "192.168.1.0/24", "ports": [443, 8443], "owner": "IT", "criticality": "medium"}`
- `GET /api/sweeps/{id}` - Get sweep details with results
- `DELETE /api/sweeps/{id}` - Delete a sweep
- `POST /api/sweeps/validate` - Validate target and get IP count
  - Body: `{"target": "10.0.0.0/24"}`

**Security:**
- `GET /api/security/issues` - Get all security issues

**Webhooks:**
- `POST /api/webhooks/test` - Test a webhook URL
  - Body: `{"webhook_url": "https://...", "message": "Test"}`

**Health:**
- `GET /health` - Health check

### Interactive API Docs

Visit `http://localhost:8000/docs` for interactive Swagger UI documentation.

## 🎨 Frontend Tech Stack

- **React 18** - UI framework
- **React Router** - Client-side routing
- **Axios** - HTTP client
- **Recharts** - Charts and data visualization
- **Tailwind CSS** - Styling
- **Lucide React** - Icons
- **Vite** - Build tool
- **date-fns** - Date formatting

## ⚙️ Backend Tech Stack

- **FastAPI** - Modern Python web framework
- **Uvicorn** - ASGI server
- **Pydantic** - Data validation
- **SQLite** - Database
- **Existing Scanner/Notifier** - Reuses core Certificate Guardian code

## 🔧 Configuration

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
```

### Frontend Configuration

For production, set environment variable:

```bash
VITE_API_URL=https://your-api-domain.com
```

## 🐳 Deployment

### Docker Compose

```bash
# Production deployment
docker-compose -f docker-compose-webapp.yaml up -d

# View logs
docker-compose -f docker-compose-webapp.yaml logs -f

# Stop services
docker-compose -f docker-compose-webapp.yaml down
```

### Kubernetes

Create deployments for:
1. Backend (FastAPI)
2. Frontend (Nginx)
3. Scanner (Cron job)

Example:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-guardian-backend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: cert-guardian-backend
  template:
    spec:
      containers:
      - name: backend
        image: cert-guardian-backend:latest
        ports:
        - containerPort: 8000
```

### Reverse Proxy (Nginx/Traefik)

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
    }
}
```

## 🔒 Security Considerations

### Authentication

**Not Included by Default.** For production, add:

1. **OAuth2/OIDC** - Integrate with your SSO
2. **JWT Tokens** - For API authentication
3. **RBAC** - Role-based access control

Example FastAPI middleware:

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer

security = HTTPBearer()

async def verify_token(credentials = Depends(security)):
    # Verify JWT token
    pass

@app.get("/api/protected", dependencies=[Depends(verify_token)])
async def protected_route():
    pass
```

### HTTPS

Always use HTTPS in production:
- Let's Encrypt for free SSL certificates
- Cloudflare for SSL proxy
- Cloud provider load balancers with SSL termination

### CORS

Update backend `api.py`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-domain.com"],  # Specify your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## 📊 Monitoring

### Application Monitoring

```bash
# Backend health
curl http://localhost:8000/health

# Check logs
docker logs cert-guardian-backend -f
docker logs cert-guardian-frontend -f
```

### Metrics

Add Prometheus metrics:

```python
from prometheus_client import Counter, Histogram
from prometheus_fastapi_instrumentator import Instrumentator

instrumentator = Instrumentator()
instrumentator.instrument(app).expose(app)
```

## 🐛 Troubleshooting

### Backend won't start

```bash
# Check logs
docker logs cert-guardian-backend

# Common issues:
# 1. Database path incorrect
# 2. Config file not found
# 3. Port 8000 already in use
```

### Frontend can't connect to backend

```bash
# Check CORS settings in backend
# Check proxy configuration in vite.config.js
# Verify backend is running: curl http://localhost:8000/health
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

### Scanning not working

```bash
# Check network connectivity from container
docker exec cert-guardian-backend ping google.com

# Check scanner logs
docker logs cert-guardian-scanner
```

## 🔄 Updates and Maintenance

### Updating the Application

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose -f docker-compose-webapp.yaml up -d --build

# Or manually
docker-compose -f docker-compose-webapp.yaml build
docker-compose -f docker-compose-webapp.yaml up -d
```

### Database Backup

```bash
# Backup database
cp data/certificates.db backups/certificates-$(date +%Y%m%d).db

# Automate with cron
0 2 * * * cp /path/to/data/certificates.db /backup/cert-guardian-$(date +\%Y\%m\%d).db
```

## 🎯 Roadmap

- [x] ~~Network sweep for IP range scanning~~
- [x] ~~Per-endpoint webhook configuration~~
- [x] ~~Search, filter, sort on all pages~~
- [ ] User authentication and authorization
- [ ] Multi-tenancy support
- [ ] Certificate renewal workflows
- [ ] Slack integration alongside Mattermost
- [ ] Export reports (PDF, CSV)
- [ ] Custom dashboards
- [ ] Alert rules configuration UI
- [ ] Dark mode
- [ ] Mobile responsive improvements

## 📝 License

MIT License - Use freely in your organization.

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📧 Support

For issues or questions:
- Check the documentation
- Review API docs at `/docs`
- Contact your IT Security team
