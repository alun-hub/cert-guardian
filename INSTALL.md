# Certificate Guardian - Installation Guide

## Projektstruktur

```
cert-guardian/
├── src/                  # Core Python (scanner, database, notifier)
├── backend/              # FastAPI REST API
├── frontend/             # React webbgränssnitt
│   └── src/pages/        # Dashboard, Certificates, Endpoints, Security
├── config/               # Konfigurationsfiler
├── kubernetes/           # K8s/OpenShift manifests
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

# 4. Verifiera
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

### OpenShift med Podman build

```bash
# Bygg lokalt med Podman
podman build -t cert-guardian .
podman build -t cert-guardian-backend -f Dockerfile.backend .
podman build -t cert-guardian-frontend frontend/

# Pusha till OpenShift registry
podman login -u $(oc whoami) -p $(oc whoami -t) image-registry.openshift-image-registry.svc:5000
podman tag cert-guardian image-registry.openshift-image-registry.svc:5000/cert-guardian/scanner:latest
podman push image-registry.openshift-image-registry.svc:5000/cert-guardian/scanner:latest
```

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

### Testa webbgränssnitt

```bash
# Health check
curl http://localhost:8000/health

# Trigga scan via API
curl -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"endpoint_id": null}'
```

### Lägg till endpoints

**Via webbgränssnitt:** Gå till Endpoints → Add Endpoint

**Via config:**
1. Redigera `config/config.yaml`
2. Restarta: `podman-compose restart scanner`

### Övervaka

```bash
# Podman logs
podman logs -f cert-guardian-scanner
podman logs -f cert-guardian-backend

# API stats
curl http://localhost:8000/api/dashboard/stats

# Databas (native)
sqlite3 data/certificates.db "SELECT COUNT(*) FROM certificates"
```

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

Om scannern rapporterar "attempt to write a readonly database":

```bash
# Problemet: Podman rootless mappar UID:s annorlunda
# Lösning: Sätt skrivbara permissions på databasfilen
chmod 666 data/certificates.db
podman restart cert-guardian-scanner
```

**OBS:** Nya databaser skapas nu automatiskt med rätt permissions (fixat i koden).

### Frontend kan inte nå backend

1. Kolla CORS i api.py
2. Verifiera backend: `curl http://localhost:8000/health`
3. Kolla network: `podman network ls`

### Container startar inte

```bash
# Kolla build-fel
podman build -t cert-guardian . 2>&1 | tail -20

# Kolla permissions
ls -la data/ config/
```

## Säkerhet

1. **Skydda config** - innehåller webhook URL
   ```bash
   chmod 600 config/config.yaml
   ```

2. **Rootless Podman** - kör utan root
   ```bash
   podman-compose up -d  # körs som din användare
   ```

3. **HTTPS för webbgränssnitt** - använd reverse proxy
   ```bash
   # Se nginx.conf för exempel
   ```

4. **Autentisering** - ej inkluderat, lägg till OAuth2/OIDC för produktion

5. **Backup**
   ```bash
   cp data/certificates.db backup/cert-guardian-$(date +%Y%m%d).db
   ```

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

## Monitoring

```bash
# Health endpoint
curl http://localhost:8000/health

# Dashboard stats
curl http://localhost:8000/api/dashboard/stats

# Container status
podman ps --filter name=cert-guardian
```

## Support

Kontakta IT Security team eller öppna ärende i ticketsystemet.
