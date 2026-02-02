# Certificate Guardian - Installation Guide

## Installation på Linux Server

### Option 1: Native Installation

```bash
# 1. Skapa användare
sudo useradd -r -s /bin/false certguardian

# 2. Skapa installation directory
sudo mkdir -p /opt/cert-guardian
sudo chown certguardian:certguardian /opt/cert-guardian

# 3. Kopiera filer
sudo cp -r src config data /opt/cert-guardian/
sudo cp requirements.txt /opt/cert-guardian/

# 4. Installera Python dependencies
sudo pip3 install -r /opt/cert-guardian/requirements.txt

# 5. Konfigurera
sudo cp config/config.yaml.example config/config.yaml
sudo nano /opt/cert-guardian/config/config.yaml
# Uppdatera Mattermost webhook URL och endpoints

# 6. Setup endpoints
cd /opt/cert-guardian
sudo -u certguardian python3 src/main.py --setup

# 7. Test run
sudo -u certguardian python3 src/main.py --once

# 8. Installera systemd service
sudo cp cert-guardian.service /etc/systemd/system/
sudo cp cert-guardian-summary.service /etc/systemd/system/
sudo cp cert-guardian-summary.timer /etc/systemd/system/

# 9. Enable och starta
sudo systemctl daemon-reload
sudo systemctl enable cert-guardian
sudo systemctl start cert-guardian
sudo systemctl enable cert-guardian-summary.timer
sudo systemctl start cert-guardian-summary.timer

# 10. Verifiera status
sudo systemctl status cert-guardian
sudo journalctl -u cert-guardian -f
```

### Option 2: Podman/Docker Installation

```bash
# 1. Klona/kopiera projektet
git clone <repo> cert-guardian
cd cert-guardian

# 2. Konfigurera
cp config/config.yaml.example config/config.yaml
nano config/config.yaml
# Uppdatera Mattermost webhook URL och endpoints

# 3. Bygg image
podman build -t cert-guardian .

# 4. Kör med compose
podman-compose up -d

# 5. Verifiera logs
podman logs -f cert-guardian
```

### Option 3: Kubernetes Deployment

```bash
# Skapa namespace
kubectl create namespace cert-guardian

# Skapa secret med config
kubectl create secret generic cert-guardian-config \
  --from-file=config.yaml=config/config.yaml \
  -n cert-guardian

# Skapa deployment
kubectl apply -f kubernetes/deployment.yaml -n cert-guardian

# Verifiera
kubectl get pods -n cert-guardian
kubectl logs -f deployment/cert-guardian -n cert-guardian
```

## Post-Installation

### Verifiera att scanning fungerar

```bash
# Kör en manuell scan
python3 src/main.py --once

# Kolla logs
tail -f cert-guardian.log
```

### Testa Mattermost integration

```bash
# Skicka test-meddelande
curl -X POST -H 'Content-Type: application/json' \
  -d '{"text":"Certificate Guardian är nu aktiv! 🔒"}' \
  YOUR_WEBHOOK_URL
```

### Lägg till fler endpoints

1. Redigera `config/config.yaml`
2. Lägg till nya endpoints under `endpoints:` sektionen
3. Kör `python3 src/main.py --setup` för att uppdatera databasen
4. Restarta servicen: `sudo systemctl restart cert-guardian`

### Övervaka systemet

```bash
# Systemd logs
sudo journalctl -u cert-guardian -f

# Application logs
tail -f /opt/cert-guardian/cert-guardian.log

# Databas statistics
sqlite3 /opt/cert-guardian/data/certificates.db "SELECT COUNT(*) FROM certificates"
sqlite3 /opt/cert-guardian/data/certificates.db "SELECT COUNT(*) FROM certificate_scans"
```

## Troubleshooting

### Problem: Inga notifieringar skickas

**Lösning:**
1. Verifiera webhook URL i config
2. Testa webhook manuellt med curl
3. Kolla firewall regler
4. Kolla logs för error messages

### Problem: Connection timeouts

**Lösning:**
1. Öka timeout i config: `scanner.timeout_seconds: 30`
2. Verifiera att endpoints är nåbara: `openssl s_client -connect HOST:PORT`
3. Kolla network connectivity från server

### Problem: Database locked errors

**Lösning:**
1. Säkerställ att bara en instans körs
2. Kolla file permissions på data/ directory
3. Starta om servicen

### Problem: För många notifieringar

**Lösning:**
1. Justera `notifications.warning_days` i config
2. Öka check-intervallet: `scanner.interval_seconds: 7200` (2h)

## Säkerhet Best Practices

1. **Skydda config-filen** - innehåller webhook URL (secret)
   ```bash
   chmod 600 /opt/cert-guardian/config/config.yaml
   ```

2. **Kör som dedikerad användare** - använd inte root
   
3. **Begränsa nätverksaccess** - firewall rules för outbound HTTPS
   
4. **Rotera logs** - konfigurera logrotate
   ```bash
   # /etc/logrotate.d/cert-guardian
   /opt/cert-guardian/cert-guardian.log {
       daily
       rotate 7
       compress
       missingok
       notifempty
   }
   ```

5. **Backup databasen** regelbundet
   ```bash
   # Backup script
   cp /opt/cert-guardian/data/certificates.db \
      /backup/cert-guardian-$(date +%Y%m%d).db
   ```

## Uppgradering

```bash
# 1. Stoppa service
sudo systemctl stop cert-guardian

# 2. Backup config och data
sudo cp -r /opt/cert-guardian/config /backup/
sudo cp -r /opt/cert-guardian/data /backup/

# 3. Uppdatera kod
sudo cp -r src/* /opt/cert-guardian/src/

# 4. Starta service
sudo systemctl start cert-guardian

# 5. Verifiera
sudo systemctl status cert-guardian
```

## Monitoring

Sätt upp monitoring för själva Certificate Guardian:

```bash
# Lägg till i din monitoring (Prometheus, etc)
# Check att processen körs
systemctl is-active cert-guardian

# Check senaste scan timestamp i databas
sqlite3 /opt/cert-guardian/data/certificates.db \
  "SELECT MAX(scanned_at) FROM certificate_scans"
```

## Support

För frågor eller issues, kontakta IT Security team eller öppna ett ärende i ticketsystemet.
