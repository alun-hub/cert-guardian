# Certificate Guardian - Future Enhancements

Detta dokument beskriver möjliga framtida förbättringar och hur man skulle kunna implementera dem.

## 1. Filesystem Scanner

Scanna lokala filer för certifikat (.pem, .crt, .p12, etc.)

**Implementation:**
```python
# src/filesystem_scanner.py
import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class FilesystemScanner:
    def scan_directory(self, path, recursive=True):
        """Scan directory for certificate files"""
        cert_extensions = ['.pem', '.crt', '.cer', '.p12', '.pfx']
        
        for root, dirs, files in os.walk(path):
            for file in files:
                if any(file.endswith(ext) for ext in cert_extensions):
                    filepath = os.path.join(root, file)
                    yield self._parse_cert_file(filepath)
            
            if not recursive:
                break
    
    def _parse_cert_file(self, filepath):
        """Parse certificate from file"""
        with open(filepath, 'rb') as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            return cert
```

**Config addition:**
```yaml
filesystem:
  enabled: true
  paths:
    - path: "/etc/ssl/certs"
      recursive: true
      owner: "System"
    - path: "/opt/app/certs"
      recursive: false
      owner: "Application Team"
```

## 2. LDAP/AD Integration

Scanna user och computer certificates i Active Directory.

**Implementation:**
```python
# src/ldap_scanner.py
import ldap
from ldap.controls import SimplePagedResultsControl

class LDAPScanner:
    def __init__(self, server, bind_dn, password):
        self.conn = ldap.initialize(server)
        self.conn.simple_bind_s(bind_dn, password)
    
    def scan_user_certificates(self, base_dn):
        """Scan user certificates in AD"""
        search_filter = '(userCertificate=*)'
        attrs = ['cn', 'userCertificate', 'mail']
        
        results = self.conn.search_s(base_dn, ldap.SCOPE_SUBTREE, 
                                     search_filter, attrs)
        
        for dn, attrs in results:
            if 'userCertificate' in attrs:
                cert_data = attrs['userCertificate'][0]
                # Parse certificate...
```

**Config addition:**
```yaml
ldap:
  enabled: true
  server: "ldaps://dc.example.com"
  bind_dn: "CN=cert-scanner,OU=Service Accounts,DC=example,DC=com"
  password: "secret"
  base_dn: "DC=example,DC=com"
```

## 3. Automated Renewal Integration

Automatisk renewal för Let's Encrypt och intern PKI.

**Implementation:**
```python
# src/renewal.py
import subprocess

class CertificateRenewer:
    def renew_letsencrypt(self, domain):
        """Renew Let's Encrypt certificate"""
        result = subprocess.run(
            ['certbot', 'renew', '--cert-name', domain],
            capture_output=True
        )
        return result.returncode == 0
    
    def renew_internal_pki(self, cert_id):
        """Request renewal from internal PKI"""
        # API call to internal CA
        pass
```

**Mattermost notification:**
```
🔄 **Automatic Renewal Initiated**

Certificate: api.example.com
Action: Renewal request sent to Let's Encrypt
Status: In Progress

Will notify when complete.
```

## 4. REST API

Exponera Certificate Guardian data via REST API.

**Implementation:**
```python
# src/api.py
from flask import Flask, jsonify
from database import Database

app = Flask(__name__)
db = Database('data/certificates.db')

@app.route('/api/certificates/expiring/<int:days>')
def get_expiring(days):
    """Get certificates expiring within X days"""
    certs = db.get_expiring_certificates(days)
    return jsonify(certs)

@app.route('/api/endpoints')
def get_endpoints():
    """Get all monitored endpoints"""
    endpoints = db.get_all_endpoints()
    return jsonify(endpoints)

@app.route('/api/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'})
```

**Användning:**
```bash
# Get certificates expiring within 30 days
curl http://localhost:5000/api/certificates/expiring/30

# Get all endpoints
curl http://localhost:5000/api/endpoints
```

## 5. Web Dashboard

Skapa en web-baserad dashboard för visualisering.

**Stack:**
- Backend: Flask/FastAPI
- Frontend: React eller Vue.js
- Charts: Chart.js eller D3.js

**Features:**
- Timeline över när certifikat går ut
- Heatmap över criticality
- Search och filter
- Manual scan trigger
- Export till CSV/JSON

## 6. Multi-Channel Notifications

Support för fler notification channels utöver Mattermost.

**Implementation:**
```python
# src/notifiers/base.py
class BaseNotifier:
    def send_alert(self, cert_info, endpoint, days):
        raise NotImplementedError

# src/notifiers/email.py
class EmailNotifier(BaseNotifier):
    def send_alert(self, cert_info, endpoint, days):
        # Send email via SMTP
        pass

# src/notifiers/slack.py
class SlackNotifier(BaseNotifier):
    def send_alert(self, cert_info, endpoint, days):
        # Send to Slack webhook
        pass

# src/notifiers/teams.py
class TeamsNotifier(BaseNotifier):
    def send_alert(self, cert_info, endpoint, days):
        # Send to Microsoft Teams
        pass
```

**Config:**
```yaml
notifications:
  channels:
    - type: mattermost
      webhook_url: "..."
    - type: email
      smtp_server: "smtp.example.com"
      recipients: ["security@example.com"]
    - type: slack
      webhook_url: "..."
```

## 7. Certificate Chain Validation

Validera hela cert chain, inte bara leaf cert.

**Implementation:**
```python
def validate_chain(self, cert_pem):
    """Validate certificate chain"""
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    
    # Build chain
    chain = []
    current = cert
    while True:
        chain.append(current)
        issuer = self._get_issuer_cert(current)
        if not issuer or issuer == current:  # Self-signed root
            break
        current = issuer
    
    # Check each cert in chain
    for i, cert in enumerate(chain):
        days = (cert.not_valid_after - datetime.now()).days
        if days < 30:
            # Intermediate/root cert expiring soon!
            pass
```

## 8. Integration med SIEM/SOAR

Skicka events till SIEM system för centraliserad logging.

**Implementation:**
```python
# src/siem_integration.py
import syslog

class SIEMIntegration:
    def send_event(self, event_type, cert_info, endpoint):
        """Send event to SIEM via syslog"""
        message = {
            'event_type': event_type,
            'timestamp': datetime.utcnow().isoformat(),
            'certificate': {
                'fingerprint': cert_info['fingerprint'],
                'subject': cert_info['subject'],
                'expires': cert_info['not_after']
            },
            'endpoint': {
                'host': endpoint['host'],
                'port': endpoint['port']
            }
        }
        
        syslog.syslog(syslog.LOG_WARNING, json.dumps(message))
```

## 9. Historical Trends och Analytics

Spåra trends över tid - hur många certs går ut per månad, vilka teams har flest problem, etc.

**Features:**
- Trend graphs över expiring certs
- Teams/owners med flest expiring certs
- Average renewal time
- SLA compliance tracking

**Implementation:**
```python
def get_expiry_trend(self, months=6):
    """Get trend of expiring certificates over time"""
    cursor = self.conn.cursor()
    cursor.execute("""
        SELECT 
            strftime('%Y-%m', not_after) as month,
            COUNT(*) as count
        FROM certificates
        WHERE julianday(not_after) - julianday('now') <= 180
        GROUP BY month
        ORDER BY month
    """)
    return cursor.fetchall()
```

## 10. Compliance Reporting

Generera compliance reports för audits.

**Report types:**
- PCI DSS compliance (cert strength, validity period)
- ISO 27001 compliance
- Custom compliance frameworks

**Implementation:**
```python
class ComplianceReporter:
    def generate_pci_report(self):
        """Generate PCI DSS compliance report"""
        report = {
            'weak_ciphers': self._check_weak_ciphers(),
            'long_validity': self._check_validity_period(),
            'self_signed': self._check_self_signed(),
            'expiring_soon': self._check_expiring()
        }
        return report
```

## 11. YubiKey/PIV Integration

Om du har central YubiKey management, scanna PIV certs på YubiKeys.

**Implementation:**
```python
# Requires ykman (YubiKey Manager)
import subprocess
import json

class YubiKeyScanner:
    def scan_yubikey(self, serial):
        """Scan certificates on YubiKey"""
        result = subprocess.run(
            ['ykman', 'piv', 'certificates', 'export', '--format', 'PEM'],
            capture_output=True
        )
        # Parse and store cert info
```

## 12. Container Registry Integration

Scanna image signatures i container registries.

**Implementation:**
```python
# src/registry_scanner.py
import docker

class RegistryScanner:
    def scan_registry(self, registry_url):
        """Scan container images for certificates"""
        client = docker.DockerClient(base_url=registry_url)
        
        for image in client.images.list():
            # Check image signature
            # Extract embedded certs
            pass
```

## Implementation Priority

Rekommenderad prioritet baserat på value vs effort:

**High Priority (Quick wins):**
1. Filesystem Scanner
2. Multi-Channel Notifications (Email, Slack)
3. REST API
4. Historical Trends

**Medium Priority:**
5. Automated Renewal (Let's Encrypt)
6. Web Dashboard
7. Certificate Chain Validation

**Low Priority (Nice to have):**
8. LDAP/AD Integration
9. SIEM Integration
10. YubiKey Scanner
11. Compliance Reporting
12. Container Registry Integration

## Contributing

Om du implementerar någon av dessa features, följ denna struktur:

1. Skapa ny modul i `src/`
2. Lägg till config options i `config.yaml`
3. Uppdatera database schema om nödvändigt
4. Skriv tester
5. Uppdatera README.md
6. Skapa PR med beskrivning

## Questions?

För frågor om implementation, kontakta development team.
