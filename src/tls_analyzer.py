#!/usr/bin/env python3
"""
TLS & Security Analyzer

Converts raw scan data (DB rows) into structured SecurityFinding objects
with severity levels, human-readable explanations, and remediation advice.
"""
import json
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

DEPRECATED_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Cipher name substrings that indicate weakness
WEAK_CIPHER_PATTERNS = [
    "RC4", "RC2", "DES", "3DES", "NULL", "EXPORT", "anon",
    "ADH", "AECDH", "MD5", "SEED", "IDEA",
]


@dataclass
class SecurityFinding:
    finding_id: str
    severity: str        # critical / high / medium / low / info
    category: str        # tls / certificate / headers
    title: str
    description: str
    recommendation: str
    detail: Optional[str] = None   # Extra context (e.g. actual value found)


def _parse_json_field(value) -> list:
    """Safely parse a JSON-encoded list field from the DB."""
    if not value:
        return []
    if isinstance(value, list):
        return value
    try:
        result = json.loads(value)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _days_until(not_after_str: str) -> Optional[float]:
    """Return days until certificate expiry, or None on parse error."""
    if not not_after_str:
        return None
    try:
        not_after = datetime.fromisoformat(not_after_str)
        return (not_after - datetime.utcnow()).total_seconds() / 86400
    except (ValueError, TypeError):
        return None


def _is_weak_cipher(cipher: Optional[str]) -> bool:
    if not cipher:
        return False
    upper = cipher.upper()
    return any(pat.upper() in upper for pat in WEAK_CIPHER_PATTERNS)


def analyze_endpoint(row: dict) -> List[SecurityFinding]:
    """
    Analyse one endpoint's latest scan data and return a list of SecurityFindings.

    Args:
        row: Dict with columns from certificates, certificate_scans, and endpoints joined.
    """
    findings: List[SecurityFinding] = []

    # ------------------------------------------------------------------ #
    # Certificate findings
    # ------------------------------------------------------------------ #

    if row.get("hostname_matches") == 0:
        findings.append(SecurityFinding(
            finding_id="HOSTNAME_MISMATCH",
            severity="critical",
            category="certificate",
            title="Hostname matchar inte certifikatet",
            description=(
                "Certifikatets Subject Alternative Names (SAN) innehåller inte "
                "det hostname som efterfrågades. Klienter avvisar anslutningen "
                "och användare ser ett certifikatfel."
            ),
            recommendation=(
                "Utfärda ett nytt certifikat som inkluderar rätt hostname i SAN-fältet. "
                "Kontrollera att du begär certifikatet för exakt det DNS-namn som används."
            ),
        ))

    if row.get("is_self_signed"):
        findings.append(SecurityFinding(
            finding_id="SELF_SIGNED",
            severity="high",
            category="certificate",
            title="Självsignerat certifikat",
            description=(
                "Certifikatet är signerat av sig självt och inte av en betrodd CA. "
                "Webbläsare och klienter visar säkerhetsvarningar, och certifikatet "
                "ger inget skydd mot man-in-the-middle-attacker."
            ),
            recommendation=(
                "Byt till ett certifikat från en betrodd CA. Let's Encrypt erbjuder "
                "gratis certifikat via ACME-protokollet (t.ex. med Certbot eller acme.sh). "
                "Självklarligen är självundertecknade certifikat OK i rent intern/dev-miljö."
            ),
        ))

    if not row.get("is_self_signed") and row.get("is_trusted_ca") == 0:
        findings.append(SecurityFinding(
            finding_id="UNTRUSTED_CA",
            severity="high",
            category="certificate",
            title="Certifikat från ej betrodd CA",
            description=(
                "Certifikatet är utfärdat av en CA som inte finns i systemets "
                "trust store. Klienter kan inte verifiera certifikatkedjan och "
                "visar varningar."
            ),
            recommendation=(
                "Lägg till CA-certifikatet i systemets trust store om det är en "
                "intern PKI. Annars — byt till ett certifikat från en publikt betrodd CA."
            ),
            detail=row.get("validation_error"),
        ))

    if row.get("weak_signature"):
        algo = row.get("signature_algorithm") or "okänd algoritm"
        findings.append(SecurityFinding(
            finding_id="WEAK_SIGNATURE_ALGO",
            severity="high",
            category="certificate",
            title="Svag signeringsalgoritm",
            description=(
                "Certifikatet använder SHA-1 eller MD5 som signeringsalgoritm. "
                "Dessa är kryptografiskt brutna och anses inte säkra. "
                "SHA-1-certifikat avvisas av moderna webbläsare."
            ),
            recommendation=(
                "Utfärda ett nytt certifikat med SHA-256 eller starkare "
                "(t.ex. sha256WithRSAEncryption eller ecdsa-with-SHA256)."
            ),
            detail=f"Algoritm: {algo}",
        ))

    # Key strength
    key_type = row.get("key_type")
    key_size = row.get("key_size")

    if key_type == "RSA" and key_size is not None and key_size < 2048:
        findings.append(SecurityFinding(
            finding_id="WEAK_RSA_KEY",
            severity="high",
            category="certificate",
            title="För kort RSA-nyckel",
            description=(
                f"RSA-nyckeln är {key_size} bitar, vilket är under det rekommenderade "
                "minimikravet på 2048 bitar. Korta RSA-nycklar kan brytas med "
                "modern hårdvara."
            ),
            recommendation=(
                "Generera en ny nyckel med minst 2048 bitar (rekommenderat: 3072 eller 4096). "
                "Begär ett nytt certifikat med den starkare nyckeln."
            ),
            detail=f"Nyckelstorlek: {key_size} bitar",
        ))

    if key_type == "DSA":
        findings.append(SecurityFinding(
            finding_id="DSA_KEY",
            severity="medium",
            category="certificate",
            title="DSA-nyckel (föråldrad)",
            description=(
                "DSA är en föråldrad algoritm som inte stöds av moderna TLS-stackar "
                "och inte rekommenderas för nya installationer."
            ),
            recommendation=(
                "Migrera till ECDSA (P-256 eller P-384) eller RSA (≥ 2048 bitar). "
                "ECDSA med P-256 ger jämförbar säkerhet med betydligt kortare nycklar."
            ),
        ))

    if key_type == "EC" and key_size is not None and key_size < 224:
        findings.append(SecurityFinding(
            finding_id="WEAK_EC_KEY",
            severity="medium",
            category="certificate",
            title="För kort EC-nyckel",
            description=(
                f"Elliptisk kurva-nyckeln är {key_size} bitar. "
                "Kurvor under 224 bitar anses svaga."
            ),
            recommendation=(
                "Använd P-256 (256 bitar) eller P-384 (384 bitar) som är "
                "NIST-rekommenderade och stöds brett."
            ),
            detail=f"Nyckelstorlek: {key_size} bitar",
        ))

    if row.get("eku_server_auth") == 0:
        findings.append(SecurityFinding(
            finding_id="MISSING_SERVER_AUTH_EKU",
            severity="medium",
            category="certificate",
            title="Extended Key Usage saknar serverautentisering",
            description=(
                "Certifikatet saknar OID id-kp-serverAuth i Extended Key Usage-fältet. "
                "Moderna TLS-klienter kräver detta för HTTPS-certifikat."
            ),
            recommendation=(
                "Begär ett nytt servercertifikat som inkluderar EKU serverAuth. "
                "De flesta offentliga CA:er lägger till detta automatiskt."
            ),
        ))

    if row.get("ocsp_present") == 0:
        findings.append(SecurityFinding(
            finding_id="NO_OCSP",
            severity="info",
            category="certificate",
            title="OCSP-URL saknas i certifikatet",
            description=(
                "Certifikatet innehåller ingen URL till en OCSP-tjänst (Online Certificate "
                "Status Protocol). Klienter kan inte kontrollera om certifikatet återkallats "
                "i realtid."
            ),
            recommendation=(
                "Be din CA om ett certifikat med OCSP-URL i AIA-fältet, "
                "eller konfigurera OCSP Stapling på servern."
            ),
        ))

    if row.get("crl_present") == 0:
        findings.append(SecurityFinding(
            finding_id="NO_CRL",
            severity="info",
            category="certificate",
            title="CRL-URL saknas i certifikatet",
            description=(
                "Certifikatet innehåller ingen URL till en Certificate Revocation List. "
                "Utan CRL eller OCSP kan klienter inte verifiera återkallningsstatus."
            ),
            recommendation=(
                "Certifikat från moderna publika CA:er inkluderar normalt CRL-URL. "
                "Kontrollera med din CA eller överväg OCSP istället."
            ),
        ))

    # Expiry
    days = _days_until(row.get("not_after"))
    if days is not None:
        if days < 14:
            findings.append(SecurityFinding(
                finding_id="CERT_EXPIRING_CRITICAL",
                severity="critical",
                category="certificate",
                title="Certifikatet löper ut inom 14 dagar",
                description=(
                    f"Certifikatet löper ut om {int(days)} dagar. "
                    "När det löpt ut avvisas alla klientanslutningar."
                ),
                recommendation="Förnya certifikatet omedelbart.",
                detail=f"Utgångsdatum: {row.get('not_after', '')[:10]}",
            ))
        elif days < 30:
            findings.append(SecurityFinding(
                finding_id="CERT_EXPIRING_HIGH",
                severity="high",
                category="certificate",
                title="Certifikatet löper ut inom 30 dagar",
                description=(
                    f"Certifikatet löper ut om {int(days)} dagar. "
                    "Planera förnyelse snarast."
                ),
                recommendation=(
                    "Förnya certifikatet. Med Let's Encrypt sker detta automatiskt "
                    "via en ACME-klient om den är korrekt konfigurerad."
                ),
                detail=f"Utgångsdatum: {row.get('not_after', '')[:10]}",
            ))
        elif days < 60:
            findings.append(SecurityFinding(
                finding_id="CERT_EXPIRING_MEDIUM",
                severity="medium",
                category="certificate",
                title="Certifikatet löper ut inom 60 dagar",
                description=f"Certifikatet löper ut om {int(days)} dagar.",
                recommendation="Schemalägg förnyelse av certifikatet.",
                detail=f"Utgångsdatum: {row.get('not_after', '')[:10]}",
            ))

    # ------------------------------------------------------------------ #
    # TLS protocol and cipher findings
    # ------------------------------------------------------------------ #

    tls_version = row.get("tls_version")
    if tls_version and tls_version in DEPRECATED_TLS_VERSIONS:
        findings.append(SecurityFinding(
            finding_id="TLS_VERSION_DEPRECATED",
            severity="high",
            category="tls",
            title=f"Föråldrad TLS-version: {tls_version}",
            description=(
                f"Anslutningen förhandlades med {tls_version}, som är officiellt "
                "föråldrad (deprecated). SSLv2, SSLv3, TLS 1.0 och TLS 1.1 har "
                "kända svagheter (POODLE, BEAST, DROWN m.fl.) och stöds inte längre "
                "av moderna webbläsare."
            ),
            recommendation=(
                "Inaktivera stödet för TLS 1.0 och 1.1 på servern. "
                "Konfigurera minst TLS 1.2, helst TLS 1.3. "
                "Exempel för nginx: ssl_protocols TLSv1.2 TLSv1.3;"
            ),
            detail=f"Förhandlad version: {tls_version}",
        ))

    cipher = row.get("cipher")
    if _is_weak_cipher(cipher):
        findings.append(SecurityFinding(
            finding_id="WEAK_CIPHER",
            severity="high",
            category="tls",
            title="Svag cipher suite",
            description=(
                "Den förhandlade cipher suiten anses kryptografiskt svag. "
                "RC4, DES, 3DES, NULL-chiffer och EXPORT-chiffer ger otillräckligt "
                "skydd och kan brytas med moderna attacker."
            ),
            recommendation=(
                "Konfigurera servern att bara erbjuda moderna cipher suites, t.ex.: "
                "TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, "
                "ECDHE-RSA-AES256-GCM-SHA384. "
                "Använd Mozilla SSL Configuration Generator för rekommenderad konfiguration."
            ),
            detail=f"Cipher: {cipher}",
        ))

    # ------------------------------------------------------------------ #
    # HTTP security header findings
    # ------------------------------------------------------------------ #

    headers_missing = _parse_json_field(row.get("headers_missing"))
    hsts_max_age = row.get("hsts_max_age")
    csp_has_unsafe_inline = row.get("csp_has_unsafe_inline")

    if "hsts" in headers_missing:
        findings.append(SecurityFinding(
            finding_id="MISSING_HSTS",
            severity="high",
            category="headers",
            title="Strict-Transport-Security saknas",
            description=(
                "HTTP Strict Transport Security (HSTS) tvingar webbläsare att alltid "
                "använda HTTPS. Utan denna header kan användare omdirigeras till HTTP "
                "av en angripare (SSL stripping)."
            ),
            recommendation=(
                "Lägg till: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            ),
        ))
    elif hsts_max_age is not None and hsts_max_age < 31536000:
        findings.append(SecurityFinding(
            finding_id="HSTS_SHORT_MAXAGE",
            severity="medium",
            category="headers",
            title="HSTS max-age är för kort",
            description=(
                f"HSTS-headern har max-age={hsts_max_age} sekunder "
                f"({hsts_max_age // 86400} dagar), vilket är under det rekommenderade "
                "minimikravet på 1 år (31536000 sekunder)."
            ),
            recommendation=(
                "Öka max-age till minst 31536000 (1 år): "
                "Strict-Transport-Security: max-age=31536000; includeSubDomains"
            ),
            detail=f"Nuvarande max-age: {hsts_max_age}s",
        ))

    if "csp" in headers_missing:
        findings.append(SecurityFinding(
            finding_id="MISSING_CSP",
            severity="medium",
            category="headers",
            title="Content-Security-Policy saknas",
            description=(
                "Content Security Policy (CSP) begränsar vilka resurser webbläsaren "
                "tillåts ladda, och är ett viktigt skydd mot XSS-attacker."
            ),
            recommendation=(
                "Implementera en CSP-header. Börja med en restriktiv policy: "
                "Content-Security-Policy: default-src 'self'; script-src 'self'"
            ),
        ))
    elif csp_has_unsafe_inline:
        findings.append(SecurityFinding(
            finding_id="CSP_UNSAFE_INLINE",
            severity="medium",
            category="headers",
            title="CSP tillåter 'unsafe-inline'",
            description=(
                "'unsafe-inline' i Content-Security-Policy neutraliserar i stort sett "
                "XSS-skyddet som CSP ger, eftersom inline-skript kan exekveras."
            ),
            recommendation=(
                "Ta bort 'unsafe-inline' och använd nonces eller hashes för legitima "
                "inline-skript: Content-Security-Policy: script-src 'self' 'nonce-{random}'"
            ),
        ))

    if "x-content-type-options" in headers_missing:
        findings.append(SecurityFinding(
            finding_id="MISSING_XCTO",
            severity="medium",
            category="headers",
            title="X-Content-Type-Options saknas",
            description=(
                "Utan X-Content-Type-Options: nosniff kan webbläsare \"sniffa\" "
                "innehållstypen och tolka filer som körbar kod, vilket möjliggör "
                "MIME-sniffing-attacker."
            ),
            recommendation="Lägg till: X-Content-Type-Options: nosniff",
        ))

    if "x-frame-options" in headers_missing:
        findings.append(SecurityFinding(
            finding_id="MISSING_XFO",
            severity="low",
            category="headers",
            title="X-Frame-Options saknas",
            description=(
                "Utan X-Frame-Options kan sidan inbäddas i en iframe av tredje part, "
                "vilket möjliggör clickjacking-attacker."
            ),
            recommendation=(
                "Lägg till: X-Frame-Options: DENY eller X-Frame-Options: SAMEORIGIN. "
                "Alternativt, använd CSP frame-ancestors: "
                "Content-Security-Policy: frame-ancestors 'self'"
            ),
        ))

    if "referrer-policy" in headers_missing:
        findings.append(SecurityFinding(
            finding_id="MISSING_REFERRER_POLICY",
            severity="low",
            category="headers",
            title="Referrer-Policy saknas",
            description=(
                "Utan Referrer-Policy skickas den fulla URL:en i Referer-headern "
                "till externa sidor, vilket kan läcka känslig information."
            ),
            recommendation=(
                "Lägg till: Referrer-Policy: strict-origin-when-cross-origin"
            ),
        ))

    # ------------------------------------------------------------------ #
    # CAA record findings
    # ------------------------------------------------------------------ #

    caa_present = row.get("caa_present")
    if caa_present == 0:
        findings.append(SecurityFinding(
            finding_id="NO_CAA_RECORD",
            severity="medium",
            category="dns",
            title="CAA-poster saknas i DNS",
            description=(
                "Certificate Authority Authorization (CAA) är en DNS-post som anger "
                "vilka CA:er som är tillåtna att utfärda certifikat för domänen. "
                "Utan CAA kan vilken som helst CA utfärda ett certifikat för din domän, "
                "vilket ökar risken för felaktigt utfärdade certifikat."
            ),
            recommendation=(
                "Lägg till en CAA-post i DNS. Exempel för Let's Encrypt: "
                "example.com. CAA 0 issue \"letsencrypt.org\" "
                "Lägg även till en IODEF-post för incidentrapportering: "
                "example.com. CAA 0 iodef \"mailto:security@example.com\""
            ),
        ))

    # ------------------------------------------------------------------ #
    # HTTP → HTTPS redirect findings
    # ------------------------------------------------------------------ #

    redirects_to_https = row.get("redirects_to_https")
    if redirects_to_https == 0:
        findings.append(SecurityFinding(
            finding_id="NO_HTTPS_REDIRECT",
            severity="medium",
            category="headers",
            title="HTTP omdirigerar inte till HTTPS",
            description=(
                "Port 80 (HTTP) svarar men omdirigerar inte trafiken till HTTPS. "
                "Användare som besöker http:// exponeras för man-in-the-middle-attacker "
                "och avlyssning innan de når den säkra anslutningen."
            ),
            recommendation=(
                "Konfigurera servern att alltid omdirigera HTTP till HTTPS med "
                "en permanent redirect (301). Exempel för nginx: "
                "server { listen 80; return 301 https://$host$request_uri; }"
            ),
        ))

    # ------------------------------------------------------------------ #
    # Cookie security flag findings
    # ------------------------------------------------------------------ #

    insecure_cookies = _parse_json_field(row.get("insecure_cookies"))
    if insecure_cookies:
        all_missing = set()
        cookie_names = []
        for cookie in insecure_cookies:
            if isinstance(cookie, dict):
                cookie_names.append(cookie.get("name", "?"))
                for flag in cookie.get("missing_flags", []):
                    all_missing.add(flag)

        missing_str = ", ".join(sorted(all_missing))
        names_str = ", ".join(cookie_names[:5])
        if len(cookie_names) > 5:
            names_str += f" (+{len(cookie_names) - 5} till)"

        findings.append(SecurityFinding(
            finding_id="INSECURE_COOKIES",
            severity="medium",
            category="headers",
            title=f"Cookies saknar säkerhetsflaggor ({missing_str})",
            description=(
                f"Följande cookies saknar viktiga säkerhetsflaggor: {names_str}. "
                "Utan Secure-flaggan kan cookies skickas över okrypterad HTTP. "
                "Utan HttpOnly kan JavaScript läsa cookievärden, vilket möjliggör "
                "session hijacking via XSS. Utan SameSite ökar risken för CSRF-attacker."
            ),
            recommendation=(
                "Sätt alla tre flaggor på sessions- och autentiseringscookies: "
                "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict"
            ),
            detail=f"Cookies: {names_str}  |  Saknade flaggor: {missing_str}",
        ))

    # ------------------------------------------------------------------ #
    # Server version disclosure
    # ------------------------------------------------------------------ #

    server_header = row.get("server_header")
    if server_header:
        findings.append(SecurityFinding(
            finding_id="SERVER_VERSION_DISCLOSURE",
            severity="low",
            category="headers",
            title="Server-header avslöjar mjukvaruversion",
            description=(
                "Servern skickar en Server- eller X-Powered-By-header som innehåller "
                "mjukvarunamn och versionsnummer. Detta hjälper angripare att identifiera "
                "känd sårbar programvara och rikta attacker mot specifika CVE:er."
            ),
            recommendation=(
                "Dölj eller generalisera Server-headern. Exempel för nginx: "
                "server_tokens off;  För Apache: ServerTokens Prod; ServerSignature Off"
            ),
            detail=f"Header-värde: {server_header}",
        ))

    # ------------------------------------------------------------------ #
    # CORS wildcard
    # ------------------------------------------------------------------ #

    cors_wildcard = row.get("cors_wildcard")
    if cors_wildcard == 1:
        findings.append(SecurityFinding(
            finding_id="CORS_WILDCARD",
            severity="medium",
            category="headers",
            title="CORS tillåter alla ursprung (Access-Control-Allow-Origin: *)",
            description=(
                "Servern returnerar Access-Control-Allow-Origin: * vilket innebär att "
                "vilken webbplats som helst kan skicka cross-origin-förfrågningar och läsa "
                "svaren. För API:er med autentisering eller känslig data kan detta "
                "möjliggöra att angripares sidor läser användardata."
            ),
            recommendation=(
                "Begränsa CORS till specifika betrodda ursprung: "
                "Access-Control-Allow-Origin: https://app.example.com  "
                "Använd aldrig * tillsammans med Access-Control-Allow-Credentials: true."
            ),
        ))

    # ------------------------------------------------------------------ #
    # HTTP TRACE method
    # ------------------------------------------------------------------ #

    trace_enabled = row.get("trace_enabled")
    if trace_enabled == 1:
        findings.append(SecurityFinding(
            finding_id="HTTP_TRACE_ENABLED",
            severity="low",
            category="headers",
            title="HTTP TRACE-metoden är aktiverad",
            description=(
                "Servern svarar på HTTP TRACE-förfrågningar med 200 OK. "
                "TRACE kan användas i Cross-Site Tracing (XST)-attacker för att "
                "stjäla autentiseringscookies och headers via JavaScript, "
                "i kombination med en XSS-sårbarhet."
            ),
            recommendation=(
                "Inaktivera TRACE-metoden. Exempel för Apache: TraceEnable Off  "
                "För nginx är TRACE inte aktiverat som standard — kontrollera eventuella "
                "proxy-konfigurationer."
            ),
        ))

    # ------------------------------------------------------------------ #
    # LDAP findings (port 636 endpoints)
    # ------------------------------------------------------------------ #

    ldap_anon = row.get("ldap_anon_bind_allowed")
    ldap_plain = row.get("ldap_plain_available")

    if ldap_anon == 1:
        findings.append(SecurityFinding(
            finding_id="LDAP_ANON_BIND",
            severity="high",
            category="ldap",
            title="LDAP tillåter anonyma bind-förfrågningar",
            description=(
                "LDAP-servern accepterar anonyma bind utan autentisering. "
                "En angripare utan inloggningsuppgifter kan bläddra i katalogen, "
                "lista användare, grupper och andra känsliga attribut."
            ),
            recommendation=(
                "Inaktivera anonymt LDAP-bind i serverns konfiguration. "
                "I OpenLDAP: sätt 'olcDisallows: bind_anon' och 'olcRequires: authc'. "
                "I Active Directory: kräv LDAP-signering och inaktivera anonym åtkomst via "
                "grupprincip (Network Security: LDAP client signing requirements)."
            ),
        ))

    if ldap_plain == 1:
        findings.append(SecurityFinding(
            finding_id="LDAP_PLAIN_AVAILABLE",
            severity="medium",
            category="ldap",
            title="Okrypterad LDAP (port 389) är tillgänglig",
            description=(
                "Port 389 (vanlig LDAP utan kryptering) är öppen vid sidan om LDAPS. "
                "Autentiseringsuppgifter och kataloginformation kan skickas i klartext "
                "om klienter av misstag ansluter till fel port."
            ),
            recommendation=(
                "Stäng port 389 i brandväggen om LDAPS (636) används. "
                "Alternativt, kräv StartTLS på port 389 och neka okrypterade bind. "
                "I OpenLDAP: konfigurera 'olcSecurity: tls=1' för att tvinga kryptering."
            ),
        ))

    # Sort by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings


def summarize_findings(findings: List[SecurityFinding]) -> dict:
    """Return a count summary dict for a list of findings."""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity in summary:
            summary[f.severity] += 1
    return summary


def analyze_ssh(row: dict) -> List[SecurityFinding]:
    """
    Analyse one SSH endpoint's latest scan data and return SecurityFindings.

    Args:
        row: Dict with columns from ssh_scans joined with endpoints.
    """
    findings: List[SecurityFinding] = []

    # Scan error → can't evaluate
    if row.get("scan_error"):
        findings.append(SecurityFinding(
            finding_id="SSH_SCAN_ERROR",
            severity="info",
            category="ssh",
            title="SSH-skanning misslyckades",
            description="SSH-skannern kunde inte ansluta eller tolka serverns svar.",
            recommendation="Kontrollera att porten är öppen och att servern svarar med en giltig SSH-banner.",
            detail=row.get("scan_error"),
        ))
        return findings

    # SSH protocol version 1
    if row.get("supports_ssh1"):
        findings.append(SecurityFinding(
            finding_id="SSH_PROTOCOL_V1",
            severity="critical",
            category="ssh",
            title="SSH-protokoll version 1 stöds",
            description=(
                "Servern stöder SSH-1, ett föråldrat protokoll med allvarliga "
                "kryptografiska svagheter. SSHv1 är sårbart för man-in-the-middle- "
                "attacker och sessionskapning."
            ),
            recommendation=(
                "Inaktivera SSH-1 omedelbart. I OpenSSH: sätt 'Protocol 2' i sshd_config "
                "och starta om tjänsten."
            ),
            detail=f"Banner: {row.get('banner', '')}",
        ))

    # Weak KEX algorithms
    weak_kex = _parse_json_field(row.get("weak_kex"))
    if weak_kex:
        findings.append(SecurityFinding(
            finding_id="SSH_WEAK_KEX",
            severity="high",
            category="ssh",
            title="Svaga nyckelutbytesalgoritmer (KEX)",
            description=(
                "Servern erbjuder föråldrade KEX-algoritmer. "
                "diffie-hellman-group1-sha1 bygger på 1024-bitars DH och SHA-1, "
                "som anses kryptografiskt svaga och kan komprometteras av resursstarka angripare."
            ),
            recommendation=(
                "Ta bort svaga KEX-algoritmer ur sshd_config. Rekommenderat: "
                "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,"
                "ecdh-sha2-nistp256,diffie-hellman-group14-sha256"
            ),
            detail=f"Svaga KEX: {', '.join(weak_kex)}",
        ))

    # Weak host key algorithms
    weak_hk = _parse_json_field(row.get("weak_host_key"))
    if weak_hk:
        findings.append(SecurityFinding(
            finding_id="SSH_WEAK_HOST_KEY",
            severity="high",
            category="ssh",
            title="Svaga värdnyckelalgoritmer",
            description=(
                "Servern erbjuder föråldrade värdnyckeltyper. "
                "ssh-dss (DSA) är formellt avvecklat (RFC 9142). "
                "ssh-rsa använder SHA-1 och är inaktiverat som standard sedan OpenSSH 8.8."
            ),
            recommendation=(
                "Generera moderna värdnycklar och konfigurera: "
                "HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256 "
                "Ta bort gamla DSA/RSA-nycklar från /etc/ssh/."
            ),
            detail=f"Svaga värdnyckeltyper: {', '.join(weak_hk)}",
        ))

    # Weak encryption algorithms
    weak_enc = _parse_json_field(row.get("weak_encryption"))
    if weak_enc:
        findings.append(SecurityFinding(
            finding_id="SSH_WEAK_ENCRYPTION",
            severity="high",
            category="ssh",
            title="Svaga krypteringsalgoritmer",
            description=(
                "Servern erbjuder svaga symmetriska krypteringsalgoritmer. "
                "CBC-lägeschiffer (AES-CBC, 3DES-CBC) är sårbara för padding-oracle-attacker. "
                "RC4 (arcfour) och DES är kryptografiskt brutna."
            ),
            recommendation=(
                "Begränsa till moderna chiffer i sshd_config: "
                "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
                "aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
            ),
            detail=f"Svaga chiffer: {', '.join(weak_enc)}",
        ))

    # Weak MAC algorithms
    weak_mac = _parse_json_field(row.get("weak_mac"))
    if weak_mac:
        findings.append(SecurityFinding(
            finding_id="SSH_WEAK_MAC",
            severity="medium",
            category="ssh",
            title="Svaga MAC-algoritmer",
            description=(
                "Servern erbjuder svaga MAC-algoritmer för meddelandeautentisering. "
                "hmac-md5 och hmac-sha1 använder kryptografiskt brutna/svaga hashfunktioner. "
                "umac-64 har en för kort tagglängd (64 bitar)."
            ),
            recommendation=(
                "Begränsa MAC-algoritmer i sshd_config: "
                "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
                "umac-128-etm@openssh.com"
            ),
            detail=f"Svaga MAC: {', '.join(weak_mac)}",
        ))

    # No weaknesses found — add an informational finding
    if not findings:
        findings.append(SecurityFinding(
            finding_id="SSH_OK",
            severity="info",
            category="ssh",
            title="SSH-konfigurationen ser bra ut",
            description="Inga uppenbara svagheter hittades i SSH-serverns algoritmlista.",
            recommendation="Fortsätt regelbundet uppdatera OpenSSH och granska konfigurationen.",
            detail=row.get("banner"),
        ))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings
