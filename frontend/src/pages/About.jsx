import { Shield, Lock, Globe, AlertTriangle, Info } from 'lucide-react'

export default function About() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">About Certificate Guardian</h1>
        <p className="text-gray-500 mt-1">
          TLS certificate monitoring and HTTP security header analysis for your infrastructure.
        </p>
      </div>

      {/* Overview */}
      <Section icon={<Info className="w-5 h-5 text-blue-500" />} title="What It Does">
        <p>
          Certificate Guardian continuously scans your endpoints to monitor TLS certificates and
          analyse HTTP security headers. It detects expiring certificates, trust issues, weak
          cryptography, and missing security headers &mdash; then surfaces actionable findings in a
          single dashboard. Notifications are sent via Mattermost webhooks when certificates approach
          expiry or trust problems are detected.
        </p>
      </Section>

      {/* TLS Certificate Monitoring */}
      <Section icon={<Lock className="w-5 h-5 text-green-600" />} title="TLS Certificate Monitoring">
        <p>Every scan cycle collects the following for each endpoint:</p>
        <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1">
          <Item label="Identity" desc="Subject, issuer, serial number, SAN entries" />
          <Item label="Validity" desc="Not-before / not-after dates, days until expiry" />
          <Item label="Fingerprint" desc="SHA-256 hash of the DER-encoded certificate" />
          <Item label="Key & Crypto" desc="Key type (RSA/EC/Ed25519), key size, signature algorithm" />
          <Item label="Chain" desc="Chain length, CA trust status, expiring intermediates" />
          <Item label="TLS Negotiation" desc="TLS version (1.2/1.3), cipher suite used" />
          <Item label="Hostname Match" desc="RFC 6125 SAN/CN matching against the scanned host" />
          <Item label="Revocation" desc="OCSP responder and CRL distribution point presence" />
          <Item label="Key Usage" desc="EKU Server Auth, Digital Signature, Key Encipherment" />
          <Item label="Trust Status" desc="Self-signed detection, CA chain validation, validation errors" />
        </div>

        <h4 className="font-semibold text-gray-800 mt-5 mb-2">Dashboard Security Signals</h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <Signal color="red" label="Expiring (7d)" desc="Certificates expiring within 7 days" />
          <Signal color="yellow" label="Expiring (30d)" desc="Certificates expiring within 30 days" />
          <Signal color="blue" label="Expiring (90d)" desc="Certificates expiring within 90 days" />
          <Signal color="red" label="Expired" desc="Certificates past their not-after date" />
          <Signal color="red" label="Self-Signed" desc="Not issued by a recognised CA" />
          <Signal color="orange" label="Untrusted" desc="CA not in system or custom trust store" />
          <Signal color="orange" label="Weak Keys" desc="RSA < 2048, EC < 256, or DSA < 2048 bits" />
          <Signal color="red" label="Legacy TLS" desc="Endpoints negotiating TLS 1.0 or 1.1" />
          <Signal color="blue" label="Cert Changes" desc="Certificate rotation detected in last 24 h" />
        </div>
      </Section>

      {/* HTTP Header Security */}
      <Section icon={<Globe className="w-5 h-5 text-purple-600" />} title="HTTP Security Header Analysis">
        <p>
          After each TLS scan, Certificate Guardian also performs an HTTPS request to analyse
          the response's security headers. Each endpoint receives a score (0&ndash;100) and a
          letter grade (A&ndash;F). Results are shown on the Dashboard, the Security page's
          &ldquo;HTTP Headers&rdquo; tab, and in each certificate's detail view.
        </p>

        <h4 className="font-semibold text-gray-800 mt-5 mb-2">Scoring Breakdown</h4>
        <div className="overflow-x-auto">
          <table className="w-full text-sm border border-gray-200 rounded">
            <thead className="bg-gray-50 text-left">
              <tr>
                <th className="px-4 py-2 font-medium text-gray-600">Header</th>
                <th className="px-4 py-2 font-medium text-gray-600">Max Points</th>
                <th className="px-4 py-2 font-medium text-gray-600">Criteria</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              <ScoreRow
                header="Strict-Transport-Security (HSTS)"
                points="30"
                criteria="30 p if present with max-age >= 31 536 000 (1 year). 15 p if present with a shorter max-age."
              />
              <ScoreRow
                header="Content-Security-Policy (CSP)"
                points="25"
                criteria="25 p if present with default-src or script-src and no 'unsafe-inline'. 15 p if present but weaker."
              />
              <ScoreRow
                header="X-Content-Type-Options"
                points="15"
                criteria="15 p if set to nosniff."
              />
              <ScoreRow
                header="X-Frame-Options"
                points="15"
                criteria="15 p if set to DENY or SAMEORIGIN."
              />
              <ScoreRow
                header="Referrer-Policy"
                points="10"
                criteria="10 p if present (any valid value)."
              />
              <ScoreRow
                header="Permissions-Policy"
                points="5"
                criteria="5 p if present (any valid value)."
              />
              <ScoreRow
                header="X-XSS-Protection"
                points="0"
                criteria="Informational only (deprecated). Not scored, but noted if present."
              />
            </tbody>
          </table>
        </div>

        <h4 className="font-semibold text-gray-800 mt-5 mb-2">Grade Scale</h4>
        <div className="flex flex-wrap gap-3">
          <GradeBadge grade="A" range="90 &ndash; 100" color="green" />
          <GradeBadge grade="B" range="70 &ndash; 89" color="blue" />
          <GradeBadge grade="C" range="50 &ndash; 69" color="yellow" />
          <GradeBadge grade="D" range="30 &ndash; 49" color="orange" />
          <GradeBadge grade="F" range="0 &ndash; 29" color="red" />
        </div>
        <p className="text-xs text-gray-500 mt-2">
          The Dashboard &ldquo;Header Issues&rdquo; card counts endpoints with grade D or F.
        </p>
      </Section>

      {/* Header Reference */}
      <Section icon={<AlertTriangle className="w-5 h-5 text-orange-500" />} title="Header Reference &amp; Recommendations">
        <div className="space-y-5">
          <HeaderRef
            name="Strict-Transport-Security (HSTS)"
            severity="HIGH"
            what="Tells browsers to only connect via HTTPS. Prevents protocol-downgrade attacks and cookie hijacking on insecure connections."
            good="Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
            bad="Missing entirely, or max-age shorter than one year (31 536 000 seconds)."
            fix="Add the header in your web server or reverse proxy configuration. Set max-age to at least 31 536 000. Consider adding includeSubDomains and submitting to the HSTS preload list."
          />
          <HeaderRef
            name="Content-Security-Policy (CSP)"
            severity="HIGH"
            what="Controls which resources the browser is allowed to load. The primary defence against cross-site scripting (XSS) attacks."
            good="Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'"
            bad="Missing entirely, or contains 'unsafe-inline' / 'unsafe-eval' which weakens the protection."
            fix="Start with a restrictive policy (default-src 'self') and add specific source directives as needed. Replace inline scripts with external files or use nonce/hash-based whitelisting to remove 'unsafe-inline'."
          />
          <HeaderRef
            name="X-Content-Type-Options"
            severity="MEDIUM"
            what="Prevents the browser from MIME-sniffing a response away from the declared Content-Type. Blocks attacks where an attacker tricks the browser into interpreting a file as a different type (e.g. treating a text file as JavaScript)."
            good="X-Content-Type-Options: nosniff"
            bad="Missing or set to any other value."
            fix="Add X-Content-Type-Options: nosniff to all responses. This is a single static header with no configuration needed."
          />
          <HeaderRef
            name="X-Frame-Options"
            severity="MEDIUM"
            what="Controls whether the page can be embedded in frames. Prevents clickjacking attacks where an attacker overlays a transparent frame to trick users into clicking hidden elements."
            good="X-Frame-Options: DENY (or SAMEORIGIN if framing is needed within the same origin)"
            bad="Missing entirely, or set to ALLOW-FROM (deprecated and poorly supported)."
            fix="Add X-Frame-Options: DENY to prevent all framing, or SAMEORIGIN if your application uses same-origin iframes. Also consider using the CSP frame-ancestors directive for more granular control."
          />
          <HeaderRef
            name="Referrer-Policy"
            severity="LOW"
            what="Controls how much referrer information is sent when navigating to another page. Prevents leaking sensitive URL paths or query parameters to third-party sites."
            good="Referrer-Policy: strict-origin-when-cross-origin (or no-referrer, same-origin)"
            bad="Missing entirely. The browser defaults can be overly permissive."
            fix="Add the header with a restrictive value. strict-origin-when-cross-origin is a good default that sends the origin (but not the path) on cross-origin requests and the full referrer on same-origin requests."
          />
          <HeaderRef
            name="Permissions-Policy"
            severity="LOW"
            what="Restricts which browser features and APIs the page can use (camera, microphone, geolocation, etc.). Limits the damage if an XSS vulnerability is exploited."
            good={'Permissions-Policy: camera=(), microphone=(), geolocation=()'}
            bad="Missing entirely. All features default to allowed."
            fix="Add the header and explicitly disable features your application does not use. Common features to disable: camera, microphone, geolocation, payment, usb, magnetometer."
          />
          <HeaderRef
            name="X-XSS-Protection"
            severity="INFO"
            what="A legacy header that controlled the browser's built-in XSS filter. Modern browsers have removed this filter; it is now deprecated."
            good="Not required. If present, 0 is the safest value (disables the filter which could itself introduce vulnerabilities)."
            bad="N/A &mdash; this header is informational only and does not affect the score."
            fix="No action needed. This header is tracked for visibility but does not contribute to the score. Use a proper Content-Security-Policy instead."
          />
        </div>
      </Section>

      {/* Scans & Scheduling */}
      <Section icon={<Shield className="w-5 h-5 text-blue-600" />} title="Scans &amp; Scheduling">
        <p>
          The scanner container runs on a configurable interval (default: 1 hour). Each cycle
          connects to every registered endpoint, performs a TLS handshake to collect certificate
          data, and then makes an HTTPS GET request to analyse response headers.
        </p>
        <ul className="mt-3 space-y-2">
          <li>Manual scans can be triggered from the Dashboard (&ldquo;Scan All&rdquo;) or per-endpoint from the Endpoints page.</li>
          <li>The scan interval can be changed in Settings &gt; Scanner (admin only, 10 s &ndash; 86 400 s).</li>
          <li>Network sweeps discover new endpoints by scanning IP ranges and port lists.</li>
          <li>Orphaned certificates (no longer returned by any endpoint) are automatically cleaned up after each scan cycle.</li>
        </ul>
      </Section>

      {/* Notifications */}
      <Section title="Notifications">
        <p>
          Alerts are sent via Mattermost incoming webhooks. Each endpoint can have its own
          webhook URL, or fall back to the global webhook configured in config.yaml.
        </p>
        <ul className="mt-3 space-y-2">
          <li>Expiry alerts fire at configurable day thresholds (e.g. 90, 60, 30, 14, 7, 1).</li>
          <li>Only one notification per threshold per certificate/endpoint pair (no repeats).</li>
          <li>Security alerts fire immediately for self-signed or untrusted certificates.</li>
        </ul>
      </Section>

      {/* Roles & Permissions */}
      <Section title="Roles &amp; Permissions">
        <div className="overflow-x-auto">
          <table className="w-full text-sm border border-gray-200 rounded">
            <thead className="bg-gray-50 text-left">
              <tr>
                <th className="px-4 py-2 font-medium text-gray-600">Role</th>
                <th className="px-4 py-2 font-medium text-gray-600">Permissions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              <tr>
                <td className="px-4 py-2 font-medium">Viewer</td>
                <td className="px-4 py-2 text-gray-700">
                  Read-only access to dashboard, certificates, endpoints, security data, and scan history.
                </td>
              </tr>
              <tr>
                <td className="px-4 py-2 font-medium">Editor</td>
                <td className="px-4 py-2 text-gray-700">
                  Everything a Viewer can do, plus: create/edit/delete their own endpoints and sweeps,
                  trigger scans, manage trusted CAs, and test webhooks.
                </td>
              </tr>
              <tr>
                <td className="px-4 py-2 font-medium">Admin</td>
                <td className="px-4 py-2 text-gray-700">
                  Full access: manage all endpoints and sweeps regardless of owner, manage user accounts
                  and roles, change scanner settings, view audit logs, configure SIEM forwarding and database health.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </Section>

      {/* Trusted CAs */}
      <Section title="Custom Trusted CAs">
        <p>
          If your infrastructure uses an internal certificate authority, you can upload
          its root or intermediate certificates in the Trusted CAs section (Settings page).
          These are combined with the system trust store and used for both chain validation
          and outbound TLS connections (e.g. to Mattermost webhooks).
        </p>
      </Section>

      {/* SIEM */}
      <Section title="SIEM &amp; Audit Logging">
        <p>
          All user actions (login, endpoint changes, scans, CA management) are recorded in an
          audit log visible to admins. Events can be forwarded to an external SIEM via:
        </p>
        <ul className="mt-3 space-y-2">
          <li><strong>stdout</strong> &mdash; JSON events printed to container logs for log aggregators.</li>
          <li><strong>syslog</strong> &mdash; Forwarded to a syslog server (TCP, optional TLS).</li>
          <li><strong>beats</strong> &mdash; Sent to Elastic Beats / Logstash (optional TLS with client certs).</li>
        </ul>
      </Section>

      {/* Footer */}
      <div className="text-center text-xs text-gray-400 py-4">
        Certificate Guardian &mdash; TLS certificate and HTTP header security monitoring
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Reusable sub-components                                           */
/* ------------------------------------------------------------------ */

function Section({ icon, title, children }) {
  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2 mb-3">
        {icon}
        {title}
      </h2>
      <div className="text-sm text-gray-700 leading-relaxed">{children}</div>
    </div>
  )
}

function Item({ label, desc }) {
  return (
    <div className="py-1">
      <span className="font-medium text-gray-800">{label}:</span>{' '}
      <span className="text-gray-600">{desc}</span>
    </div>
  )
}

function Signal({ color, label, desc }) {
  const colors = {
    red: 'border-red-300 bg-red-50',
    orange: 'border-orange-300 bg-orange-50',
    yellow: 'border-yellow-300 bg-yellow-50',
    blue: 'border-blue-300 bg-blue-50',
  }
  return (
    <div className={`border rounded-lg px-3 py-2 text-xs ${colors[color] || colors.blue}`}>
      <span className="font-semibold">{label}</span>
      <span className="text-gray-600 ml-1">&mdash; {desc}</span>
    </div>
  )
}

function ScoreRow({ header, points, criteria }) {
  return (
    <tr>
      <td className="px-4 py-2 font-medium text-gray-900 whitespace-nowrap">{header}</td>
      <td className="px-4 py-2 text-center font-mono">{points}</td>
      <td className="px-4 py-2 text-gray-600">{criteria}</td>
    </tr>
  )
}

function GradeBadge({ grade, range, color }) {
  const cls = {
    green: 'bg-green-100 text-green-800 border-green-300',
    blue: 'bg-blue-100 text-blue-800 border-blue-300',
    yellow: 'bg-yellow-100 text-yellow-800 border-yellow-300',
    orange: 'bg-orange-100 text-orange-800 border-orange-300',
    red: 'bg-red-100 text-red-800 border-red-300',
  }
  return (
    <div className={`border rounded-lg px-3 py-2 text-sm font-medium ${cls[color]}`}>
      <span className="font-bold text-lg mr-1">{grade}</span>
      <span className="text-xs" dangerouslySetInnerHTML={{ __html: range }} />
    </div>
  )
}

function HeaderRef({ name, severity, what, good, bad, fix }) {
  const sevColors = {
    HIGH: 'bg-red-100 text-red-800',
    MEDIUM: 'bg-yellow-100 text-yellow-800',
    LOW: 'bg-blue-100 text-blue-800',
    INFO: 'bg-gray-100 text-gray-700',
  }
  return (
    <div className="border border-gray-200 rounded-lg p-4">
      <div className="flex items-center gap-3 mb-2">
        <h4 className="font-semibold text-gray-900">{name}</h4>
        <span className={`px-2 py-0.5 text-xs font-medium rounded ${sevColors[severity] || sevColors.INFO}`}>
          {severity}
        </span>
      </div>
      <p className="text-gray-700 mb-3">{what}</p>
      <div className="space-y-2 text-xs">
        <div>
          <span className="font-medium text-green-800 bg-green-50 px-1.5 py-0.5 rounded">Good</span>
          <span className="ml-2 text-gray-600 font-mono">{good}</span>
        </div>
        <div>
          <span className="font-medium text-red-800 bg-red-50 px-1.5 py-0.5 rounded">Problem</span>
          <span className="ml-2 text-gray-600">{bad}</span>
        </div>
        <div>
          <span className="font-medium text-blue-800 bg-blue-50 px-1.5 py-0.5 rounded">Fix</span>
          <span className="ml-2 text-gray-600">{fix}</span>
        </div>
      </div>
    </div>
  )
}
