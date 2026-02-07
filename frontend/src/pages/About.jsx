export default function About() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">About</h1>
        <p className="text-gray-500 mt-1">
          Certificate Guardian monitors TLS certificates, tracks risk signals, and helps you stay ahead of outages.
        </p>
      </div>

      <div className="bg-white rounded-lg shadow-md p-6 space-y-4">
        <div>
          <h2 className="text-lg font-semibold text-gray-900">What It Does</h2>
          <ul className="mt-2 text-sm text-gray-700 space-y-2">
            <li>Scans endpoints for TLS certificates and records every scan.</li>
            <li>Detects expiry risk, trust issues, and weak crypto.</li>
            <li>Surfaces per-certificate details and per-endpoint scan history.</li>
            <li>Discovers endpoints via network sweeps.</li>
            <li>Sends notifications and security alerts.</li>
          </ul>
        </div>

        <div>
          <h2 className="text-lg font-semibold text-gray-900">Key Features</h2>
          <ul className="mt-2 text-sm text-gray-700 space-y-2">
            <li>Certificates view with drill-down details, SANs, and crypto metadata.</li>
            <li>Endpoint tracking with recent scan trend.</li>
            <li>Network sweep discovery and rescan support.</li>
            <li>Security signals: hostname mismatch, missing OCSP/CRL, EKU/Key Usage gaps, weak signature, expiring chain.</li>
            <li>Dashboard summary for expiry windows, trust status, and TLS hygiene.</li>
          </ul>
        </div>

        <div>
          <h2 className="text-lg font-semibold text-gray-900">Scans & Scheduling</h2>
          <p className="text-sm text-gray-700 mt-2">
            The scanner runs on a configurable interval and records each scan with TLS version, cipher, and outcome.
            You can also trigger manual scans for specific endpoints or scan everything at once.
          </p>
        </div>

        <div>
          <h2 className="text-lg font-semibold text-gray-900">Roles & Permissions</h2>
          <ul className="mt-2 text-sm text-gray-700 space-y-2">
            <li>Viewers can see data but cannot modify endpoints or sweeps.</li>
            <li>Editors can create and manage their own endpoints and sweeps.</li>
            <li>Admins can manage all objects and user accounts.</li>
          </ul>
        </div>

        <div>
          <h2 className="text-lg font-semibold text-gray-900">Data Collected</h2>
          <ul className="mt-2 text-sm text-gray-700 space-y-2">
            <li>Certificate identity, validity, and fingerprint.</li>
            <li>SAN entries and issuer chain length.</li>
            <li>Key type/size, signature algorithm, TLS version, cipher.</li>
            <li>Verification and trust status with validation errors.</li>
          </ul>
        </div>
      </div>
    </div>
  )
}
