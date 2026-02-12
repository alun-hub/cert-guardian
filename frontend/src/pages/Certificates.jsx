import { useState, useEffect, Fragment } from 'react'
import { Search, Lock, AlertCircle, CheckCircle, ChevronUp, ChevronDown, ChevronRight, ChevronDown as ChevronDownIcon } from 'lucide-react'
import { certificateService } from '../services/api'
import { format } from 'date-fns'

export default function Certificates() {
  const [certificates, setCertificates] = useState([])
  const [loading, setLoading] = useState(true)
  const [expandedId, setExpandedId] = useState(null)
  const [detailsById, setDetailsById] = useState({})
  const [detailsLoading, setDetailsLoading] = useState({})
  const [filters, setFilters] = useState({
    search: '',
    expiringDays: null,
    selfSigned: null,
    untrusted: null,
    status: '',
  })
  const [sortConfig, setSortConfig] = useState({ key: 'days_until_expiry', direction: 'asc' })

  const loadCertificates = async () => {
    try {
      setLoading(true)
      const params = {}
      
      if (filters.expiringDays) params.expiring_days = filters.expiringDays
      if (filters.selfSigned !== null) params.self_signed = filters.selfSigned
      if (filters.untrusted !== null) params.untrusted = filters.untrusted
      
      const response = await certificateService.getAll(params)
      setCertificates(response.data.certificates)
    } catch (error) {
      console.error('Failed to load certificates:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadCertificates()
  }, [filters])

  const loadCertificateDetails = async (certId) => {
    try {
      setDetailsLoading(prev => ({ ...prev, [certId]: true }))
      const response = await certificateService.getById(certId)
      setDetailsById(prev => ({ ...prev, [certId]: response.data }))
    } catch (error) {
      console.error('Failed to load certificate details:', error)
    } finally {
      setDetailsLoading(prev => ({ ...prev, [certId]: false }))
    }
  }

  const toggleDetails = (certId) => {
    if (expandedId === certId) {
      setExpandedId(null)
      return
    }
    setExpandedId(certId)
    if (!detailsById[certId]) {
      loadCertificateDetails(certId)
    }
  }

  const filteredCerts = certificates
    .filter(cert => {
      if (!filters.search) return true

      const searchLower = filters.search.toLowerCase()
      return (
        cert.subject.toLowerCase().includes(searchLower) ||
        cert.issuer.toLowerCase().includes(searchLower) ||
        cert.endpoints?.some(ep => ep.host.toLowerCase().includes(searchLower))
      )
    })
    .filter(cert => {
      if (!filters.status) return true
      const daysLeft = Math.floor(cert.days_until_expiry)
      if (filters.status === 'expired') return daysLeft < 0
      if (filters.status === 'urgent') return daysLeft >= 0 && daysLeft <= 7
      if (filters.status === 'warning') return daysLeft > 7 && daysLeft <= 30
      if (filters.status === 'valid') return daysLeft > 30
      return true
    })
    .sort((a, b) => {
      let aVal, bVal
      switch (sortConfig.key) {
        case 'subject':
          aVal = a.subject.toLowerCase()
          bVal = b.subject.toLowerCase()
          break
        case 'days_until_expiry':
          aVal = a.days_until_expiry
          bVal = b.days_until_expiry
          break
        case 'is_trusted_ca':
          aVal = a.is_trusted_ca ? 1 : 0
          bVal = b.is_trusted_ca ? 1 : 0
          break
        case 'endpoints':
          aVal = a.endpoints?.[0]?.host || ''
          bVal = b.endpoints?.[0]?.host || ''
          break
        default:
          return 0
      }
      if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1
      if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1
      return 0
    })

  const handleSort = (key) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc'
    }))
  }

  const SortHeader = ({ label, sortKey }) => (
    <th
      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
      onClick={() => handleSort(sortKey)}
    >
      <div className="flex items-center gap-1">
        {label}
        {sortConfig.key === sortKey && (
          sortConfig.direction === 'asc'
            ? <ChevronUp className="w-3 h-3" />
            : <ChevronDown className="w-3 h-3" />
        )}
      </div>
    </th>
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Certificates</h1>
        <p className="text-gray-500 mt-1">
          {certificates.length} certificates monitored
        </p>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-md p-4">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
          {/* Search */}
          <div className="lg:col-span-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search certificates..."
                value={filters.search}
                onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          {/* Expiring filter */}
          <select
            value={filters.expiringDays || ''}
            onChange={(e) => setFilters({ ...filters, expiringDays: e.target.value ? parseInt(e.target.value) : null })}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Expiry</option>
            <option value="7">Expiring in 7 days</option>
            <option value="30">Expiring in 30 days</option>
            <option value="90">Expiring in 90 days</option>
          </select>

          {/* Status filter */}
          <select
            value={filters.status}
            onChange={(e) => setFilters({ ...filters, status: e.target.value })}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Status</option>
            <option value="expired">Expired</option>
            <option value="urgent">Urgent (0-7)</option>
            <option value="warning">Warning (8-30)</option>
            <option value="valid">Valid (31+)</option>
          </select>

          {/* Trust filter */}
          <select
            value={filters.untrusted === null ? '' : (filters.untrusted ? 'untrusted' : 'trusted')}
            onChange={(e) => {
              if (e.target.value === '') {
                setFilters({ ...filters, untrusted: null, selfSigned: null })
              } else if (e.target.value === 'trusted') {
                setFilters({ ...filters, untrusted: false, selfSigned: null })
              } else {
                setFilters({ ...filters, untrusted: true, selfSigned: null })
              }
            }}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Types</option>
            <option value="trusted">Trusted Only</option>
            <option value="untrusted">Untrusted Only</option>
          </select>

          {/* Clear filters */}
          <button
            onClick={() => setFilters({ search: '', expiringDays: null, selfSigned: null, untrusted: null, status: '' })}
            className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200"
          >
            Clear Filters
          </button>
        </div>
      </div>

      {/* Certificates List */}
      <div className="bg-white rounded-lg shadow-md overflow-hidden">
        {loading ? (
          <div className="p-8 text-center">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-300 border-t-blue-600"></div>
          </div>
        ) : filteredCerts.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            No certificates found
          </div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-50 border-b">
              <tr>
                <SortHeader label="Certificate" sortKey="subject" />
                <SortHeader label="Endpoints" sortKey="endpoints" />
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <SortHeader label="Expires" sortKey="days_until_expiry" />
                <SortHeader label="Trust" sortKey="is_trusted_ca" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {filteredCerts.map(cert => (
                <Fragment key={cert.id}>
                  <CertificateRow
                    cert={cert}
                    isExpanded={expandedId === cert.id}
                    onToggle={() => toggleDetails(cert.id)}
                  />
                  {expandedId === cert.id && (
                    <CertificateDetailsRow
                      cert={detailsById[cert.id]}
                      loading={detailsLoading[cert.id]}
                    />
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function extractCN(distinguishedName) {
  if (!distinguishedName) return 'Unknown'
  // Try to find commonName= or CN= in the string
  const cnMatch = distinguishedName.match(/(?:commonName|CN)=([^,]+)/i)
  if (cnMatch) return cnMatch[1].trim()
  // Fallback: return first attribute value
  const firstAttr = distinguishedName.split(',')[0]
  const eqIndex = firstAttr.indexOf('=')
  if (eqIndex > -1) return firstAttr.substring(eqIndex + 1).trim()
  return distinguishedName
}

function CertificateRow({ cert, isExpanded, onToggle }) {
  const daysLeft = Math.floor(cert.days_until_expiry)
  const isExpired = daysLeft < 0
  const isUrgent = daysLeft <= 7 && daysLeft >= 0
  const isWarning = daysLeft <= 30 && daysLeft > 7

  const getStatusBadge = () => {
    if (isExpired) {
      return <span className="px-2 py-1 text-xs font-medium bg-red-100 text-red-800 rounded">Expired</span>
    }
    if (isUrgent) {
      return <span className="px-2 py-1 text-xs font-medium bg-red-100 text-red-800 rounded">Urgent</span>
    }
    if (isWarning) {
      return <span className="px-2 py-1 text-xs font-medium bg-yellow-100 text-yellow-800 rounded">Warning</span>
    }
    return <span className="px-2 py-1 text-xs font-medium bg-green-100 text-green-800 rounded">Valid</span>
  }

  const getTrustBadge = () => {
    if (cert.is_self_signed) {
      return (
        <div className="flex items-center gap-1 text-red-600">
          <AlertCircle className="w-4 h-4" />
          <span className="text-xs font-medium">Self-Signed</span>
        </div>
      )
    }
    if (!cert.is_trusted_ca) {
      return (
        <div className="flex items-center gap-1 text-orange-600">
          <AlertCircle className="w-4 h-4" />
          <span className="text-xs font-medium">Untrusted</span>
        </div>
      )
    }
    return (
      <div className="flex items-center gap-1 text-green-600">
        <CheckCircle className="w-4 h-4" />
        <span className="text-xs font-medium">Trusted</span>
      </div>
    )
  }

  const normalizeTri = (value) => {
    if (value === null || value === undefined) return null
    if (value === 0 || value === '0') return false
    return Boolean(value)
  }

  const getIssueBadges = () => {
    const issues = []
    const hostnameMatches = normalizeTri(cert.hostname_matches)
    const ocspPresent = normalizeTri(cert.ocsp_present)
    const crlPresent = normalizeTri(cert.crl_present)
    const ekuServerAuth = normalizeTri(cert.eku_server_auth)
    const keyUsageDS = normalizeTri(cert.key_usage_digital_signature)
    const keyUsageKE = normalizeTri(cert.key_usage_key_encipherment)
    const chainHasExpiring = normalizeTri(cert.chain_has_expiring)
    const weakSignature = normalizeTri(cert.weak_signature)

    if (hostnameMatches === false) issues.push({ label: 'Hostname mismatch', tone: 'red' })
    if (weakSignature === true) issues.push({ label: 'Weak signature', tone: 'red' })
    if (chainHasExpiring === true) issues.push({ label: 'Chain expiring', tone: 'orange' })
    if (ocspPresent === false) issues.push({ label: 'OCSP missing', tone: 'orange' })
    if (crlPresent === false) issues.push({ label: 'CRL missing', tone: 'orange' })
    if (ekuServerAuth === false) issues.push({ label: 'EKU missing', tone: 'orange' })
    if (keyUsageDS === false) issues.push({ label: 'KU DS missing', tone: 'orange' })
    if (keyUsageKE === false) issues.push({ label: 'KU KE missing', tone: 'orange' })

    return issues.slice(0, 3)
  }

  const issues = getIssueBadges()

  return (
    <tr className="hover:bg-gray-50 cursor-pointer" onClick={onToggle}>
      <td className="px-6 py-4">
        <div className="flex items-start gap-3">
          <div className="mt-1 text-gray-400">
            {isExpanded ? <ChevronDownIcon className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </div>
          <Lock className="w-5 h-5 text-gray-400 mt-1" />
          <div>
            <p className="font-medium text-gray-900">
              {extractCN(cert.subject)}
            </p>
            <p className="text-xs text-gray-500 mt-1">
              Issued by: {extractCN(cert.issuer)}
            </p>
            <p className="text-xs text-gray-400 mt-1">
              {cert.fingerprint.substring(0, 16)}...
            </p>
            {issues.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-2">
                {issues.map((issue, idx) => (
                  <span
                    key={`${issue.label}-${idx}`}
                    className={`px-2 py-0.5 text-xs font-medium rounded ${
                      issue.tone === 'red'
                        ? 'bg-red-100 text-red-800'
                        : 'bg-orange-100 text-orange-800'
                    }`}
                  >
                    {issue.label}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      </td>
      <td className="px-6 py-4">
        {cert.endpoints && cert.endpoints.length > 0 ? (
          <div className="space-y-1">
            {cert.endpoints.slice(0, 2).map((ep, i) => (
              <div key={i} className="text-sm text-gray-900">
                {ep.host}:{ep.port}
                <span className="ml-2 text-xs text-gray-500">
                  ({ep.criticality})
                </span>
              </div>
            ))}
            {cert.endpoints.length > 2 && (
              <p className="text-xs text-gray-500">
                +{cert.endpoints.length - 2} more
              </p>
            )}
          </div>
        ) : (
          <span className="text-sm text-gray-500">No endpoints</span>
        )}
      </td>
      <td className="px-6 py-4">
        {getStatusBadge()}
      </td>
      <td className="px-6 py-4">
        <div>
          <p className={`font-medium ${
            isExpired ? 'text-red-600' :
            isUrgent ? 'text-red-600' :
            isWarning ? 'text-yellow-600' :
            'text-gray-900'
          }`}>
            {isExpired ? `${Math.abs(daysLeft)} days ago` : `${daysLeft} days`}
          </p>
          <p className="text-xs text-gray-500 mt-1">
            {format(new Date(cert.not_after), 'MMM dd, yyyy')}
          </p>
        </div>
      </td>
      <td className="px-6 py-4">
        {getTrustBadge()}
      </td>
    </tr>
  )
}

function CertificateDetailsRow({ cert, loading }) {
  if (loading) {
    return (
      <tr>
        <td colSpan={5} className="px-6 py-4 bg-gray-50">
          <div className="text-sm text-gray-500">Loading details...</div>
        </td>
      </tr>
    )
  }

  if (!cert) {
    return (
      <tr>
        <td colSpan={5} className="px-6 py-4 bg-gray-50">
          <div className="text-sm text-gray-500">No details available.</div>
        </td>
      </tr>
    )
  }

  const sanList = Array.isArray(cert.san_list)
    ? cert.san_list
    : (cert.san_list ? [cert.san_list] : [])

  const latestScan = cert.scan_history?.[0]

  const normalizeTri = (value) => {
    if (value === null || value === undefined) return null
    if (value === 0 || value === '0') return false
    return Boolean(value)
  }

  const renderFlag = (value, { goodLabel, badLabel, invert = false }) => {
    const normalized = normalizeTri(value)
    if (normalized === null) {
      return <span className="text-xs text-gray-500">Unknown</span>
    }
    const isGood = invert ? !normalized : normalized
    const label = isGood ? goodLabel : badLabel
    const color = isGood ? 'text-green-700' : 'text-red-700'
    return <span className={`text-xs font-medium ${color}`}>{label}</span>
  }

  return (
    <tr>
      <td colSpan={5} className="px-6 py-5 bg-gray-50">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 text-sm">
          <div className="space-y-3">
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider">Identity</p>
              <p className="text-gray-900 mt-1">Subject: {cert.subject || 'Unknown'}</p>
              <p className="text-gray-900">Issuer: {cert.issuer || 'Unknown'}</p>
              <p className="text-gray-900">Serial: {cert.serial_number || 'Unknown'}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider">Validity</p>
              <p className="text-gray-900 mt-1">
                Not Before: {cert.not_before ? format(new Date(cert.not_before), 'MMM dd, yyyy HH:mm') : 'Unknown'}
              </p>
              <p className="text-gray-900">
                Not After: {cert.not_after ? format(new Date(cert.not_after), 'MMM dd, yyyy HH:mm') : 'Unknown'}
              </p>
            </div>
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider">Fingerprint</p>
              <p className="font-mono text-xs text-gray-700 mt-1 break-all">{cert.fingerprint}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider">SAN</p>
              {sanList.length > 0 ? (
                <div className="flex flex-wrap gap-2 mt-1">
                  {sanList.map((san, i) => (
                    <span key={i} className="px-2 py-1 text-xs bg-white border rounded">
                      {san}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-gray-500 mt-1">No SAN entries</p>
              )}
            </div>
          </div>

          <div className="space-y-3">
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider">Crypto</p>
              <p className="text-gray-900 mt-1">
                Key: {cert.key_type || 'Unknown'}{cert.key_size ? ` ${cert.key_size}` : ''}
              </p>
              <p className="text-gray-900">
                Signature: {cert.signature_algorithm || 'Unknown'}
              </p>
              <p className="text-gray-900">
                Chain Length: {cert.chain_length ?? 'Unknown'}
              </p>
            </div>
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider">Latest TLS</p>
              <p className="text-gray-900 mt-1">
                Version: {latestScan?.tls_version || 'Unknown'}
              </p>
              <p className="text-gray-900">
                Cipher: {latestScan?.cipher || 'Unknown'}
              </p>
              <p className="text-gray-900">
                Scanned: {latestScan?.scanned_at ? format(new Date(latestScan.scanned_at), 'MMM dd, yyyy HH:mm') : 'Unknown'}
              </p>
            </div>
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider">Checks</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-1">
                <div className="flex items-center justify-between">
                  <span className="text-gray-700">Hostname match</span>
                  {renderFlag(cert.hostname_matches, { goodLabel: 'Match', badLabel: 'Mismatch' })}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-700">OCSP</span>
                  {renderFlag(cert.ocsp_present, { goodLabel: 'Present', badLabel: 'Missing' })}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-700">CRL</span>
                  {renderFlag(cert.crl_present, { goodLabel: 'Present', badLabel: 'Missing' })}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-700">EKU Server Auth</span>
                  {renderFlag(cert.eku_server_auth, { goodLabel: 'Allowed', badLabel: 'Not set' })}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-700">Key Usage: DS</span>
                  {renderFlag(cert.key_usage_digital_signature, { goodLabel: 'Allowed', badLabel: 'Not set' })}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-700">Key Usage: KE</span>
                  {renderFlag(cert.key_usage_key_encipherment, { goodLabel: 'Allowed', badLabel: 'Not set' })}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-700">Chain expiring</span>
                  {renderFlag(cert.chain_has_expiring, { goodLabel: 'No', badLabel: 'Yes', invert: true })}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-700">Weak signature</span>
                  {renderFlag(cert.weak_signature, { goodLabel: 'No', badLabel: 'Yes', invert: true })}
                </div>
              </div>
            </div>
            {/* HTTP Headers */}
            {cert.header_grade && (
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">HTTP Headers</p>
                <div className="mt-1 flex items-center gap-3">
                  <span className={`px-2 py-1 text-xs font-bold rounded ${
                    cert.header_grade === 'A' ? 'bg-green-100 text-green-800' :
                    cert.header_grade === 'B' ? 'bg-blue-100 text-blue-800' :
                    cert.header_grade === 'C' ? 'bg-yellow-100 text-yellow-800' :
                    cert.header_grade === 'D' ? 'bg-orange-100 text-orange-800' :
                    'bg-red-100 text-red-800'
                  }`}>
                    Grade {cert.header_grade}
                  </span>
                  <span className="text-gray-700">{cert.header_score}/100</span>
                </div>
                {(() => {
                  const missing = Array.isArray(cert.headers_missing)
                    ? cert.headers_missing
                    : (cert.headers_missing ? [cert.headers_missing] : [])
                  return missing.length > 0 && (
                    <div className="mt-2">
                      <p className="text-xs text-gray-500 mb-1">Missing:</p>
                      <div className="flex flex-wrap gap-1">
                        {missing.map((h) => (
                          <span key={h} className="px-2 py-0.5 text-xs bg-red-50 text-red-700 rounded">
                            {h}
                          </span>
                        ))}
                      </div>
                    </div>
                  )
                })()}
                {(() => {
                  const recs = Array.isArray(cert.header_recommendations)
                    ? cert.header_recommendations
                    : (cert.header_recommendations ? [cert.header_recommendations] : [])
                  return recs.length > 0 && (
                    <div className="mt-2">
                      <p className="text-xs text-gray-500 mb-1">Recommendations:</p>
                      <ul className="space-y-1">
                        {recs.map((rec, i) => (
                          <li key={i} className="text-xs text-gray-700">- {rec}</li>
                        ))}
                      </ul>
                    </div>
                  )
                })()}
              </div>
            )}
            {cert.validation_error && (
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Validation</p>
                <p className="text-red-700 mt-1">{cert.validation_error}</p>
              </div>
            )}
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider">Endpoints</p>
              {cert.endpoints?.length ? (
                <div className="mt-1 space-y-1">
                  {cert.endpoints.slice(0, 5).map((ep, i) => (
                    <div key={i} className="text-gray-900">
                      {ep.host}:{ep.port} {ep.status ? `(${ep.status})` : ''}
                      {ep.scanned_at ? ` - ${format(new Date(ep.scanned_at), 'MMM dd, yyyy HH:mm')}` : ''}
                      {ep.tls_version ? ` - ${ep.tls_version}` : ''}
                      {ep.cipher ? ` - ${ep.cipher}` : ''}
                    </div>
                  ))}
                  {cert.endpoints.length > 5 && (
                    <div className="text-gray-500">+{cert.endpoints.length - 5} more</div>
                  )}
                </div>
              ) : (
                <p className="text-gray-500 mt-1">No endpoints</p>
              )}
            </div>
          </div>
        </div>
      </td>
    </tr>
  )
}
