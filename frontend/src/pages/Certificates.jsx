import { useState, useEffect } from 'react'
import { Search, Filter, Lock, AlertCircle, CheckCircle, Shield, ChevronUp, ChevronDown } from 'lucide-react'
import { certificateService } from '../services/api'
import { format } from 'date-fns'

export default function Certificates() {
  const [certificates, setCertificates] = useState([])
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState({
    search: '',
    expiringDays: null,
    selfSigned: null,
    untrusted: null,
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
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
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
            onClick={() => setFilters({ search: '', expiringDays: null, selfSigned: null, untrusted: null })}
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
                <CertificateRow key={cert.id} cert={cert} />
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

function CertificateRow({ cert }) {
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

  return (
    <tr className="hover:bg-gray-50">
      <td className="px-6 py-4">
        <div className="flex items-start gap-3">
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
