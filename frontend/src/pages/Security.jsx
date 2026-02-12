import { useState, useEffect } from 'react'
import { Shield, AlertCircle, AlertTriangle, CheckCircle, Globe, ChevronDown, ChevronRight } from 'lucide-react'
import { securityService } from '../services/api'

const GRADE_COLORS = {
  A: 'bg-green-100 text-green-800',
  B: 'bg-blue-100 text-blue-800',
  C: 'bg-yellow-100 text-yellow-800',
  D: 'bg-orange-100 text-orange-800',
  F: 'bg-red-100 text-red-800',
}

export default function Security() {
  const [activeTab, setActiveTab] = useState('issues')
  const [issues, setIssues] = useState([])
  const [stats, setStats] = useState({ total: 0, self_signed_count: 0, untrusted_count: 0 })
  const [headers, setHeaders] = useState([])
  const [loading, setLoading] = useState(true)
  const [headersLoading, setHeadersLoading] = useState(true)

  const loadSecurityIssues = async () => {
    try {
      setLoading(true)
      const response = await securityService.getIssues()
      setIssues(response.data.issues)
      setStats({
        total: response.data.total,
        self_signed_count: response.data.self_signed_count,
        untrusted_count: response.data.untrusted_count,
      })
    } catch (error) {
      console.error('Failed to load security issues:', error)
    } finally {
      setLoading(false)
    }
  }

  const loadHeaders = async () => {
    try {
      setHeadersLoading(true)
      const response = await securityService.getHeaders()
      setHeaders(response.data.headers)
    } catch (error) {
      console.error('Failed to load header analysis:', error)
    } finally {
      setHeadersLoading(false)
    }
  }

  useEffect(() => {
    loadSecurityIssues()
    loadHeaders()
  }, [])

  const handleRefresh = () => {
    loadSecurityIssues()
    loadHeaders()
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Issues</h1>
          <p className="text-gray-500 mt-1">
            Certificate trust, validation, and HTTP header problems
          </p>
        </div>
        <button
          onClick={handleRefresh}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow-md p-6 border-l-4 border-red-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 font-medium">Self-Signed</p>
              <p className="text-3xl font-bold text-red-600 mt-2">
                {stats.self_signed_count}
              </p>
            </div>
            <AlertCircle className="w-8 h-8 text-red-500" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-md p-6 border-l-4 border-orange-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 font-medium">Untrusted CA</p>
              <p className="text-3xl font-bold text-orange-600 mt-2">
                {stats.untrusted_count}
              </p>
            </div>
            <AlertTriangle className="w-8 h-8 text-orange-500" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-md p-6 border-l-4 border-purple-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 font-medium">Header Issues</p>
              <p className="text-3xl font-bold text-purple-600 mt-2">
                {headers.filter(h => h.header_grade === 'D' || h.header_grade === 'F').length}
              </p>
            </div>
            <Globe className="w-8 h-8 text-purple-500" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-md p-6 border-l-4 border-green-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 font-medium">Total Issues</p>
              <p className="text-3xl font-bold text-gray-900 mt-2">
                {stats.total}
              </p>
            </div>
            <Shield className="w-8 h-8 text-green-500" />
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-8">
          <button
            onClick={() => setActiveTab('issues')}
            className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'issues'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            Certificate Issues ({stats.total})
          </button>
          <button
            onClick={() => setActiveTab('headers')}
            className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'headers'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            HTTP Headers ({headers.length})
          </button>
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'issues' && (
        <div className="bg-white rounded-lg shadow-md overflow-hidden">
          {loading ? (
            <div className="p-8 text-center">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-300 border-t-blue-600"></div>
            </div>
          ) : issues.length === 0 ? (
            <div className="p-12 text-center">
              <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 mb-2">
                No Security Issues Found
              </h3>
              <p className="text-gray-600">
                All certificates are properly trusted and validated
              </p>
            </div>
          ) : (
            <div className="divide-y divide-gray-200">
              {issues.map((issue, index) => (
                <IssueCard key={index} issue={issue} />
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'headers' && (
        <HeadersTab headers={headers} loading={headersLoading} />
      )}
    </div>
  )
}

function HeadersTab({ headers, loading }) {
  const [expandedId, setExpandedId] = useState(null)

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow-md p-8 text-center">
        <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-300 border-t-blue-600"></div>
      </div>
    )
  }

  if (headers.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow-md p-12 text-center">
        <Globe className="w-16 h-16 text-gray-400 mx-auto mb-4" />
        <h3 className="text-xl font-semibold text-gray-900 mb-2">
          No Header Data Available
        </h3>
        <p className="text-gray-600">
          Run a scan to analyse HTTP security headers
        </p>
      </div>
    )
  }

  return (
    <div className="bg-white rounded-lg shadow-md overflow-hidden">
      <table className="w-full">
        <thead className="bg-gray-50 border-b">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Endpoint
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Score
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Grade
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Missing Headers
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200">
          {headers.map((entry) => {
            const key = `${entry.endpoint_id}-${entry.cert_id}`
            const isExpanded = expandedId === key
            return (
              <HeaderRow
                key={key}
                entry={entry}
                isExpanded={isExpanded}
                onToggle={() => setExpandedId(isExpanded ? null : key)}
              />
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function HeaderRow({ entry, isExpanded, onToggle }) {
  const gradeClass = GRADE_COLORS[entry.header_grade] || 'bg-gray-100 text-gray-800'
  const missingArr = Array.isArray(entry.headers_missing) ? entry.headers_missing : []
  const presentArr = Array.isArray(entry.headers_present) ? entry.headers_present : []
  const recommendArr = Array.isArray(entry.header_recommendations) ? entry.header_recommendations : []

  return (
    <>
      <tr className="hover:bg-gray-50 cursor-pointer" onClick={onToggle}>
        <td className="px-6 py-4">
          <div className="flex items-center gap-2">
            {isExpanded
              ? <ChevronDown className="w-4 h-4 text-gray-400" />
              : <ChevronRight className="w-4 h-4 text-gray-400" />}
            <span className="font-medium text-gray-900">
              {entry.host}:{entry.port}
            </span>
          </div>
        </td>
        <td className="px-6 py-4">
          <span className="font-medium text-gray-900">{entry.header_score}/100</span>
        </td>
        <td className="px-6 py-4">
          <span className={`px-2 py-1 text-xs font-bold rounded ${gradeClass}`}>
            {entry.header_grade}
          </span>
        </td>
        <td className="px-6 py-4">
          <div className="flex flex-wrap gap-1">
            {missingArr.slice(0, 4).map((h) => (
              <span key={h} className="px-2 py-0.5 text-xs bg-red-50 text-red-700 rounded">
                {h}
              </span>
            ))}
            {missingArr.length > 4 && (
              <span className="text-xs text-gray-500">+{missingArr.length - 4}</span>
            )}
          </div>
        </td>
      </tr>
      {isExpanded && (
        <tr>
          <td colSpan={4} className="px-6 py-5 bg-gray-50">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-sm">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Present Headers</p>
                <div className="flex flex-wrap gap-2">
                  {presentArr.length > 0 ? presentArr.map((h) => (
                    <span key={h} className="px-2 py-1 text-xs bg-green-50 text-green-700 rounded border border-green-200">
                      {h}
                    </span>
                  )) : (
                    <span className="text-gray-500">None</span>
                  )}
                </div>

                <p className="text-xs text-gray-500 uppercase tracking-wider mt-4 mb-2">Missing Headers</p>
                <div className="flex flex-wrap gap-2">
                  {missingArr.length > 0 ? missingArr.map((h) => (
                    <span key={h} className="px-2 py-1 text-xs bg-red-50 text-red-700 rounded border border-red-200">
                      {h}
                    </span>
                  )) : (
                    <span className="text-gray-500">None</span>
                  )}
                </div>

                {entry.hsts_max_age != null && (
                  <div className="mt-4">
                    <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">HSTS Max-Age</p>
                    <p className="text-gray-900">{entry.hsts_max_age.toLocaleString()} seconds</p>
                  </div>
                )}
                {entry.csp_has_unsafe_inline != null && (
                  <div className="mt-2">
                    <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">CSP unsafe-inline</p>
                    <span className={`text-xs font-medium ${entry.csp_has_unsafe_inline ? 'text-red-700' : 'text-green-700'}`}>
                      {entry.csp_has_unsafe_inline ? 'Present (bad)' : 'Not present (good)'}
                    </span>
                  </div>
                )}
              </div>

              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Recommendations</p>
                {recommendArr.length > 0 ? (
                  <ul className="space-y-2">
                    {recommendArr.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-blue-500 mt-0.5">&#8226;</span>
                        <span className="text-gray-700">{rec}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-green-700">No recommendations - headers look good!</p>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function IssueCard({ issue }) {
  const isSelfSigned = issue.is_self_signed

  const getCriticalityColor = (criticality) => {
    switch (criticality) {
      case 'critical': return 'text-red-600 bg-red-50'
      case 'high': return 'text-orange-600 bg-orange-50'
      case 'medium': return 'text-yellow-600 bg-yellow-50'
      case 'low': return 'text-green-600 bg-green-50'
      default: return 'text-gray-600 bg-gray-50'
    }
  }

  return (
    <div className={`p-6 ${isSelfSigned ? 'bg-red-50' : 'bg-orange-50'}`}>
      <div className="flex items-start gap-4">
        <div className="flex-shrink-0">
          {isSelfSigned ? (
            <div className="p-3 bg-red-100 rounded-full">
              <AlertCircle className="w-6 h-6 text-red-600" />
            </div>
          ) : (
            <div className="p-3 bg-orange-100 rounded-full">
              <AlertTriangle className="w-6 h-6 text-orange-600" />
            </div>
          )}
        </div>

        <div className="flex-1">
          <div className="flex items-start justify-between mb-3">
            <div>
              <h3 className="text-lg font-semibold text-gray-900">
                {issue.host}:{issue.port}
              </h3>
              <p className="text-sm text-gray-600 mt-1">
                {isSelfSigned ? 'Self-Signed Certificate' : 'Untrusted CA'}
              </p>
            </div>
            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getCriticalityColor(issue.criticality)}`}>
              {issue.criticality.toUpperCase()}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
              <p className="text-xs text-gray-500 font-medium mb-1">Subject</p>
              <p className="text-sm text-gray-900 font-mono">
                {issue.subject}
              </p>
            </div>
            <div>
              <p className="text-xs text-gray-500 font-medium mb-1">Issuer</p>
              <p className="text-sm text-gray-900 font-mono">
                {issue.issuer}
              </p>
            </div>
          </div>

          {issue.validation_error && (
            <div className="bg-white border border-gray-200 rounded-lg p-3 mb-4">
              <p className="text-xs text-gray-500 font-medium mb-1">Validation Error</p>
              <p className="text-sm text-gray-900 font-mono">
                {issue.validation_error}
              </p>
            </div>
          )}

          <div className="flex items-center gap-6 text-sm">
            <div>
              <span className="text-gray-500">Owner:</span>
              <span className="ml-2 font-medium">{issue.owner || 'Unassigned'}</span>
            </div>
            {issue.chain_length > 0 && (
              <div>
                <span className="text-gray-500">Chain Length:</span>
                <span className="ml-2 font-medium">{issue.chain_length}</span>
              </div>
            )}
          </div>

          {/* Recommendations */}
          <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
            <p className="text-xs font-medium text-blue-900 mb-1">Recommendation</p>
            <p className="text-sm text-blue-800">
              {isSelfSigned ? (
                <>
                  Replace this self-signed certificate with one from a trusted CA like Let's Encrypt.
                  Self-signed certificates are not trusted by browsers and should only be used for
                  development/testing.
                </>
              ) : (
                <>
                  This certificate is signed by a CA that is not in the system trust store.
                  Either add the CA to your trust store if it's an internal CA, or replace
                  the certificate with one from a publicly trusted CA.
                </>
              )}
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
