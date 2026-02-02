import { useState, useEffect } from 'react'
import { Shield, AlertCircle, AlertTriangle, CheckCircle } from 'lucide-react'
import { securityService } from '../services/api'

export default function Security() {
  const [issues, setIssues] = useState([])
  const [stats, setStats] = useState({ total: 0, self_signed_count: 0, untrusted_count: 0 })
  const [loading, setLoading] = useState(true)

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

  useEffect(() => {
    loadSecurityIssues()
  }, [])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Issues</h1>
          <p className="text-gray-500 mt-1">
            Certificate trust and validation problems
          </p>
        </div>
        <button
          onClick={loadSecurityIssues}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
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

      {/* Issues List */}
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
    </div>
  )
}

function IssueCard({ issue }) {
  const isSelfSigned = issue.is_self_signed
  const isUntrusted = !issue.is_trusted_ca && !issue.is_self_signed

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
                {isSelfSigned ? '⛔ Self-Signed Certificate' : '❌ Untrusted CA'}
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
            <p className="text-xs font-medium text-blue-900 mb-1">💡 Recommendation</p>
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
