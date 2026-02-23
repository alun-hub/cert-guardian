import { useState, useEffect } from 'react'
import {
  Shield, AlertCircle, AlertTriangle, CheckCircle, Globe,
  ChevronDown, ChevronRight, Lock, Info, Terminal, Database,
} from 'lucide-react'
import { securityService } from '../services/api'

const GRADE_COLORS = {
  A: 'bg-green-100 text-green-800',
  B: 'bg-blue-100 text-blue-800',
  C: 'bg-yellow-100 text-yellow-800',
  D: 'bg-orange-100 text-orange-800',
  F: 'bg-red-100 text-red-800',
}

const SEVERITY_STYLES = {
  critical: { bg: 'bg-red-100 text-red-800 border-red-200',   dot: 'bg-red-500',    label: 'Kritisk'  },
  high:     { bg: 'bg-orange-100 text-orange-800 border-orange-200', dot: 'bg-orange-500', label: 'Hög'   },
  medium:   { bg: 'bg-yellow-100 text-yellow-800 border-yellow-200', dot: 'bg-yellow-500', label: 'Medium' },
  low:      { bg: 'bg-blue-100 text-blue-800 border-blue-200', dot: 'bg-blue-400',   label: 'Låg'    },
  info:     { bg: 'bg-gray-100 text-gray-700 border-gray-200', dot: 'bg-gray-400',   label: 'Info'   },
}

const CATEGORY_LABELS = {
  certificate: 'Certifikat',
  tls: 'TLS-konfiguration',
  headers: 'HTTP-headers',
  dns: 'DNS',
  ssh: 'SSH',
  ldap: 'LDAP',
}

const ENDPOINT_TYPE_BADGE = {
  tls:  { label: 'HTTPS',  className: 'bg-blue-100 text-blue-700',   icon: Lock },
  ssh:  { label: 'SSH',    className: 'bg-purple-100 text-purple-700', icon: Terminal },
  ldap: { label: 'LDAPS',  className: 'bg-teal-100 text-teal-700',   icon: Database },
}

export default function Security() {
  const [activeTab, setActiveTab] = useState('tls')
  const [issues, setIssues] = useState([])
  const [stats, setStats] = useState({ total: 0, self_signed_count: 0, untrusted_count: 0 })
  const [headers, setHeaders] = useState([])
  const [report, setReport] = useState([])
  const [reportSummary, setReportSummary] = useState({ critical: 0, high: 0, medium: 0, low: 0, info: 0 })
  const [loading, setLoading] = useState(true)
  const [headersLoading, setHeadersLoading] = useState(true)
  const [reportLoading, setReportLoading] = useState(true)

  const loadAll = async () => {
    setLoading(true)
    setHeadersLoading(true)
    setReportLoading(true)

    try {
      const res = await securityService.getIssues()
      setIssues(res.data.issues)
      setStats({
        total: res.data.total,
        self_signed_count: res.data.self_signed_count,
        untrusted_count: res.data.untrusted_count,
      })
    } catch (e) {
      console.error('Failed to load security issues:', e)
    } finally {
      setLoading(false)
    }

    try {
      const res = await securityService.getHeaders()
      setHeaders(res.data.headers)
    } catch (e) {
      console.error('Failed to load headers:', e)
    } finally {
      setHeadersLoading(false)
    }

    try {
      const res = await securityService.getReport()
      setReport(res.data.report)
      setReportSummary(res.data.total_summary)
    } catch (e) {
      console.error('Failed to load security report:', e)
    } finally {
      setReportLoading(false)
    }
  }

  useEffect(() => { loadAll() }, [])

  const tlsReport = report.filter(e => e.endpoint_type !== 'ssh')
  const sshReport  = report.filter(e => e.endpoint_type === 'ssh')
  const totalFindings = Object.values(reportSummary).reduce((a, b) => a + b, 0)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Säkerhetsanalys</h1>
          <p className="text-gray-500 mt-1">
            TLS, SSH och HTTP-säkerhetsanalys
          </p>
        </div>
        <button
          onClick={loadAll}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          Uppdatera
        </button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
          const s = SEVERITY_STYLES[sev]
          return (
            <div key={sev} className="bg-white rounded-lg shadow-sm border p-4 flex flex-col items-center">
              <span className={`text-2xl font-bold ${reportSummary[sev] > 0 ? 'text-gray-900' : 'text-gray-400'}`}>
                {reportSummary[sev]}
              </span>
              <span className={`mt-1 px-2 py-0.5 text-xs font-medium rounded border ${s.bg}`}>
                {s.label}
              </span>
            </div>
          )
        })}
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-8">
          {[
            { id: 'tls',     label: `TLS/HTTPS (${tlsReport.length})` },
            { id: 'ssh',     label: `SSH (${sshReport.length})` },
            { id: 'issues',  label: `Certifikatproblem (${stats.total})` },
            { id: 'headers', label: `HTTP-headers (${headers.length})` },
          ].map(({ id, label }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === id
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              {label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab content */}
      {activeTab === 'tls' && (
        <ReportTab report={tlsReport} loading={reportLoading} />
      )}
      {activeTab === 'ssh' && (
        <ReportTab report={sshReport} loading={reportLoading} />
      )}
      {activeTab === 'issues' && (
        <IssuesTab issues={issues} loading={loading} />
      )}
      {activeTab === 'headers' && (
        <HeadersTab headers={headers} loading={headersLoading} />
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS Analysis tab
// ─────────────────────────────────────────────────────────────────────────────

function ReportTab({ report, loading }) {
  const [expandedId, setExpandedId] = useState(null)

  if (loading) {
    return <LoadingSpinner />
  }

  if (report.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow-md p-12 text-center">
        <Shield className="w-16 h-16 text-gray-400 mx-auto mb-4" />
        <h3 className="text-xl font-semibold text-gray-900 mb-2">Inga skanningsdata</h3>
        <p className="text-gray-600">Kör en skanning för att se säkerhetsanalys</p>
      </div>
    )
  }

  // Sort: endpoints with most severe findings first
  const sorted = [...report].sort((a, b) => {
    const score = (s) => s.critical * 1000 + s.high * 100 + s.medium * 10 + s.low
    return score(b.summary) - score(a.summary)
  })

  return (
    <div className="space-y-4">
      {sorted.map((entry) => {
        const key = `${entry.endpoint_type}-${entry.endpoint_id}`
        const isExpanded = expandedId === key
        const hasFindings = entry.findings.length > 0
        const typeBadge = ENDPOINT_TYPE_BADGE[entry.endpoint_type] || ENDPOINT_TYPE_BADGE.tls
        const TypeIcon = typeBadge.icon
        return (
          <div key={key} className="bg-white rounded-lg shadow-sm border overflow-hidden">
            {/* Endpoint header */}
            <button
              className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors text-left"
              onClick={() => setExpandedId(isExpanded ? null : key)}
            >
              <div className="flex items-center gap-4">
                {isExpanded
                  ? <ChevronDown className="w-5 h-5 text-gray-400 flex-shrink-0" />
                  : <ChevronRight className="w-5 h-5 text-gray-400 flex-shrink-0" />}
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-gray-900">{entry.host}:{entry.port}</span>
                    <span className={`inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded ${typeBadge.className}`}>
                      <TypeIcon className="w-3 h-3" />
                      {typeBadge.label}
                    </span>
                    {entry.tls_version && (
                      <span className="text-xs text-gray-500 bg-gray-100 px-2 py-0.5 rounded">
                        {entry.tls_version}
                      </span>
                    )}
                    {entry.header_grade && (
                      <span className={`text-xs font-bold px-2 py-0.5 rounded ${GRADE_COLORS[entry.header_grade] || 'bg-gray-100 text-gray-700'}`}>
                        Header: {entry.header_grade}
                      </span>
                    )}
                  </div>
                  {entry.owner && (
                    <p className="text-xs text-gray-500 mt-0.5">Ägare: {entry.owner}</p>
                  )}
                </div>
              </div>

              {/* Severity summary chips */}
              <div className="flex items-center gap-2 flex-shrink-0">
                {hasFindings ? (
                  ['critical', 'high', 'medium', 'low', 'info']
                    .filter(sev => entry.summary[sev] > 0)
                    .map(sev => {
                      const s = SEVERITY_STYLES[sev]
                      return (
                        <span key={sev} className={`text-xs font-medium px-2 py-1 rounded border ${s.bg}`}>
                          {entry.summary[sev]} {s.label}
                        </span>
                      )
                    })
                ) : (
                  <span className="flex items-center gap-1 text-sm text-green-700">
                    <CheckCircle className="w-4 h-4" /> Inga fynd
                  </span>
                )}
              </div>
            </button>

            {/* Expanded findings */}
            {isExpanded && (
              <div className="border-t border-gray-100 divide-y divide-gray-50">
                {!hasFindings ? (
                  <div className="px-6 py-6 text-center text-green-700 flex items-center justify-center gap-2">
                    <CheckCircle className="w-5 h-5" />
                    <span>Inga säkerhetsproblem hittades</span>
                  </div>
                ) : (
                  entry.findings.map((finding) => (
                    <FindingRow key={finding.finding_id} finding={finding} />
                  ))
                )}
                <div className="px-6 py-2 bg-gray-50 text-xs text-gray-400">
                  Senast skannad: {entry.scanned_at ? entry.scanned_at.slice(0, 19).replace('T', ' ') : '—'}
                  {entry.cipher && <span className="ml-4">Cipher: {entry.cipher}</span>}
                </div>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

function FindingRow({ finding }) {
  const [open, setOpen] = useState(false)
  const s = SEVERITY_STYLES[finding.severity] || SEVERITY_STYLES.info
  const catLabel = CATEGORY_LABELS[finding.category] || finding.category

  return (
    <div className="px-6 py-4">
      <button
        className="w-full flex items-start gap-4 text-left"
        onClick={() => setOpen(!open)}
      >
        <span className={`mt-0.5 w-2 h-2 rounded-full flex-shrink-0 ${s.dot}`} style={{ marginTop: '7px' }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-gray-900">{finding.title}</span>
            <span className={`text-xs px-2 py-0.5 rounded border ${s.bg}`}>{s.label}</span>
            <span className="text-xs text-gray-400 bg-gray-100 px-2 py-0.5 rounded">{catLabel}</span>
          </div>
          {finding.detail && (
            <p className="text-xs text-gray-500 font-mono mt-0.5">{finding.detail}</p>
          )}
        </div>
        {open
          ? <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0 mt-1" />
          : <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0 mt-1" />}
      </button>

      {open && (
        <div className="mt-3 ml-6 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-gray-50 rounded-lg p-4">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-1">
              <Info className="w-3 h-3" /> Förklaring
            </p>
            <p className="text-sm text-gray-700 leading-relaxed">{finding.description}</p>
          </div>
          <div className="bg-blue-50 rounded-lg p-4">
            <p className="text-xs font-semibold text-blue-700 uppercase tracking-wider mb-2 flex items-center gap-1">
              <Shield className="w-3 h-3" /> Åtgärd
            </p>
            <p className="text-sm text-blue-900 leading-relaxed">{finding.recommendation}</p>
          </div>
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Certificate issues tab (unchanged logic, Swedish labels)
// ─────────────────────────────────────────────────────────────────────────────

function IssuesTab({ issues, loading }) {
  if (loading) return <LoadingSpinner />

  if (issues.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow-md p-12 text-center">
        <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
        <h3 className="text-xl font-semibold text-gray-900 mb-2">Inga certifikatproblem</h3>
        <p className="text-gray-600">Alla certifikat är korrekt betrodda och validerade</p>
      </div>
    )
  }

  return (
    <div className="bg-white rounded-lg shadow-md overflow-hidden">
      <div className="divide-y divide-gray-200">
        {issues.map((issue, index) => (
          <IssueCard key={index} issue={issue} />
        ))}
      </div>
    </div>
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
                {isSelfSigned ? 'Självundertecknat certifikat' : 'Ej betrodd CA'}
              </p>
            </div>
            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getCriticalityColor(issue.criticality)}`}>
              {issue.criticality?.toUpperCase()}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
              <p className="text-xs text-gray-500 font-medium mb-1">Subject</p>
              <p className="text-sm text-gray-900 font-mono">{issue.subject}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500 font-medium mb-1">Issuer</p>
              <p className="text-sm text-gray-900 font-mono">{issue.issuer}</p>
            </div>
          </div>

          {issue.validation_error && (
            <div className="bg-white border border-gray-200 rounded-lg p-3 mb-4">
              <p className="text-xs text-gray-500 font-medium mb-1">Valideringsfel</p>
              <p className="text-sm text-gray-900 font-mono">{issue.validation_error}</p>
            </div>
          )}

          <div className="flex items-center gap-6 text-sm">
            <div>
              <span className="text-gray-500">Ägare:</span>
              <span className="ml-2 font-medium">{issue.owner || 'Ej tilldelad'}</span>
            </div>
            {issue.chain_length > 0 && (
              <div>
                <span className="text-gray-500">Kedjelängd:</span>
                <span className="ml-2 font-medium">{issue.chain_length}</span>
              </div>
            )}
          </div>

          <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
            <p className="text-xs font-medium text-blue-900 mb-1">Rekommendation</p>
            <p className="text-sm text-blue-800">
              {isSelfSigned
                ? 'Byt ut detta självundertecknade certifikat mot ett från en betrodd CA, t.ex. Let\'s Encrypt. Självundertecknade certifikat är inte betrodda av webbläsare.'
                : 'Certifikatet är signerat av en CA som inte finns i systemets trust store. Lägg till CA-certifikatet i trust store om det är en intern CA, annars byt till ett publikt betrodd CA.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP headers tab
// ─────────────────────────────────────────────────────────────────────────────

function HeadersTab({ headers, loading }) {
  const [expandedId, setExpandedId] = useState(null)

  if (loading) return <LoadingSpinner />

  if (headers.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow-md p-12 text-center">
        <Globe className="w-16 h-16 text-gray-400 mx-auto mb-4" />
        <h3 className="text-xl font-semibold text-gray-900 mb-2">Ingen headerdata</h3>
        <p className="text-gray-600">Kör en skanning för att analysera HTTP-säkerhetsheaders</p>
      </div>
    )
  }

  return (
    <div className="bg-white rounded-lg shadow-md overflow-hidden">
      <table className="w-full">
        <thead className="bg-gray-50 border-b">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Endpoint</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Poäng</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Betyg</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Saknade headers</th>
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
            <span className="font-medium text-gray-900">{entry.host}:{entry.port}</span>
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
              <span key={h} className="px-2 py-0.5 text-xs bg-red-50 text-red-700 rounded">{h}</span>
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
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Befintliga headers</p>
                <div className="flex flex-wrap gap-2">
                  {presentArr.length > 0 ? presentArr.map((h) => (
                    <span key={h} className="px-2 py-1 text-xs bg-green-50 text-green-700 rounded border border-green-200">{h}</span>
                  )) : <span className="text-gray-500">Inga</span>}
                </div>

                <p className="text-xs text-gray-500 uppercase tracking-wider mt-4 mb-2">Saknade headers</p>
                <div className="flex flex-wrap gap-2">
                  {missingArr.length > 0 ? missingArr.map((h) => (
                    <span key={h} className="px-2 py-1 text-xs bg-red-50 text-red-700 rounded border border-red-200">{h}</span>
                  )) : <span className="text-gray-500">Inga</span>}
                </div>

                {entry.hsts_max_age != null && (
                  <div className="mt-4">
                    <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">HSTS Max-Age</p>
                    <p className="text-gray-900">{entry.hsts_max_age.toLocaleString()} sekunder</p>
                  </div>
                )}
                {entry.csp_has_unsafe_inline != null && (
                  <div className="mt-2">
                    <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">CSP unsafe-inline</p>
                    <span className={`text-xs font-medium ${entry.csp_has_unsafe_inline ? 'text-red-700' : 'text-green-700'}`}>
                      {entry.csp_has_unsafe_inline ? 'Finns (dåligt)' : 'Saknas (bra)'}
                    </span>
                  </div>
                )}
              </div>

              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Rekommendationer</p>
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
                  <p className="text-green-700">Inga rekommendationer — headers ser bra ut!</p>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

function LoadingSpinner() {
  return (
    <div className="bg-white rounded-lg shadow-md p-8 text-center">
      <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-300 border-t-blue-600" />
    </div>
  )
}
