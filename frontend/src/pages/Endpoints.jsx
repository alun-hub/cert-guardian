import { useState, useEffect } from 'react'
import { Plus, Server, Trash2, Edit2, Play, Bell, CheckCircle, XCircle, Loader2, Search, ChevronUp, ChevronDown } from 'lucide-react'
import { endpointService, scanService } from '../services/api'
import api from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import { format } from 'date-fns'

export default function Endpoints() {
  const { isEditor, isAdmin, user } = useAuth()
  const [endpoints, setEndpoints] = useState([])
  const [loading, setLoading] = useState(true)
  const [showAddModal, setShowAddModal] = useState(false)
  const [editingEndpoint, setEditingEndpoint] = useState(null)
  const [scanning, setScanning] = useState({})
  const [filters, setFilters] = useState({
    search: '',
    criticality: null,
    hasWebhook: null,
    expiringDays: null,
  })
  const [sortConfig, setSortConfig] = useState({ key: 'host', direction: 'asc' })

  const loadEndpoints = async () => {
    try {
      setLoading(true)
      const response = await endpointService.getAll()
      setEndpoints(response.data.endpoints)
    } catch (error) {
      console.error('Failed to load endpoints:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadEndpoints()
  }, [])

  const handleScan = async (endpointId) => {
    try {
      setScanning(prev => ({ ...prev, [endpointId]: true }))
      await scanService.triggerScan(endpointId)
      setTimeout(loadEndpoints, 2000)
    } catch (error) {
      console.error('Scan failed:', error)
    } finally {
      setScanning(prev => ({ ...prev, [endpointId]: false }))
    }
  }

  const handleDelete = async (endpointId) => {
    if (!confirm('Are you sure you want to delete this endpoint?')) return

    try {
      await endpointService.delete(endpointId)
      loadEndpoints()
    } catch (error) {
      console.error('Delete failed:', error)
    }
  }

  const getCriticalityColor = (criticality) => {
    switch (criticality) {
      case 'critical': return 'bg-red-100 text-red-800'
      case 'high': return 'bg-orange-100 text-orange-800'
      case 'medium': return 'bg-yellow-100 text-yellow-800'
      case 'low': return 'bg-green-100 text-green-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const getExpiryColor = (days) => {
    if (days <= 7) return 'text-red-600'
    if (days <= 30) return 'text-yellow-600'
    return 'text-green-600'
  }

  const filteredEndpoints = endpoints
    .filter(ep => {
      if (filters.search) {
        const searchLower = filters.search.toLowerCase()
        const matchesSearch =
          ep.host.toLowerCase().includes(searchLower) ||
          (ep.owner && ep.owner.toLowerCase().includes(searchLower))
        if (!matchesSearch) return false
      }
      if (filters.criticality && ep.criticality !== filters.criticality) return false
      if (filters.hasWebhook === true && !ep.webhook_url) return false
      if (filters.hasWebhook === false && ep.webhook_url) return false
      if (filters.expiringDays) {
        const daysLeft = ep.last_scan ? Math.floor(ep.last_scan.days_until_expiry) : null
        if (daysLeft === null || daysLeft > filters.expiringDays) return false
      }
      return true
    })
    .sort((a, b) => {
      let aVal, bVal
      switch (sortConfig.key) {
        case 'host':
          aVal = a.host.toLowerCase()
          bVal = b.host.toLowerCase()
          break
        case 'port':
          aVal = a.port
          bVal = b.port
          break
        case 'owner':
          aVal = (a.owner || '').toLowerCase()
          bVal = (b.owner || '').toLowerCase()
          break
        case 'criticality':
          const order = { critical: 0, high: 1, medium: 2, low: 3 }
          aVal = order[a.criticality] ?? 4
          bVal = order[b.criticality] ?? 4
          break
        case 'webhook':
          aVal = a.webhook_url ? 0 : 1
          bVal = b.webhook_url ? 0 : 1
          break
        case 'expires':
          aVal = a.last_scan?.days_until_expiry ?? 9999
          bVal = b.last_scan?.days_until_expiry ?? 9999
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
      className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
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

  const canManageEndpoint = (endpoint) => {
    if (!isEditor) return false
    if (isAdmin) return true
    if (!endpoint?.created_by) return true
    return endpoint.created_by === user?.email
  }

  const renderScanTrend = (scans) => {
    if (!Array.isArray(scans) || scans.length === 0) {
      return <span className="text-sm text-gray-400">-</span>
    }

    const ordered = [...scans].reverse()
    return (
      <div className="flex items-end gap-1">
        {ordered.map((scan, index) => {
          const status = scan.status
          const color =
            status === 'success' ? 'bg-green-500' :
            status === 'failed' ? 'bg-red-500' :
            'bg-gray-300'
          const title = scan.scanned_at
            ? `${status} • ${format(new Date(scan.scanned_at), 'MMM dd HH:mm')}`
            : status
          return (
            <span
              key={`${status}-${index}`}
              className={`w-2 h-4 ${color} rounded-sm`}
              title={title}
            />
          )
        })}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Endpoints</h1>
          <p className="text-gray-500 mt-1">
            {filteredEndpoints.length} of {endpoints.length} endpoints
          </p>
        </div>
        {isEditor && (
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            <Plus className="w-4 h-4" />
            Add Endpoint
          </button>
        )}
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
                placeholder="Search host or owner..."
                value={filters.search}
                onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          {/* Criticality filter */}
          <select
            value={filters.criticality || ''}
            onChange={(e) => setFilters({ ...filters, criticality: e.target.value || null })}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Criticality</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

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

          {/* Webhook filter */}
          <select
            value={filters.hasWebhook === null ? '' : (filters.hasWebhook ? 'yes' : 'no')}
            onChange={(e) => {
              const val = e.target.value
              setFilters({ ...filters, hasWebhook: val === '' ? null : val === 'yes' })
            }}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Webhooks</option>
            <option value="yes">With Webhook</option>
            <option value="no">Without Webhook</option>
          </select>

          {/* Clear filters */}
          <button
            onClick={() => setFilters({ search: '', criticality: null, hasWebhook: null, expiringDays: null })}
            className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200"
          >
            Clear Filters
          </button>
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="bg-white rounded-lg shadow-md overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b">
            <tr>
              <SortHeader label="Host" sortKey="host" />
              <SortHeader label="Port" sortKey="port" />
              <SortHeader label="Owner" sortKey="owner" />
              <SortHeader label="Criticality" sortKey="criticality" />
              <SortHeader label="Webhook" sortKey="webhook" />
              <SortHeader label="Expires" sortKey="expires" />
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Recent</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading ? (
              <tr>
                <td colSpan="8" className="px-4 py-8 text-center">
                  <Loader2 className="w-8 h-8 mx-auto animate-spin text-blue-500" />
                </td>
              </tr>
            ) : filteredEndpoints.length === 0 ? (
              <tr>
                <td colSpan="8" className="px-4 py-8 text-center text-gray-500">
                  <Server className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                  <p>{endpoints.length === 0 ? 'No endpoints configured. Add your first endpoint to start monitoring.' : 'No endpoints match the current filters.'}</p>
                </td>
              </tr>
            ) : (
              filteredEndpoints.map(endpoint => {
                const lastScan = endpoint.last_scan
                const daysLeft = lastScan ? Math.floor(lastScan.days_until_expiry) : null

                return (
                  <tr key={endpoint.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <span className="font-medium text-gray-900">{endpoint.host}</span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600">{endpoint.port}</td>
                    <td className="px-4 py-3 text-sm text-gray-600">{endpoint.owner || '-'}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 text-xs font-medium rounded ${getCriticalityColor(endpoint.criticality)}`}>
                        {endpoint.criticality}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {endpoint.webhook_url ? (
                        <Bell className="w-4 h-4 text-green-500" />
                      ) : (
                        <span className="text-gray-300">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {daysLeft !== null ? (
                        <span className={`text-sm font-medium ${getExpiryColor(daysLeft)}`}>
                          {daysLeft} days
                        </span>
                      ) : (
                        <span className="text-sm text-gray-400">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {renderScanTrend(endpoint.recent_scans)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-1">
                        {isEditor && (
                          <>
                            <button
                              onClick={() => handleScan(endpoint.id)}
                              disabled={scanning[endpoint.id]}
                              className="p-2 text-blue-600 hover:bg-blue-50 rounded disabled:opacity-50"
                              title="Scan"
                            >
                              {scanning[endpoint.id] ? (
                                <Loader2 className="w-4 h-4 animate-spin" />
                              ) : (
                                <Play className="w-4 h-4" />
                              )}
                            </button>
                            {canManageEndpoint(endpoint) && (
                              <>
                                <button
                                  onClick={() => setEditingEndpoint(endpoint)}
                                  className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded"
                                  title="Edit"
                                >
                                  <Edit2 className="w-4 h-4" />
                                </button>
                                <button
                                  onClick={() => handleDelete(endpoint.id)}
                                  className="p-2 text-red-400 hover:text-red-600 hover:bg-red-50 rounded"
                                  title="Delete"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </>
                            )}
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Add Endpoint Modal */}
      {showAddModal && (
        <AddEndpointModal
          onClose={() => setShowAddModal(false)}
          onSuccess={() => {
            setShowAddModal(false)
            loadEndpoints()
          }}
        />
      )}

      {/* Edit Endpoint Modal */}
      {editingEndpoint && (
        <EditEndpointModal
          endpoint={editingEndpoint}
          onClose={() => setEditingEndpoint(null)}
          onSuccess={() => {
            setEditingEndpoint(null)
            loadEndpoints()
          }}
        />
      )}
    </div>
  )
}

function AddEndpointModal({ onClose, onSuccess }) {
  const [formData, setFormData] = useState({
    host: '',
    port: 443,
    owner: '',
    criticality: 'medium',
    webhook_url: '',
  })
  const [submitting, setSubmitting] = useState(false)
  const [testingWebhook, setTestingWebhook] = useState(false)
  const [webhookResult, setWebhookResult] = useState(null)

  const handleTestWebhook = async () => {
    if (!formData.webhook_url) return

    try {
      setTestingWebhook(true)
      setWebhookResult(null)

      const response = await api.post('/webhooks/test', {
        webhook_url: formData.webhook_url,
        message: `Test notification for ${formData.host || 'new endpoint'}:${formData.port}`
      })
      setWebhookResult(response.data)
    } catch (error) {
      setWebhookResult({ success: false, message: error.message })
    } finally {
      setTestingWebhook(false)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    try {
      setSubmitting(true)
      await endpointService.create(formData)
      onSuccess()
    } catch (error) {
      console.error('Failed to create endpoint:', error)
      alert('Failed to create endpoint')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-md w-full mx-4">
        <div className="p-6 border-b">
          <h2 className="text-xl font-semibold">Add New Endpoint</h2>
        </div>
        
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Hostname *
            </label>
            <input
              type="text"
              required
              value={formData.host}
              onChange={(e) => setFormData({ ...formData, host: e.target.value })}
              placeholder="example.com"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Port *
            </label>
            <input
              type="number"
              required
              value={formData.port}
              onChange={(e) => setFormData({ ...formData, port: parseInt(e.target.value) })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Owner
            </label>
            <input
              type="text"
              value={formData.owner}
              onChange={(e) => setFormData({ ...formData, owner: e.target.value })}
              placeholder="Team or person responsible"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Criticality *
            </label>
            <select
              value={formData.criticality}
              onChange={(e) => setFormData({ ...formData, criticality: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Mattermost Webhook URL
            </label>
            <div className="flex gap-2">
              <input
                type="url"
                value={formData.webhook_url}
                onChange={(e) => {
                  setFormData({ ...formData, webhook_url: e.target.value })
                  setWebhookResult(null)
                }}
                placeholder="https://mattermost.example.com/hooks/..."
                className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                type="button"
                onClick={handleTestWebhook}
                disabled={!formData.webhook_url || testingWebhook}
                className="px-3 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 disabled:opacity-50 text-sm"
              >
                {testingWebhook ? 'Testing...' : 'Test'}
              </button>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Optional: Send notifications for this endpoint to a specific webhook
            </p>

            {webhookResult && (
              <div className={`mt-2 p-2 rounded text-sm flex items-center gap-2 ${
                webhookResult.success ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
              }`}>
                {webhookResult.success ? (
                  <CheckCircle className="w-4 h-4" />
                ) : (
                  <XCircle className="w-4 h-4" />
                )}
                {webhookResult.message}
              </div>
            )}
          </div>

          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {submitting ? 'Creating...' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function EditEndpointModal({ endpoint, onClose, onSuccess }) {
  const [formData, setFormData] = useState({
    owner: endpoint.owner || '',
    criticality: endpoint.criticality || 'medium',
    webhook_url: endpoint.webhook_url || '',
  })
  const [submitting, setSubmitting] = useState(false)
  const [testingWebhook, setTestingWebhook] = useState(false)
  const [webhookResult, setWebhookResult] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()

    try {
      setSubmitting(true)
      await endpointService.update(endpoint.id, formData)
      onSuccess()
    } catch (error) {
      console.error('Failed to update endpoint:', error)
      alert('Failed to update endpoint')
    } finally {
      setSubmitting(false)
    }
  }

  const handleTestWebhook = async () => {
    if (!formData.webhook_url) return

    try {
      setTestingWebhook(true)
      setWebhookResult(null)

      const response = await api.post('/webhooks/test', {
        webhook_url: formData.webhook_url,
        message: `Test notification for ${endpoint.host}:${endpoint.port}`
      })
      setWebhookResult(response.data)
    } catch (error) {
      setWebhookResult({ success: false, message: error.message })
    } finally {
      setTestingWebhook(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-md w-full mx-4">
        <div className="p-6 border-b">
          <h2 className="text-xl font-semibold">Edit Endpoint</h2>
          <p className="text-sm text-gray-500 mt-1">{endpoint.host}:{endpoint.port}</p>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Owner
            </label>
            <input
              type="text"
              value={formData.owner}
              onChange={(e) => setFormData({ ...formData, owner: e.target.value })}
              placeholder="Team or person responsible"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Criticality
            </label>
            <select
              value={formData.criticality}
              onChange={(e) => setFormData({ ...formData, criticality: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Mattermost Webhook URL
            </label>
            <div className="flex gap-2">
              <input
                type="url"
                value={formData.webhook_url}
                onChange={(e) => {
                  setFormData({ ...formData, webhook_url: e.target.value })
                  setWebhookResult(null)
                }}
                placeholder="https://mattermost.example.com/hooks/..."
                className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                type="button"
                onClick={handleTestWebhook}
                disabled={!formData.webhook_url || testingWebhook}
                className="px-3 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 disabled:opacity-50 text-sm"
              >
                {testingWebhook ? 'Testing...' : 'Test'}
              </button>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Optional: Send notifications for this endpoint to a specific webhook
            </p>

            {webhookResult && (
              <div className={`mt-2 p-2 rounded text-sm flex items-center gap-2 ${
                webhookResult.success ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
              }`}>
                {webhookResult.success ? (
                  <CheckCircle className="w-4 h-4" />
                ) : (
                  <XCircle className="w-4 h-4" />
                )}
                {webhookResult.message}
              </div>
            )}
          </div>

          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {submitting ? 'Saving...' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
