import { useState, useEffect, useRef } from 'react'
import {
  Network, Plus, Trash2, CheckCircle, XCircle,
  Clock, Loader2, Search, X
} from 'lucide-react'
import { sweepService } from '../services/api'
import { useAuth } from '../contexts/AuthContext'

export default function Sweeps() {
  const { isEditor } = useAuth()
  const [sweeps, setSweeps] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [selectedSweep, setSelectedSweep] = useState(null)
  const intervalRef = useRef(null)

  const loadSweeps = async () => {
    try {
      const response = await sweepService.getAll()
      setSweeps(response.data.sweeps)
    } catch (error) {
      console.error('Failed to load sweeps:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadSweeps()

    // Auto-refresh every 3 seconds for running sweeps
    intervalRef.current = setInterval(() => {
      loadSweeps()
    }, 3000)

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
      }
    }
  }, [])

  const handleDelete = async (sweepId) => {
    if (!confirm('Delete this sweep and all its results?')) return
    try {
      await sweepService.delete(sweepId)
      loadSweeps()
    } catch (error) {
      console.error('Delete failed:', error)
      alert(error.response?.data?.detail || 'Failed to delete sweep')
    }
  }

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-5 h-5 text-green-500" />
      case 'running': return <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />
      case 'failed': return <XCircle className="w-5 h-5 text-red-500" />
      default: return <Clock className="w-5 h-5 text-gray-400" />
    }
  }

  const formatPorts = (portsJson) => {
    try {
      const ports = JSON.parse(portsJson)
      return ports.join(', ')
    } catch {
      return portsJson
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Network Sweeps</h1>
          <p className="text-gray-500 mt-1">
            Discover TLS endpoints in your network
          </p>
        </div>
        {isEditor && (
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            <Plus className="w-4 h-4" />
            New Sweep
          </button>
        )}
      </div>

      {/* Sweeps Table */}
      <div className="bg-white rounded-lg shadow-md overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Name
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Target
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Ports
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Progress
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Found
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Status
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading ? (
              <tr>
                <td colSpan="7" className="px-6 py-8 text-center">
                  <Loader2 className="w-8 h-8 mx-auto animate-spin text-blue-500" />
                </td>
              </tr>
            ) : sweeps.length === 0 ? (
              <tr>
                <td colSpan="7" className="px-6 py-8 text-center text-gray-500">
                  <Network className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                  <p>No sweeps yet. Create your first sweep to discover endpoints.</p>
                </td>
              </tr>
            ) : (
              sweeps.map(sweep => (
                <tr key={sweep.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 font-medium">{sweep.name}</td>
                  <td className="px-6 py-4 text-sm text-gray-600 font-mono">{sweep.target}</td>
                  <td className="px-6 py-4 text-sm">
                    {formatPorts(sweep.ports)}
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 bg-gray-200 rounded-full h-2 max-w-24">
                        <div
                          className="bg-blue-600 h-2 rounded-full transition-all"
                          style={{
                            width: `${sweep.progress_total ?
                              (sweep.progress_scanned / sweep.progress_total * 100) : 0}%`
                          }}
                        />
                      </div>
                      <span className="text-xs text-gray-500 whitespace-nowrap">
                        {sweep.progress_scanned}/{sweep.progress_total}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="px-2 py-1 bg-green-100 text-green-800 rounded-full text-sm">
                      {sweep.progress_found}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      {getStatusIcon(sweep.status)}
                      <span className="capitalize text-sm">{sweep.status}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <div className="flex justify-end gap-2">
                      <button
                        onClick={() => setSelectedSweep(sweep)}
                        className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded"
                        title="View details"
                      >
                        <Search className="w-4 h-4" />
                      </button>
                      {isEditor && (
                        <button
                          onClick={() => handleDelete(sweep.id)}
                          disabled={sweep.status === 'running'}
                          className="p-2 text-red-400 hover:text-red-600 hover:bg-red-50 rounded disabled:opacity-50 disabled:cursor-not-allowed"
                          title="Delete sweep"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {showCreateModal && (
        <CreateSweepModal
          onClose={() => setShowCreateModal(false)}
          onSuccess={() => {
            setShowCreateModal(false)
            loadSweeps()
          }}
        />
      )}

      {selectedSweep && (
        <SweepDetailsModal
          sweep={selectedSweep}
          onClose={() => setSelectedSweep(null)}
        />
      )}
    </div>
  )
}

function CreateSweepModal({ onClose, onSuccess }) {
  const [formData, setFormData] = useState({
    name: '',
    target: '',
    ports: '443',
    owner: '',
    criticality: 'medium',
    webhook_url: '',
  })
  const [validation, setValidation] = useState(null)
  const [validating, setValidating] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const validateTimeoutRef = useRef(null)

  const validateTarget = async (target) => {
    if (!target) {
      setValidation(null)
      return
    }
    try {
      setValidating(true)
      const response = await sweepService.validate(target)
      setValidation(response.data)
    } catch (error) {
      setValidation({ valid: false, error: 'Validation failed' })
    } finally {
      setValidating(false)
    }
  }

  const handleTargetChange = (e) => {
    const target = e.target.value
    setFormData({ ...formData, target })
    // Debounce validation
    if (validateTimeoutRef.current) {
      clearTimeout(validateTimeoutRef.current)
    }
    validateTimeoutRef.current = setTimeout(() => validateTarget(target), 500)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()

    // Parse ports
    const ports = formData.ports
      .split(',')
      .map(p => parseInt(p.trim()))
      .filter(p => p > 0 && p <= 65535)

    if (ports.length === 0) {
      alert('Please specify valid ports')
      return
    }

    try {
      setSubmitting(true)
      await sweepService.create({
        name: formData.name,
        target: formData.target,
        ports,
        owner: formData.owner || null,
        criticality: formData.criticality,
        webhook_url: formData.webhook_url || null,
      })
      onSuccess()
    } catch (error) {
      alert(error.response?.data?.detail || 'Failed to create sweep')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-lg w-full mx-4">
        <div className="p-6 border-b flex justify-between items-center">
          <div>
            <h2 className="text-xl font-semibold">Create Network Sweep</h2>
            <p className="text-sm text-gray-500 mt-1">
              Discover TLS endpoints in an IP range
            </p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Name *
            </label>
            <input
              type="text"
              required
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="Production Subnet Scan"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Target (CIDR or IP Range) *
            </label>
            <input
              type="text"
              required
              value={formData.target}
              onChange={handleTargetChange}
              placeholder="10.0.0.0/24 or 192.168.1.1-50"
              className={`w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono ${
                validation?.valid === false ? 'border-red-500' : 'border-gray-300'
              }`}
            />
            {validating && (
              <p className="text-sm text-gray-500 mt-1 flex items-center gap-1">
                <Loader2 className="w-3 h-3 animate-spin" /> Validating...
              </p>
            )}
            {validation && !validating && (
              <p className={`text-sm mt-1 ${validation.valid ? 'text-green-600' : 'text-red-600'}`}>
                {validation.valid
                  ? `Valid: ${validation.ip_count.toLocaleString()} IPs to scan`
                  : validation.error
                }
              </p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Ports (comma-separated) *
            </label>
            <input
              type="text"
              required
              value={formData.ports}
              onChange={(e) => setFormData({ ...formData, ports: e.target.value })}
              placeholder="443, 8443, 636"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <p className="text-xs text-gray-500 mt-1">Default: 443 (HTTPS)</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Default Owner
              </label>
              <input
                type="text"
                value={formData.owner}
                onChange={(e) => setFormData({ ...formData, owner: e.target.value })}
                placeholder="Infrastructure Team"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Default Criticality
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
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Default Webhook URL
            </label>
            <input
              type="url"
              value={formData.webhook_url}
              onChange={(e) => setFormData({ ...formData, webhook_url: e.target.value })}
              placeholder="https://mattermost.example.com/hooks/..."
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <p className="text-xs text-gray-500 mt-1">
              Discovered endpoints will use this webhook
            </p>
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
              disabled={submitting || !validation?.valid}
              className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Starting...
                </>
              ) : (
                'Start Sweep'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function SweepDetailsModal({ sweep, onClose }) {
  const [details, setDetails] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const loadDetails = async () => {
      try {
        const response = await sweepService.getById(sweep.id)
        setDetails(response.data)
      } catch (error) {
        console.error('Failed to load sweep details:', error)
      } finally {
        setLoading(false)
      }
    }
    loadDetails()

    // Auto-refresh if running
    let interval
    if (sweep.status === 'running') {
      interval = setInterval(loadDetails, 2000)
    }
    return () => {
      if (interval) clearInterval(interval)
    }
  }, [sweep.id, sweep.status])

  const formatDate = (isoString) => {
    if (!isoString) return '-'
    return new Date(isoString).toLocaleString()
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[80vh] overflow-hidden flex flex-col">
        <div className="p-6 border-b flex justify-between items-center shrink-0">
          <div>
            <h2 className="text-xl font-semibold">{sweep.name}</h2>
            <p className="text-sm text-gray-500 font-mono">{sweep.target}</p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 overflow-y-auto flex-1">
          {loading ? (
            <div className="text-center py-8">
              <Loader2 className="w-8 h-8 mx-auto animate-spin text-blue-500" />
            </div>
          ) : (
            <>
              {/* Sweep Info */}
              <div className="grid grid-cols-2 gap-4 mb-6 text-sm">
                <div>
                  <span className="text-gray-500">Status:</span>
                  <span className="ml-2 capitalize font-medium">{details?.status}</span>
                </div>
                <div>
                  <span className="text-gray-500">Progress:</span>
                  <span className="ml-2 font-medium">
                    {details?.progress_scanned} / {details?.progress_total}
                  </span>
                </div>
                <div>
                  <span className="text-gray-500">Started:</span>
                  <span className="ml-2">{formatDate(details?.started_at)}</span>
                </div>
                <div>
                  <span className="text-gray-500">Completed:</span>
                  <span className="ml-2">{formatDate(details?.completed_at)}</span>
                </div>
                {details?.owner && (
                  <div>
                    <span className="text-gray-500">Owner:</span>
                    <span className="ml-2">{details.owner}</span>
                  </div>
                )}
                {details?.error_message && (
                  <div className="col-span-2">
                    <span className="text-gray-500">Error:</span>
                    <span className="ml-2 text-red-600">{details.error_message}</span>
                  </div>
                )}
              </div>

              {/* Results */}
              <h3 className="font-medium text-gray-700 mb-3">
                Discovered Endpoints ({details?.results?.length || 0})
              </h3>
              {details?.results?.length === 0 ? (
                <p className="text-center text-gray-500 py-4">
                  {details?.status === 'running'
                    ? 'Scanning in progress...'
                    : 'No endpoints discovered'}
                </p>
              ) : (
                <div className="space-y-2">
                  {details?.results?.map((result, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                    >
                      <div className="flex items-center gap-3">
                        <span className={`w-2 h-2 rounded-full ${
                          result.status === 'open' ? 'bg-green-500' : 'bg-gray-400'
                        }`} />
                        <span className="font-mono text-sm">
                          {result.ip_address}:{result.port}
                        </span>
                      </div>
                      <span className="text-xs text-gray-400">
                        {formatDate(result.scanned_at)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>

        <div className="p-6 border-t shrink-0">
          <button
            onClick={onClose}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
