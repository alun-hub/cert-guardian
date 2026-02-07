import { useState, useEffect } from 'react'
import { Shield, Plus, Trash2, Upload, Clock } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import api from '../services/api'

export default function Settings() {
  const { isEditor, isAdmin } = useAuth()
  const [trustedCAs, setTrustedCAs] = useState([])
  const [loading, setLoading] = useState(true)
  const [showAddModal, setShowAddModal] = useState(false)
  const [scannerSettings, setScannerSettings] = useState(null)
  const [scannerLoading, setScannerLoading] = useState(true)
  const [scannerSaving, setScannerSaving] = useState(false)
  const [scannerError, setScannerError] = useState('')
  const [intervalMinutes, setIntervalMinutes] = useState(60)
  const [dbHealth, setDbHealth] = useState(null)
  const [dbHealthLoading, setDbHealthLoading] = useState(true)
  const [dbHealthError, setDbHealthError] = useState('')
  const [siemSettings, setSiemSettings] = useState({ mode: 'disabled', tls_enabled: true, tls_verify: true })
  const [siemLoading, setSiemLoading] = useState(true)
  const [siemSaving, setSiemSaving] = useState(false)
  const [siemError, setSiemError] = useState('')

  const loadTrustedCAs = async () => {
    try {
      setLoading(true)
      const response = await api.get('/trusted-cas')
      setTrustedCAs(response.data.trusted_cas)
    } catch (error) {
      console.error('Failed to load trusted CAs:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadTrustedCAs()
  }, [])

  const loadScannerSettings = async () => {
    try {
      setScannerLoading(true)
      const response = await api.get('/settings/scanner')
      setScannerSettings(response.data)
      const minutes = Math.max(1, Math.round(response.data.interval_seconds / 60))
      setIntervalMinutes(minutes)
    } catch (error) {
      console.error('Failed to load scanner settings:', error)
    } finally {
      setScannerLoading(false)
    }
  }

  useEffect(() => {
    loadScannerSettings()
  }, [])

  const loadDbHealth = async () => {
    if (!isAdmin) return
    try {
      setDbHealthLoading(true)
      const response = await api.get('/settings/db-health')
      setDbHealth(response.data)
    } catch (error) {
      const detail = error.response?.data?.detail
      setDbHealthError(detail || 'Failed to load DB health')
    } finally {
      setDbHealthLoading(false)
    }
  }

  useEffect(() => {
    loadDbHealth()
  }, [isAdmin])

  const loadSiemSettings = async () => {
    if (!isAdmin) return
    try {
      setSiemLoading(true)
      const response = await api.get('/settings/siem')
      setSiemSettings(response.data)
    } catch (error) {
      const detail = error.response?.data?.detail
      setSiemError(detail || 'Failed to load SIEM settings')
    } finally {
      setSiemLoading(false)
    }
  }

  useEffect(() => {
    loadSiemSettings()
  }, [isAdmin])

  const handleSaveSiemSettings = async () => {
    try {
      setSiemSaving(true)
      setSiemError('')
      const response = await api.put('/settings/siem', siemSettings)
      setSiemSettings(response.data)
    } catch (error) {
      const detail = error.response?.data?.detail
      setSiemError(detail || 'Failed to update SIEM settings')
    } finally {
      setSiemSaving(false)
    }
  }

  const handleSaveScannerSettings = async () => {
    try {
      setScannerSaving(true)
      setScannerError('')
      const intervalSeconds = Math.max(10, Math.round(intervalMinutes * 60))
      const response = await api.put('/settings/scanner', { interval_seconds: intervalSeconds })
      setScannerSettings(response.data)
    } catch (error) {
      const detail = error.response?.data?.detail
      setScannerError(detail || 'Failed to update scanner settings')
    } finally {
      setScannerSaving(false)
    }
  }

  const handleDelete = async (caId) => {
    if (!confirm('Are you sure you want to delete this trusted CA?')) return

    try {
      await api.delete(`/trusted-cas/${caId}`)
      loadTrustedCAs()
    } catch (error) {
      console.error('Delete failed:', error)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Settings</h1>
        <p className="text-gray-500 mt-1">Manage trusted CAs and global settings</p>
      </div>

      {/* Trusted CAs Section */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-blue-600" />
            <div>
              <h2 className="text-lg font-semibold">Trusted CA Certificates</h2>
              <p className="text-sm text-gray-500">
                Add custom root CAs to trust certificates signed by them
              </p>
            </div>
          </div>
          {isEditor && (
            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              <Plus className="w-4 h-4" />
              Add CA
            </button>
          )}
        </div>

        {loading ? (
          <div className="text-center py-8">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-300 border-t-blue-600"></div>
          </div>
        ) : trustedCAs.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <Shield className="w-12 h-12 mx-auto mb-3 text-gray-300" />
            <p>No custom trusted CAs configured</p>
            <p className="text-sm mt-1">System default CAs are always used</p>
          </div>
        ) : (
          <div className="space-y-3">
            {trustedCAs.map(ca => (
              <div
                key={ca.id}
                className="flex items-center justify-between p-4 bg-gray-50 rounded-lg border"
              >
                <div className="flex-1">
                  <p className="font-medium text-gray-900">{ca.name}</p>
                  <p className="text-sm text-gray-600 mt-1">{ca.subject}</p>
                  <p className="text-xs text-gray-400 mt-1">
                    Fingerprint: {ca.fingerprint.substring(0, 16)}...
                  </p>
                </div>
                {isEditor && (
                  <button
                    onClick={() => handleDelete(ca.id)}
                    className="p-2 text-red-600 hover:bg-red-100 rounded-lg"
                  >
                    <Trash2 className="w-5 h-5" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Scanner Settings */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="flex items-center gap-3 mb-6">
          <Clock className="w-6 h-6 text-blue-600" />
          <div>
            <h2 className="text-lg font-semibold">Scanner Settings</h2>
            <p className="text-sm text-gray-500">
              Configure how often the scanner runs
            </p>
          </div>
        </div>

        {scannerLoading ? (
          <div className="text-center py-6">
            <div className="inline-block animate-spin rounded-full h-6 w-6 border-4 border-gray-300 border-t-blue-600"></div>
          </div>
        ) : (
          <div className="space-y-4">
            {scannerError && (
              <div className="p-3 bg-red-100 border border-red-300 text-red-700 rounded-lg text-sm">
                {scannerError}
              </div>
            )}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Scan interval (minutes)
              </label>
              <input
                type="number"
                min="1"
                value={intervalMinutes}
                onChange={(e) => setIntervalMinutes(Number(e.target.value))}
                className="w-40 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-gray-500 mt-2">
                Current interval: {scannerSettings?.interval_seconds ?? 3600} seconds
              </p>
            </div>

            {isAdmin && (
              <button
                onClick={handleSaveScannerSettings}
                disabled={scannerSaving}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {scannerSaving ? 'Saving...' : 'Save Interval'}
              </button>
            )}

            {!isAdmin && (
              <p className="text-xs text-gray-500">
                Only admins can change scanner settings.
              </p>
            )}
          </div>
        )}
      </div>

      {isAdmin && (
        <div className="bg-white rounded-lg shadow-md p-6">
          <div className="flex items-center gap-3 mb-6">
            <Shield className="w-6 h-6 text-blue-600" />
            <div>
              <h2 className="text-lg font-semibold">Database Health</h2>
              <p className="text-sm text-gray-500">
                Size, table counts, and recent scan volume
              </p>
            </div>
          </div>

          {dbHealthLoading ? (
            <div className="text-center py-6">
              <div className="inline-block animate-spin rounded-full h-6 w-6 border-4 border-gray-300 border-t-blue-600"></div>
            </div>
          ) : dbHealthError ? (
            <div className="p-3 bg-red-100 border border-red-300 text-red-700 rounded-lg text-sm">
              {dbHealthError}
            </div>
          ) : (
            <div className="space-y-4 text-sm text-gray-700">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 bg-gray-50 rounded-lg border">
                  <p className="text-xs text-gray-500">DB Size</p>
                  <p className="text-lg font-semibold">
                    {formatBytes(dbHealth.db_size_bytes)}
                  </p>
                </div>
                <div className="p-4 bg-gray-50 rounded-lg border">
                  <p className="text-xs text-gray-500">Approx Used</p>
                  <p className="text-lg font-semibold">
                    {formatBytes(dbHealth.approx_db_bytes - dbHealth.approx_free_bytes)}
                  </p>
                </div>
                <div className="p-4 bg-gray-50 rounded-lg border">
                  <p className="text-xs text-gray-500">Scans (30 days)</p>
                  <p className="text-lg font-semibold">
                    {dbHealth.scans_last_30_days}
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {Object.entries(dbHealth.counts).map(([table, count]) => (
                  <div key={table} className="flex items-center justify-between px-3 py-2 bg-gray-50 rounded border">
                    <span className="text-gray-600">{table}</span>
                    <span className="font-medium">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {isAdmin && (
        <div className="bg-white rounded-lg shadow-md p-6">
          <div className="flex items-center gap-3 mb-6">
            <Shield className="w-6 h-6 text-blue-600" />
            <div>
              <h2 className="text-lg font-semibold">SIEM Forwarding</h2>
              <p className="text-sm text-gray-500">
                Configure external log forwarding via Syslog or Beats (TLS required)
              </p>
            </div>
          </div>

          {siemLoading ? (
            <div className="text-center py-6">
              <div className="inline-block animate-spin rounded-full h-6 w-6 border-4 border-gray-300 border-t-blue-600"></div>
            </div>
          ) : (
            <div className="space-y-4">
              {siemError && (
                <div className="p-3 bg-red-100 border border-red-300 text-red-700 rounded-lg text-sm">
                  {siemError}
                </div>
              )}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Mode</label>
                  <select
                    value={siemSettings.mode || 'disabled'}
                    onChange={(e) => setSiemSettings(prev => ({ ...prev, mode: e.target.value }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="disabled">Disabled</option>
                    <option value="stdout">Stdout (Kubernetes)</option>
                    <option value="syslog">Syslog (TLS)</option>
                    <option value="beats">Beats (TLS)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Host</label>
                  <input
                    type="text"
                    value={siemSettings.host || ''}
                    onChange={(e) => setSiemSettings(prev => ({ ...prev, host: e.target.value }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Port</label>
                  <input
                    type="number"
                    value={siemSettings.port || ''}
                    onChange={(e) => setSiemSettings(prev => ({ ...prev, port: Number(e.target.value) }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <label className="flex items-center gap-2 text-sm text-gray-700">
                  <input
                    type="checkbox"
                    checked={Boolean(siemSettings.tls_enabled)}
                    onChange={(e) => setSiemSettings(prev => ({ ...prev, tls_enabled: e.target.checked }))}
                  />
                  TLS enabled
                </label>
                <label className="flex items-center gap-2 text-sm text-gray-700">
                  <input
                    type="checkbox"
                    checked={Boolean(siemSettings.tls_verify)}
                    onChange={(e) => setSiemSettings(prev => ({ ...prev, tls_verify: e.target.checked }))}
                  />
                  Verify TLS
                </label>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">CA PEM</label>
                <textarea
                  value={siemSettings.ca_pem || ''}
                  onChange={(e) => setSiemSettings(prev => ({ ...prev, ca_pem: e.target.value }))}
                  rows={3}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-xs"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Client Cert PEM</label>
                  <textarea
                    value={siemSettings.client_cert_pem || ''}
                    onChange={(e) => setSiemSettings(prev => ({ ...prev, client_cert_pem: e.target.value }))}
                    rows={3}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-xs"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Client Key PEM</label>
                  <textarea
                    value={siemSettings.client_key_pem || ''}
                    onChange={(e) => setSiemSettings(prev => ({ ...prev, client_key_pem: e.target.value }))}
                    rows={3}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-xs"
                  />
                </div>
              </div>

              <button
                onClick={handleSaveSiemSettings}
                disabled={siemSaving}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {siemSaving ? 'Saving...' : 'Save SIEM Settings'}
              </button>
              <button
                onClick={async () => {
                  try {
                    setSiemSaving(true)
                    setSiemError('')
                    await api.post('/settings/siem/test', { message: 'Test event from Certificate Guardian' })
                  } catch (error) {
                    const detail = error.response?.data?.detail
                    setSiemError(detail || 'Failed to send test event')
                  } finally {
                    setSiemSaving(false)
                  }
                }}
                disabled={siemSaving}
                className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 disabled:opacity-50"
              >
                Send Test Event
              </button>
            </div>
          )}
        </div>
      )}

      {showAddModal && (
        <AddCAModal
          onClose={() => setShowAddModal(false)}
          onSuccess={() => {
            setShowAddModal(false)
            loadTrustedCAs()
          }}
        />
      )}
    </div>
  )
}

function AddCAModal({ onClose, onSuccess }) {
  const [name, setName] = useState('')
  const [pemData, setPemData] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  const handleFileUpload = (e) => {
    const file = e.target.files[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = (event) => {
        setPemData(event.target.result)
        if (!name) {
          setName(file.name.replace(/\.(pem|crt|cer)$/i, ''))
        }
      }
      reader.readAsText(file)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    if (!pemData.includes('-----BEGIN CERTIFICATE-----')) {
      setError('Invalid PEM format. Must contain -----BEGIN CERTIFICATE-----')
      return
    }

    try {
      setSubmitting(true)
      await api.post('/trusted-cas', { name, pem_data: pemData })
      onSuccess()
    } catch (err) {
      const detail = err.response?.data?.detail
      setError(detail || 'Failed to add CA')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-lg w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div className="p-6 border-b">
          <h2 className="text-xl font-semibold">Add Trusted CA Certificate</h2>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="p-3 bg-red-100 border border-red-300 text-red-700 rounded-lg text-sm">
              {error}
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Name *
            </label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Internal CA"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Upload PEM File
            </label>
            <div className="flex items-center gap-2">
              <label className="flex-1 flex items-center justify-center gap-2 px-4 py-3 border-2 border-dashed border-gray-300 rounded-lg cursor-pointer hover:border-blue-500">
                <Upload className="w-5 h-5 text-gray-400" />
                <span className="text-sm text-gray-600">
                  Click to upload .pem, .crt, or .cer file
                </span>
                <input
                  type="file"
                  accept=".pem,.crt,.cer"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Or Paste PEM Data *
            </label>
            <textarea
              required
              value={pemData}
              onChange={(e) => setPemData(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
              rows={8}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
            />
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
              {submitting ? 'Adding...' : 'Add CA'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return '-'
  if (bytes < 1024) return `${bytes} B`
  const kb = bytes / 1024
  if (kb < 1024) return `${kb.toFixed(1)} KB`
  const mb = kb / 1024
  if (mb < 1024) return `${mb.toFixed(1)} MB`
  const gb = mb / 1024
  return `${gb.toFixed(1)} GB`
}
