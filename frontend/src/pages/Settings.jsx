import { useState, useEffect } from 'react'
import { Shield, Plus, Trash2, Upload, CheckCircle, XCircle } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import api from '../services/api'

const API_BASE = '/api'

export default function Settings() {
  const { isEditor } = useAuth()
  const [trustedCAs, setTrustedCAs] = useState([])
  const [loading, setLoading] = useState(true)
  const [showAddModal, setShowAddModal] = useState(false)

  const loadTrustedCAs = async () => {
    try {
      setLoading(true)
      const response = await fetch(`${API_BASE}/trusted-cas`)
      const data = await response.json()
      setTrustedCAs(data.trusted_cas)
    } catch (error) {
      console.error('Failed to load trusted CAs:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadTrustedCAs()
  }, [])

  const handleDelete = async (caId) => {
    if (!confirm('Are you sure you want to delete this trusted CA?')) return

    try {
      const response = await fetch(`${API_BASE}/trusted-cas/${caId}`, {
        method: 'DELETE'
      })
      if (response.ok) {
        loadTrustedCAs()
      }
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
      const response = await fetch(`${API_BASE}/trusted-cas`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, pem_data: pemData })
      })

      const data = await response.json()

      if (response.ok) {
        onSuccess()
      } else {
        setError(data.detail || 'Failed to add CA')
      }
    } catch (err) {
      setError('Failed to add CA: ' + err.message)
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
