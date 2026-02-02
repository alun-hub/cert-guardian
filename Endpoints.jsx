import { useState, useEffect } from 'react'
import { Plus, Server, Trash2, Edit2, Play } from 'lucide-react'
import { endpointService, scanService } from '../services/api'

export default function Endpoints() {
  const [endpoints, setEndpoints] = useState([])
  const [loading, setLoading] = useState(true)
  const [showAddModal, setShowAddModal] = useState(false)
  const [scanning, setScanning] = useState({})

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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Endpoints</h1>
          <p className="text-gray-500 mt-1">
            {endpoints.length} endpoints being monitored
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          <Plus className="w-4 h-4" />
          Add Endpoint
        </button>
      </div>

      {/* Endpoints Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {loading ? (
          <div className="col-span-full p-8 text-center">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-300 border-t-blue-600"></div>
          </div>
        ) : endpoints.length === 0 ? (
          <div className="col-span-full p-8 text-center text-gray-500">
            No endpoints configured. Add your first endpoint to start monitoring.
          </div>
        ) : (
          endpoints.map(endpoint => (
            <EndpointCard
              key={endpoint.id}
              endpoint={endpoint}
              onScan={() => handleScan(endpoint.id)}
              onDelete={() => handleDelete(endpoint.id)}
              scanning={scanning[endpoint.id]}
            />
          ))
        )}
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
    </div>
  )
}

function EndpointCard({ endpoint, onScan, onDelete, scanning }) {
  const getCriticalityColor = (criticality) => {
    switch (criticality) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200'
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'low': return 'bg-green-100 text-green-800 border-green-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const lastScan = endpoint.last_scan
  const daysLeft = lastScan ? Math.floor(lastScan.days_until_expiry) : null

  return (
    <div className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-100 rounded-lg">
            <Server className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <h3 className="font-semibold text-gray-900">{endpoint.host}</h3>
            <p className="text-sm text-gray-500">Port {endpoint.port}</p>
          </div>
        </div>
      </div>

      <div className="space-y-3 mb-4">
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600">Owner</span>
          <span className="text-sm font-medium">{endpoint.owner || 'Unassigned'}</span>
        </div>
        
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600">Criticality</span>
          <span className={`px-2 py-1 text-xs font-medium rounded ${getCriticalityColor(endpoint.criticality)}`}>
            {endpoint.criticality.toUpperCase()}
          </span>
        </div>

        {lastScan && (
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-600">Expires in</span>
            <span className={`text-sm font-medium ${
              daysLeft <= 7 ? 'text-red-600' :
              daysLeft <= 30 ? 'text-yellow-600' :
              'text-green-600'
            }`}>
              {daysLeft} days
            </span>
          </div>
        )}
      </div>

      <div className="flex gap-2">
        <button
          onClick={onScan}
          disabled={scanning}
          className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 text-sm"
        >
          <Play className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} />
          {scanning ? 'Scanning...' : 'Scan'}
        </button>
        <button
          onClick={onDelete}
          className="px-3 py-2 bg-red-100 text-red-600 rounded-lg hover:bg-red-200 text-sm"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
    </div>
  )
}

function AddEndpointModal({ onClose, onSuccess }) {
  const [formData, setFormData] = useState({
    host: '',
    port: 443,
    owner: '',
    criticality: 'medium',
  })
  const [submitting, setSubmitting] = useState(false)

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
