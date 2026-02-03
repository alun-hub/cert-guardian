import { useState, useEffect } from 'react'
import { 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Clock,
  RefreshCw,
  Shield,
  AlertOctagon
} from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts'
import { dashboardService, certificateService, scanService } from '../services/api'

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [timeline, setTimeline] = useState([])
  const [recentCerts, setRecentCerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)

  const loadData = async () => {
    try {
      setLoading(true)
      const [statsRes, timelineRes, certsRes] = await Promise.all([
        dashboardService.getStats(),
        dashboardService.getTimeline(),
        certificateService.getAll({ expiring_days: 30, limit: 5 })
      ])
      
      setStats(statsRes.data)
      setTimeline(timelineRes.data.timeline)
      setRecentCerts(certsRes.data.certificates)
    } catch (error) {
      console.error('Failed to load dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleScanAll = async () => {
    try {
      setScanning(true)
      await scanService.triggerScan()
      setTimeout(loadData, 2000) // Reload after scan
    } catch (error) {
      console.error('Scan failed:', error)
    } finally {
      setScanning(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-gray-500 mt-1">Certificate monitoring overview</p>
        </div>
        <button
          onClick={handleScanAll}
          disabled={scanning}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} />
          {scanning ? 'Scanning...' : 'Scan All'}
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Certificates"
          value={stats.total_certificates}
          icon={<CheckCircle className="w-6 h-6 text-blue-500" />}
          color="blue"
        />
        <StatCard
          title="Expiring Soon"
          value={stats.expiring_soon}
          subtitle="Within 30 days"
          icon={<Clock className="w-6 h-6 text-yellow-500" />}
          color="yellow"
        />
        <StatCard
          title="Self-Signed"
          value={stats.self_signed}
          icon={<Shield className="w-6 h-6 text-red-500" />}
          color="red"
        />
        <StatCard
          title="Untrusted CA"
          value={stats.untrusted}
          icon={<AlertOctagon className="w-6 h-6 text-orange-500" />}
          color="orange"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Expiry Timeline */}
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-lg font-semibold mb-4">Certificate Expiry Timeline</h2>
          <p className="text-sm text-gray-500 mb-4">Certificates expiring per month</p>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis
                dataKey="label"
                tick={{ fontSize: 12 }}
                interval={0}
                angle={-45}
                textAnchor="end"
                height={60}
              />
              <YAxis allowDecimals={false} />
              <Tooltip
                formatter={(value) => [value, 'Certificates']}
                labelFormatter={(label) => `Month: ${label}`}
              />
              <Bar dataKey="count" name="Expiring">
                {timeline.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={entry.count > 0 ? (index === 0 ? '#ef4444' : index < 3 ? '#f59e0b' : '#3b82f6') : '#e5e7eb'}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Recent Expiring Certificates */}
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-lg font-semibold mb-4">Urgent: Expiring Soon</h2>
          <div className="space-y-3">
            {recentCerts.length === 0 ? (
              <p className="text-gray-500 text-center py-8">
                No certificates expiring soon
              </p>
            ) : (
              recentCerts.map(cert => (
                <CertificateCard key={cert.id} cert={cert} />
              ))
            )}
          </div>
        </div>
      </div>

      {/* Endpoints Status */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-lg font-semibold mb-4">Monitored Endpoints</h2>
        <p className="text-3xl font-bold text-gray-900">
          {stats.total_endpoints}
        </p>
        <p className="text-gray-500 text-sm mt-1">
          Total endpoints being monitored
        </p>
      </div>
    </div>
  )
}

function StatCard({ title, value, subtitle, icon, color }) {
  const colors = {
    blue: 'bg-blue-50 border-blue-200',
    yellow: 'bg-yellow-50 border-yellow-200',
    red: 'bg-red-50 border-red-200',
    orange: 'bg-orange-50 border-orange-200',
  }

  return (
    <div className={`${colors[color]} border rounded-lg p-6`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600 font-medium">{title}</p>
          <p className="text-3xl font-bold mt-2">{value}</p>
          {subtitle && (
            <p className="text-xs text-gray-500 mt-1">{subtitle}</p>
          )}
        </div>
        <div>{icon}</div>
      </div>
    </div>
  )
}

function CertificateCard({ cert }) {
  const daysLeft = Math.floor(cert.days_until_expiry)
  const isUrgent = daysLeft <= 7
  const isWarning = daysLeft <= 30

  return (
    <div className={`border-l-4 ${
      isUrgent ? 'border-red-500 bg-red-50' : 
      isWarning ? 'border-yellow-500 bg-yellow-50' : 
      'border-blue-500 bg-blue-50'
    } p-4 rounded`}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="font-medium text-gray-900">
            {cert.subject.split(',')[0].replace('CN=', '')}
          </p>
          <p className="text-sm text-gray-600 mt-1">
            {cert.endpoints?.[0]?.host || 'Unknown endpoint'}
          </p>
        </div>
        <div className="text-right">
          <p className={`text-lg font-bold ${
            isUrgent ? 'text-red-600' : 
            isWarning ? 'text-yellow-600' : 
            'text-blue-600'
          }`}>
            {daysLeft} days
          </p>
          {cert.is_self_signed && (
            <span className="text-xs text-red-600 font-medium">
              Self-Signed
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
