import React from 'react'
import { BrowserRouter as Router, Routes, Route, Link, Navigate, useLocation } from 'react-router-dom'
import { Lock, LayoutDashboard, Server, Shield, Settings, Network, Users, LogOut, User, Info, ScrollText } from 'lucide-react'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import Dashboard from './pages/Dashboard'
import Certificates from './pages/Certificates'
import Endpoints from './pages/Endpoints'
import Sweeps from './pages/Sweeps'
import Security from './pages/Security'
import SettingsPage from './pages/Settings'
import About from './pages/About'
import AuditLogs from './pages/AuditLogs'
import Login from './pages/Login'
import UserManagement from './pages/UserManagement'

function ProtectedRoute({ children, requireAdmin = false }) {
  const { isAuthenticated, isAdmin, loading } = useAuth()
  const location = useLocation()

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">Loading...</div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  if (requireAdmin && !isAdmin) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
        <h2 className="text-lg font-semibold text-red-800">Access Denied</h2>
        <p className="text-red-600 mt-2">You need administrator privileges to access this page.</p>
      </div>
    )
  }

  return children
}

function AppContent() {
  const { user, isAuthenticated, isAdmin, logout, loading } = useAuth()

  // Show login page if not authenticated
  if (!loading && !isAuthenticated) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  // Show loading while checking auth
  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-gray-400">Loading...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Sidebar */}
      <div className="fixed inset-y-0 left-0 w-64 bg-gray-900 text-white flex flex-col overflow-y-auto">
        <Link to="/" className="flex items-center gap-3 p-6 border-b border-gray-800 hover:bg-gray-800">
          <Lock className="w-8 h-8 text-blue-400" />
          <div>
            <h1 className="text-xl font-bold">Certificate Guardian</h1>
            <p className="text-xs text-gray-400">TLS Monitor</p>
          </div>
        </Link>

        <nav className="p-4 space-y-2 flex-1 min-h-0">
          <NavLink to="/" icon={<LayoutDashboard className="w-5 h-5" />}>
            Dashboard
          </NavLink>
          <NavLink to="/certificates" icon={<Lock className="w-5 h-5" />}>
            Certificates
          </NavLink>
          <NavLink to="/endpoints" icon={<Server className="w-5 h-5" />}>
            Endpoints
          </NavLink>
          <NavLink to="/sweeps" icon={<Network className="w-5 h-5" />}>
            Network Sweeps
          </NavLink>
          <NavLink to="/security" icon={<Shield className="w-5 h-5" />}>
            Security
          </NavLink>
          <NavLink to="/settings" icon={<Settings className="w-5 h-5" />}>
            Settings
          </NavLink>
          {isAdmin && (
            <NavLink to="/users" icon={<Users className="w-5 h-5" />}>
              User Management
            </NavLink>
          )}
          {isAdmin && (
            <NavLink to="/audit-logs" icon={<ScrollText className="w-5 h-5" />}>
              Audit Logs
            </NavLink>
          )}
          <NavLink to="/about" icon={<Info className="w-5 h-5" />}>
            About
          </NavLink>
        </nav>

        <div className="px-4 pb-4 mt-auto">
          <p className="text-xs text-gray-600">v1.2.0</p>
        </div>
      </div>

      {/* Main content */}
      <div className="ml-64 p-8">
        <div className="flex justify-end mb-6">
          <div className="flex items-center gap-4 bg-white border border-gray-200 rounded-lg px-4 py-2 shadow-sm">
            <div className="flex items-center gap-2">
              <div className="w-9 h-9 bg-gray-100 rounded-full flex items-center justify-center">
                <User className="w-4 h-4 text-gray-500" />
              </div>
              <div className="leading-tight">
                <p className="text-sm font-medium text-gray-900">{user?.username}</p>
                <p className="text-xs text-gray-500 capitalize">{user?.role}</p>
              </div>
            </div>
            <button
              onClick={logout}
              className="flex items-center gap-2 px-3 py-2 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span>Sign out</span>
            </button>
          </div>
        </div>
        <Routes>
          <Route path="/login" element={<Navigate to="/" replace />} />
          <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/certificates" element={<ProtectedRoute><Certificates /></ProtectedRoute>} />
          <Route path="/endpoints" element={<ProtectedRoute><Endpoints /></ProtectedRoute>} />
          <Route path="/sweeps" element={<ProtectedRoute><Sweeps /></ProtectedRoute>} />
          <Route path="/security" element={<ProtectedRoute><Security /></ProtectedRoute>} />
          <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
          <Route path="/audit-logs" element={<ProtectedRoute requireAdmin><AuditLogs /></ProtectedRoute>} />
          <Route path="/about" element={<ProtectedRoute><About /></ProtectedRoute>} />
          <Route
            path="/users"
            element={
              <ProtectedRoute requireAdmin>
                <UserManagement />
              </ProtectedRoute>
            }
          />
        </Routes>
      </div>
    </div>
  )
}

function NavLink({ to, icon, children }) {
  const location = useLocation()
  const isActive = location.pathname === to

  return (
    <Link
      to={to}
      className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
        isActive
          ? 'bg-blue-600 text-white'
          : 'hover:bg-gray-800 text-gray-300 hover:text-white'
      }`}
    >
      {icon}
      <span>{children}</span>
    </Link>
  )
}

function App() {
  return (
    <Router>
      <ErrorBoundary>
        <AuthProvider>
          <AppContent />
        </AuthProvider>
      </ErrorBoundary>
    </Router>
  )
}

export default App

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error, info) {
    console.error('UI error:', error, info)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
          <div className="bg-gray-800 p-8 rounded-lg shadow-xl max-w-md w-full text-center">
            <h1 className="text-2xl font-bold text-white mb-2">Something went wrong</h1>
            <p className="text-gray-400 mb-6">Please reload the page and try again.</p>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Reload
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
