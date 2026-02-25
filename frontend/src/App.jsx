import React from 'react'
import { BrowserRouter as Router, Routes, Route, Link, Navigate, useLocation } from 'react-router'
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
        <div className="text-gray-400 text-sm font-mono">Loading...</div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  if (requireAdmin && !isAdmin) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-center">
        <h2 className="text-lg font-semibold text-red-800">Access Denied</h2>
        <p className="text-red-600 mt-2">You need administrator privileges to access this page.</p>
      </div>
    )
  }

  return children
}

function AppContent() {
  const { user, isAuthenticated, isAdmin, logout, loading } = useAuth()

  if (!loading && !isAuthenticated) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0b1120] flex items-center justify-center">
        <div className="text-gray-400 text-sm font-mono tracking-wider">Loading...</div>
      </div>
    )
  }

  return (
    <div className="bg-slate-50">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 w-64 bg-[#0b1120] text-white flex flex-col border-r border-white/5 z-20">
        {/* Logo */}
        <Link
          to="/"
          className="flex items-center gap-3 px-5 py-5 border-b border-white/[0.06] hover:bg-white/[0.04] transition-colors group"
        >
          <div className="relative flex-shrink-0">
            <div className="absolute inset-0 bg-blue-500 rounded-lg blur-lg opacity-20 group-hover:opacity-40 transition-opacity" />
            <div className="relative bg-blue-500/10 p-2 rounded-lg border border-blue-500/20">
              <Lock className="w-5 h-5 text-blue-400" />
            </div>
          </div>
          <div className="min-w-0">
            <h1 className="text-sm font-semibold text-white tracking-tight truncate">Certificate Guardian</h1>
            <p className="text-[10px] text-blue-400/60 font-mono tracking-widest mt-0.5">TLS · SSH · PKI</p>
          </div>
        </Link>

        {/* Navigation */}
        <nav className="flex-1 p-3 overflow-y-auto scrollbar-thin">
          <div className="space-y-0.5">
            <NavLink to="/" icon={<LayoutDashboard className="w-4 h-4" />}>Dashboard</NavLink>
            <NavLink to="/certificates" icon={<Lock className="w-4 h-4" />}>Certificates</NavLink>
            <NavLink to="/endpoints" icon={<Server className="w-4 h-4" />}>Endpoints</NavLink>
            <NavLink to="/sweeps" icon={<Network className="w-4 h-4" />}>Network Sweeps</NavLink>
            <NavLink to="/security" icon={<Shield className="w-4 h-4" />}>Security</NavLink>
            <NavLink to="/settings" icon={<Settings className="w-4 h-4" />}>Settings</NavLink>
          </div>

          {isAdmin && (
            <>
              <div className="mt-5 mb-2 px-3">
                <p className="text-[10px] font-semibold text-gray-600 uppercase tracking-widest">Administration</p>
              </div>
              <div className="space-y-0.5">
                <NavLink to="/users" icon={<Users className="w-4 h-4" />}>User Management</NavLink>
                <NavLink to="/audit-logs" icon={<ScrollText className="w-4 h-4" />}>Audit Logs</NavLink>
              </div>
            </>
          )}

          <div className="mt-5 pt-4 border-t border-white/[0.06]">
            <NavLink to="/about" icon={<Info className="w-4 h-4" />}>About</NavLink>
          </div>
        </nav>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-white/[0.06] flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          <p className="text-[10px] font-mono text-gray-600">v1.2.0</p>
        </div>
      </aside>

      {/* Main */}
      <div className="ml-64 flex flex-col min-h-screen">
        {/* Sticky top bar */}
        <header className="sticky top-0 z-10 bg-white/80 backdrop-blur-md border-b border-gray-100 px-8 py-3 flex justify-end items-center gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-full flex items-center justify-center text-white text-[11px] font-bold flex-shrink-0 select-none">
              {user?.username?.[0]?.toUpperCase() ?? <User className="w-3.5 h-3.5" />}
            </div>
            <div className="leading-tight">
              <p className="text-sm font-medium text-gray-900">{user?.username}</p>
              <p className="text-[10px] text-gray-400 capitalize font-medium tracking-wide">{user?.role}</p>
            </div>
          </div>
          <div className="w-px h-6 bg-gray-200" />
          <button
            onClick={logout}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-gray-500 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sign out
          </button>
        </header>

        {/* Page content */}
        <main className="flex-1 p-8">
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
        </main>
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
      className={`flex items-center gap-2.5 px-3 py-2 rounded-lg transition-all duration-150 text-sm ${
        isActive
          ? 'bg-blue-500/15 text-blue-300 font-medium'
          : 'text-gray-500 hover:bg-white/[0.06] hover:text-gray-200'
      }`}
    >
      <span className={`flex-shrink-0 ${isActive ? 'text-blue-400' : ''}`}>{icon}</span>
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
        <div className="min-h-screen bg-[#0b1120] flex items-center justify-center p-4">
          <div className="bg-white/5 p-8 rounded-2xl shadow-2xl max-w-md w-full text-center border border-white/10">
            <h1 className="text-2xl font-bold text-white mb-2">Something went wrong</h1>
            <p className="text-gray-400 mb-6">Please reload the page and try again.</p>
            <button
              onClick={() => window.location.reload()}
              className="px-5 py-2.5 bg-blue-600 text-white rounded-xl hover:bg-blue-500 transition-colors font-medium"
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
