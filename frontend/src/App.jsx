import { BrowserRouter as Router, Routes, Route, Link, Navigate, useLocation } from 'react-router-dom'
import { Lock, LayoutDashboard, Server, Shield, Settings, Network, Users, LogOut, User } from 'lucide-react'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import Dashboard from './pages/Dashboard'
import Certificates from './pages/Certificates'
import Endpoints from './pages/Endpoints'
import Sweeps from './pages/Sweeps'
import Security from './pages/Security'
import SettingsPage from './pages/Settings'
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
      <div className="fixed inset-y-0 left-0 w-64 bg-gray-900 text-white flex flex-col">
        <div className="flex items-center gap-3 p-6 border-b border-gray-800">
          <Lock className="w-8 h-8 text-blue-400" />
          <div>
            <h1 className="text-xl font-bold">Certificate Guardian</h1>
            <p className="text-xs text-gray-400">TLS Monitor</p>
          </div>
        </div>

        <nav className="p-4 space-y-2 flex-1">
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
            <>
              <div className="pt-4 pb-2">
                <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                  Admin
                </div>
              </div>
              <NavLink to="/users" icon={<Users className="w-5 h-5" />}>
                User Management
              </NavLink>
            </>
          )}
        </nav>

        {/* User info and logout */}
        <div className="border-t border-gray-800 p-4">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 bg-gray-700 rounded-full flex items-center justify-center">
              <User className="w-5 h-5 text-gray-400" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-white truncate">{user?.username}</p>
              <p className="text-xs text-gray-400 capitalize">{user?.role}</p>
            </div>
          </div>
          <button
            onClick={logout}
            className="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg transition-colors"
          >
            <LogOut className="w-4 h-4" />
            <span>Sign out</span>
          </button>
        </div>

        <div className="px-4 pb-4">
          <p className="text-xs text-gray-600">v1.2.0</p>
        </div>
      </div>

      {/* Main content */}
      <div className="ml-64 p-8">
        <Routes>
          <Route path="/login" element={<Navigate to="/" replace />} />
          <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/certificates" element={<ProtectedRoute><Certificates /></ProtectedRoute>} />
          <Route path="/endpoints" element={<ProtectedRoute><Endpoints /></ProtectedRoute>} />
          <Route path="/sweeps" element={<ProtectedRoute><Sweeps /></ProtectedRoute>} />
          <Route path="/security" element={<ProtectedRoute><Security /></ProtectedRoute>} />
          <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
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
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </Router>
  )
}

export default App
