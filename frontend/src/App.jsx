import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom'
import { Lock, LayoutDashboard, Server, Shield, Settings, Network } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Certificates from './pages/Certificates'
import Endpoints from './pages/Endpoints'
import Sweeps from './pages/Sweeps'
import Security from './pages/Security'
import SettingsPage from './pages/Settings'

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        {/* Sidebar */}
        <div className="fixed inset-y-0 left-0 w-64 bg-gray-900 text-white">
          <div className="flex items-center gap-3 p-6 border-b border-gray-800">
            <Lock className="w-8 h-8 text-blue-400" />
            <div>
              <h1 className="text-xl font-bold">Certificate Guardian</h1>
              <p className="text-xs text-gray-400">TLS Monitor</p>
            </div>
          </div>

          <nav className="p-4 space-y-2">
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
          </nav>

          <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-gray-800">
            <p className="text-xs text-gray-500">v1.0.0</p>
          </div>
        </div>

        {/* Main content */}
        <div className="ml-64 p-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/certificates" element={<Certificates />} />
            <Route path="/endpoints" element={<Endpoints />} />
            <Route path="/sweeps" element={<Sweeps />} />
            <Route path="/security" element={<Security />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </div>
      </div>
    </Router>
  )
}

function NavLink({ to, icon, children }) {
  return (
    <Link
      to={to}
      className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-gray-800 transition-colors"
    >
      {icon}
      <span>{children}</span>
    </Link>
  )
}

export default App
