import { useState } from 'react'
import { Navigate } from 'react-router'
import { Lock, AlertCircle } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'

export default function Login() {
  const { isAuthenticated, loading, error, login, authMode } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [localError, setLocalError] = useState('')

  if (isAuthenticated && !loading) {
    return <Navigate to="/" replace />
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLocalError('')

    if (!username.trim() || !password) {
      setLocalError('Please enter username and password')
      return
    }

    try {
      setSubmitting(true)
      const result = await login(username, password)
      if (!result?.success) {
        setLocalError(result?.error || 'Login failed')
      }
    } catch (err) {
      setLocalError('Login failed')
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0b1120] flex items-center justify-center">
        <div className="text-gray-400 text-sm font-mono tracking-wider">Loading...</div>
      </div>
    )
  }

  if (authMode !== 'local' && authMode !== 'none') {
    return (
      <div className="min-h-screen bg-[#0b1120] flex items-center justify-center p-4">
        <div className="bg-white/5 border border-white/10 p-8 rounded-2xl shadow-2xl max-w-md w-full text-center">
          <div className="relative inline-block mb-5">
            <div className="absolute inset-0 bg-blue-500 rounded-2xl blur-xl opacity-25" />
            <div className="relative bg-blue-500/15 border border-blue-500/30 p-4 rounded-2xl">
              <Lock className="w-8 h-8 text-blue-400" />
            </div>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight mb-2">Certificate Guardian</h1>
          <p className="text-gray-400 text-sm mb-2">
            Authentication is handled by {authMode === 'proxy' ? 'Pomerium' : 'your identity provider'}.
          </p>
          <p className="text-gray-600 text-xs">
            Please ensure you are accessing this application through the correct URL.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#0b1120] flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background glow orbs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-indigo-700/8 rounded-full blur-3xl pointer-events-none" />

      <div className="relative bg-white/[0.04] backdrop-blur-xl p-8 rounded-2xl shadow-2xl max-w-sm w-full border border-white/[0.08]">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="relative mb-5">
            <div className="absolute inset-0 bg-blue-500 rounded-2xl blur-xl opacity-25" />
            <div className="relative bg-blue-500/15 border border-blue-500/25 p-4 rounded-2xl">
              <Lock className="w-8 h-8 text-blue-400" />
            </div>
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight">Certificate Guardian</h1>
          <p className="text-gray-500 text-sm mt-1">Sign in to continue</p>
        </div>

        {(localError || error) && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-3.5 mb-6 flex items-start gap-3">
            <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
            <p className="text-red-300 text-sm">{localError || error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label htmlFor="username" className="block text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-2">
              Username
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-3 bg-white/[0.06] border border-white/[0.08] rounded-xl text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/40 transition-all text-sm"
              placeholder="Enter your username"
              disabled={submitting}
              autoComplete="username"
              autoFocus
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-2">
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 bg-white/[0.06] border border-white/[0.08] rounded-xl text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/40 transition-all text-sm"
              placeholder="Enter your password"
              disabled={submitting}
              autoComplete="current-password"
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-colors shadow-lg shadow-blue-500/20 text-sm mt-2"
          >
            {submitting ? 'Signing in…' : 'Sign In'}
          </button>
        </form>

        <div className="mt-6 pt-5 border-t border-white/[0.06]">
          <p className="text-gray-700 text-[11px] text-center font-mono tracking-wide">
            TLS Certificate Monitoring System
          </p>
        </div>
      </div>
    </div>
  )
}
