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

  // If already authenticated, redirect to dashboard
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

  // Show loading while checking auth status
  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-gray-400">Loading...</div>
      </div>
    )
  }

  // If auth mode is not local, show different message
  if (authMode !== 'local' && authMode !== 'none') {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="bg-gray-800 p-8 rounded-lg shadow-xl max-w-md w-full text-center">
          <Lock className="w-16 h-16 text-blue-400 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-white mb-2">Certificate Guardian</h1>
          <p className="text-gray-400 mb-6">
            Authentication is handled by {authMode === 'proxy' ? 'Pomerium' : 'your identity provider'}.
          </p>
          <p className="text-gray-500 text-sm">
            Please ensure you are accessing this application through the correct URL.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div className="bg-gray-800 p-8 rounded-lg shadow-xl max-w-md w-full">
        <div className="flex flex-col items-center mb-8">
          <Lock className="w-16 h-16 text-blue-400 mb-4" />
          <h1 className="text-2xl font-bold text-white">Certificate Guardian</h1>
          <p className="text-gray-400">Sign in to continue</p>
        </div>

        {(localError || error) && (
          <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 mb-6 flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <p className="text-red-300 text-sm">{localError || error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="username" className="block text-sm font-medium text-gray-300 mb-2">
              Username
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Enter your username"
              disabled={submitting}
              autoComplete="username"
              autoFocus
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-2">
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Enter your password"
              disabled={submitting}
              autoComplete="current-password"
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors"
          >
            {submitting ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <div className="mt-6 pt-6 border-t border-gray-700">
          <p className="text-gray-500 text-xs text-center">
            TLS Certificate Monitoring System
          </p>
        </div>
      </div>
    </div>
  )
}
