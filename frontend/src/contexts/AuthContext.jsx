import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { authService, setAccessToken, clearAccessToken } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [authMode, setAuthMode] = useState('local')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Check auth mode and try to restore session on mount
  useEffect(() => {
    const initAuth = async () => {
      try {
        // Get auth mode
        const modeResponse = await authService.getMode()
        setAuthMode(modeResponse.data.mode)

        // Try to refresh token (will work if we have a valid cookie)
        const refreshResponse = await authService.refresh()
        setAccessToken(refreshResponse.data.access_token)

        // Get user info
        const userResponse = await authService.me()
        setUser(userResponse.data)
      } catch (err) {
        // Not logged in or token expired - that's fine
        clearAccessToken()
        setUser(null)
      } finally {
        setLoading(false)
      }
    }

    initAuth()
  }, [])

  // Listen for forced logout events
  useEffect(() => {
    const handleLogout = () => {
      setUser(null)
      clearAccessToken()
    }

    window.addEventListener('auth:logout', handleLogout)
    return () => window.removeEventListener('auth:logout', handleLogout)
  }, [])

  const login = useCallback(async (username, password) => {
    setError(null)
    try {
      const response = await authService.login(username, password)
      setAccessToken(response.data.access_token)
      setUser(response.data.user)
      return { success: true }
    } catch (err) {
      const message = err.response?.data?.detail || 'Login failed'
      setError(message)
      return { success: false, error: message }
    }
  }, [])

  const logout = useCallback(async () => {
    try {
      await authService.logout()
    } catch (err) {
      // Ignore logout errors
    } finally {
      clearAccessToken()
      setUser(null)
    }
  }, [])

  const refreshUser = useCallback(async () => {
    try {
      const response = await authService.me()
      setUser(response.data)
    } catch (err) {
      // User might be logged out
      setUser(null)
    }
  }, [])

  const changePassword = useCallback(async (currentPassword, newPassword) => {
    try {
      await authService.changePassword(currentPassword, newPassword)
      return { success: true }
    } catch (err) {
      const message = err.response?.data?.detail || 'Password change failed'
      return { success: false, error: message }
    }
  }, [])

  const value = {
    user,
    authMode,
    loading,
    error,
    isAuthenticated: !!user,
    isAdmin: user?.role === 'admin',
    isEditor: user?.role === 'admin' || user?.role === 'editor',
    login,
    logout,
    refreshUser,
    changePassword,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
