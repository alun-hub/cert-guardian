import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react'
import { authService, setAccessToken, clearAccessToken, getAccessToken } from '../services/api'

const AuthContext = createContext(null)

function getTokenExpiry(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]))
    return payload.exp ? payload.exp * 1000 : null
  } catch {
    return null
  }
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [authMode, setAuthMode] = useState('local')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const refreshTimerRef = useRef(null)

  const scheduleRefresh = useCallback((token) => {
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current)
      refreshTimerRef.current = null
    }

    const expiry = getTokenExpiry(token)
    if (!expiry) return

    // Refresh at 80% of token lifetime (e.g. 12 min for a 15 min token)
    const now = Date.now()
    const lifetime = expiry - now
    const refreshAt = lifetime * 0.8

    if (refreshAt <= 0) return

    refreshTimerRef.current = setTimeout(async () => {
      try {
        const response = await authService.refresh()
        const newToken = response.data.access_token
        setAccessToken(newToken)
        scheduleRefresh(newToken)
      } catch {
        // Refresh failed — interceptor will handle logout on next API call
      }
    }, refreshAt)
  }, [])

  const cancelRefresh = useCallback(() => {
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current)
      refreshTimerRef.current = null
    }
  }, [])

  // Check auth mode and try to restore session on mount
  useEffect(() => {
    const initAuth = async () => {
      try {
        // Get auth mode
        const modeResponse = await authService.getMode()
        setAuthMode(modeResponse.data.mode)

        // Try to refresh token (will work if we have a valid cookie)
        const refreshResponse = await authService.refresh()
        const token = refreshResponse.data.access_token
        setAccessToken(token)
        scheduleRefresh(token)

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
    return () => cancelRefresh()
  }, [scheduleRefresh, cancelRefresh])

  // Listen for forced logout events
  useEffect(() => {
    const handleLogout = () => {
      cancelRefresh()
      setUser(null)
      clearAccessToken()
    }

    // If the interceptor refreshes the token, reschedule our timer
    const handleRefreshed = () => {
      const token = getAccessToken()
      if (token) scheduleRefresh(token)
    }

    window.addEventListener('auth:logout', handleLogout)
    window.addEventListener('auth:refreshed', handleRefreshed)
    return () => {
      window.removeEventListener('auth:logout', handleLogout)
      window.removeEventListener('auth:refreshed', handleRefreshed)
    }
  }, [cancelRefresh, scheduleRefresh])

  const login = useCallback(async (username, password) => {
    setError(null)
    try {
      const response = await authService.login(username, password)
      const token = response.data.access_token
      setAccessToken(token)
      scheduleRefresh(token)
      setUser(response.data.user)
      return { success: true }
    } catch (err) {
      const message = err.response?.data?.detail || 'Login failed'
      setError(message)
      return { success: false, error: message }
    }
  }, [scheduleRefresh])

  const logout = useCallback(async () => {
    cancelRefresh()
    try {
      await authService.logout()
    } catch (err) {
      // Ignore logout errors
    } finally {
      clearAccessToken()
      setUser(null)
    }
  }, [cancelRefresh])

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
