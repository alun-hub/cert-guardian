import axios from 'axios'

const API_BASE = '/api'

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Send cookies for refresh token
})

// Token management
let accessToken = null

export const setAccessToken = (token) => {
  accessToken = token
}

export const getAccessToken = () => accessToken

export const clearAccessToken = () => {
  accessToken = null
}

// Add auth header to all requests
api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`
  }
  return config
})

// Handle 401 responses - try to refresh token
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      try {
        // Try to refresh token
        const response = await axios.post(
          `${API_BASE}/auth/refresh`,
          {},
          { withCredentials: true }
        )

        const newToken = response.data.access_token
        setAccessToken(newToken)

        // Retry original request with new token
        originalRequest.headers.Authorization = `Bearer ${newToken}`
        return api(originalRequest)
      } catch (refreshError) {
        // Refresh failed - user needs to login again
        clearAccessToken()
        window.dispatchEvent(new CustomEvent('auth:logout'))
        return Promise.reject(refreshError)
      }
    }

    return Promise.reject(error)
  }
)

export const authService = {
  getMode: () => api.get('/auth/mode'),
  login: (username, password) =>
    api.post('/auth/login', { username, password }),
  logout: () => api.post('/auth/logout'),
  refresh: () => api.post('/auth/refresh'),
  me: () => api.get('/auth/me'),
  changePassword: (currentPassword, newPassword) =>
    api.post('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    }),
}

export const userService = {
  getAll: () => api.get('/users'),
  getById: (id) => api.get(`/users/${id}`),
  create: (data) => api.post('/users', data),
  update: (id, data) => api.put(`/users/${id}`, data),
  delete: (id) => api.delete(`/users/${id}`),
  resetPassword: (id, newPassword) =>
    api.post(`/users/${id}/password`, { new_password: newPassword }),
}

export const dashboardService = {
  getStats: () => api.get('/dashboard/stats'),
  getTimeline: (months = 12) => api.get(`/timeline?months=${months}`),
}

export const certificateService = {
  getAll: (params = {}) => api.get('/certificates', { params }),
  getById: (id) => api.get(`/certificates/${id}`),
}

export const endpointService = {
  getAll: () => api.get('/endpoints'),
  create: (data) => api.post('/endpoints', data),
  update: (id, data) => api.put(`/endpoints/${id}`, data),
  delete: (id) => api.delete(`/endpoints/${id}`),
}

export const scanService = {
  triggerScan: (endpointId = null) =>
    api.post('/scan', { endpoint_id: endpointId }),
}

export const securityService = {
  getIssues: () => api.get('/security/issues'),
}

export const notificationService = {
  sendTest: () => api.post('/notifications/test'),
}

export const sweepService = {
  getAll: () => api.get('/sweeps'),
  getById: (id) => api.get(`/sweeps/${id}`),
  create: (data) => api.post('/sweeps', data),
  delete: (id) => api.delete(`/sweeps/${id}`),
  restart: (id) => api.post(`/sweeps/${id}/restart`),
  validate: (target) => api.post('/sweeps/validate', { target }),
}

export default api
