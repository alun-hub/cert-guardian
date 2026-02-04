import axios from 'axios'

const API_BASE = '/api'

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
})

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
  validate: (target) => api.post('/sweeps/validate', { target }),
}

export default api
