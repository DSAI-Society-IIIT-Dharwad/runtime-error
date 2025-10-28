import axios from 'axios'
import toast from 'react-hot-toast'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized
      localStorage.removeItem('token')
      window.location.href = '/login'
    } else if (error.response?.status >= 500) {
      toast.error('Server error. Please try again later.')
    }
    return Promise.reject(error)
  }
)

// Device APIs
export const deviceApi = {
  getAll: () => api.get('/api/devices'),
  getOne: (mac: string) => api.get(`/api/devices/${mac}`),
  getActivity: (mac: string, hours = 24) => 
    api.get(`/api/devices/${mac}/activity?hours=${hours}`),
  getRisk: (mac: string) => api.get(`/api/devices/${mac}/risk`),
}

// Flow APIs
export const flowApi = {
  getAll: (since?: string, limit = 100) => 
    api.get('/api/flows', { params: { since, limit } }),
  getStatistics: (windowMinutes = 60) => 
    api.get('/api/flows/statistics', { params: { window_minutes: windowMinutes } }),
  getTopTalkers: (limit = 10, windowMinutes = 60) => 
    api.get('/api/flows/top-talkers', { params: { limit, window_minutes: windowMinutes } }),
}

// Alert APIs
export const alertApi = {
  getAll: (params?: { since?: string; severity?: string; status?: string; limit?: number }) =>
    api.get('/api/alerts', { params }),
  create: (data: any) => api.post('/api/alerts', data),
  update: (id: number, data: { status?: string; notes?: string }) =>
    api.patch(`/api/alerts/${id}`, data),
  getStatistics: (windowHours = 24) =>
    api.get('/api/alerts/statistics', { params: { window_hours: windowHours } }),
}

// Capture APIs
export const captureApi = {
  getStatus: () => api.get('/api/capture/status'),
  switchMode: (data: { mode: string; interface?: string; pcap_path?: string }) =>
    api.post('/api/capture/mode', data),
  uploadPcap: (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/api/capture/pcap', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
}

// Detection APIs
export const detectionApi = {
  detectAnomaly: (deviceMac: string) =>
    api.post('/api/detect/anomaly', null, { params: { device_mac: deviceMac } }),
  trainModel: () => api.post('/api/model/train'),
  getModelInfo: () => api.get('/api/model/info'),
}

export default api
