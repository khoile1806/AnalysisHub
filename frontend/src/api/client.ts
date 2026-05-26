import axios from 'axios'
import { useAuthStore } from '@/store/auth'

const apiClient = axios.create({
  baseURL: `${import.meta.env.VITE_API_URL ?? ''}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30_000,
})

// Request interceptor: attach Bearer token
apiClient.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().token
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor: handle 401
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      useAuthStore.getState().clearAuth()
      // Redirect to login, preserving current path as next param
      const currentPath = window.location.pathname
      if (currentPath !== '/login') {
        window.location.href = `/login?next=${encodeURIComponent(currentPath)}`
      }
    }
    return Promise.reject(error)
  }
)

export default apiClient
