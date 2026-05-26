import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuthStore } from '@/store/auth'
import Layout from '@/components/Layout'
import LoginPage from '@/pages/Login'
import DashboardPage from '@/pages/Dashboard'
import React, { Suspense, lazy } from 'react'

// Lazy-loaded routes — kept out of the main bundle so mobile clients only pay
// the download/parse cost for the page they actually open. Login + Dashboard
// stay eager because they're the entry points after auth.
const ToolsPage = lazy(() => import('@/pages/Tools'))
const AgentsPage = lazy(() => import('@/pages/Agents'))
const AgentDetailPage = lazy(() => import('@/pages/AgentDetail'))
const JobsPage = lazy(() => import('@/pages/Jobs'))
const JobDetailPage = lazy(() => import('@/pages/JobDetail'))
const CVEPage = lazy(() => import('@/pages/CVE'))
const OpenCTIPage = lazy(() => import('@/pages/OpenCTI'))
const WebshellScannerPage = lazy(() => import('@/pages/WebshellScanner'))
const CVECollectionPage = lazy(() => import('@/pages/CVECollection'))

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((s) => s.token)
  if (!token) {
    return <Navigate to="/login" replace />
  }
  return <>{children}</>
}

function PageFallback() {
  return (
    <div className="flex items-center justify-center p-10">
      <div className="h-6 w-6 rounded-full border-2 border-emerald-500/40 border-t-emerald-500 animate-spin" />
    </div>
  )
}

// Catches chunk-load failures (network blip after a deploy invalidates the old
// hashed chunks). Without this, the whole app blanks out when a lazy import
// rejects. We show a recoverable message instead.
class ChunkErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean }
> {
  state = { hasError: false }
  static getDerivedStateFromError() {
    return { hasError: true }
  }
  componentDidCatch(err: unknown) {
    console.error('[lazy-route] chunk load failed:', err)
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="p-10 text-center space-y-3">
          <p className="text-gray-300">Failed to load this page.</p>
          <button className="btn-primary" onClick={() => window.location.reload()}>
            Reload
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Navigate to="/dashboard" replace />
          </ProtectedRoute>
        }
      />

      <Route
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route
          path="/dashboard"
          element={<DashboardPage />}
        />
        <Route
          path="/tools"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <ToolsPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/agents"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <AgentsPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/agents/:id"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <AgentDetailPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/jobs"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <JobsPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/jobs/:id"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <JobDetailPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/cve"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <CVEPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/opencti"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <OpenCTIPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/webshell-scanner"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <WebshellScannerPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/cve-collection"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <CVECollectionPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
      </Route>

      {/* Catch-all */}
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}