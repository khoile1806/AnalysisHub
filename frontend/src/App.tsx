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
const CasesPage = lazy(() => import('@/pages/CaseManager'))
const CaseDetailPage = lazy(() => import('@/pages/CaseDetail'))
const AgentsPage = lazy(() => import('@/pages/Agents'))
const AgentDetailPage = lazy(() => import('@/pages/AgentDetail'))
const JobsPage = lazy(() => import('@/pages/Jobs'))
const JobDetailPage = lazy(() => import('@/pages/JobDetail'))
const CVEPage = lazy(() => import('@/pages/CVE'))
const OpenCTIPage = lazy(() => import('@/pages/OpenCTI'))
const WebshellScannerPage = lazy(() => import('@/pages/WebshellScanner'))
const CVECollectionPage = lazy(() => import('@/pages/CVECollection'))
const HuntingPage = lazy(() => import('@/pages/Hunting'))
const CollectionChecklistPage = lazy(() => import('@/pages/CollectionChecklist'))
const AIAnalysisPage = lazy(() => import('@/pages/AIAnalysis'))
const AIProviderSettingsPage = lazy(() => import('@/pages/AIProviderSettings'))
const TestCasesPage = lazy(() => import('@/pages/TestCases'))
const SystemHealthPage = lazy(() => import('@/pages/SystemHealth'))
const OfflineBundlesPage = lazy(() => import('@/pages/OfflineBundles'))

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
  { hasError: boolean; errorMsg: string; errorStack: string }
> {
  state = { hasError: false, errorMsg: '', errorStack: '' }

  static getDerivedStateFromError(err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    const stack = err instanceof Error ? (err.stack ?? '') : ''
    return { hasError: true, errorMsg: msg, errorStack: stack }
  }

  componentDidCatch(err: unknown, info: React.ErrorInfo) {
    console.error('[page-render-error]', err, info.componentStack)
  }

  handleRetry = () => {
    this.setState({ hasError: false, errorMsg: '', errorStack: '' })
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center p-10 space-y-4 text-center min-h-[200px]">
          <div className="h-10 w-10 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center">
            <span className="text-red-400 text-lg">!</span>
          </div>
          <div className="space-y-1">
            <p className="text-gray-200 font-medium text-sm">Trang gặp lỗi khi hiển thị</p>
            <p className="text-gray-500 text-xs max-w-sm">
              Thử bấm "Thử lại" để phục hồi, hoặc "Tải lại trang" nếu lỗi vẫn tiếp tục.
            </p>
          </div>
          {/* Show error details in dev */}
          {import.meta.env.DEV && this.state.errorMsg && (
            <pre className="text-xs text-left text-red-400 bg-red-900/10 border border-red-500/20 rounded-lg p-3 max-w-lg w-full overflow-auto max-h-36 font-mono">
              {this.state.errorMsg}
              {this.state.errorStack && '\n\n' + this.state.errorStack.slice(0, 600)}
            </pre>
          )}
          <div className="flex gap-3">
            <button
              className="px-4 py-2 text-sm bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg border border-gray-700 transition"
              onClick={this.handleRetry}
            >
              Thử lại
            </button>
            <button
              className="px-4 py-2 text-sm bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg transition"
              onClick={() => window.location.reload()}
            >
              Tải lại trang
            </button>
          </div>
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
          path="/cases"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <CasesPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/cases/:id"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <CaseDetailPage />
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
          path="/hunting"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <HuntingPage />
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
        <Route
          path="/collection-checklist"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <CollectionChecklistPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/ai-analysis"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <AIAnalysisPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/ai-providers"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <AIProviderSettingsPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/test-cases"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <TestCasesPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/system-health"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <SystemHealthPage />
              </Suspense>
            </ChunkErrorBoundary>
          }
        />
        <Route
          path="/offline-bundles"
          element={
            <ChunkErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <OfflineBundlesPage />
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