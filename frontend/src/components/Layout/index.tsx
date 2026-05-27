import { useState, useRef, useEffect } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Wrench,
  Server,
  Terminal,
  LogOut,
  ChevronRight,
  Shield,
  Bug,
  ShieldAlert,
  LibraryBig,
  ArrowUp,
  Menu,
  X,
  Crosshair,
} from 'lucide-react'
import { useAuthStore } from '@/store/auth'
import { authApi } from '@/api/auth'
import toast from 'react-hot-toast'
import { useLocation } from 'react-router-dom'

const NAV_GROUPS = [
  {
    label: 'Overview',
    items: [
      { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    ]
  },
  {
    label: 'Forensic & Hunting',
    items: [
      { to: '/agents',    icon: Server,          label: 'Agents' },
      { to: '/tools',     icon: Wrench,          label: 'Tools' },
      { to: '/hunting',   icon: Crosshair,       label: 'Scenario Hunting' },
      { to: '/webshell-scanner', icon: Shield,      label: 'Webshell Scanner' },
    ]
  },
  {
    label: 'Threat Intel',
    items: [
      { to: '/cve',       icon: Bug,             label: 'Vulnerability Search' },
      { to: '/cve-collection', icon: LibraryBig, label: 'Threat Intelligence' },
      { to: '/opencti',   icon: ShieldAlert,     label: 'OpenCTI' },
    ]
  },
]

const BREADCRUMB_MAP: Record<string, string> = {
  dashboard: 'Dashboard',
  tools:     'Tool Library',
  agents:    'Agent Management',
  jobs:      'Jobs',
  cve:       'Vulnerability Search',
  opencti:   'OpenCTI Config',
  'webshell-scanner': 'Webshell Scanner',
  'hunting': 'Scenario Hunting',
  'cve-collection': 'Threat Intelligence',
}

function Breadcrumbs() {
  const location = useLocation()
  const segments = location.pathname.split('/').filter(Boolean)

  return (
    <nav className="flex items-center gap-1 text-xs sm:text-sm text-gray-400 truncate">
      <span className="text-gray-500 hidden sm:inline">ForensicHub</span>
      {segments.map((seg, i) => {
        const label = BREADCRUMB_MAP[seg] ?? (seg.length > 16 ? `${seg.slice(0, 8)}…` : seg)
        const isLast = i === segments.length - 1
        return (
          <span key={i} className="flex items-center gap-1 truncate">
            {i > 0 || segments.length > 0 ? (
              <ChevronRight className="h-3 w-3 text-gray-600 shrink-0" />
            ) : null}
            <span className={`truncate ${isLast ? 'text-gray-200 font-medium' : 'text-gray-400 hidden sm:inline'}`}>
              {label}
            </span>
          </span>
        )
      })}
    </nav>
  )
}

export default function Layout() {
  const { user, clearAuth } = useAuthStore()
  const navigate = useNavigate()
  const mainRef = useRef<HTMLElement>(null)
  const [showScrollTop, setShowScrollTop] = useState(false)
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const location = useLocation()

  // Close mobile menu on route change
  useEffect(() => {
    setIsMobileMenuOpen(false)
  }, [location.pathname])

  const handleScroll = (e: React.UIEvent<HTMLElement>) => {
    setShowScrollTop(e.currentTarget.scrollTop > 300)
  }

  const scrollToTop = () => {
    mainRef.current?.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const handleLogout = async () => {
    try {
      await authApi.logout()
    } catch {
      // Ignore API errors on logout
    } finally {
      clearAuth()
      navigate('/login', { replace: true })
      toast.success('Logged out successfully')
    }
  }

  return (
    <div className="flex h-screen bg-gray-950 overflow-hidden relative">
      {/* Mobile Overlay */}
      {isMobileMenuOpen && (
        <div 
          className="fixed inset-0 bg-black/60 z-40 md:hidden transition-opacity"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside 
        className={`fixed inset-y-0 left-0 z-50 flex flex-col w-64 shrink-0 bg-gray-900 border-r border-gray-800 transform transition-transform duration-300 ease-in-out md:relative md:translate-x-0 ${
          isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Logo */}
        <div className="flex items-center justify-between px-5 py-5 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded bg-emerald-500/10 border border-emerald-500/30">
              <Terminal className="h-4 w-4 text-forensic-500" style={{ color: '#00ff41' }} />
            </div>
            <div>
              <span className="font-mono font-bold text-sm text-forensic-500 tracking-wider" style={{ color: '#00ff41' }}>
                ForensicHub
              </span>
              <div className="text-[10px] text-gray-500 font-mono tracking-widest">DFIR PLATFORM</div>
            </div>
          </div>
          <button 
            className="md:hidden text-gray-400 hover:text-white"
            onClick={() => setIsMobileMenuOpen(false)}
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 overflow-y-auto custom-scrollbar">
          {NAV_GROUPS.map((group) => (
            <div key={group.label} className="mb-6 last:mb-0">
              <h3 className="px-3 mb-2 text-[10px] font-bold text-gray-600 uppercase tracking-widest">
                {group.label}
              </h3>
              <div className="space-y-0.5">
                {group.items.map(({ to, icon: Icon, label }) => (
                  <NavLink
                    key={to}
                    to={to}
                    onClick={() => setIsMobileMenuOpen(false)}
                    className={({ isActive }) =>
                      `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors duration-150 group ${
                        isActive
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <Icon
                          className={`h-4 w-4 shrink-0 ${isActive ? 'text-emerald-400' : 'text-gray-500 group-hover:text-gray-300'}`}
                        />
                        {label}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* User info & logout */}
        <div className="px-3 py-4 border-t border-gray-800 space-y-2">
          <div className="flex items-center gap-3 px-3 py-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-emerald-500/10 border border-emerald-500/20 shrink-0">
              <Shield className="h-4 w-4 text-emerald-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-xs font-medium text-gray-200 truncate">{user?.email ?? 'analyst'}</div>
              <div className="text-[10px] text-gray-500 uppercase tracking-wider">{user?.role ?? 'analyst'}</div>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="flex w-full items-center gap-3 px-3 py-2 rounded-lg text-sm text-gray-400 hover:text-red-400 hover:bg-red-900/20 transition-colors duration-150"
          >
            <LogOut className="h-4 w-4" />
            Sign out
          </button>
        </div>
      </aside>

      {/* Main area */}
      <div className="flex flex-col flex-1 overflow-hidden min-w-0">
        {/* Top header */}
        <header className="flex items-center justify-between px-4 sm:px-6 py-3 bg-gray-900/50 border-b border-gray-800 shrink-0 gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <button 
              className="md:hidden text-gray-400 hover:text-white shrink-0"
              onClick={() => setIsMobileMenuOpen(true)}
            >
              <Menu className="h-5 w-5" />
            </button>
            <div className="min-w-0 truncate">
              <Breadcrumbs />
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs text-gray-500 font-mono shrink-0">
            <span className="text-emerald-500 text-[10px] hidden sm:inline">● SECURE</span>
            <span className="hidden sm:inline">{new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' })}</span>
          </div>
        </header>

        {/* Page content */}
        <main 
          ref={mainRef}
          onScroll={handleScroll}
          className="flex-1 overflow-y-auto overflow-x-hidden bg-grid-pattern bg-grid bg-gray-950 p-4 sm:p-6 relative"
        >
          <div className="max-w-full">
            <Outlet />
          </div>
          
          {/* Scroll to Top Button */}
          {showScrollTop && (
            <button
              onClick={scrollToTop}
              className="fixed bottom-6 right-6 sm:bottom-8 sm:right-8 p-3 rounded-full bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500 hover:text-white border border-emerald-500/20 shadow-lg shadow-emerald-900/20 transition-all duration-300 z-40 animate-in fade-in slide-in-from-bottom-4"
              title="Scroll to top"
            >
              <ArrowUp className="w-5 h-5" />
            </button>
          )}
        </main>
      </div>
    </div>
  )
}
