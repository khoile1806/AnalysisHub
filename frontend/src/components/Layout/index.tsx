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
  Database,
  Fingerprint,
  ArrowUp,
  Briefcase,
  BookOpen,
  Menu,
  X,
  Crosshair,
  ClipboardList,
  BrainCircuit,
  FlaskConical,
  Activity,
  Package,
  Cpu,
  PanelLeftClose,
  PanelLeftOpen,
  Boxes,
} from 'lucide-react'
import { useAuthStore } from '@/store/auth'
import { authApi } from '@/api/auth'
import toast from 'react-hot-toast'
import { useLocation } from 'react-router-dom'

// Sidebar groups follow the DFIR investigation lifecycle top-to-bottom, so even
// a new analyst can read it as a workflow: see overview → prepare endpoints &
// tools → collect evidence → analyze → look up threat intel → check system.
// (AI Providers config lives inside the AI Analysis page, not as its own item.)
const NAV_GROUPS = [
  {
    label: 'Overview',
    items: [
      { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/cases',     icon: Briefcase,       label: 'Case Manager' },
    ]
  },
  {
    label: 'Endpoints & Tools',
    items: [
      { to: '/agents',          icon: Server,  label: 'Agents' },
      { to: '/fleet',           icon: Boxes,   label: 'Fleet' },
      { to: '/tools',           icon: Wrench,  label: 'Tools' },
      { to: '/offline-bundles', icon: Package, label: 'Offline Bundles' },
    ]
  },
  {
    label: 'Collection & Hunting',
    items: [
      { to: '/hunting',              icon: Crosshair,     label: 'Scenario Hunting' },
      { to: '/collection-checklist', icon: ClipboardList, label: 'Evidence & Compliance' },
      { to: '/playbooks',            icon: BookOpen,      label: 'Playbooks' },
    ]
  },
  {
    label: 'Analysis',
    items: [
      { to: '/sandbox',     icon: Cpu,          label: 'Sandbox Analysis' },
      { to: '/ai-analysis', icon: BrainCircuit, label: 'AI Analysis' },
      { to: '/opencti',     icon: ShieldAlert,  label: 'SIEM Threat Hunting' },
    ]
  },
  {
    label: 'Threat Intelligence',
    items: [
      { to: '/cve',            icon: Bug,         label: 'Vulnerability Search' },
      { to: '/cve-collection', icon: LibraryBig,  label: 'Threat Intelligence' },
      { to: '/ioc-store',      icon: Database,    label: 'IOC Store' },
      { to: '/osint',          icon: Fingerprint, label: 'OSINT' },
    ]
  },
  {
    label: 'System',
    items: [
      { to: '/system-health', icon: Activity,     label: 'System Health' },
      { to: '/test-cases',    icon: FlaskConical, label: 'Test Cases' },
    ]
  },
]

const BREADCRUMB_MAP: Record<string, string> = {
  dashboard: 'Dashboard',
  cases:     'Case Manager',
  tools:     'Tool Library',
  agents:    'Agent Management',
  jobs:      'Jobs',
  cve:       'Vulnerability Search',
  opencti:   'SIEM Threat Hunting',
  'yara-scanner': 'YARA Scanner',
  'hunting': 'Scenario Hunting',
  'cve-collection': 'Threat Intelligence',
  'ioc-store': 'IOC Store',
  'osint': 'OSINT',
  'collection-checklist': 'Evidence & Compliance',
  'playbooks': 'Playbooks',
  'ai-analysis': 'AI Analysis',
  'sandbox':     'Sandbox Analysis',
  'ai-providers': 'AI Providers',
  'test-cases':     'Test Cases',
  'system-health':  'System Health',
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
  // Desktop-only collapse: shrink the sidebar to an icon rail. Persisted so the
  // choice survives reloads. (On mobile the sidebar is a full drawer instead.)
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('sidebar-collapsed') === '1')
  const location = useLocation()

  const toggleCollapsed = () => {
    setCollapsed((prev) => {
      const next = !prev
      localStorage.setItem('sidebar-collapsed', next ? '1' : '0')
      return next
    })
  }

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
        className={`fixed inset-y-0 left-0 z-50 flex flex-col shrink-0 bg-gray-900 border-r border-gray-800 transform transition-all duration-300 ease-in-out md:relative md:translate-x-0 ${
          isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        } ${collapsed ? 'w-64 md:w-[4.5rem]' : 'w-64'}`}
      >
        {/* Logo */}
        <div className={`flex items-center border-b border-gray-800 py-5 ${collapsed ? 'md:flex-col md:gap-3 md:px-0 px-5 justify-between md:justify-center' : 'px-5 justify-between'}`}>
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded bg-emerald-500/10 border border-emerald-500/30 shrink-0">
              <Terminal className="h-4 w-4 text-forensic-500" style={{ color: '#00ff41' }} />
            </div>
            <div className={collapsed ? 'md:hidden' : ''}>
              <span className="font-mono font-bold text-sm text-forensic-500 tracking-wider" style={{ color: '#00ff41' }}>
                ForensicHub
              </span>
              <div className="text-[10px] text-gray-500 font-mono tracking-widest">DFIR PLATFORM</div>
            </div>
          </div>
          {/* Mobile close */}
          <button
            className="md:hidden text-gray-400 hover:text-white"
            onClick={() => setIsMobileMenuOpen(false)}
          >
            <X className="h-5 w-5" />
          </button>
          {/* Desktop collapse toggle */}
          <button
            className="hidden md:flex items-center justify-center text-gray-500 hover:text-emerald-400 transition-colors"
            onClick={toggleCollapsed}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
          </button>
        </div>

        {/* Nav */}
        <nav className={`flex-1 py-4 overflow-y-auto custom-scrollbar ${collapsed ? 'px-2 md:px-2' : 'px-3'}`}>
          {NAV_GROUPS.map((group) => (
            <div key={group.label} className="mb-5 last:mb-0">
              <h3 className={`px-3 mb-2 text-[10px] font-bold text-gray-500 uppercase tracking-widest ${collapsed ? 'md:hidden' : ''}`}>
                {group.label}
              </h3>
              {/* Divider replaces group label when collapsed */}
              {collapsed && <div className="hidden md:block mx-2 mb-2 h-px bg-gray-800" />}
              <div className="space-y-0.5">
                {group.items.map(({ to, icon: Icon, label }) => (
                  <NavLink
                    key={to}
                    to={to}
                    onClick={() => setIsMobileMenuOpen(false)}
                    title={collapsed ? label : undefined}
                    className={({ isActive }) =>
                      `flex items-center gap-3 py-2 rounded-lg text-sm font-medium transition-colors duration-150 group ${
                        collapsed ? 'px-3 md:px-0 md:justify-center' : 'px-3'
                      } ${
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
                        <span className={collapsed ? 'md:hidden' : ''}>{label}</span>
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* User info & logout */}
        <div className={`py-4 border-t border-gray-800 space-y-2 ${collapsed ? 'px-2 md:px-2' : 'px-3'}`}>
          <div className={`flex items-center gap-3 py-2 ${collapsed ? 'px-3 md:px-0 md:justify-center' : 'px-3'}`}>
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-emerald-500/10 border border-emerald-500/20 shrink-0" title={collapsed ? (user?.email ?? 'analyst') : undefined}>
              <Shield className="h-4 w-4 text-emerald-400" />
            </div>
            <div className={`flex-1 min-w-0 ${collapsed ? 'md:hidden' : ''}`}>
              <div className="text-xs font-medium text-gray-200 truncate">{user?.email ?? 'analyst'}</div>
              <div className="text-[10px] text-gray-500 uppercase tracking-wider">{user?.role ?? 'analyst'}</div>
            </div>
          </div>
          <button
            onClick={handleLogout}
            title={collapsed ? 'Sign out' : undefined}
            className={`flex w-full items-center gap-3 py-2 rounded-lg text-sm text-gray-400 hover:text-red-400 hover:bg-red-900/20 transition-colors duration-150 ${
              collapsed ? 'px-3 md:px-0 md:justify-center' : 'px-3'
            }`}
          >
            <LogOut className="h-4 w-4 shrink-0" />
            <span className={collapsed ? 'md:hidden' : ''}>Sign out</span>
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
          className="flex-1 flex flex-col overflow-y-auto overflow-x-hidden bg-grid-pattern bg-grid bg-gray-950 p-4 sm:p-6 relative"
        >
          <div className="max-w-full flex-1 flex flex-col">
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
