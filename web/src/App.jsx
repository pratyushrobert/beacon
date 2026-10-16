import { useState, lazy, Suspense } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { Menu, Shield, Flame, Loader2 } from 'lucide-react'
import Sidebar from './components/Sidebar'
import { ModeProvider, useMode } from './context/ModeContext'
import { AuthProvider } from './context/AuthContext'

// Code-split all page routes into lazy chunks
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Upload = lazy(() => import('./pages/Upload'))
const Findings = lazy(() => import('./pages/Findings'))
const Hosts = lazy(() => import('./pages/Hosts'))
const Conversations = lazy(() => import('./pages/Conversations'))
const Timeline = lazy(() => import('./pages/Timeline'))
const PacketExplorer = lazy(() => import('./pages/PacketExplorer'))
const IOCs = lazy(() => import('./pages/IOCs'))
const NetworkGraph = lazy(() => import('./pages/NetworkGraph'))
const Storyline = lazy(() => import('./pages/Storyline'))
const Workspace = lazy(() => import('./pages/Workspace'))
const CaptureComparison = lazy(() => import('./pages/CaptureComparison'))
const MemoryView = lazy(() => import('./pages/MemoryView'))
const LiveCapture = lazy(() => import('./pages/LiveCapture'))

function PageLoader() {
  return (
    <div className="flex h-full min-h-[60vh] w-full items-center justify-center p-8 bg-canvas">
      <div className="flex flex-col items-center gap-3">
        <Loader2 className="w-7 h-7 text-primary-400 animate-spin" />
        <span className="text-xs font-mono text-dark-400 uppercase tracking-widest">
          Loading Module...
        </span>
      </div>
    </div>
  )
}

function MobileTopBar({ onOpenMenu }) {
  const { isFreeBird, isBlue, isRed } = useMode()
  return (
    <header
      className="md:hidden flex items-center justify-between h-14 px-4 border-b select-none shrink-0"
      style={{
        backgroundColor: 'var(--bg-sidebar)',
        borderColor: 'var(--border-subtle)',
      }}
    >
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onOpenMenu}
          aria-label="Open Navigation Menu"
          className="p-2 -ml-1 text-dark-300 hover:text-white hover:bg-white/10 rounded-md focus:outline-none min-h-[38px] min-w-[38px] flex items-center justify-center"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2">
          {/* Dual / Mode Identity Glyph */}
          <div className="relative flex items-center justify-center w-6 h-6 rounded bg-dark-900 border border-dark-800 shadow-sm overflow-hidden">
            {isFreeBird ? (
              <div className="flex w-full h-full">
                <div className="w-1/2 h-full bg-blue-500/80 flex items-center justify-center">
                  <div className="w-1 h-1 rounded-full bg-white shadow-sm" />
                </div>
                <div className="w-1/2 h-full bg-rose-500/80 flex items-center justify-center">
                  <div className="w-1 h-1 rounded-full bg-white shadow-sm" />
                </div>
              </div>
            ) : isBlue ? (
              <div className="flex items-center justify-center w-full h-full bg-sky-500/20 text-sky-400">
                <Shield className="w-3.5 h-3.5" />
              </div>
            ) : (
              <div className="flex items-center justify-center w-full h-full bg-rose-500/20 text-rose-400">
                <Flame className="w-3.5 h-3.5" />
              </div>
            )}
          </div>
          <span className="font-bold text-sm tracking-tight text-white font-sans">
            BEACON
          </span>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <span
          className="text-[9px] font-mono px-1.5 py-0.5 rounded font-semibold uppercase tracking-wider"
          style={{
            backgroundColor: isFreeBird
              ? 'rgba(56, 189, 248, 0.15)'
              : isBlue
              ? 'rgba(56, 189, 248, 0.15)'
              : 'rgba(244, 63, 94, 0.15)',
            color: isFreeBird ? '#38bdf8' : isBlue ? '#38bdf8' : '#f43f5e',
            border: `1px solid ${isFreeBird ? 'rgba(244, 63, 94, 0.3)' : 'currentColor'}`,
          }}
        >
          {isFreeBird ? 'FREE BIRD' : isBlue ? 'BLUE' : 'RED'}
        </span>
      </div>
    </header>
  )
}

function AppLayout() {
  const [currentAnalysis, setCurrentAnalysis] = useState(null)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  return (
    <div className="flex flex-col md:flex-row h-screen overflow-hidden bg-canvas text-dark-100">
      {/* Mobile Top Header (Small Screens) */}
      <MobileTopBar onOpenMenu={() => setMobileMenuOpen(true)} />

      {/* Mobile Off-Canvas Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 md:hidden">
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-sm transition-opacity"
            onClick={() => setMobileMenuOpen(false)}
          />
          <div className="fixed inset-y-0 left-0 w-64 shadow-2xl flex flex-col z-50">
            <Sidebar
              currentAnalysis={currentAnalysis}
              onClose={() => setMobileMenuOpen(false)}
            />
          </div>
        </div>
      )}

      {/* Desktop Persistent Sidebar */}
      <div className="hidden md:flex shrink-0">
        <Sidebar currentAnalysis={currentAnalysis} />
      </div>

      {/* Main Content Area */}
      <main className="flex-1 overflow-y-auto">
        <Suspense fallback={<PageLoader />}>
          <Routes>
            <Route path="/" element={<Navigate to="/upload" replace />} />
            <Route
              path="/upload"
              element={<Upload setCurrentAnalysis={setCurrentAnalysis} />}
            />
            <Route
              path="/dashboard/:analysisId"
              element={<Dashboard />}
            />
            <Route
              path="/storyline/:analysisId"
              element={<Storyline />}
            />
            <Route
              path="/findings/:analysisId"
              element={<Findings />}
            />
            <Route
              path="/hosts/:analysisId"
              element={<Hosts />}
            />
            <Route
              path="/conversations/:analysisId"
              element={<Conversations />}
            />
            <Route
              path="/timeline/:analysisId"
              element={<Timeline />}
            />
            <Route
              path="/packets/:analysisId"
              element={<PacketExplorer />}
            />
            <Route
              path="/iocs/:analysisId"
              element={<IOCs />}
            />
            <Route
              path="/graph/:analysisId"
              element={<NetworkGraph />}
            />
            <Route
              path="/workspace/:analysisId"
              element={<Workspace />}
            />
            <Route
              path="/compare"
              element={<CaptureComparison />}
            />
            <Route
              path="/memory/:analysisId"
              element={<MemoryView />}
            />
            <Route
              path="/memory"
              element={<MemoryView />}
            />
            <Route
              path="/live"
              element={<LiveCapture />}
            />
          </Routes>
        </Suspense>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <ModeProvider>
        <Router>
          <AppLayout />
        </Router>
      </ModeProvider>
    </AuthProvider>
  )
}
