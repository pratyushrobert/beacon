import { useState, useEffect } from 'react'
import { useParams, useNavigate, Link, useLocation } from 'react-router-dom'
import axios from 'axios'
import {
  FileText,
  Clock,
  Layers,
  Download,
  Search,
  ChevronDown,
  Pin,
  Shield,
  Flame,
  CheckCircle2,
  Share2,
  Radio
} from 'lucide-react'
import { useMode } from '../context/ModeContext'

export default function CaptureHeader({ onModeChange }) {
  const { analysisId } = useParams()
  const navigate = useNavigate()
  const location = useLocation()
  const { mode, setMode, isFreeBird, isBlue, isRed } = useMode()

  const [analysis, setAnalysis] = useState(null)
  const [modeSwitching, setModeSwitching] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)
  const [pinnedCount, setPinnedCount] = useState(0)
  const [breadcrumbs, setBreadcrumbs] = useState(() => {
    try {
      const saved = sessionStorage.getItem(`beacon_breadcrumbs_${analysisId}`)
      return saved ? JSON.parse(saved) : []
    } catch (e) {
      return []
    }
  })

  // Track investigation breadcrumb trail across the session
  useEffect(() => {
    if (!analysisId) return
    const path = location.pathname
    const search = location.search
    const fullPath = path + search

    let label = 'Dashboard'
    if (path.includes('/storyline')) label = 'Storyline'
    else if (path.includes('/findings')) label = 'Findings'
    else if (path.includes('/hosts')) label = 'Hosts'
    else if (path.includes('/conversations')) label = 'Conversations'
    else if (path.includes('/timeline')) label = 'Timeline'
    else if (path.includes('/graph')) label = 'Forensic Map'
    else if (path.includes('/workspace')) label = 'Workspace'
    else if (path.includes('/packets')) {
      const params = new URLSearchParams(search)
      if (params.get('packet')) label = `Packet #${params.get('packet')}`
      else if (params.get('ip')) label = `Host ${params.get('ip')}`
      else if (params.get('conv')) label = `Session`
      else label = 'Packet Explorer'
    } else if (path.includes('/memory')) label = 'Memory & Changes'
    else if (path.includes('/iocs')) label = 'IOCs'
    else if (path.includes('/dashboard')) label = 'Dashboard'

    setBreadcrumbs((prev) => {
      if (prev.length > 0 && prev[prev.length - 1].path === fullPath) {
        return prev
      }
      const existingIdx = prev.findIndex((b) => b.label === label)
      let updated
      if (existingIdx !== -1) {
        updated = [...prev.slice(0, existingIdx), { label, path: fullPath }]
      } else {
        updated = [...prev, { label, path: fullPath }].slice(-6)
      }
      try {
        sessionStorage.setItem(`beacon_breadcrumbs_${analysisId}`, JSON.stringify(updated))
      } catch (e) {}
      return updated
    })
  }, [location.pathname, location.search, analysisId])

  useEffect(() => {
    if (analysisId) {
      loadAnalysisSummary()
      updatePinnedCount()
    }
    if (analysisId === 'live') {
      const interval = setInterval(() => {
        loadAnalysisSummary()
      }, 3000)
      return () => clearInterval(interval)
    }
  }, [analysisId])

  const loadAnalysisSummary = async () => {
    try {
      const response = await axios.get(`/api/analysis/${analysisId}/status`)
      setAnalysis(response.data)
      if (response.data?.mode && response.data.mode !== mode) {
        setMode(response.data.mode)
      }
    } catch (err) {
      console.error('Failed to load capture summary:', err)
    }
  }

  const updatePinnedCount = () => {
    try {
      const saved = localStorage.getItem(`beacon_workspace_${analysisId}`)
      if (saved) {
        const data = JSON.parse(saved)
        const total = (data.pinned_hosts?.length || 0) + (data.pinned_findings?.length || 0)
        setPinnedCount(total)
      } else {
        setPinnedCount(0)
      }
    } catch (e) {
      // ignore
    }
  }

  const handleModeChange = async (newMode) => {
    if (mode === newMode || modeSwitching) return
    setModeSwitching(true)
    setMode(newMode)
    try {
      await axios.post(`/api/analysis/${analysisId}/mode`, { mode: newMode })
      setAnalysis((prev) => (prev ? { ...prev, mode: newMode } : null))
      window.dispatchEvent(new CustomEvent('beacon_mode_changed', { detail: newMode }))
      if (onModeChange) {
        onModeChange(newMode)
      }
    } catch (err) {
      console.error('Failed to change mode:', err)
    } finally {
      setModeSwitching(false)
    }
  }

  if (!analysis) {
    return null
  }

  return (
    <header
      className="border-b px-4 py-2 flex flex-wrap items-center justify-between gap-3 sticky top-0 z-30 transition-colors duration-200"
      style={{
        backgroundColor: 'var(--bg-app)',
        borderColor: 'var(--border-subtle)',
      }}
    >
      {/* Left: Active Capture Metadata */}
      <div className="flex items-center gap-3 min-w-0">
        <div
          className="p-1.5 rounded-md border text-dark-300"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-subtle)',
          }}
        >
          {analysis.is_live || analysisId === 'live' ? (
            <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
          ) : (
            <FileText className="w-4 h-4 text-primary-400" />
          )}
        </div>

        <div className="flex items-center gap-2 truncate">
          <span
            className="text-xs font-mono font-bold text-white truncate max-w-[200px] sm:max-w-xs"
            title={analysis.filename}
          >
            {analysis.filename}
          </span>

          {analysis.is_live || analysisId === 'live' ? (
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
              LIVE
            </span>
          ) : (
            <span
              className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold uppercase tracking-wider ${
                analysis.status === 'complete'
                  ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/50'
                  : 'bg-amber-950/60 text-amber-400 border border-amber-800/50'
              }`}
            >
              {analysis.status}
            </span>
          )}

          <span className="text-[11px] font-mono text-dark-500 hidden md:inline">
            • ID: {analysisId.slice(0, 8)}
          </span>
        </div>
      </div>

      {/* Center: Mode Identity Pill (Blue, Red, Free Bird) */}
      <div className="flex items-center gap-2">
        <div
          className="inline-flex rounded-md p-0.5 border text-xs font-mono select-none"
          style={{
            backgroundColor: 'var(--bg-subtle)',
            borderColor: 'var(--border-subtle)',
          }}
        >
          <button
            onClick={() => handleModeChange('blue')}
            disabled={modeSwitching}
            className={`px-2.5 py-1 rounded text-xs font-semibold transition-all ${
              isBlue
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-dark-400 hover:text-dark-200'
            }`}
            title="Blue Mode: Defensive Analysis & Threat Detection"
          >
            Blue
          </button>

          <button
            onClick={() => handleModeChange('red')}
            disabled={modeSwitching}
            className={`px-2.5 py-1 rounded text-xs font-semibold transition-all ${
              isRed
                ? 'bg-rose-600 text-white shadow-sm'
                : 'text-dark-400 hover:text-dark-200'
            }`}
            title="Red Mode: Offensive Security & Vulnerability Exposure"
          >
            Red
          </button>

          <button
            onClick={() => handleModeChange('white')}
            disabled={modeSwitching}
            className={`px-2.5 py-1 rounded text-xs font-bold transition-all relative ${
              isFreeBird
                ? 'text-white shadow-sm'
                : 'text-dark-400 hover:text-dark-200'
            }`}
            style={
              isFreeBird
                ? {
                    background: 'linear-gradient(90deg, #1d4ed8 0%, #be123c 100%)',
                    border: '1px solid rgba(255, 255, 255, 0.25)',
                  }
                : {}
            }
            title="Free Bird: Unified Identity combining Red + Blue"
          >
            <span className="flex items-center gap-1">
              <span>Free Bird</span>
              {isFreeBird && (
                <span className="flex items-center gap-0.5 ml-0.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-sky-300" />
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-300" />
                </span>
              )}
            </span>
          </button>
        </div>
      </div>

      {/* Right: Quick Links & Actions */}
      <div className="flex items-center gap-2">
        {/* Live Controller Quick Link */}
        <Link
          to="/live"
          className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono rounded-md border text-emerald-300 hover:text-white transition-colors bg-emerald-500/10 border-emerald-500/30"
          title="Open Beacon Live Continuous Monitor"
        >
          <Radio className="w-3.5 h-3.5 text-emerald-400" />
          <span className="hidden sm:inline">Live Console</span>
        </Link>

        {/* Workspace Quick Link */}
        <Link
          to={`/workspace/${analysisId}`}
          className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono rounded-md border text-dark-300 hover:text-white transition-colors"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-subtle)',
          }}
          title="Analyst Workspace (Pinned Hosts, Findings, Notes)"
        >
          <Pin className="w-3.5 h-3.5 text-amber-500" />
          <span>Workspace</span>
          {pinnedCount > 0 && (
            <span className="px-1.5 py-0.2 bg-amber-500 text-dark-950 rounded text-[10px] font-bold">
              {pinnedCount}
            </span>
          )}
        </Link>

        {/* Export Dropdown */}
        <div className="relative">
          <button
            onClick={() => setExportOpen(!exportOpen)}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono rounded-md border text-dark-300 hover:text-white transition-colors"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-subtle)',
            }}
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export</span>
            <ChevronDown className="w-3 h-3 text-dark-400" />
          </button>

          {exportOpen && (
            <div
              className="absolute right-0 mt-1 w-52 rounded-md shadow-xl py-1 z-40 text-xs font-mono border"
              style={{
                backgroundColor: 'var(--bg-card)',
                borderColor: 'var(--border-default)',
              }}
              onMouseLeave={() => setExportOpen(false)}
            >
              <div className="px-3 py-1 text-[10px] text-dark-500 uppercase tracking-wider border-b border-dark-800">
                Investigation Reports
              </div>
              <a
                href={`/api/analysis/${analysisId}/export?format=html`}
                download
                className="block px-3 py-1.5 text-dark-300 hover:bg-white/5 hover:text-white"
              >
                HTML Interactive Report
              </a>
              <a
                href={`/api/analysis/${analysisId}/export?format=json`}
                download
                className="block px-3 py-1.5 text-dark-300 hover:bg-white/5 hover:text-white"
              >
                JSON Investigation Data
              </a>
              <a
                href={`/api/analysis/${analysisId}/export?format=findings_csv`}
                download
                className="block px-3 py-1.5 text-dark-300 hover:bg-white/5 hover:text-white"
              >
                Findings CSV
              </a>
              <a
                href={`/api/analysis/${analysisId}/export?format=hosts_csv`}
                download
                className="block px-3 py-1.5 text-dark-300 hover:bg-white/5 hover:text-white"
              >
                Host Inventory CSV
              </a>
              <a
                href={`/api/analysis/${analysisId}/export?format=convs_csv`}
                download
                className="block px-3 py-1.5 text-dark-300 hover:bg-white/5 hover:text-white"
              >
                Conversations CSV
              </a>
            </div>
          )}
        </div>
      </div>

      {/* Investigation Breadcrumb Navigation Trail */}
      {breadcrumbs.length > 1 && (
        <div
          className="w-full border-t border-b px-4 py-1 flex items-center gap-1.5 text-[11px] font-mono overflow-x-auto select-none backdrop-blur-md"
          style={{
            backgroundColor: 'rgba(7, 10, 18, 0.95)',
            borderColor: 'var(--border-subtle)',
          }}
        >
          <span className="text-dark-500 uppercase tracking-wider text-[10px] mr-1">Trail:</span>
          {breadcrumbs.map((b, i) => {
            const isLast = i === breadcrumbs.length - 1
            return (
              <div key={i} className="flex items-center gap-1.5 shrink-0">
                {isLast ? (
                  <span className="font-bold text-sky-400 bg-sky-950/40 border border-sky-800/50 px-1.5 py-0.2 rounded">
                    {b.label}
                  </span>
                ) : (
                  <Link
                    to={b.path}
                    className="text-dark-400 hover:text-white transition-colors"
                  >
                    {b.label}
                  </Link>
                )}
                {!isLast && <span className="text-dark-600">›</span>}
              </div>
            )
          })}
        </div>
      )}
    </header>
  )
}
