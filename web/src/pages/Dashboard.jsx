import { useState, useEffect, useRef } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import axios from 'axios'
import {
  Loader2,
  Package,
  Clock,
  Users,
  ShieldAlert,
  ArrowRight,
  Search,
  X,
  Compass,
  Share2,
  Pin,
  GitCompare,
  Activity,
  Layers,
  Server,
  Filter,
  BarChart2,
  PieChart as PieIcon,
  History
} from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts'
import CaptureHeader from '../components/CaptureHeader'
import { useMode } from '../context/ModeContext'

function ProtocolCustomTooltip({ active, payload, totalPackets }) {
  if (!active || !payload || !payload.length) return null
  const item = payload[0]
  const pct = ((item.value / (totalPackets || 1)) * 100).toFixed(1)
  const color = item.payload?.fill || item.color || '#38bdf8'
  return (
    <div className="bg-[#0b101d] border border-slate-700/90 rounded-md p-2.5 shadow-2xl text-xs font-mono backdrop-blur-md z-50 min-w-[190px] pointer-events-none">
      <div className="flex items-center justify-between gap-2 mb-1.5 pb-1 border-b border-slate-800">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full inline-block shrink-0" style={{ backgroundColor: color }} />
          <span className="font-bold text-white text-xs">{item.name}</span>
        </div>
        <span className="text-[10px] text-sky-400 font-bold bg-sky-950/40 border border-sky-800/50 px-1.5 py-0.2 rounded">
          {pct}%
        </span>
      </div>
      <div className="space-y-1 text-slate-300 text-[11px]">
        <div className="flex justify-between items-center">
          <span className="text-slate-400">Packet Volume:</span>
          <span className="font-bold text-white">{item.value.toLocaleString()} pkts</span>
        </div>
      </div>
    </div>
  )
}

function SeverityCustomTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null
  const item = payload[0]
  const sev = (item.payload?.severity || '').toLowerCase()
  const count = item.value || 0
  const sevColors = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#38bdf8',
    info: '#64748b'
  }
  const color = sevColors[sev] || '#64748b'
  const descriptions = {
    critical: 'Confirmed severe exploit or C2 beacon requiring immediate containment.',
    high: 'Substantial security exposure, cleartext credentials, or port sweeps.',
    medium: 'Suspicious anomaly, administrative protocol shift, or connection spike.',
    low: 'Informational policy deviation or non-critical configuration weakness.',
    info: 'Standard telemetry observation or baseline protocol handshake.'
  }
  return (
    <div className="bg-[#0b101d] border border-slate-700/90 rounded-md p-2.5 shadow-2xl text-xs font-mono max-w-[240px] backdrop-blur-md pointer-events-none">
      <div className="flex items-center justify-between gap-3 mb-1.5 pb-1 border-b border-slate-800">
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: color }} />
          <span className="font-bold text-white uppercase tracking-wider text-[11px]">{item.name}</span>
        </div>
        <span className="font-bold px-1.5 py-0.5 rounded text-[10px]" style={{ color, backgroundColor: `${color}1a` }}>
          {count} {count === 1 ? 'detection' : 'detections'}
        </span>
      </div>
      <p className="text-[10px] font-sans text-slate-300 leading-snug">
        {descriptions[sev] || 'Security detections identified at this severity tier.'}
      </p>
    </div>
  )
}

export default function Dashboard() {
  const { analysisId } = useParams()
  const navigate = useNavigate()
  const { mode, isFreeBird, isBlue, isRed, themeColors, getProtocolColor } = useMode()

  const [loading, setLoading] = useState(true)
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [protocolViewMode, setProtocolViewMode] = useState('donut') // 'donut' | 'bars'

  // Global search state
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState(null)
  const [searching, setSearching] = useState(false)
  const [showSearchDropdown, setShowSearchDropdown] = useState(false)
  const searchRef = useRef(null)

  useEffect(() => {
    loadData(false)
    if (analysisId === 'live') {
      const interval = setInterval(() => {
        loadData(true)
      }, 2500)
      return () => clearInterval(interval)
    }
  }, [analysisId])

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (searchRef.current && !searchRef.current.contains(event.target)) {
        setShowSearchDropdown(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const loadData = async (isBackground = false) => {
    if (!isBackground) setLoading(true)
    try {
      const response = await axios.get(`/api/analysis/${analysisId}/results`)
      setData(response.data)
    } catch (err) {
      if (!isBackground) setError(err.response?.data?.detail || 'Failed to load analysis results')
    } finally {
      if (!isBackground) setLoading(false)
    }
  }

  const handleSearch = async (e) => {
    const q = e.target.value
    setSearchQuery(q)
    if (!q.trim()) {
      setSearchResults(null)
      setShowSearchDropdown(false)
      return
    }
    setSearching(true)
    setShowSearchDropdown(true)
    try {
      const res = await axios.get(`/api/analysis/${analysisId}/search`, { params: { q } })
      setSearchResults(res.data)
    } catch (err) {
      console.error('Search error:', err)
    } finally {
      setSearching(false)
    }
  }

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
  }

  const formatDuration = (seconds) => {
    if (!seconds && seconds !== 0) return '-'
    if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`
    if (seconds < 60) return `${seconds.toFixed(1)}s`
    const mins = Math.floor(seconds / 60)
    const secs = (seconds % 60).toFixed(0)
    return `${mins}m ${secs}s`
  }

  if (loading) {
    return (
      <div className="flex flex-col h-screen bg-canvas">
        <CaptureHeader />
        <div className="flex-1 flex items-center justify-center">
          <div className="flex flex-col items-center gap-2">
            <Loader2 className="w-8 h-8 text-primary-400 animate-spin" />
            <span className="text-xs font-mono text-dark-400">Loading capture telemetry...</span>
          </div>
        </div>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="flex flex-col h-screen bg-canvas">
        <CaptureHeader />
        <div className="flex-1 flex items-center justify-center p-6">
          <div className="card p-6 max-w-md w-full text-center space-y-3">
            <ShieldAlert className="w-10 h-10 text-red-500 mx-auto" />
            <h2 className="text-base font-bold text-white">Capture Analysis Failed</h2>
            <p className="text-xs text-dark-400">{error || 'Unable to load analysis metrics.'}</p>
            <Link to="/upload" className="btn btn-secondary text-xs inline-block">
              Return to Upload
            </Link>
          </div>
        </div>
      </div>
    )
  }

  // Protocol chart data
  const protocolData = Object.entries(data.protocols || {})
    .map(([name, value]) => ({ name: name.toUpperCase(), value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 6)

  // Severity chart data
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info']
  const severityData = severityOrder.map((sev) => ({
    name: sev.charAt(0).toUpperCase() + sev.slice(1),
    count: data.findings_by_severity?.[sev] || 0,
    severity: sev,
  }))

  const totalFindings = data.findings_count || 0
  const findingsSevBreakdown = data.findings_by_severity || {}

  return (
    <div className="flex flex-col min-h-screen bg-canvas text-dark-100">
      <CaptureHeader onModeChange={loadData} />

      <div className="flex-1 p-5 max-w-7xl mx-auto w-full space-y-5">
        {/* Top Telemetry Strip & Global Search */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase tracking-wider text-dark-400">
                CYBERSECURITY TELEMETRY WORKSTATION
              </span>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            </div>
            <h1 className="text-xl font-bold text-white font-sans tracking-tight mt-0.5 flex items-center gap-2">
              <span>Traffic Analysis & Incident Overview</span>
              {analysisId === 'live' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 inline-flex items-center gap-1.5 align-middle">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  LIVE STREAM
                </span>
              )}
            </h1>
          </div>

          {/* Global Search Bar */}
          <div className="relative w-full lg:w-96" ref={searchRef}>
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-dark-400" />
              <input
                type="text"
                placeholder="Search IP, domain, URI, protocol, finding..."
                value={searchQuery}
                onChange={handleSearch}
                onFocus={() => { if (searchQuery) setShowSearchDropdown(true) }}
                className="input pl-8 pr-7 w-full text-xs font-mono"
              />
              {searchQuery && (
                <button
                  onClick={() => { setSearchQuery(''); setSearchResults(null); setShowSearchDropdown(false) }}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-dark-400 hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Search Dropdown */}
            {showSearchDropdown && (
              <div className="absolute left-0 right-0 mt-1.5 bg-dark-900 border border-dark-700 rounded-md shadow-2xl z-50 max-h-80 overflow-y-auto divide-y divide-dark-800 text-xs font-mono">
                {searching ? (
                  <div className="p-3 text-center text-dark-400 flex items-center justify-center gap-2">
                    <Loader2 className="w-3.5 h-3.5 animate-spin text-primary-400" />
                    <span>Searching capture...</span>
                  </div>
                ) : searchResults ? (
                  <>
                    {searchResults.hosts?.length > 0 && (
                      <div className="p-2">
                        <div className="text-[10px] font-bold text-dark-500 uppercase px-2 py-0.5">Matching Hosts</div>
                        {searchResults.hosts.slice(0, 4).map((h, i) => (
                          <div
                            key={i}
                            onClick={() => { setShowSearchDropdown(false); navigate(`/packets/${analysisId}?ip=${h.ip}`) }}
                            className="px-2.5 py-1 hover:bg-dark-800 rounded cursor-pointer flex justify-between"
                          >
                            <span className="text-primary-400 font-bold">{h.ip}</span>
                            <span className="text-dark-500">{formatBytes(h.total_bytes)}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {searchResults.findings?.length > 0 && (
                      <div className="p-2">
                        <div className="text-[10px] font-bold text-dark-500 uppercase px-2 py-0.5">Matching Findings</div>
                        {searchResults.findings.slice(0, 4).map((f, i) => (
                          <div
                            key={i}
                            onClick={() => { setShowSearchDropdown(false); navigate(`/findings/${analysisId}`) }}
                            className="px-2.5 py-1 hover:bg-dark-800 rounded cursor-pointer flex items-center justify-between gap-2"
                          >
                            <span className="truncate text-dark-200">{f.title}</span>
                            <span className={`badge badge-${f.severity} text-[9px] uppercase`}>{f.severity}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {searchResults.packets?.length > 0 && (
                      <div className="p-2">
                        <div className="text-[10px] font-bold text-dark-500 uppercase px-2 py-0.5">Matching Packets</div>
                        {searchResults.packets.slice(0, 4).map((p, i) => (
                          <div
                            key={i}
                            onClick={() => { setShowSearchDropdown(false); navigate(`/packets/${analysisId}?packet=${p.number}`) }}
                            className="px-2.5 py-1 hover:bg-dark-800 rounded cursor-pointer flex items-center justify-between text-dark-300"
                          >
                            <span>#{p.number} • {p.src} → {p.dst}</span>
                            <span className="text-primary-400 text-[10px] uppercase font-bold">{p.protocol}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                ) : null}
              </div>
            )}
          </div>
        </div>

        {/* Live Capture Telemetry Banner */}
        {analysisId === 'live' && (
          <div className="card p-3 bg-emerald-500/5 border-emerald-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-2.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shrink-0" />
              <span className="text-xs font-medium text-emerald-300">
                Connected to real-time live capture feed. Metrics, protocol distributions, and security detections refresh continuously as packets are processed.
              </span>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <Link
                to="/live"
                className="text-xs text-emerald-400 hover:text-emerald-300 font-mono font-medium underline flex items-center gap-1"
              >
                Open Live Capture Console →
              </Link>
            </div>
          </div>
        )}

        {/* Unified 5-Metric Command Strip */}
        <div
          className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 rounded-lg border divide-y sm:divide-y-0 sm:divide-x"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-subtle)',
          }}
        >
          {/* 1. Packets */}
          <div className="p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-dark-400 mb-1">
              <span className="text-[11px] font-mono font-medium uppercase tracking-wider">Total Packets</span>
              <Package className="w-3.5 h-3.5 text-primary-400" />
            </div>
            <div className="text-xl font-bold font-mono text-white">
              {data.total_packets?.toLocaleString() || 0}
            </div>
            <span className="text-[10px] text-dark-500 font-mono mt-1">100% normalized</span>
          </div>

          {/* 2. Volume */}
          <div className="p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-dark-400 mb-1">
              <span className="text-[11px] font-mono font-medium uppercase tracking-wider">Traffic Volume</span>
              <Activity className="w-3.5 h-3.5 text-sky-400" />
            </div>
            <div className="text-xl font-bold font-mono text-white">
              {formatBytes(data.total_bytes)}
            </div>
            <span className="text-[10px] text-dark-500 font-mono mt-1">wire capture payload</span>
          </div>

          {/* 3. Unique Hosts */}
          <div className="p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-dark-400 mb-1">
              <span className="text-[11px] font-mono font-medium uppercase tracking-wider">Unique Hosts</span>
              <Users className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <div className="text-xl font-bold font-mono text-white">
              {data.unique_hosts || 0}
            </div>
            <span className="text-[10px] text-dark-500 font-mono mt-1">communicating endpoints</span>
          </div>

          {/* 4. Duration */}
          <div className="p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-dark-400 mb-1">
              <span className="text-[11px] font-mono font-medium uppercase tracking-wider">Duration</span>
              <Clock className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <div className="text-xl font-bold font-mono text-white">
              {formatDuration(data.duration_seconds)}
            </div>
            <span className="text-[10px] text-dark-500 font-mono mt-1">timespan analyzed</span>
          </div>

          {/* 5. Findings */}
          <div className="p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-dark-400 mb-1">
              <span className="text-[11px] font-mono font-medium uppercase tracking-wider">Security Findings</span>
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            </div>
            <div className="flex items-baseline gap-2">
              <span className={`text-xl font-bold font-mono ${totalFindings > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                {totalFindings}
              </span>
              {totalFindings > 0 && (
                <span className="text-[10px] font-mono text-rose-300">
                  ({findingsSevBreakdown.critical || 0} crit, {findingsSevBreakdown.high || 0} high)
                </span>
              )}
            </div>
            <Link to={`/findings/${analysisId}`} className="text-[10px] text-primary-400 hover:underline font-mono mt-1">
              view detections →
            </Link>
          </div>
        </div>

        {/* Investigation Workstation Pivots Banner */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <Link
            to={`/storyline/${analysisId}`}
            className="card p-3.5 group flex flex-col justify-between hover:border-primary-500 transition-all"
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2">
                <Compass className="w-4 h-4 text-primary-400" />
                <span className="font-bold text-xs text-white">Storyline</span>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-dark-500 group-hover:text-primary-400 group-hover:translate-x-0.5 transition-all" />
            </div>
            <p className="text-[11px] text-dark-400 leading-snug">
              Sequential incident milestones linking DNS, sessions, and auth.
            </p>
          </Link>

          <Link
            to={`/memory/${analysisId}`}
            className="card p-3.5 group flex flex-col justify-between hover:border-sky-500 transition-all"
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2">
                <History className="w-4 h-4 text-sky-400" />
                <span className="font-bold text-xs text-white">Beacon Memory</span>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-dark-500 group-hover:text-sky-400 group-hover:translate-x-0.5 transition-all" />
            </div>
            <p className="text-[11px] text-dark-400 leading-snug">
              Historical baseline diff, first-seen destinations, and explainable change detection.
            </p>
          </Link>

          <Link
            to={`/graph/${analysisId}`}
            className="card p-3.5 group flex flex-col justify-between hover:border-emerald-500 transition-all"
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2">
                <Share2 className="w-4 h-4 text-emerald-400" />
                <span className="font-bold text-xs text-white">Evidence Graph</span>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-dark-500 group-hover:text-emerald-400 group-hover:translate-x-0.5 transition-all" />
            </div>
            <p className="text-[11px] text-dark-400 leading-snug">
              Multi-entity topology connecting communicating hosts and threat vectors.
            </p>
          </Link>

          <Link
            to={`/workspace/${analysisId}`}
            className="card p-3.5 group flex flex-col justify-between hover:border-amber-500 transition-all"
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2">
                <Pin className="w-4 h-4 text-amber-400" />
                <span className="font-bold text-xs text-white">Workspace</span>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-dark-500 group-hover:text-amber-400 group-hover:translate-x-0.5 transition-all" />
            </div>
            <p className="text-[11px] text-dark-400 leading-snug">
              Pinned suspect hosts, flagged detections, and auto-saving notes.
            </p>
          </Link>

          <Link
            to="/compare"
            className="card p-3.5 group flex flex-col justify-between hover:border-purple-500 transition-all"
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2">
                <GitCompare className="w-4 h-4 text-purple-400" />
                <span className="font-bold text-xs text-white">Capture Diff</span>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-dark-500 group-hover:text-purple-400 group-hover:translate-x-0.5 transition-all" />
            </div>
            <p className="text-[11px] text-dark-400 leading-snug">
              Pairwise diff between two PCAPs to detect traffic drift.
            </p>
          </Link>
        </div>

        {/* Primary Data Visualizations Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* Left Chart: Protocol Distribution */}
          <div className="card p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-primary-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                  Protocol Distribution & Stack Composition
                </h3>
              </div>
              
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-mono text-dark-500 hidden sm:inline">
                  {Object.keys(data.protocols || {}).length} protocols
                </span>
                <div className="flex items-center bg-dark-900 border border-slate-700/80 rounded-md p-0.5 text-[10px] font-mono">
                  <button
                    type="button"
                    onClick={() => setProtocolViewMode('donut')}
                    className={`px-2 py-0.5 rounded transition-all ${
                      protocolViewMode === 'donut'
                        ? 'bg-primary-600 text-white font-bold'
                        : 'text-dark-400 hover:text-white'
                    }`}
                    title="View Donut Breakdown"
                  >
                    Donut
                  </button>
                  <button
                    type="button"
                    onClick={() => setProtocolViewMode('bars')}
                    className={`px-2 py-0.5 rounded transition-all ${
                      protocolViewMode === 'bars'
                        ? 'bg-primary-600 text-white font-bold'
                        : 'text-dark-400 hover:text-white'
                    }`}
                    title="View Ranked Progress Bars"
                  >
                    Ranked Bars
                  </button>
                </div>
              </div>
            </div>

            {protocolData.length > 0 ? (
              protocolViewMode === 'donut' ? (
                <div className="flex flex-col sm:flex-row items-center gap-4">
                  <div className="w-full sm:w-1/2 h-44 relative flex items-center justify-center">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={protocolData}
                          cx="50%"
                          cy="50%"
                          innerRadius={46}
                          outerRadius={72}
                          paddingAngle={3}
                          dataKey="value"
                        >
                          {protocolData.map((entry, index) => (
                            <Cell
                              key={`cell-${index}`}
                              fill={getProtocolColor(entry.name, index)}
                              stroke="#090c15"
                              strokeWidth={2}
                            />
                          ))}
                        </Pie>
                        <Tooltip content={<ProtocolCustomTooltip totalPackets={data.total_packets} />} />
                      </PieChart>
                    </ResponsiveContainer>
                    {/* Centered Monospace Metric Overlay */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center">
                      <span className="text-sm font-bold font-mono text-white leading-tight">
                        {data.total_packets?.toLocaleString() || 0}
                      </span>
                      <span className="text-[9px] font-mono text-dark-400 uppercase tracking-wider">
                        Packets
                      </span>
                    </div>
                  </div>

                  {/* Protocol Breakdown Legend Table */}
                  <div className="w-full sm:w-1/2 space-y-1.5 font-mono text-xs">
                    {protocolData.map((p, i) => {
                      const pct = ((p.value / (data.total_packets || 1)) * 100).toFixed(1)
                      const color = getProtocolColor(p.name, i)
                      return (
                        <div key={p.name} className="flex items-center justify-between p-1 rounded hover:bg-white/5 transition-colors">
                          <div className="flex items-center gap-2">
                            <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
                            <span className="font-bold text-white uppercase text-[11px]">{p.name}</span>
                          </div>
                          <div className="text-right text-dark-300 text-xs">
                            <span className="font-semibold text-white">{p.value.toLocaleString()}</span>
                            <span className="text-dark-500 ml-1.5 font-normal">({pct}%)</span>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              ) : (
                /* Ranked Bars Mode: Ideal for reading exact proportions without circular compression */
                <div className="space-y-2 py-1 font-mono text-xs">
                  {protocolData.map((p, i) => {
                    const pct = ((p.value / (data.total_packets || 1)) * 100).toFixed(1)
                    const color = getProtocolColor(p.name, i)
                    return (
                      <div key={p.name} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                            <span className="font-bold text-white uppercase">{p.name}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-white font-semibold">{p.value.toLocaleString()} pkts</span>
                            <span className="text-sky-400 font-bold bg-sky-950/40 border border-sky-800/50 px-1.5 py-0.2 rounded text-[10px]">
                              {pct}%
                            </span>
                          </div>
                        </div>
                        <div className="w-full bg-dark-900 rounded-full h-2 overflow-hidden border border-slate-800">
                          <div
                            className="h-full rounded-full transition-all duration-500"
                            style={{
                              width: `${Math.max(2, parseFloat(pct))}%`,
                              backgroundColor: color,
                            }}
                          />
                        </div>
                      </div>
                    )
                  })}
                </div>
              )
            ) : (
              <div className="py-12 text-center text-dark-500 text-xs font-mono">No protocol telemetry recorded in capture.</div>
            )}
          </div>

          {/* Right Chart: Severity Matrix */}
          <div className="card p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                  Detection Severity Matrix ({totalFindings} total)
                </h3>
              </div>
              <Link to={`/findings/${analysisId}`} className="text-[11px] text-primary-400 hover:underline font-mono">
                Inspect All Detections →
              </Link>
            </div>

            <div className="h-44 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <XAxis
                    dataKey="name"
                    stroke="#94a3b8"
                    fontSize={11}
                    tickLine={false}
                    fontFamily="monospace"
                  />
                  <YAxis
                    stroke="#94a3b8"
                    fontSize={10}
                    tickLine={false}
                    allowDecimals={false}
                    fontFamily="monospace"
                  />
                  <Tooltip content={<SeverityCustomTooltip />} position={{ y: 0 }} cursor={{ fill: 'rgba(255, 255, 255, 0.04)' }} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {severityData.map((entry, index) => {
                      let barColor = '#64748b'
                      if (entry.severity === 'critical') barColor = '#ef4444'
                      else if (entry.severity === 'high') barColor = '#f97316'
                      else if (entry.severity === 'medium') barColor = '#eab308'
                      else if (entry.severity === 'low') barColor = '#38bdf8'
                      return <Cell key={`bar-${index}`} fill={barColor} />
                    })}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="grid grid-cols-5 gap-1.5 pt-2 border-t border-dark-800 text-center font-mono text-[10px]">
              <div>
                <span className={`block font-mono ${findingsSevBreakdown.critical > 0 ? 'text-rose-400 font-bold text-xs' : 'text-slate-500 font-normal'}`}>
                  {findingsSevBreakdown.critical || 0}
                </span>
                <span className="text-dark-500 text-[10px]">CRIT</span>
              </div>
              <div>
                <span className={`block font-mono ${findingsSevBreakdown.high > 0 ? 'text-orange-400 font-bold text-xs' : 'text-slate-500 font-normal'}`}>
                  {findingsSevBreakdown.high || 0}
                </span>
                <span className="text-dark-500 text-[10px]">HIGH</span>
              </div>
              <div>
                <span className={`block font-mono ${findingsSevBreakdown.medium > 0 ? 'text-yellow-400 font-bold text-xs' : 'text-slate-500 font-normal'}`}>
                  {findingsSevBreakdown.medium || 0}
                </span>
                <span className="text-dark-500 text-[10px]">MED</span>
              </div>
              <div>
                <span className={`block font-mono ${findingsSevBreakdown.low > 0 ? 'text-sky-400 font-bold text-xs' : 'text-slate-500 font-normal'}`}>
                  {findingsSevBreakdown.low || 0}
                </span>
                <span className="text-dark-500 text-[10px]">LOW</span>
              </div>
              <div>
                <span className={`block font-mono ${findingsSevBreakdown.info > 0 ? 'text-slate-300 font-bold text-xs' : 'text-slate-500 font-normal'}`}>
                  {findingsSevBreakdown.info || 0}
                </span>
                <span className="text-dark-500 text-[10px]">INFO</span>
              </div>
            </div>
          </div>
        </div>

        {/* Secondary Grid: Top Hosts Inventory & High Priority Findings */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* Top Hosts Table (2 Columns) */}
          <div className="lg:col-span-2 card p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-primary-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                  Top Communicating Hosts & Bandwidth
                </h3>
              </div>
              <Link to={`/hosts/${analysisId}`} className="text-[11px] text-primary-400 hover:underline font-mono">
                Full Inventory ({data.unique_hosts || 0}) →
              </Link>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-dark-800 text-[10px] text-dark-500 uppercase tracking-wider">
                    <th className="py-2 px-2.5">Host IP</th>
                    <th className="py-2 px-2.5">Scope</th>
                    <th className="py-2 px-2.5 text-right">Packets</th>
                    <th className="py-2 px-2.5 text-right">Bandwidth</th>
                    <th className="py-2 px-2.5">Protocols</th>
                    <th className="py-2 px-2.5 text-right">Pivot</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-800/60">
                  {data.hosts?.slice(0, 7).map((host) => (
                    <tr
                      key={host.ip}
                      onClick={() => navigate(`/packets/${analysisId}?ip=${host.ip}`)}
                      className="hover:bg-white/5 cursor-pointer transition-colors"
                    >
                      <td className="py-2 px-2.5 font-bold text-white">
                        {host.ip}
                      </td>
                      <td className="py-2 px-2.5">
                        <span
                          className={`badge text-[9px] ${
                            host.is_internal ? 'badge-low' : 'badge-info'
                          }`}
                        >
                          {host.is_internal ? 'Internal' : 'External'}
                        </span>
                      </td>
                      <td className="py-2 px-2.5 text-right text-dark-300">
                        {host.total_packets?.toLocaleString() || 0}
                      </td>
                      <td className="py-2 px-2.5 text-right font-bold text-white">
                        {formatBytes(host.total_bytes)}
                      </td>
                      <td className="py-2 px-2.5 text-dark-400 text-[11px]">
                        {host.protocols?.slice(0, 3).join(', ') || '-'}
                      </td>
                      <td className="py-2 px-2.5 text-right text-primary-400 hover:underline text-[11px]">
                        Packets →
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Highest Priority Findings (1 Column) */}
          <div className="card p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                    Priority Detections
                  </h3>
                </div>
                <Link to={`/findings/${analysisId}`} className="text-[11px] text-primary-400 hover:underline font-mono">
                  All ({totalFindings}) →
                </Link>
              </div>

              {!data.findings || data.findings.length === 0 ? (
                <div className="py-12 text-center text-dark-500 text-xs">
                  No critical or high security anomalies detected in this capture.
                </div>
              ) : (
                <div className="space-y-2.5">
                  {data.findings.slice(0, 4).map((f, i) => (
                    <div
                      key={i}
                      onClick={() => navigate(`/findings/${analysisId}`)}
                      className="p-2.5 rounded border border-dark-800 bg-dark-900/60 hover:border-dark-700 cursor-pointer transition-colors space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className={`badge badge-${f.severity} text-[9px] uppercase font-bold`}>
                          {f.severity}
                        </span>
                        {f.protocol && (
                          <span className="text-[10px] font-mono text-dark-400 uppercase">
                            {f.protocol}
                          </span>
                        )}
                      </div>
                      <h4 className="text-xs font-bold text-white leading-snug line-clamp-1">
                        {f.title}
                      </h4>
                      <p className="text-[11px] text-dark-400 line-clamp-2">
                        {f.description}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <Link
              to={`/storyline/${analysisId}`}
              className="mt-3 w-full py-1.5 px-3 rounded text-xs font-mono text-center border border-dark-800 text-dark-300 hover:bg-white/5 hover:text-white transition-colors block"
            >
              Trace in Investigation Storyline →
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
