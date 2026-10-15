import { useState, useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import axios from 'axios'
import {
  Radio,
  Play,
  Square,
  Pause,
  RefreshCw,
  Shield,
  Flame,
  AlertTriangle,
  Pin,
  Download,
  Search,
  Filter,
  CheckCircle2,
  Clock,
  HardDrive,
  Cpu,
  Layers,
  ArrowRight,
  ChevronRight,
  X,
  FileText,
  Activity,
  Sliders,
  ExternalLink,
  Lock,
  Eye,
  AlertOctagon,
  Sparkles,
  Share2,
  Users,
  Network,
  History,
  Compass,
  Package
} from 'lucide-react'
import { useMode } from '../context/ModeContext'

export default function LiveCapture() {
  const { mode, isFreeBird, isBlue, isRed } = useMode()

  // Capture State & Service Status
  const [stats, setStats] = useState(null)
  const [interfaces, setInterfaces] = useState([])
  const [selectedInterface, setSelectedInterface] = useState('')
  const [captureFilter, setCaptureFilter] = useState('')
  const [bufferCapacity, setBufferCapacity] = useState(1000)
  const [isStarting, setIsStarting] = useState(false)
  const [isStopping, setIsStopping] = useState(false)
  const [actionError, setActionError] = useState(null)

  // Real-time Packets & WebSocket
  const [packets, setPackets] = useState([])
  const [wsConnected, setWsConnected] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const [packetSearch, setPacketSearch] = useState('')
  const [selectedPacket, setSelectedPacket] = useState(null)

  // Preserved Incidents
  const [incidents, setIncidents] = useState([])
  const [selectedIncident, setSelectedIncident] = useState(null)
  const [incidentLoading, setIncidentLoading] = useState(false)
  const [incidentFilterSev, setIncidentFilterSev] = useState('all')
  const [pinnedOnly, setPinnedOnly] = useState(false)

  // Active view tab
  const [activeTab, setActiveTab] = useState('monitor') // 'monitor' | 'incidents'

  // Inline Note Editor State
  const [editingNoteId, setEditingNoteId] = useState(null)
  const [noteText, setNoteText] = useState('')

  const packetsContainerRef = useRef(null)
  const wsRef = useRef(null)
  const reconnectTimeoutRef = useRef(null)

  // 1. Load Interfaces & Initial Status
  useEffect(() => {
    fetchInterfaces()
    fetchStatus()
    fetchIncidents()

    return () => {
      if (wsRef.current) {
        wsRef.current.close()
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
    }
  }, [])

  // 2. Setup WebSocket for real-time telemetry
  useEffect(() => {
    connectWebSocket()
    return () => {
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [])

  // Auto-scroll packet stream table if enabled
  useEffect(() => {
    if (autoScroll && packetsContainerRef.current) {
      packetsContainerRef.current.scrollTop = 0
    }
  }, [packets, autoScroll])

  const connectWebSocket = () => {
    try {
      const loc = window.location
      const protocol = loc.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsUrl = `${protocol}//${loc.hostname}:8000/api/live/ws`

      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        setWsConnected(true)
        setActionError(null)
      }

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          if (msg.type === 'initial' || msg.type === 'telemetry') {
            if (msg.stats) {
              setStats(msg.stats)
            }
            if (msg.recent_packets) {
              setPackets((prev) => {
                // Merge packets avoiding duplicates by number
                const existingNums = new Set(prev.map((p) => p.number))
                const newItems = msg.recent_packets.filter((p) => !existingNums.has(p.number))
                return [...newItems, ...prev].slice(0, 200)
              })
            }
          } else if (msg.type === 'incident') {
            // New incident preserved
            setIncidents((prev) => [msg.data, ...prev.filter((i) => i.id !== msg.data.id)])
            fetchStatus()
          }
        } catch (e) {
          console.error('Error parsing live WS frame:', e)
        }
      }

      ws.onclose = () => {
        setWsConnected(false)
        // Auto-reconnect after 2 seconds
        reconnectTimeoutRef.current = setTimeout(() => {
          connectWebSocket()
        }, 2000)
      }

      ws.onerror = () => {
        setWsConnected(false)
      }
    } catch (e) {
      setWsConnected(false)
    }
  }

  // Fallback Polling (in case WebSocket is disconnected)
  useEffect(() => {
    if (wsConnected) return
    const interval = setInterval(() => {
      fetchStatus()
      fetchRecentPackets()
      fetchIncidents()
    }, 2000)
    return () => clearInterval(interval)
  }, [wsConnected])

  const fetchInterfaces = async () => {
    try {
      const res = await axios.get('/api/live/interfaces')
      const ifaces = res.data.interfaces || []
      setInterfaces(ifaces)
      if (ifaces.length > 0 && !selectedInterface) {
        setSelectedInterface(ifaces[0].id)
      }
    } catch (err) {
      console.error('Failed to list interfaces:', err)
    }
  }

  const fetchStatus = async () => {
    try {
      const res = await axios.get('/api/live/status')
      setStats(res.data)
    } catch (err) {
      console.error('Failed to fetch live status:', err)
    }
  }

  const fetchRecentPackets = async () => {
    try {
      const res = await axios.get('/api/live/packets', { params: { limit: 50 } })
      if (res.data.packets) {
        setPackets(res.data.packets)
      }
    } catch (err) {
      console.error('Failed to fetch recent packets:', err)
    }
  }

  const fetchIncidents = async () => {
    try {
      const res = await axios.get('/api/live/incidents', {
        params: {
          severity: incidentFilterSev !== 'all' ? incidentFilterSev : undefined,
          pinned_only: pinnedOnly,
          limit: 50,
        },
      })
      setIncidents(res.data.incidents || [])
    } catch (err) {
      console.error('Failed to fetch incidents:', err)
    }
  }

  const handleStartCapture = async () => {
    if (!selectedInterface) return
    setIsStarting(true)
    setActionError(null)
    try {
      await axios.post('/api/live/start', {
        interface: selectedInterface,
        capture_filter: captureFilter.trim() || null,
        buffer_capacity: Number(bufferCapacity) || 1000,
        mode: mode,
      })
      await fetchStatus()
    } catch (err) {
      setActionError(err.response?.data?.detail || 'Failed to start live network capture')
    } finally {
      setIsStarting(false)
    }
  }

  const handleStopCapture = async () => {
    setIsStopping(true)
    setActionError(null)
    try {
      await axios.post('/api/live/stop')
      await fetchStatus()
      await fetchIncidents()
    } catch (err) {
      setActionError(err.response?.data?.detail || 'Failed to stop live network capture')
    } finally {
      setIsStopping(false)
    }
  }

  const handlePauseResume = async () => {
    if (!stats) return
    try {
      if (stats.status === 'capturing') {
        await axios.post('/api/live/pause')
      } else if (stats.status === 'paused') {
        await axios.post('/api/live/resume')
      }
      await fetchStatus()
    } catch (err) {
      setActionError(err.response?.data?.detail || 'Failed to pause/resume capture')
    }
  }

  const handleTogglePin = async (incidentId, currentPin) => {
    try {
      await axios.post(`/api/live/incidents/${incidentId}/pin`, { pinned: !currentPin })
      setIncidents((prev) =>
        prev.map((inc) => (inc.id === incidentId ? { ...inc, analyst_pinned: !currentPin } : inc))
      )
      if (selectedIncident && selectedIncident.id === incidentId) {
        setSelectedIncident((prev) => ({ ...prev, analyst_pinned: !currentPin }))
      }
      fetchStatus()
    } catch (err) {
      console.error('Failed to toggle pin:', err)
    }
  }

  const handleSaveNotes = async (incidentId) => {
    try {
      await axios.post(`/api/live/incidents/${incidentId}/notes`, { notes: noteText })
      setIncidents((prev) =>
        prev.map((inc) => (inc.id === incidentId ? { ...inc, analyst_notes: noteText } : inc))
      )
      if (selectedIncident && selectedIncident.id === incidentId) {
        setSelectedIncident((prev) => ({ ...prev, analyst_notes: noteText }))
      }
      setEditingNoteId(null)
    } catch (err) {
      console.error('Failed to save notes:', err)
    }
  }

  const handleInspectIncident = async (incidentId) => {
    setIncidentLoading(true)
    try {
      const res = await axios.get(`/api/live/incidents/${incidentId}`)
      setSelectedIncident(res.data)
    } catch (err) {
      console.error('Failed to inspect incident:', err)
    } finally {
      setIncidentLoading(false)
    }
  }

  const formatBytes = (bytes) => {
    if (!bytes && bytes !== 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(Math.max(1, bytes)) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
  }

  const formatDuration = (seconds) => {
    if (!seconds && seconds !== 0) return '0s'
    const hrs = Math.floor(seconds / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    const secs = Math.floor(seconds % 60)
    if (hrs > 0) return `${hrs}h ${mins}m ${secs}s`
    if (mins > 0) return `${mins}m ${secs}s`
    return `${secs}s`
  }

  // Filter recent packets by query
  const filteredPackets = packets.filter((p) => {
    if (!packetSearch.trim()) return true
    const q = packetSearch.toLowerCase()
    return (
      (p.ip_src && p.ip_src.toLowerCase().includes(q)) ||
      (p.ip_dst && p.ip_dst.toLowerCase().includes(q)) ||
      (p.app_proto && p.app_proto.toLowerCase().includes(q)) ||
      (p.transport_proto && p.transport_proto.toLowerCase().includes(q)) ||
      (p.http_uri && p.http_uri.toLowerCase().includes(q)) ||
      (p.dns_query_name && p.dns_query_name.toLowerCase().includes(q)) ||
      (p.tls_server_name && p.tls_server_name.toLowerCase().includes(q)) ||
      String(p.src_port).includes(q) ||
      String(p.dst_port).includes(q) ||
      String(p.number).includes(q)
    )
  })

  const isCapturing = stats?.status === 'capturing'
  const isPaused = stats?.status === 'paused'

  // Severity color helpers
  const getSeverityBadge = (sev) => {
    const s = (sev || 'medium').toLowerCase()
    if (s === 'critical') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
          <AlertOctagon className="w-3 h-3 text-rose-400" /> CRITICAL
        </span>
      )
    }
    if (s === 'high') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
          <AlertTriangle className="w-3 h-3 text-amber-400" /> HIGH
        </span>
      )
    }
    if (s === 'medium') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-sky-500/20 text-sky-400 border border-sky-500/30">
          MEDIUM
        </span>
      )
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-dark-800 text-dark-300 border border-dark-700">
        LOW
      </span>
    )
  }

  const getEvidenceStatusBadge = (status, missingReason) => {
    const st = (status || '').toLowerCase()
    if (st === 'complete') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
          <CheckCircle2 className="w-3 h-3 text-emerald-400" /> COMPLETE
        </span>
      )
    }
    if (st === 'collecting') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse">
          <Clock className="w-3 h-3 text-amber-400" /> COLLECTING
        </span>
      )
    }
    return (
      <span
        title={missingReason || 'Initial packets evicted from rolling buffer before detection'}
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-fuchsia-500/20 text-fuchsia-400 border border-fuchsia-500/30 cursor-help"
      >
        <AlertTriangle className="w-3 h-3 text-fuchsia-400" /> PARTIAL
      </span>
    )
  }

  return (
    <div className="flex flex-col h-screen bg-canvas overflow-hidden">
      {/* 1. TOP HEADER & TELEMETRY CONTROL BAR */}
      <header
        className="flex-none border-b px-6 py-3.5 select-none"
        style={{
          backgroundColor: 'var(--bg-surface)',
          borderColor: 'var(--border-subtle)',
        }}
      >
        <div className="flex items-center justify-between gap-4">
          {/* Title & Live Status Indicator */}
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-8 h-8 rounded-lg bg-dark-900 border border-dark-800">
              <Radio
                className={`w-4 h-4 ${
                  isCapturing
                    ? 'text-emerald-400 animate-pulse'
                    : isPaused
                    ? 'text-amber-400'
                    : 'text-dark-400'
                }`}
              />
              {isCapturing && (
                <span className="absolute -top-0.5 -right-0.5 flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
                </span>
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-bold text-white tracking-wide">BEACON LIVE</h1>
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider ${
                    isCapturing
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      : isPaused
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      : 'bg-dark-800 text-dark-400 border border-dark-700'
                  }`}
                >
                  {stats?.status || 'STOPPED'}
                </span>
                <span
                  className={`flex items-center gap-1 text-[10px] font-mono ${
                    wsConnected ? 'text-emerald-400' : 'text-amber-400'
                  }`}
                  title={wsConnected ? 'WebSocket Live Telemetry Active' : 'WebSocket Reconnecting (Fallback Polling)'}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      wsConnected ? 'bg-emerald-400' : 'bg-amber-400 animate-pulse'
                    }`}
                  />
                  {wsConnected ? 'LIVE FEED' : 'POLLING'}
                </span>
              </div>
              <p className="text-[11px] text-dark-400 font-mono">
                Continuous 24/7 capture with bounded RAM rolling buffer & smart evidence retention
              </p>
            </div>
          </div>

          {/* Quick Capture Control Actions */}
          <div className="flex items-center gap-3">
            {isCapturing || isPaused ? (
              <>
                <button
                  onClick={handlePauseResume}
                  className={`btn text-xs flex items-center gap-1.5 py-1.5 px-3 rounded-md transition-all ${
                    isPaused
                      ? 'bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30 border border-emerald-500/30'
                      : 'bg-amber-600/20 text-amber-400 hover:bg-amber-600/30 border border-amber-500/30'
                  }`}
                >
                  {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
                  {isPaused ? 'Resume Capture' : 'Pause Capture'}
                </button>

                <button
                  onClick={handleStopCapture}
                  disabled={isStopping}
                  className="btn bg-rose-600/20 hover:bg-rose-600/30 text-rose-400 border border-rose-500/30 text-xs flex items-center gap-1.5 py-1.5 px-3 rounded-md transition-all"
                >
                  <Square className="w-3.5 h-3.5 fill-current" />
                  {isStopping ? 'Stopping...' : 'Stop Monitoring'}
                </button>
              </>
            ) : (
              <button
                onClick={handleStartCapture}
                disabled={isStarting || !selectedInterface}
                className="btn bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs flex items-center gap-1.5 py-1.5 px-4 rounded-md shadow-sm transition-all"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                {isStarting ? 'Starting Capture...' : 'Start Continuous Capture'}
              </button>
            )}
          </div>
        </div>

        {/* Interface & Filter Configuration Bar */}
        <div className="mt-3 pt-3 border-t border-dark-800/80 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2 flex-wrap flex-1">
            {/* Interface Selector */}
            <div className="flex items-center gap-1.5 bg-dark-900 border border-dark-800 rounded px-2.5 py-1">
              <span className="text-dark-400 font-mono text-[11px]">Interface:</span>
              <select
                disabled={isCapturing || isPaused}
                value={selectedInterface}
                onChange={(e) => setSelectedInterface(e.target.value)}
                className="bg-transparent text-white font-mono text-xs focus:outline-none cursor-pointer max-w-[220px]"
              >
                {interfaces.map((iface) => (
                  <option key={iface.id} value={iface.id} className="bg-dark-900 text-white">
                    {iface.id}. {iface.name} {iface.is_loopback ? '(Loopback)' : ''}
                  </option>
                ))}
              </select>
            </div>

            {/* BPF Filter Input */}
            <div className="flex items-center gap-1.5 bg-dark-900 border border-dark-800 rounded px-2.5 py-1 flex-1 min-w-[260px]">
              <Filter className="w-3.5 h-3.5 text-dark-400" />
              <input
                disabled={isCapturing || isPaused}
                type="text"
                value={captureFilter}
                onChange={(e) => setCaptureFilter(e.target.value)}
                placeholder="BPF capture filter (e.g. 'tcp port 80 or udp port 53')"
                className="bg-transparent text-white placeholder-dark-500 font-mono text-xs focus:outline-none w-full"
              />
              {captureFilter && (
                <button
                  disabled={isCapturing || isPaused}
                  onClick={() => setCaptureFilter('')}
                  className="text-dark-400 hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* BPF Filter Quick Presets */}
            {!isCapturing && !isPaused && (
              <div className="flex items-center gap-1 text-[11px] font-mono text-dark-400">
                <span className="text-dark-500">Presets:</span>
                <button
                  onClick={() => setCaptureFilter('')}
                  className={`px-1.5 py-0.5 rounded hover:bg-dark-800 hover:text-white transition-colors ${
                    captureFilter === '' ? 'text-primary-400 font-bold' : ''
                  }`}
                >
                  All
                </button>
                <button
                  onClick={() => setCaptureFilter('tcp port 80 or tcp port 443')}
                  className="px-1.5 py-0.5 rounded hover:bg-dark-800 hover:text-white transition-colors"
                >
                  Web
                </button>
                <button
                  onClick={() => setCaptureFilter('udp port 53 or tcp port 53')}
                  className="px-1.5 py-0.5 rounded hover:bg-dark-800 hover:text-white transition-colors"
                >
                  DNS
                </button>
                <button
                  onClick={() => setCaptureFilter('not port 22')}
                  className="px-1.5 py-0.5 rounded hover:bg-dark-800 hover:text-white transition-colors"
                >
                  No-SSH
                </button>
              </div>
            )}
          </div>

          {/* Buffer Capacity Selector */}
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 bg-dark-900 border border-dark-800 rounded px-2.5 py-1">
              <span className="text-dark-400 font-mono text-[11px]">Buffer:</span>
              <select
                disabled={isCapturing || isPaused}
                value={bufferCapacity}
                onChange={(e) => setBufferCapacity(Number(e.target.value))}
                className="bg-transparent text-white font-mono text-xs focus:outline-none cursor-pointer"
              >
                <option value={500} className="bg-dark-900 text-white">500 pkts</option>
                <option value={1000} className="bg-dark-900 text-white">1,000 pkts (Default)</option>
                <option value={2500} className="bg-dark-900 text-white">2,500 pkts</option>
                <option value={5000} className="bg-dark-900 text-white">5,000 pkts</option>
              </select>
            </div>

            {/* View Switcher Tabs */}
            <div className="flex items-center rounded bg-dark-900 p-0.5 border border-dark-800">
              <button
                onClick={() => setActiveTab('monitor')}
                className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                  activeTab === 'monitor'
                    ? 'bg-dark-800 text-white shadow-sm'
                    : 'text-dark-400 hover:text-dark-200'
                }`}
              >
                Live Monitor
              </button>
              <button
                onClick={() => setActiveTab('incidents')}
                className={`px-3 py-1 rounded text-xs font-medium flex items-center gap-1.5 transition-all ${
                  activeTab === 'incidents'
                    ? 'bg-dark-800 text-white shadow-sm'
                    : 'text-dark-400 hover:text-dark-200'
                }`}
              >
                <span>Preserved Incidents</span>
                {(stats?.incidents_count || 0) > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold bg-rose-500/30 text-rose-300">
                    {stats?.incidents_count}
                  </span>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Action Error Banner */}
        {actionError && (
          <div className="mt-2.5 p-2 rounded bg-rose-500/10 border border-rose-500/30 flex items-center justify-between text-xs text-rose-300">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 flex-none" />
              <span>{actionError}</span>
            </div>
            <button onClick={() => setActionError(null)} className="text-rose-400 hover:text-rose-200">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </header>

      {/* QUICK-PIVOT INVESTIGATION RIBBON */}
      <div
        className="flex-none px-6 py-2 border-b flex flex-wrap items-center justify-between gap-2 text-xs font-mono select-none"
        style={{
          backgroundColor: 'var(--bg-elevated)',
          borderColor: 'var(--border-subtle)',
        }}
      >
        <div className="flex items-center gap-2 text-dark-300">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-semibold text-white">Investigate Live Traffic:</span>
          <span className="text-[11px] text-dark-400 hidden md:inline">
            Seamless real-time correlation across Beacon investigation views
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <Link
            to="/graph/live"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-dark-700 bg-dark-900/80 text-dark-200 hover:text-white hover:border-sky-500/50 hover:bg-sky-500/10 transition-all"
            title="Inspect Real-time Topology & Evidence Graph"
          >
            <Share2 className="w-3.5 h-3.5 text-sky-400" />
            <span>Evidence Graph</span>
          </Link>

          <Link
            to="/hosts/live"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-dark-700 bg-dark-900/80 text-dark-200 hover:text-white hover:border-sky-500/50 hover:bg-sky-500/10 transition-all"
            title="Inspect Communicating Hosts Inventory"
          >
            <Users className="w-3.5 h-3.5 text-sky-400" />
            <span>Hosts</span>
            {(stats?.top_hosts?.length || 0) > 0 && (
              <span className="text-[10px] px-1 rounded bg-dark-800 text-dark-400">
                {stats?.top_hosts?.length}
              </span>
            )}
          </Link>

          <Link
            to="/conversations/live"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-dark-700 bg-dark-900/80 text-dark-200 hover:text-white hover:border-sky-500/50 hover:bg-sky-500/10 transition-all"
            title="Inspect Active Conversation Flows"
          >
            <Network className="w-3.5 h-3.5 text-sky-400" />
            <span>Conversations</span>
          </Link>

          <Link
            to="/timeline/live"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-dark-700 bg-dark-900/80 text-dark-200 hover:text-white hover:border-cyan-500/50 hover:bg-cyan-500/10 transition-all"
            title="Inspect Chronological Protocol & Alert Milestones"
          >
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Timeline</span>
          </Link>

          <Link
            to="/findings/live"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-dark-700 bg-dark-900/80 text-dark-200 hover:text-white hover:border-rose-500/50 hover:bg-rose-500/10 transition-all"
            title="Inspect Real-time Security Findings"
          >
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            <span>Findings</span>
            {(stats?.incidents_count || 0) > 0 && (
              <span className="text-[10px] px-1 rounded bg-rose-500/30 text-rose-300 font-bold">
                {stats?.incidents_count}
              </span>
            )}
          </Link>

          <Link
            to="/packets/live"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-dark-700 bg-dark-900/80 text-dark-200 hover:text-white hover:border-primary-500/50 hover:bg-primary-500/10 transition-all"
            title="Deep Packet Inspection of Rolling Buffer"
          >
            <Package className="w-3.5 h-3.5 text-primary-400" />
            <span>Packet Explorer</span>
          </Link>

          <Link
            to="/storyline/live"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-dark-700 bg-dark-900/80 text-dark-200 hover:text-white hover:border-indigo-500/50 hover:bg-indigo-500/10 transition-all"
            title="Chronological Investigation Storyline"
          >
            <Compass className="w-3.5 h-3.5 text-indigo-400" />
            <span>Storyline</span>
          </Link>

          <Link
            to="/memory/live"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-dark-700 bg-dark-900/80 text-dark-200 hover:text-white hover:border-purple-500/50 hover:bg-purple-500/10 transition-all"
            title="Compare Live Traffic against Historical Baseline"
          >
            <History className="w-3.5 h-3.5 text-purple-400" />
            <span>Memory</span>
          </Link>
        </div>
      </div>

      {/* 2. REAL-TIME METRICS & HEALTH STRIP */}
      <section
        className="flex-none border-b px-6 py-2.5 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 select-none"
        style={{
          backgroundColor: 'var(--bg-canvas)',
          borderColor: 'var(--border-subtle)',
        }}
      >
        {/* Packet Throughput */}
        <div className="flex flex-col">
          <span className="text-[10px] font-mono uppercase tracking-wider text-dark-400">Packet Rate</span>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-lg font-bold font-mono text-white">
              {stats?.packets_per_second?.toFixed(1) || '0.0'}
            </span>
            <span className="text-[11px] font-mono text-dark-400">pkts/s</span>
          </div>
          <span className="text-[10px] font-mono text-dark-500">
            {formatBytes(stats?.bytes_per_second || 0)}/s
          </span>
        </div>

        {/* Total Captured Wire Traffic */}
        <div className="flex flex-col">
          <span className="text-[10px] font-mono uppercase tracking-wider text-dark-400">Total Volume</span>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-lg font-bold font-mono text-white">
              {formatBytes(stats?.total_bytes || 0)}
            </span>
          </div>
          <span className="text-[10px] font-mono text-dark-500">
            {stats?.total_packets?.toLocaleString() || 0} total packets
          </span>
        </div>

        {/* Rolling Buffer Health & Strict Eviction Occupancy */}
        <div className="flex flex-col">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase tracking-wider text-dark-400">Buffer Occupancy</span>
            <span className="text-[10px] font-mono text-dark-400">
              {stats?.buffer_occupancy || 0}/{stats?.buffer_capacity || bufferCapacity}
            </span>
          </div>
          <div className="w-full bg-dark-800 rounded-full h-2 mt-1.5 overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${
                ((stats?.buffer_occupancy || 0) / (stats?.buffer_capacity || 1000)) > 0.9
                  ? 'bg-amber-400'
                  : 'bg-primary-500'
              }`}
              style={{
                width: `${Math.min(
                  100,
                  ((stats?.buffer_occupancy || 0) / (stats?.buffer_capacity || 1000)) * 100
                )}%`,
              }}
            />
          </div>
          <span className="text-[10px] font-mono text-dark-500 mt-1">
            FIFO bounded ({formatBytes(stats?.buffer_memory_bytes || 0)})
          </span>
        </div>

        {/* Process RSS Memory */}
        <div className="flex flex-col">
          <span className="text-[10px] font-mono uppercase tracking-wider text-dark-400">Process Memory</span>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-lg font-bold font-mono text-white">
              {stats?.process_memory_mb?.toFixed(1) || '0.0'}
            </span>
            <span className="text-[11px] font-mono text-dark-400">MB</span>
          </div>
          <span className="text-[10px] font-mono text-emerald-400">
            Safe (<span className="text-dark-400">Target &lt;250 MB</span>)
          </span>
        </div>

        {/* Preserved Security Incidents */}
        <div className="flex flex-col">
          <span className="text-[10px] font-mono uppercase tracking-wider text-dark-400">Preserved Incidents</span>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span
              className={`text-lg font-bold font-mono ${
                (stats?.incidents_count || 0) > 0 ? 'text-rose-400' : 'text-white'
              }`}
            >
              {stats?.incidents_count || 0}
            </span>
            <span className="text-[11px] font-mono text-dark-400">
              ({stats?.pinned_incidents_count || 0} pinned)
            </span>
          </div>
          <span className="text-[10px] font-mono text-dark-500">
            {stats?.active_collection_windows_count || 0} active windows
          </span>
        </div>

        {/* Session Elapsed Time */}
        <div className="flex flex-col">
          <span className="text-[10px] font-mono uppercase tracking-wider text-dark-400">Session Uptime</span>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-lg font-bold font-mono text-white">
              {formatDuration(stats?.elapsed_seconds || 0)}
            </span>
          </div>
          <span className="text-[10px] font-mono text-dark-500">
            Drops: {stats?.dropped_packets || 0}
          </span>
        </div>
      </section>

      {/* 3. MAIN WORKSPACE AREA */}
      <main className="flex-1 overflow-hidden flex flex-col">
        {activeTab === 'monitor' ? (
          <div className="flex-1 grid grid-cols-1 lg:grid-cols-3 gap-0 overflow-hidden">
            {/* LEFT / CENTER: LIVE STREAMING PACKET FEED (Takes 2 cols on lg) */}
            <div className="lg:col-span-2 flex flex-col border-r border-dark-800/80 overflow-hidden">
              {/* Packet Feed Toolbar */}
              <div className="flex-none px-4 py-2 border-b border-dark-800/80 bg-dark-900/60 flex items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2 flex-1">
                  <span className="font-mono text-dark-300 font-semibold flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5 text-primary-400" />
                    LIVE PACKET FEED
                  </span>
                  <span className="text-[10px] font-mono text-dark-500">
                    ({filteredPackets.length} in buffer view)
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  {/* Search / Filter in buffer */}
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-dark-500 absolute left-2 top-2" />
                    <input
                      type="text"
                      value={packetSearch}
                      onChange={(e) => setPacketSearch(e.target.value)}
                      placeholder="Filter stream (IP, port, proto)..."
                      className="bg-dark-950 border border-dark-800 rounded pl-7 pr-2 py-1 text-xs text-white placeholder-dark-500 font-mono focus:outline-none w-52"
                    />
                  </div>

                  {/* Auto-scroll Lock Toggle */}
                  <button
                    onClick={() => setAutoScroll(!autoScroll)}
                    className={`px-2 py-1 rounded text-[11px] font-mono flex items-center gap-1 transition-colors ${
                      autoScroll
                        ? 'bg-primary-500/20 text-primary-400 border border-primary-500/30'
                        : 'bg-dark-800 text-dark-400 border border-dark-700'
                    }`}
                    title={autoScroll ? 'Auto-scroll is locked to newest packets' : 'Auto-scroll paused'}
                  >
                    <span>Auto-scroll</span>
                    <span className={`w-1.5 h-1.5 rounded-full ${autoScroll ? 'bg-primary-400' : 'bg-dark-500'}`} />
                  </button>
                </div>
              </div>

              {/* Live Streaming Table */}
              <div ref={packetsContainerRef} className="flex-1 overflow-y-auto font-mono text-xs select-text">
                <table className="w-full text-left border-collapse">
                  <thead className="sticky top-0 bg-dark-900/95 backdrop-blur z-10 border-b border-dark-800 text-[10px] text-dark-400 uppercase tracking-wider">
                    <tr>
                      <th className="py-2 px-3 w-16 text-right">#</th>
                      <th className="py-2 px-3 w-24">Time</th>
                      <th className="py-2 px-3">Source</th>
                      <th className="py-2 px-3">Destination</th>
                      <th className="py-2 px-3 w-20">Protocol</th>
                      <th className="py-2 px-3 w-16 text-right">Bytes</th>
                      <th className="py-2 px-3">Context / Info</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-dark-900/60">
                    {filteredPackets.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="py-16 text-center text-dark-500">
                          {isCapturing ? (
                            <div className="flex flex-col items-center gap-2">
                              <RefreshCw className="w-5 h-5 animate-spin text-primary-400" />
                              <span>Listening for live network traffic on interface...</span>
                            </div>
                          ) : (
                            <span>No active packets. Press "Start Continuous Capture" to monitor live traffic.</span>
                          )}
                        </td>
                      </tr>
                    ) : (
                      filteredPackets.map((pkt) => {
                        const isSelected = selectedPacket?.number === pkt.number
                        const protoLabel = (pkt.app_proto || pkt.transport_proto || 'other').toUpperCase()
                        const infoText =
                          pkt.http_uri ||
                          pkt.dns_query_name ||
                          pkt.tls_server_name ||
                          pkt.tcp_flags ||
                          pkt.http_method ||
                          ''

                        return (
                          <tr
                            key={pkt.number}
                            onClick={() => setSelectedPacket(pkt)}
                            className={`cursor-pointer transition-colors ${
                              isSelected
                                ? 'bg-primary-950/40 text-primary-200'
                                : 'hover:bg-dark-900/50 text-dark-200'
                            }`}
                          >
                            <td className="py-1.5 px-3 text-right text-dark-500 text-[11px]">{pkt.number}</td>
                            <td className="py-1.5 px-3 text-dark-400 text-[11px]">
                              {pkt.timestamp
                                ? new Date(pkt.timestamp * 1000).toISOString().substr(11, 12)
                                : '-'}
                            </td>
                            <td className="py-1.5 px-3 text-sky-400 truncate max-w-[160px]">
                              {pkt.ip_src}
                              {pkt.src_port ? `:${pkt.src_port}` : ''}
                            </td>
                            <td className="py-1.5 px-3 text-indigo-400 truncate max-w-[160px]">
                              {pkt.ip_dst}
                              {pkt.dst_port ? `:${pkt.dst_port}` : ''}
                            </td>
                            <td className="py-1.5 px-3">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  protoLabel === 'TLS' || protoLabel === 'HTTPS'
                                    ? 'bg-emerald-500/10 text-emerald-400'
                                    : protoLabel === 'DNS'
                                    ? 'bg-amber-500/10 text-amber-400'
                                    : protoLabel === 'HTTP'
                                    ? 'bg-cyan-500/10 text-cyan-400'
                                    : protoLabel === 'TCP'
                                    ? 'bg-blue-500/10 text-blue-400'
                                    : protoLabel === 'UDP'
                                    ? 'bg-violet-500/10 text-violet-400'
                                    : 'bg-dark-800 text-dark-400'
                                }`}
                              >
                                {protoLabel}
                              </span>
                            </td>
                            <td className="py-1.5 px-3 text-right text-dark-400 text-[11px]">{pkt.length}</td>
                            <td className="py-1.5 px-3 text-dark-300 text-[11px] truncate max-w-[260px]">
                              {infoText}
                            </td>
                          </tr>
                        )
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* RIGHT COLUMN: ACTIVE CONVERSATIONS, PROTOCOLS & PACKET INSPECTOR */}
            <div className="flex flex-col bg-dark-950/40 overflow-y-auto">
              {/* Selected Packet Inspector Drawer (if packet clicked) */}
              {selectedPacket ? (
                <div className="p-4 border-b border-dark-800/80 bg-dark-900/60">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-bold text-white font-mono flex items-center gap-1.5">
                      <Eye className="w-3.5 h-3.5 text-primary-400" />
                      PACKET #{selectedPacket.number} INSPECTOR
                    </span>
                    <button
                      onClick={() => setSelectedPacket(null)}
                      className="text-dark-400 hover:text-white"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>

                  <div className="space-y-2 text-xs font-mono">
                    <div className="grid grid-cols-2 gap-2 p-2 bg-dark-950 rounded border border-dark-800">
                      <div>
                        <span className="text-dark-500 text-[10px] block">SOURCE</span>
                        <span className="text-sky-400 font-bold">
                          {selectedPacket.ip_src}
                          {selectedPacket.src_port ? `:${selectedPacket.src_port}` : ''}
                        </span>
                      </div>
                      <div>
                        <span className="text-dark-500 text-[10px] block">DESTINATION</span>
                        <span className="text-indigo-400 font-bold">
                          {selectedPacket.ip_dst}
                          {selectedPacket.dst_port ? `:${selectedPacket.dst_port}` : ''}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-2">
                      <div className="p-2 bg-dark-950 rounded border border-dark-800">
                        <span className="text-dark-500 text-[10px] block">PROTOCOL</span>
                        <span className="text-amber-400 font-bold">
                          {(selectedPacket.app_proto || selectedPacket.transport_proto || 'UNKNOWN').toUpperCase()}
                        </span>
                      </div>
                      <div className="p-2 bg-dark-950 rounded border border-dark-800">
                        <span className="text-dark-500 text-[10px] block">WIRE LENGTH</span>
                        <span className="text-white font-bold">{selectedPacket.length} bytes</span>
                      </div>
                      <div className="p-2 bg-dark-950 rounded border border-dark-800">
                        <span className="text-dark-500 text-[10px] block">DIRECTION</span>
                        <span className="text-white capitalize font-bold">
                          {selectedPacket.direction || 'In/Out'}
                        </span>
                      </div>
                    </div>

                    {/* Metadata fields */}
                    {selectedPacket.dns_query_name && (
                      <div className="p-2 bg-dark-950 rounded border border-dark-800">
                        <span className="text-dark-500 text-[10px] block">DNS QUERY</span>
                        <span className="text-emerald-400 break-all">{selectedPacket.dns_query_name}</span>
                      </div>
                    )}
                    {selectedPacket.http_uri && (
                      <div className="p-2 bg-dark-950 rounded border border-dark-800">
                        <span className="text-dark-500 text-[10px] block">HTTP REQUEST</span>
                        <span className="text-cyan-400 break-all">
                          {selectedPacket.http_method || 'GET'} {selectedPacket.http_uri}
                        </span>
                      </div>
                    )}
                    {selectedPacket.tls_server_name && (
                      <div className="p-2 bg-dark-950 rounded border border-dark-800">
                        <span className="text-dark-500 text-[10px] block">TLS SNI</span>
                        <span className="text-purple-400 break-all">{selectedPacket.tls_server_name}</span>
                      </div>
                    )}

                    {/* Hex Preview */}
                    {selectedPacket.raw_hex && (
                      <div>
                        <span className="text-dark-500 text-[10px] block mb-1">RAW WIRE HEX PREVIEW</span>
                        <div className="bg-dark-950 p-2 rounded border border-dark-800 text-[10px] font-mono text-dark-300 overflow-x-auto max-h-32">
                          {selectedPacket.raw_hex.match(/.{1,32}/g)?.map((chunk, i) => (
                            <div key={i} className="tracking-widest">
                              {chunk.match(/.{1,2}/g)?.join(' ')}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : null}

              {/* Protocol Distribution Widget */}
              <div className="p-4 border-b border-dark-800/80">
                <h3 className="text-xs font-bold text-white font-mono flex items-center gap-1.5 mb-3">
                  <Layers className="w-3.5 h-3.5 text-primary-400" />
                  PROTOCOL DISTRIBUTION
                </h3>
                {stats?.top_protocols && Object.keys(stats.top_protocols).length > 0 ? (
                  <div className="space-y-2">
                    {Object.entries(stats.top_protocols)
                      .sort((a, b) => b[1] - a[1])
                      .slice(0, 6)
                      .map(([proto, count]) => {
                        const total = stats.total_packets || 1
                        const pct = Math.round((count / total) * 100)
                        return (
                          <div key={proto} className="text-xs font-mono">
                            <div className="flex justify-between text-[11px] mb-1">
                              <span className="text-dark-300 font-bold">{proto}</span>
                              <span className="text-dark-400">
                                {count.toLocaleString()} ({pct}%)
                              </span>
                            </div>
                            <div className="w-full bg-dark-800 rounded-full h-1.5 overflow-hidden">
                              <div
                                className="bg-primary-500 h-full rounded-full"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                        )
                      })}
                  </div>
                ) : (
                  <p className="text-xs text-dark-500 font-mono">No protocol metrics accumulated yet.</p>
                )}
              </div>

              {/* Top Communicating Hosts Widget */}
              <div className="p-4 border-b border-dark-800/80">
                <h3 className="text-xs font-bold text-white font-mono flex items-center gap-1.5 mb-3">
                  <HardDrive className="w-3.5 h-3.5 text-primary-400" />
                  TOP COMMUNICATING HOSTS
                </h3>
                {stats?.top_hosts && stats.top_hosts.length > 0 ? (
                  <div className="space-y-2">
                    {stats.top_hosts.map((host) => (
                      <div
                        key={host.ip}
                        onClick={() => setPacketSearch(host.ip)}
                        className="p-2 rounded bg-dark-900 border border-dark-800 hover:border-dark-700 cursor-pointer text-xs font-mono transition-colors"
                        title="Click to filter packet stream by this IP"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-sky-400 font-bold">{host.ip}</span>
                          <span className="text-dark-400 text-[11px]">{formatBytes(host.bytes)}</span>
                        </div>
                        <div className="flex items-center justify-between text-[10px] text-dark-500 mt-1">
                          <span>{host.packets.toLocaleString()} pkts</span>
                          <span>{host.protocols.join(', ') || 'N/A'}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-dark-500 font-mono">No host activity detected yet.</p>
                )}
              </div>

              {/* Active Conversations (Flows) */}
              <div className="p-4">
                <h3 className="text-xs font-bold text-white font-mono flex items-center gap-1.5 mb-3">
                  <Activity className="w-3.5 h-3.5 text-primary-400" />
                  ACTIVE CONVERSATION FLOWS
                </h3>
                {stats?.active_conversations && stats.active_conversations.length > 0 ? (
                  <div className="space-y-2">
                    {stats.active_conversations.map((flow) => (
                      <div
                        key={flow.key}
                        className="p-2 rounded bg-dark-900 border border-dark-800 text-xs font-mono"
                      >
                        <div className="text-indigo-400 truncate font-semibold" title={flow.key}>
                          {flow.key}
                        </div>
                        <div className="flex items-center justify-between text-[10px] text-dark-400 mt-1">
                          <span>{flow.packets.toLocaleString()} pkts</span>
                          <span>{formatBytes(flow.bytes)}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-dark-500 font-mono">No conversation flows recorded yet.</p>
                )}
              </div>
            </div>
          </div>
        ) : (
          /* TAB 2: PRESERVED INCIDENTS & EVIDENCE CENTER */
          <div className="flex-1 flex overflow-hidden">
            {/* Incidents List (Left 1/2) */}
            <div className="w-full lg:w-1/2 flex flex-col border-r border-dark-800/80 overflow-hidden">
              {/* Filter Toolbar */}
              <div className="flex-none px-4 py-2.5 border-b border-dark-800/80 bg-dark-900/60 flex items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-dark-300 font-semibold flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5 text-rose-400" />
                    PRESERVED SECURITY INCIDENTS
                  </span>
                  <span className="text-[10px] font-mono text-dark-500">
                    ({incidents.length} preserved)
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  {/* Severity Filter */}
                  <select
                    value={incidentFilterSev}
                    onChange={(e) => {
                      setIncidentFilterSev(e.target.value)
                      setTimeout(fetchIncidents, 50)
                    }}
                    className="bg-dark-950 border border-dark-800 rounded px-2 py-1 text-xs text-white font-mono focus:outline-none"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>

                  {/* Pinned Only Toggle */}
                  <button
                    onClick={() => {
                      setPinnedOnly(!pinnedOnly)
                      setTimeout(fetchIncidents, 50)
                    }}
                    className={`px-2 py-1 rounded text-xs font-mono flex items-center gap-1 transition-colors ${
                      pinnedOnly
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        : 'bg-dark-950 text-dark-400 border border-dark-800'
                    }`}
                  >
                    <Pin className="w-3 h-3" />
                    <span>Pinned</span>
                  </button>
                </div>
              </div>

              {/* Incidents Cards List */}
              <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono">
                {incidents.length === 0 ? (
                  <div className="p-12 text-center text-dark-500 text-xs">
                    <Shield className="w-8 h-8 text-dark-600 mx-auto mb-2" />
                    <p className="font-bold text-dark-300">No Security Incidents Preserved Yet</p>
                    <p className="text-[11px] text-dark-500 mt-1 max-w-sm mx-auto">
                      When live streaming rules detect suspicious port sweeps, cleartext credentials, beaconing,
                      surges, or tunneling, relevant packets are preserved automatically.
                    </p>
                  </div>
                ) : (
                  incidents.map((inc) => {
                    const isSelected = selectedIncident?.id === inc.id
                    return (
                      <div
                        key={inc.id}
                        onClick={() => handleInspectIncident(inc.id)}
                        className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                          isSelected
                            ? 'bg-dark-900 border-primary-500/60 shadow-md'
                            : 'bg-dark-900/60 border-dark-800 hover:border-dark-700'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2 mb-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            {getSeverityBadge(inc.severity)}
                            {getEvidenceStatusBadge(inc.evidence_status, inc.missing_context_reason)}
                            <span className="text-[10px] text-dark-400">
                              {inc.created_timestamp
                                ? new Date(inc.created_timestamp * 1000).toLocaleTimeString()
                                : ''}
                            </span>
                          </div>

                          <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                            <button
                              onClick={() => handleTogglePin(inc.id, inc.analyst_pinned)}
                              className={`p-1 rounded transition-colors ${
                                inc.analyst_pinned
                                  ? 'bg-amber-500/20 text-amber-400'
                                  : 'text-dark-500 hover:text-dark-300'
                              }`}
                              title={inc.analyst_pinned ? 'Pinned (Protected from budget eviction)' : 'Pin incident'}
                            >
                              <Pin className="w-3.5 h-3.5" />
                            </button>

                            <a
                              href={`/api/live/incidents/${inc.id}/export`}
                              download
                              className="p-1 rounded text-dark-400 hover:text-emerald-400 transition-colors"
                              title="Export preserved PCAP"
                            >
                              <Download className="w-3.5 h-3.5" />
                            </a>
                          </div>
                        </div>

                        <h4 className="text-xs font-bold text-white mb-1">{inc.title}</h4>
                        <div className="text-[11px] text-dark-400 mb-2 flex items-center justify-between">
                          <span>Target: <span className="text-sky-400">{inc.target_entity}</span></span>
                          <span className="text-dark-500">
                            {inc.total_retained_packets} packets retained
                          </span>
                        </div>

                        {inc.analyst_notes && (
                          <div className="p-2 rounded bg-dark-950 border border-dark-800 text-[11px] text-dark-300 italic">
                            "{inc.analyst_notes}"
                          </div>
                        )}
                      </div>
                    )
                  })
                )}
              </div>
            </div>

            {/* Incident Details & Packet Inspector (Right 1/2) */}
            <div className="hidden lg:flex lg:w-1/2 flex-col bg-dark-950/40 overflow-hidden font-mono">
              {incidentLoading ? (
                <div className="flex-1 flex items-center justify-center">
                  <RefreshCw className="w-6 h-6 animate-spin text-primary-400" />
                </div>
              ) : selectedIncident ? (
                <div className="flex-1 flex flex-col overflow-hidden">
                  {/* Incident Header */}
                  <div className="p-4 border-b border-dark-800 bg-dark-900/60 flex-none">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        {getSeverityBadge(selectedIncident.severity)}
                        {getEvidenceStatusBadge(
                          selectedIncident.evidence_status,
                          selectedIncident.missing_context_reason
                        )}
                      </div>
                      <a
                        href={`/api/live/incidents/${selectedIncident.id}/export`}
                        download
                        className="btn bg-emerald-600 hover:bg-emerald-500 text-white text-xs py-1 px-3 rounded flex items-center gap-1.5 transition-colors"
                      >
                        <Download className="w-3.5 h-3.5" />
                        Download PCAP
                      </a>
                    </div>

                    <h3 className="text-sm font-bold text-white mb-1">{selectedIncident.title}</h3>
                    <p className="text-xs text-dark-300 mb-3">{selectedIncident.description}</p>

                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="p-2 bg-dark-950 rounded border border-dark-800">
                        <span className="text-dark-500 text-[10px] block">TARGET ENTITY</span>
                        <span className="text-sky-400 font-bold">{selectedIncident.target_entity}</span>
                      </div>
                      <div className="p-2 bg-dark-950 rounded border border-dark-800">
                        <span className="text-dark-500 text-[10px] block">CONFIDENCE</span>
                        <span className="text-amber-400 font-bold uppercase">
                          {selectedIncident.confidence}
                        </span>
                      </div>
                    </div>

                    {/* Missing context notice if partial */}
                    {selectedIncident.missing_context_reason && (
                      <div className="mt-2.5 p-2 rounded bg-amber-500/10 border border-amber-500/30 text-[11px] text-amber-300">
                        <strong>Evidence Partial:</strong> {selectedIncident.missing_context_reason}
                      </div>
                    )}

                    {/* Analyst Notes Section */}
                    <div className="mt-3">
                      <div className="flex items-center justify-between mb-1 text-xs">
                        <span className="text-dark-400 font-bold">ANALYST NOTES</span>
                        {editingNoteId !== selectedIncident.id ? (
                          <button
                            onClick={() => {
                              setEditingNoteId(selectedIncident.id)
                              setNoteText(selectedIncident.analyst_notes || '')
                            }}
                            className="text-primary-400 hover:text-primary-300 text-[11px]"
                          >
                            Edit Notes
                          </button>
                        ) : null}
                      </div>

                      {editingNoteId === selectedIncident.id ? (
                        <div className="space-y-2">
                          <textarea
                            value={noteText}
                            onChange={(e) => setNoteText(e.target.value)}
                            placeholder="Add investigation findings, root cause, or disposition notes..."
                            className="w-full bg-dark-950 border border-dark-800 rounded p-2 text-xs text-white placeholder-dark-500 font-mono focus:outline-none focus:border-primary-500 h-20"
                          />
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => setEditingNoteId(null)}
                              className="px-2.5 py-1 text-xs text-dark-400 hover:text-white"
                            >
                              Cancel
                            </button>
                            <button
                              onClick={() => handleSaveNotes(selectedIncident.id)}
                              className="btn bg-primary-600 hover:bg-primary-500 text-white text-xs px-3 py-1 rounded"
                            >
                              Save Notes
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div className="p-2 rounded bg-dark-950 border border-dark-800 text-xs text-dark-300 min-h-[36px]">
                          {selectedIncident.analyst_notes || (
                            <span className="text-dark-500 italic">No notes recorded yet.</span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Retained Evidence Packets Sequence */}
                  <div className="flex-1 flex flex-col overflow-hidden">
                    <div className="px-4 py-2 border-b border-dark-800 bg-dark-900/40 text-xs text-dark-400 font-bold flex items-center justify-between">
                      <span>RETAINED PACKETS TIMELINE</span>
                      <span className="text-[11px] font-normal text-dark-500">
                        {selectedIncident.pre_trigger_packets?.length || 0} pre &bull; 1 trigger &bull;{' '}
                        {selectedIncident.post_trigger_packets?.length || 0} post
                      </span>
                    </div>

                    <div className="flex-1 overflow-y-auto divide-y divide-dark-900 text-xs">
                      {(selectedIncident.all_packets || []).map((pkt) => {
                        const isTrigger = pkt.number === selectedIncident.trigger_packet?.number
                        const isPre = pkt.number < selectedIncident.trigger_packet?.number
                        return (
                          <div
                            key={pkt.number}
                            className={`p-2.5 transition-colors ${
                              isTrigger
                                ? 'bg-rose-950/30 border-l-2 border-rose-500'
                                : isPre
                                ? 'bg-dark-950/20 border-l-2 border-sky-500/40'
                                : 'bg-dark-950/40 border-l-2 border-amber-500/40'
                            }`}
                          >
                            <div className="flex items-center justify-between text-[11px] mb-1">
                              <span
                                className={`font-bold ${
                                  isTrigger
                                    ? 'text-rose-400'
                                    : isPre
                                    ? 'text-sky-400'
                                    : 'text-amber-400'
                                }`}
                              >
                                {isTrigger
                                  ? '⚡ TRIGGER PACKET'
                                  : isPre
                                  ? 'PRE-TRIGGER CONTEXT'
                                  : 'POST-TRIGGER OBSERVATION'}
                              </span>
                              <span className="text-dark-500">
                                #{pkt.number} &bull;{' '}
                                {pkt.timestamp
                                  ? new Date(pkt.timestamp * 1000).toISOString().substr(11, 12)
                                  : ''}
                              </span>
                            </div>
                            <div className="text-dark-200">
                              <span className="text-sky-400">{pkt.ip_src}:{pkt.src_port || '-'}</span>
                              <span className="text-dark-500 mx-1.5">&rarr;</span>
                              <span className="text-indigo-400">{pkt.ip_dst}:{pkt.dst_port || '-'}</span>
                              <span className="ml-2 px-1 rounded text-[10px] bg-dark-800 text-dark-400">
                                {(pkt.app_proto || pkt.transport_proto || 'OTHER').toUpperCase()}
                              </span>
                            </div>
                            {(pkt.http_uri || pkt.dns_query_name || pkt.tls_server_name) && (
                              <div className="text-[11px] text-dark-400 truncate mt-0.5">
                                {pkt.http_uri || pkt.dns_query_name || pkt.tls_server_name}
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex-1 flex items-center justify-center p-8 text-center text-dark-500 text-xs">
                  <p>Select an incident from the list to inspect retained evidence packets.</p>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  )
}
