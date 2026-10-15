import { useState, useEffect, useMemo, useRef } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import axios from 'axios'
import {
  Share2,
  Filter,
  Loader2,
  ShieldAlert,
  ArrowRight,
  RefreshCw,
  Search,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Globe,
  Server,
  Pin,
  Layers,
  Sparkles,
  Download,
  Maximize2,
  Focus,
  Eye,
  EyeOff,
  Radio,
  ExternalLink,
  Clock,
  Package,
  Activity
} from 'lucide-react'
import CaptureHeader from '../components/CaptureHeader'
import { useMode } from '../context/ModeContext'

// Intelligent two-line wrapping for long IPv6 addresses and hostnames without silent truncation
function formatNodeLabelLines(label) {
  if (!label) return ['']
  if (label.length <= 16) return [label]

  // If IPv6 (contains :)
  if (label.includes(':')) {
    const parts = label.split(':')
    const mid = Math.ceil(parts.length / 2)
    const line1 = parts.slice(0, mid).join(':') + ':'
    const line2 = parts.slice(mid).join(':')
    return [line1, line2]
  }

  // If domain or hostname (contains .)
  if (label.includes('.')) {
    const parts = label.split('.')
    if (parts.length > 2) {
      const mid = Math.ceil(parts.length / 2)
      const line1 = parts.slice(0, mid).join('.') + '.'
      const line2 = parts.slice(mid).join('.')
      return [line1, line2]
    }
  }

  // General split around 14 characters
  return [label.slice(0, 14), label.slice(14, 28)]
}

export default function NetworkGraph() {
  const { analysisId } = useParams()
  const navigate = useNavigate()
  const { mode, isFreeBird, isBlue, isRed, themeColors } = useMode()

  const [loading, setLoading] = useState(true)
  const [graphMode, setGraphMode] = useState('topology') // 'topology' | 'evidence'
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] })
  const [positions, setPositions] = useState({})

  // Selection states (mutually coordinated)
  const [selectedNode, setSelectedNode] = useState(null)
  const [selectedEdge, setSelectedEdge] = useState(null)

  // Floating hover tooltips state (coordinates & content)
  const [hoveredNode, setHoveredNode] = useState(null) // { node, x, y }
  const [hoveredEdge, setHoveredEdge] = useState(null) // { edge, x, y }

  // Advanced investigation filters
  const [searchQuery, setSearchQuery] = useState('')
  const [protocolFilter, setProtocolFilter] = useState('')
  const [internalOnly, setInternalOnly] = useState(false)
  const [findingsOnly, setFindingsOnly] = useState(false)
  const [timeFilter, setTimeFilter] = useState('all') // 'all' | 'early' | 'mid' | 'late'
  const [neighborhoodFocus, setNeighborhoodFocus] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)

  // Pinned entities
  const [pinnedNodes, setPinnedNodes] = useState(() => {
    try {
      const saved = localStorage.getItem(`beacon_workspace_${analysisId}`)
      if (saved) {
        const parsed = JSON.parse(saved)
        return new Set(parsed.pinned_hosts || [])
      }
    } catch (e) {
      // ignore
    }
    return new Set()
  })

  // Pan and Zoom state
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [isPanning, setIsPanning] = useState(false)
  const panStartRef = useRef({ x: 0, y: 0 })

  // Node Dragging state
  const [draggedNodeId, setDraggedNodeId] = useState(null)
  const dragStartRef = useRef({ x: 0, y: 0 })
  const hasDraggedRef = useRef(false)
  const svgRef = useRef(null)
  const containerRef = useRef(null)

  useEffect(() => {
    loadGraph(false)
  }, [analysisId, graphMode])

  useEffect(() => {
    if (analysisId !== 'live') return
    const timer = setInterval(() => {
      loadGraph(true)
    }, 2500)
    return () => clearInterval(timer)
  }, [analysisId, graphMode])

  const loadGraph = async (isIncremental = false) => {
    if (!isIncremental) {
      setLoading(true)
      setSelectedEdge(null)
    }
    try {
      const endpoint =
        graphMode === 'evidence'
          ? `/api/analysis/${analysisId}/evidence-graph`
          : `/api/analysis/${analysisId}/graph`

      const response = await axios.get(endpoint, {
        params: { max_nodes: graphMode === 'evidence' ? 60 : 45 }
      })

      const data = response.data || { nodes: [], edges: [] }
      setGraphData(data)

      if (isIncremental) {
        updateIncrementalLayout(data.nodes)
      } else {
        computeInitialLayout(data.nodes)
        if (data.nodes.length > 0 && !selectedNode) {
          setSelectedNode(data.nodes[0])
        }
      }
    } catch (err) {
      console.error('Failed to load graph:', err)
    } finally {
      if (!isIncremental) {
        setLoading(false)
      }
    }
  }

  const updateIncrementalLayout = (nodes) => {
    setPositions((prev) => {
      const unplaced = nodes.filter((n) => !prev[n.id])
      if (unplaced.length === 0) return prev
      const allPos = calculateStaticPositions(nodes)
      const nextPos = { ...prev }
      unplaced.forEach((n) => {
        if (allPos[n.id]) {
          nextPos[n.id] = allPos[n.id]
        }
      })
      return nextPos
    })
  }

  // Calculate stable static initial positions with multi-tier radial tiers and deterministic relaxation
  const calculateStaticPositions = (nodes) => {
    const width = 900
    const height = 620
    const centerX = width / 2
    const centerY = height / 2
    const initialPositions = {}

    if (graphMode === 'evidence') {
      const hosts = nodes.filter((n) => n.type === 'host' || !n.type)
      const domains = nodes.filter((n) => n.type === 'domain')
      const findings = nodes.filter((n) => n.type === 'finding')

      // Inner ring: Hosts (staggered radii if many hosts)
      hosts.forEach((node, i) => {
        const radius = hosts.length > 8 ? (i % 2 === 0 ? 140 : 180) : 150
        const angle = (2 * Math.PI * i) / (hosts.length || 1)
        initialPositions[node.id] = {
          x: Math.round(centerX + radius * Math.cos(angle)),
          y: Math.round(centerY + radius * Math.sin(angle)),
        }
      })

      // Outer ring: Domains (staggered radii to prevent overlap)
      domains.forEach((node, i) => {
        const radius = domains.length > 10 ? (i % 2 === 0 ? 250 : 295) : 260
        const angle = (2 * Math.PI * i) / (domains.length || 1) + 0.3
        initialPositions[node.id] = {
          x: Math.round(centerX + radius * Math.cos(angle)),
          y: Math.round(centerY + radius * Math.sin(angle)),
        }
      })

      // Top arc: Findings
      const findingRadius = 260
      findings.forEach((node, i) => {
        const angle = Math.PI + ((i + 0.5) * Math.PI) / (findings.length || 1)
        initialPositions[node.id] = {
          x: Math.round(centerX + findingRadius * Math.cos(angle)),
          y: Math.round(centerY + (findingRadius * 0.7) * Math.sin(angle)),
        }
      })
    } else {
      // Standard topology layout
      const internal = nodes.filter((n) => n.is_internal)
      const external = nodes.filter((n) => !n.is_internal && !n.is_multicast)
      const multicast = nodes.filter((n) => n.is_multicast)

      // Inner ring: internal hosts
      internal.forEach((node, i) => {
        const radius = internal.length > 6 ? (i % 2 === 0 ? 120 : 160) : 135
        const angle = (2 * Math.PI * i) / (internal.length || 1)
        initialPositions[node.id] = {
          x: Math.round(centerX + radius * Math.cos(angle)),
          y: Math.round(centerY + radius * Math.sin(angle)),
        }
      })

      // Bottom arc / cluster: multicast groups
      multicast.forEach((node, i) => {
        const angle = Math.PI * 0.5 + ((i - (multicast.length - 1) / 2) * 0.38)
        const radius = 225
        initialPositions[node.id] = {
          x: Math.round(centerX + radius * Math.cos(angle)),
          y: Math.round(centerY + radius * Math.sin(angle)),
        }
      })

      // Outer ring: external hosts (staggered tiers to prevent crowding)
      external.forEach((node, i) => {
        const tier = i % 3
        const radius = 250 + tier * 40
        const angle = (2 * Math.PI * i) / (external.length || 1)
        initialPositions[node.id] = {
          x: Math.round(centerX + radius * Math.cos(angle)),
          y: Math.round(centerY + radius * Math.sin(angle)),
        }
      })
    }

    // Deterministic static relaxation loop (25 iterations) to eliminate overlaps
    const nodeIds = Object.keys(initialPositions)
    const minDistance = 72
    for (let iter = 0; iter < 25; iter++) {
      for (let i = 0; i < nodeIds.length; i++) {
        for (let j = i + 1; j < nodeIds.length; j++) {
          const id1 = nodeIds[i]
          const id2 = nodeIds[j]
          const p1 = initialPositions[id1]
          const p2 = initialPositions[id2]
          const dx = p2.x - p1.x
          const dy = p2.y - p1.y
          const dist = Math.sqrt(dx * dx + dy * dy) || 1
          if (dist < minDistance) {
            const overlap = (minDistance - dist) / 2
            const pushX = (dx / dist) * overlap * 0.8
            const pushY = (dy / dist) * overlap * 0.8
            p1.x = Math.round(p1.x - pushX)
            p1.y = Math.round(p1.y - pushY)
            p2.x = Math.round(p2.x + pushX)
            p2.y = Math.round(p2.y + pushY)
          }
        }
      }
    }

    return initialPositions
  }

  const computeInitialLayout = (nodes) => {
    const width = 900
    const height = 620
    const initialPositions = calculateStaticPositions(nodes)
    setPositions(initialPositions)

    // Automatically compute boundary-aware bounding box and fit to view with 70px padding
    const coords = Object.values(initialPositions)
    if (coords.length > 0) {
      let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity
      coords.forEach((p) => {
        if (p.x < minX) minX = p.x
        if (p.x > maxX) maxX = p.x
        if (p.y < minY) minY = p.y
        if (p.y > maxY) maxY = p.y
      })

      const pad = 70
      const graphW = Math.max(100, maxX - minX + pad * 2)
      const graphH = Math.max(100, maxY - minY + pad * 2)
      const scale = Math.min(1.4, Math.max(0.4, Math.min(width / graphW, height / graphH)))
      const midX = (minX + maxX) / 2
      const midY = (minY + maxY) / 2

      setZoom(scale)
      setPan({
        x: Math.round(width / 2 - midX * scale),
        y: Math.round(height / 2 - midY * scale),
      })
    } else {
      setZoom(1)
      setPan({ x: 0, y: 0 })
    }
  }

  // Auto-frame / Fit to View
  const fitToView = () => {
    const coords = Object.values(positions)
    if (coords.length === 0) return

    let minX = Infinity
    let maxX = -Infinity
    let minY = Infinity
    let maxY = -Infinity

    coords.forEach((p) => {
      if (p.x < minX) minX = p.x
      if (p.x > maxX) maxX = p.x
      if (p.y < minY) minY = p.y
      if (p.y > maxY) maxY = p.y
    })

    const pad = 70
    const graphW = Math.max(100, maxX - minX + pad * 2)
    const graphH = Math.max(100, maxY - minY + pad * 2)
    const viewW = 900
    const viewH = 620

    const scale = Math.min(1.4, Math.max(0.4, Math.min(viewW / graphW, viewH / graphH)))
    const midX = (minX + maxX) / 2
    const midY = (minY + maxY) / 2

    setZoom(scale)
    setPan({
      x: Math.round(viewW / 2 - midX * scale),
      y: Math.round(viewH / 2 - midY * scale),
    })
  }

  // Select node and smoothly zoom in to inspect connections
  const handleSelectNode = (node) => {
    if (hasDraggedRef.current) return
    setSelectedNode(node)
    setSelectedEdge(null)

    const pos = positions[node.id]
    if (pos) {
      const targetZoom = Math.max(zoom, 1.25)
      setZoom(targetZoom)
      setPan({
        x: Math.round(450 - pos.x * targetZoom),
        y: Math.round(310 - pos.y * targetZoom),
      })
    }
  }

  // Filter nodes & edges without altering established positions
  const filteredData = useMemo(() => {
    let nodes = graphData.nodes

    if (internalOnly && graphMode === 'topology') {
      nodes = nodes.filter((n) => n.is_internal)
    }

    if (findingsOnly) {
      nodes = nodes.filter((n) => (n.findings_count && n.findings_count > 0) || n.type === 'finding' || n.severity === 'critical' || n.severity === 'high')
    }

    const nodeIds = new Set(nodes.map((n) => n.id))
    let edges = graphData.edges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target))

    if (protocolFilter) {
      edges = edges.filter((e) => (e.protocol || '').toLowerCase() === protocolFilter.toLowerCase())
    }

    if (timeFilter !== 'all' && edges.length > 0) {
      // Divide edges chronologically
      const sortedByTime = [...edges].sort((a, b) => (a.first_seen || 0) - (b.first_seen || 0))
      const count = sortedByTime.length
      const chunk = Math.ceil(count / 3)
      if (timeFilter === 'early') {
        edges = sortedByTime.slice(0, chunk)
      } else if (timeFilter === 'mid') {
        edges = sortedByTime.slice(chunk, chunk * 2)
      } else if (timeFilter === 'late') {
        edges = sortedByTime.slice(chunk * 2)
      }
    }

    return { nodes, edges }
  }, [graphData, internalOnly, findingsOnly, protocolFilter, timeFilter, graphMode])

  // Map of direct neighbors for the selected entity (for 1-Hop focus)
  const directNeighborIds = useMemo(() => {
    if (!selectedNode) return new Set()
    const set = new Set([selectedNode.id])
    filteredData.edges.forEach((e) => {
      if (e.source === selectedNode.id) set.add(e.target)
      if (e.target === selectedNode.id) set.add(e.source)
    })
    return set
  }, [selectedNode, filteredData.edges])

  // Mouse Wheel Zoom
  const handleWheel = (e) => {
    e.preventDefault()
    const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9
    setZoom((prevZoom) => Math.min(3.5, Math.max(0.3, prevZoom * zoomFactor)))
  }

  // SVG Pan Handlers
  const handleSvgMouseDown = (e) => {
    if (e.target.tagName === 'svg' || e.target.id === 'canvas-bg' || e.target.id === 'dot-grid-rect') {
      setIsPanning(true)
      panStartRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y }
    }
  }

  const handleMouseMove = (e) => {
    if (isPanning) {
      setPan({
        x: e.clientX - panStartRef.current.x,
        y: e.clientY - panStartRef.current.y,
      })
    } else if (draggedNodeId) {
      hasDraggedRef.current = true
      const svg = svgRef.current
      if (!svg) return

      const rect = svg.getBoundingClientRect()
      const svgX = (e.clientX - rect.left - pan.x) / zoom
      const svgY = (e.clientY - rect.top - pan.y) / zoom

      setPositions((prev) => ({
        ...prev,
        [draggedNodeId]: {
          x: Math.round(svgX),
          y: Math.round(svgY),
        },
      }))
    }
  }

  const handleMouseUp = () => {
    setIsPanning(false)
    setDraggedNodeId(null)
  }

  const handleNodeMouseDown = (e, node) => {
    e.stopPropagation()
    hasDraggedRef.current = false
    setDraggedNodeId(node.id)
    dragStartRef.current = { x: e.clientX, y: e.clientY }
  }

  // Node Hover Tooltip coordinates
  const handleNodeMouseEnter = (e, node) => {
    const rect = containerRef.current?.getBoundingClientRect()
    if (rect) {
      setHoveredNode({
        node,
        x: e.clientX - rect.left + 15,
        y: e.clientY - rect.top - 15,
      })
    }
  }

  // Edge Hover Tooltip coordinates
  const handleEdgeMouseEnter = (e, edge) => {
    const rect = containerRef.current?.getBoundingClientRect()
    if (rect) {
      setHoveredEdge({
        edge,
        x: e.clientX - rect.left + 15,
        y: e.clientY - rect.top - 15,
      })
    }
  }

  // Node Coloring honoring Free Bird (Red + Blue Duality), Blue, and Red modes
  const getNodeColor = (node) => {
    if (node.type === 'domain') {
      return '#06b6d4' // Cool cyan for domains
    }
    if (node.type === 'finding') {
      if (node.severity === 'critical') return '#ef4444'
      if (node.severity === 'high') return '#f43f5e'
      return '#eab308'
    }

    if (node.severity === 'critical') return '#ef4444'
    if (node.severity === 'high') return '#f43f5e'
    if (node.severity === 'medium') return '#eab308'

    if (node.is_multicast) {
      return '#0d9488' // Distinct teal for multicast groups
    }

    if (isFreeBird) {
      // Free Bird combines Electric Blue (hosts) with Red (threats)
      return node.is_internal ? '#38bdf8' : '#0284c7'
    }
    if (isRed) {
      return node.is_internal ? '#f43f5e' : '#78716c'
    }
    // Blue mode
    return node.is_internal ? '#38bdf8' : '#64748b'
  }

  const togglePinHost = (nodeId) => {
    const updated = new Set(pinnedNodes)
    if (updated.has(nodeId)) {
      updated.delete(nodeId)
    } else {
      updated.add(nodeId)
    }
    setPinnedNodes(updated)

    try {
      const storageKey = `beacon_workspace_${analysisId}`
      const saved = localStorage.getItem(storageKey)
      const data = saved ? JSON.parse(saved) : { pinned_hosts: [], pinned_findings: [], notes: '' }
      data.pinned_hosts = Array.from(updated)
      localStorage.setItem(storageKey, JSON.stringify(data))
    } catch (e) {
      console.error('Failed to save pinned node:', e)
    }
  }

  // Export Snapshot
  const handleExportSnapshot = (format) => {
    setExportOpen(false)
    if (format === 'json') {
      const payload = {
        capture_id: analysisId,
        timestamp: new Date().toISOString(),
        mode,
        graph_mode: graphMode,
        nodes: filteredData.nodes.map((n) => ({
          ...n,
          coordinates: positions[n.id] || null,
        })),
        edges: filteredData.edges,
      }
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `beacon_graph_snapshot_${analysisId.slice(0, 8)}.json`
      a.click()
      URL.revokeObjectURL(url)
    } else if (format === 'svg') {
      if (!svgRef.current) return
      const svgXml = new XMLSerializer().serializeToString(svgRef.current)
      const blob = new Blob([svgXml], { type: 'image/svg+xml;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `beacon_network_map_${analysisId.slice(0, 8)}.svg`
      a.click()
      URL.revokeObjectURL(url)
    }
  }

  const formatBytes = (bytes) => {
    if (!bytes && bytes !== 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(Math.abs(bytes) || 1) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
  }

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-canvas text-dark-100">
      <CaptureHeader onModeChange={loadGraph} />

      <div className="flex flex-1 overflow-hidden">
        {/* Main Canvas Area */}
        <div className="flex-1 flex flex-col p-4 overflow-hidden">
          {/* Top Control Bar */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 mb-3">
            <div className="flex items-center gap-2">
              <Share2 className="w-4 h-4 text-primary-400" />
              <h1 className="text-base font-bold text-white font-sans tracking-tight">
                {graphMode === 'evidence' ? 'Investigation Evidence Graph' : 'Forensic Network Map'}
              </h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-dark-900 border-slate-700/80 text-dark-300">
                {filteredData.nodes.length} nodes • {filteredData.edges.length} links
              </span>
              {analysisId === 'live' && (
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  LIVE STREAM
                </span>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {/* Mode Toggle */}
              <div className="flex rounded-md p-0.5 border border-slate-700/80 bg-dark-900 text-xs font-mono">
                <button
                  type="button"
                  onClick={() => {
                    setGraphMode('topology')
                    setSelectedEdge(null)
                  }}
                  className={`px-2.5 py-1 rounded text-xs transition-colors ${
                    graphMode === 'topology'
                      ? 'bg-primary-600 text-white font-bold shadow-sm'
                      : 'text-dark-400 hover:text-white'
                  }`}
                >
                  Topology
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setGraphMode('evidence')
                    setSelectedEdge(null)
                  }}
                  className={`px-2.5 py-1 rounded text-xs transition-colors ${
                    graphMode === 'evidence'
                      ? 'bg-primary-600 text-white font-bold shadow-sm'
                      : 'text-dark-400 hover:text-white'
                  }`}
                >
                  Evidence Graph
                </button>
              </div>

              {/* Search Filter */}
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-dark-400" />
                <input
                  type="text"
                  placeholder="Filter host/IP/domain..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="input pl-8 pr-2.5 py-1 text-xs w-40 font-mono"
                />
              </div>

              {/* Protocol Selector */}
              <select
                value={protocolFilter}
                onChange={(e) => setProtocolFilter(e.target.value)}
                className="py-1 px-2.5 text-xs bg-dark-900 border border-slate-700/80 rounded-md text-white font-mono focus:outline-none"
              >
                <option value="">All Protocols</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="http">HTTP</option>
                <option value="dns">DNS</option>
                <option value="ssh">SSH</option>
              </select>

              {/* Time Range Filter */}
              <select
                value={timeFilter}
                onChange={(e) => setTimeFilter(e.target.value)}
                className="py-1 px-2.5 text-xs bg-dark-900 border border-slate-700/80 rounded-md text-white font-mono focus:outline-none"
                title="Filter active relationships across capture timespan"
              >
                <option value="all">All Timespan</option>
                <option value="early">Phase 1: Early</option>
                <option value="mid">Phase 2: Mid</option>
                <option value="late">Phase 3: Late</option>
              </select>

              {/* Findings Only Filter */}
              <button
                type="button"
                onClick={() => setFindingsOnly(!findingsOnly)}
                className={`px-2.5 py-1 text-xs font-mono rounded-md border transition-colors flex items-center gap-1.5 ${
                  findingsOnly
                    ? 'bg-rose-950/50 text-rose-300 border-rose-800'
                    : 'bg-dark-900 border-slate-700/80 text-dark-300 hover:text-white'
                }`}
                title="Isolate entities with flagged security detections"
              >
                <ShieldAlert className="w-3 h-3 text-rose-400" />
                <span>Threats Only</span>
              </button>

              {/* Neighborhood 1-Hop Focus */}
              {selectedNode && (
                <button
                  type="button"
                  onClick={() => setNeighborhoodFocus(!neighborhoodFocus)}
                  className={`px-2.5 py-1 text-xs font-mono rounded-md border transition-colors flex items-center gap-1.5 ${
                    neighborhoodFocus
                      ? 'bg-sky-950/60 text-sky-300 border-sky-700 shadow-sm'
                      : 'bg-dark-900 border-slate-700/80 text-dark-300 hover:text-white'
                  }`}
                  title="Isolate 1-hop direct communicating neighbors of the selected host"
                >
                  <Focus className="w-3 h-3 text-sky-400" />
                  <span>1-Hop Subgraph</span>
                </button>
              )}

              {/* Export Snapshot Dropdown */}
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setExportOpen(!exportOpen)}
                  className="btn btn-secondary py-1 px-2.5 text-xs flex items-center gap-1.5"
                  title="Export Forensic Map"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Export</span>
                </button>

                {exportOpen && (
                  <div className="absolute right-0 mt-1 w-44 bg-dark-900 border border-slate-700 rounded-lg shadow-2xl py-1 z-50 text-xs font-mono">
                    <button
                      onClick={() => handleExportSnapshot('svg')}
                      className="w-full text-left px-3 py-2 text-dark-200 hover:bg-slate-800 hover:text-white flex items-center gap-2"
                    >
                      <Download className="w-3.5 h-3.5 text-sky-400" />
                      <span>Vector SVG Image</span>
                    </button>
                    <button
                      onClick={() => handleExportSnapshot('json')}
                      className="w-full text-left px-3 py-2 text-dark-200 hover:bg-slate-800 hover:text-white flex items-center gap-2"
                    >
                      <Share2 className="w-3.5 h-3.5 text-amber-400" />
                      <span>Forensic Evidence JSON</span>
                    </button>
                  </div>
                )}
              </div>

              <button
                type="button"
                onClick={loadGraph}
                className="btn btn-secondary p-1.5"
                title="Reset Graph Layout"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Interactive SVG Canvas */}
          <div
            ref={containerRef}
            className="card p-0 flex-1 overflow-hidden relative flex items-center justify-center border"
            style={{
              backgroundColor: '#070a12',
              borderColor: 'var(--border-subtle)',
            }}
            onWheel={handleWheel}
          >
            {loading ? (
              <div className="flex flex-col items-center gap-2">
                <Loader2 className="w-6 h-6 animate-spin text-primary-400" />
                <span className="text-xs font-mono text-dark-400">Rendering forensic map...</span>
              </div>
            ) : filteredData.nodes.length === 0 ? (
              <div className="text-dark-400 text-xs font-mono p-8 text-center">
                No communicating entities found with active filter criteria.
              </div>
            ) : (
              <svg
                ref={svgRef}
                viewBox="0 0 900 620"
                className="w-full h-full select-none cursor-grab active:cursor-grabbing"
                onMouseDown={handleSvgMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={handleMouseUp}
              >
                {/* Technical SVG Definitions & Arrowhead Markers */}
                <defs>
                  {/* Precision Dot Grid */}
                  <pattern id="dot-grid" x="0" y="0" width="24" height="24" patternUnits="userSpaceOnUse">
                    <circle cx="2" cy="2" r="0.85" fill="#334155" opacity="0.45" />
                  </pattern>

                  {/* Directional Arrowheads */}
                  <marker
                    id="arrow-traffic"
                    viewBox="0 0 10 10"
                    refX="22"
                    refY="5"
                    markerWidth="5"
                    markerHeight="5"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#38bdf8" opacity="0.85" />
                  </marker>

                  <marker
                    id="arrow-alert"
                    viewBox="0 0 10 10"
                    refX="22"
                    refY="5"
                    markerWidth="5"
                    markerHeight="5"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#f43f5e" opacity="0.9" />
                  </marker>

                  <marker
                    id="arrow-resolution"
                    viewBox="0 0 10 10"
                    refX="22"
                    refY="5"
                    markerWidth="5"
                    markerHeight="5"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#38bdf8" opacity="0.8" />
                  </marker>
                </defs>

                {/* Background click target for panning with dot grid */}
                <rect
                  id="canvas-bg"
                  x="-4000"
                  y="-4000"
                  width="8000"
                  height="8000"
                  fill="url(#dot-grid)"
                />

                {/* Transformable Canvas Container */}
                <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                  {/* Edges */}
                  {filteredData.edges.map((edge, i) => {
                    const s = positions[edge.source]
                    const t = positions[edge.target]
                    if (!s || !t) return null

                    const isSelectedEdge = selectedEdge && selectedEdge.id === edge.id
                    const isConnectedToSelectedNode =
                      selectedNode && (selectedNode.id === edge.source || selectedNode.id === edge.target)
                    const isConnectedToHoverNode =
                      hoveredNode && (hoveredNode.node.id === edge.source || hoveredNode.node.id === edge.target)
                    const isHoveredEdge = hoveredEdge && hoveredEdge.edge.id === edge.id

                    // 1-Hop Neighborhood Dimming
                    let edgeDimmed = false
                    if (neighborhoodFocus && selectedNode) {
                      edgeDimmed = !(edge.source === selectedNode.id || edge.target === selectedNode.id)
                    }

                    let strokeColor = '#334155'
                    let strokeDash = undefined
                    let marker = 'url(#arrow-traffic)'

                    if (edge.type === 'alert') {
                      strokeColor = '#f43f5e'
                      strokeDash = '4 2'
                      marker = 'url(#arrow-alert)'
                    } else if (edge.type === 'resolution') {
                      strokeColor = '#38bdf8'
                      strokeDash = '3 3'
                      marker = 'url(#arrow-resolution)'
                    } else if (isSelectedEdge || isHoveredEdge) {
                      strokeColor = '#38bdf8'
                    } else if (isConnectedToSelectedNode || isConnectedToHoverNode) {
                      strokeColor = isFreeBird ? '#38bdf8' : isRed ? '#f43f5e' : '#38bdf8'
                    }

                    const strokeW = isSelectedEdge ? 3 : isHoveredEdge || isConnectedToSelectedNode ? 2.2 : 1.2
                    const strokeOp = edgeDimmed ? 0.05 : isSelectedEdge || isConnectedToSelectedNode || isHoveredEdge ? 0.95 : 0.35

                    return (
                      <g key={`edge-group-${edge.id || i}`}>
                        {/* Invisible Wide Hit-Target for Edge Hover & Click Selection */}
                        <line
                          x1={s.x}
                          y1={s.y}
                          x2={t.x}
                          y2={t.y}
                          stroke="transparent"
                          strokeWidth={14}
                          className="cursor-pointer"
                          onMouseEnter={(e) => handleEdgeMouseEnter(e, edge)}
                          onMouseLeave={() => setHoveredEdge(null)}
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedEdge(edge)
                            setSelectedNode(null)
                          }}
                        />

                        {/* Visible Directional Line with Arrowhead */}
                        <line
                          x1={s.x}
                          y1={s.y}
                          x2={t.x}
                          y2={t.y}
                          stroke={strokeColor}
                          strokeWidth={strokeW}
                          strokeOpacity={strokeOp}
                          strokeDasharray={strokeDash}
                          markerEnd={marker}
                          pointerEvents="none"
                        />
                      </g>
                    )
                  })}

                  {/* Nodes */}
                  {filteredData.nodes.map((node) => {
                    const pos = positions[node.id]
                    if (!pos) return null

                    const isSelected = selectedNode && selectedNode.id === node.id
                    const isHovered = hoveredNode && hoveredNode.node.id === node.id
                    const isMatch = searchQuery && node.label.toLowerCase().includes(searchQuery.toLowerCase())
                    const isPinned = pinnedNodes.has(node.id)

                    // 1-Hop Neighborhood Dimming
                    let isDimmed = false
                    if (neighborhoodFocus && selectedNode) {
                      isDimmed = !directNeighborIds.has(node.id)
                    }

                    const nodeColor = getNodeColor(node)
                    let radius = 14
                    if (node.type === 'finding') radius = 13
                    else if (node.type === 'domain') radius = 13
                    else {
                      radius = Math.min(22, Math.max(13, Math.log10(node.total_bytes || 10) * 3.2))
                    }

                    return (
                      <g
                        key={node.id}
                        className="cursor-pointer"
                        opacity={isDimmed ? 0.12 : 1}
                        style={{ transition: 'opacity 0.2s ease' }}
                      >
                        {/* Outer Selection / Match Halo (pointerEvents: none prevents hover flutter) */}
                        {(isSelected || isHovered || isMatch) && (
                          <circle
                            cx={pos.x}
                            cy={pos.y}
                            r={radius + 6}
                            fill="none"
                            stroke={isSelected ? (isFreeBird ? '#38bdf8' : isRed ? '#f43f5e' : '#38bdf8') : isMatch ? '#f59e0b' : '#94a3b8'}
                            strokeWidth={isSelected ? 2.5 : 1.5}
                            strokeDasharray={isSelected ? '4 2' : undefined}
                            opacity={0.95}
                            pointerEvents="none"
                          />
                        )}

                        {/* Multicast Dashed Accent Ring */}
                        {node.is_multicast && (
                          <circle
                            cx={pos.x}
                            cy={pos.y}
                            r={radius + 3.5}
                            fill="none"
                            stroke="#14b8a6"
                            strokeWidth="1.5"
                            strokeDasharray="3 2"
                            opacity={0.9}
                            pointerEvents="none"
                          />
                        )}

                        {/* IPv6 Marker Indicator */}
                        {node.is_ipv6 && (
                          <g pointerEvents="none">
                            <rect
                              x={pos.x - radius - 11}
                              y={pos.y - radius - 2}
                              width="16"
                              height="10"
                              rx="2"
                              fill="#0b1120"
                              stroke="#38bdf8"
                              strokeWidth="0.8"
                            />
                            <text
                              x={pos.x - radius - 3}
                              y={pos.y - radius + 6}
                              textAnchor="middle"
                              fontSize="7"
                              fontFamily="monospace"
                              fontWeight="bold"
                              fill="#38bdf8"
                            >
                              v6
                            </text>
                          </g>
                        )}

                        {/* Visible Node Circle (Geometry remains completely stable without CSS scale) */}
                        <circle
                          cx={pos.x}
                          cy={pos.y}
                          r={radius}
                          fill={nodeColor}
                          stroke={node.severity && node.severity !== 'info' ? '#ffffff' : node.is_multicast ? '#14b8a6' : '#070a12'}
                          strokeWidth={node.severity && node.severity !== 'info' ? 1.5 : 1}
                          pointerEvents="none"
                        />

                        {/* Pinned Marker Indicator */}
                        {isPinned && (
                          <circle
                            cx={pos.x + radius - 2}
                            cy={pos.y - radius + 2}
                            r={4}
                            fill="#f59e0b"
                            stroke="#ffffff"
                            strokeWidth="1"
                            pointerEvents="none"
                          />
                        )}

                        {/* Invisible Fixed-Size Hit Target Circle (Eliminates Vibration/Jitter on Hover) */}
                        <circle
                          cx={pos.x}
                          cy={pos.y}
                          r={radius + 8}
                          fill="transparent"
                          pointerEvents="all"
                          className="cursor-pointer"
                          onMouseEnter={(e) => handleNodeMouseEnter(e, node)}
                          onMouseLeave={() => setHoveredNode(null)}
                          onMouseDown={(e) => handleNodeMouseDown(e, node)}
                          onClick={() => handleSelectNode(node)}
                        />

                        {/* Node Label Text with High-Contrast Background Stroke & Two-Line Wrapping for Long IPv6/Hostnames */}
                        {(() => {
                          const lines = formatNodeLabelLines(node.label)
                          const isMultiLine = lines.length > 1
                          return (
                            <text
                              x={pos.x}
                              y={pos.y + radius + 13}
                              textAnchor="middle"
                              stroke="#070a12"
                              strokeWidth="3.5"
                              paintOrder="stroke fill"
                              className={`text-[11px] font-mono pointer-events-none select-none ${
                                isSelected
                                  ? 'fill-white font-bold'
                                  : isMatch
                                  ? 'fill-amber-400 font-bold'
                                  : node.is_multicast
                                  ? 'fill-teal-300 font-medium'
                                  : 'fill-slate-300 font-medium'
                              }`}
                            >
                              <tspan x={pos.x} dy="0">{lines[0]}</tspan>
                              {isMultiLine && (
                                <tspan x={pos.x} dy="12">{lines[1]}</tspan>
                              )}
                            </text>
                          )
                        })()}
                      </g>
                    )
                  })}
                </g>
              </svg>
            )}

            {/* Contextual Floating Hover Tooltip for Node */}
            {hoveredNode && (
              <div
                className="absolute z-40 bg-[#090d19] border border-slate-700/90 rounded-lg p-3 shadow-2xl text-xs font-mono backdrop-blur-md pointer-events-none min-w-[200px]"
                style={{
                  left: `${Math.min(hoveredNode.x, 650)}px`,
                  top: `${Math.max(15, hoveredNode.y)}px`,
                }}
              >
                <div className="flex items-center gap-2 mb-1.5 pb-1 border-b border-slate-800">
                  <span
                    className="w-2.5 h-2.5 rounded-full shrink-0"
                    style={{ backgroundColor: getNodeColor(hoveredNode.node) }}
                  />
                  <span className="font-bold text-white text-xs truncate max-w-[220px]">
                    {hoveredNode.node.label}
                  </span>
                </div>
                <div className="space-y-1 text-slate-300 text-[11px]">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Classification:</span>
                    <span className="text-white capitalize">
                      {hoveredNode.node.type === 'domain'
                        ? 'Queried Domain'
                        : hoveredNode.node.type === 'finding'
                        ? `${hoveredNode.node.severity} Threat`
                        : hoveredNode.node.is_multicast
                        ? 'Multicast Group'
                        : hoveredNode.node.is_internal
                        ? 'Internal Host'
                        : 'External Host'}
                    </span>
                  </div>
                  {hoveredNode.node.total_bytes !== undefined && (
                    <div className="flex justify-between">
                      <span className="text-slate-400">Traffic Volume:</span>
                      <span className="text-white font-bold">{formatBytes(hoveredNode.node.total_bytes)}</span>
                    </div>
                  )}
                  {hoveredNode.node.findings_count !== undefined && hoveredNode.node.findings_count > 0 && (
                    <div className="flex justify-between">
                      <span className="text-rose-400 font-semibold">Security Alerts:</span>
                      <span className="text-rose-400 font-bold">{hoveredNode.node.findings_count}</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Contextual Floating Hover Tooltip for Edge */}
            {hoveredEdge && (
              <div
                className="absolute z-40 bg-[#090d19] border border-slate-700/90 rounded-lg p-3 shadow-2xl text-xs font-mono backdrop-blur-md pointer-events-none min-w-[220px]"
                style={{
                  left: `${Math.min(hoveredEdge.x, 640)}px`,
                  top: `${Math.max(15, hoveredEdge.y)}px`,
                }}
              >
                <div className="flex items-center gap-2 mb-1.5 pb-1 border-b border-slate-800">
                  <Activity className="w-3.5 h-3.5 text-sky-400" />
                  <span className="font-bold text-white uppercase text-[11px]">
                    {hoveredEdge.edge.protocol || 'Traffic'} Session
                  </span>
                </div>
                <div className="space-y-1 text-slate-300 text-[11px]">
                  <div className="text-slate-200 truncate">
                    {hoveredEdge.edge.source} ↔ {hoveredEdge.edge.target}
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Packets:</span>
                    <span className="text-white font-bold">{hoveredEdge.edge.packet_count?.toLocaleString() || 1} pkts</span>
                  </div>
                  {hoveredEdge.edge.byte_count !== undefined && (
                    <div className="flex justify-between">
                      <span className="text-slate-400">Payload Volume:</span>
                      <span className="text-white font-bold">{formatBytes(hoveredEdge.edge.byte_count)}</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Minimap / Overview Navigator */}
            <div
              className="absolute bottom-3 right-3 w-36 h-24 bg-[#090d18]/90 border border-slate-700/80 rounded-md overflow-hidden shadow-2xl hidden sm:block select-none"
              title="Overview Minimap"
            >
              <svg viewBox="0 0 900 620" className="w-full h-full">
                {/* Miniature Edges */}
                {filteredData.edges.slice(0, 30).map((edge, i) => {
                  const s = positions[edge.source]
                  const t = positions[edge.target]
                  if (!s || !t) return null
                  return (
                    <line
                      key={`mini-edge-${i}`}
                      x1={s.x}
                      y1={s.y}
                      x2={t.x}
                      y2={t.y}
                      stroke="#334155"
                      strokeWidth="3"
                      opacity="0.3"
                    />
                  )
                })}
                {/* Miniature Nodes */}
                {filteredData.nodes.map((node) => {
                  const p = positions[node.id]
                  if (!p) return null
                  return (
                    <circle
                      key={`mini-node-${node.id}`}
                      cx={p.x}
                      cy={p.y}
                      r="12"
                      fill={getNodeColor(node)}
                    />
                  )
                })}
                {/* Viewport Frame Box */}
                <rect
                  x={Math.max(0, -pan.x / zoom)}
                  y={Math.max(0, -pan.y / zoom)}
                  width={900 / zoom}
                  height={620 / zoom}
                  fill="rgba(56, 189, 248, 0.08)"
                  stroke="#38bdf8"
                  strokeWidth="6"
                  strokeDasharray="12 6"
                />
              </svg>
            </div>

            {/* Floating Canvas Controls */}
            <div
              className="absolute top-3 right-3 flex flex-col gap-1 p-1 rounded-md border shadow-xl backdrop-blur-md"
              style={{
                backgroundColor: 'rgba(9, 13, 24, 0.9)',
                borderColor: 'var(--border-subtle)',
              }}
            >
              <button
                type="button"
                onClick={() => setZoom((z) => Math.min(3.5, z * 1.25))}
                className="p-1.5 text-dark-300 hover:text-white hover:bg-white/10 rounded transition-colors"
                title="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={() => setZoom((z) => Math.max(0.3, z * 0.8))}
                className="p-1.5 text-dark-300 hover:text-white hover:bg-white/10 rounded transition-colors"
                title="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={fitToView}
                className="p-1.5 text-dark-300 hover:text-white hover:bg-white/10 rounded transition-colors"
                title="Fit to View"
              >
                <Maximize2 className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={() => {
                  setZoom(1)
                  setPan({ x: 0, y: 0 })
                }}
                className="p-1.5 text-dark-300 hover:text-white hover:bg-white/10 rounded transition-colors"
                title="Reset View (1:1)"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Forensic Legend */}
            <div
              className="absolute bottom-3 left-3 flex flex-wrap items-center gap-3 text-[11px] font-mono p-2 rounded-md border backdrop-blur-md"
              style={{
                backgroundColor: 'rgba(9, 13, 24, 0.9)',
                borderColor: 'var(--border-subtle)',
              }}
            >
              {graphMode === 'evidence' ? (
                <>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-sky-500 inline-block" />
                    <span className="text-dark-300 font-medium">Host (Blue)</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-teal-500 inline-block" />
                    <span className="text-dark-300 font-medium">Multicast</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block" />
                    <span className="text-dark-300 font-medium">Domain</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" />
                    <span className="text-dark-300 font-medium">Threat Finding (Red)</span>
                  </div>
                </>
              ) : (
                <>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-sky-500 inline-block" />
                    <span className="text-dark-300 font-medium">Internal Host</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-slate-500 inline-block" />
                    <span className="text-dark-300 font-medium">External Host</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-teal-500 inline-block" />
                    <span className="text-dark-300 font-medium">Multicast</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" />
                    <span className="text-dark-300 font-medium">Flagged Alert</span>
                  </div>
                </>
              )}
              <div className="text-dark-500 border-l border-slate-700 pl-2">
                Arrows indicate traffic initiator → responder
              </div>
            </div>
          </div>
        </div>

        {/* Right Drawer: Selected Entity or Edge Inspector */}
        <div
          className="w-80 border-l p-4 flex flex-col justify-between h-[calc(100vh-57px)] overflow-y-auto"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-subtle)',
          }}
        >
          {selectedEdge ? (
            /* Selected Socket Edge Inspector */
            <div className="space-y-4">
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-sky-400 font-bold block mb-1">
                  SOCKET CONNECTION INSPECTION
                </span>
                <h3 className="font-mono text-sm font-bold text-white break-all">
                  {selectedEdge.source} ↔ {selectedEdge.target}
                </h3>
                <span className="badge badge-info text-[10px] uppercase font-mono mt-1.5 inline-block">
                  {selectedEdge.protocol || 'TCP'} Session
                </span>
              </div>

              <div className="card p-3 space-y-2 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-dark-400">Endpoint 1:</span>
                  <span className="text-white font-bold">{selectedEdge.source}</span>
                </div>
                {selectedEdge.port1 && (
                  <div className="flex justify-between">
                    <span className="text-dark-400">Port 1:</span>
                    <span className="text-white">{selectedEdge.port1}</span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-dark-400">Endpoint 2:</span>
                  <span className="text-white font-bold">{selectedEdge.target}</span>
                </div>
                {selectedEdge.port2 && (
                  <div className="flex justify-between">
                    <span className="text-dark-400">Port 2:</span>
                    <span className="text-white">{selectedEdge.port2}</span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-dark-400">Packets Exchanged:</span>
                  <span className="text-white">{selectedEdge.packet_count?.toLocaleString() || 1}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-dark-400">Byte Volume:</span>
                  <span className="text-white font-bold">{formatBytes(selectedEdge.byte_count)}</span>
                </div>
                {selectedEdge.first_seen && (
                  <div className="flex justify-between">
                    <span className="text-dark-400">First Observed:</span>
                    <span className="text-slate-300 text-[11px]">
                      {new Date(selectedEdge.first_seen * 1000).toISOString().slice(11, 23)}
                    </span>
                  </div>
                )}
              </div>

              {/* Action Buttons for Selected Edge */}
              <div className="pt-2 border-t border-dark-800 space-y-2">
                <Link
                  to={`/packets/${analysisId}?ip=${selectedEdge.source}`}
                  className="btn btn-primary w-full text-xs py-1.5 flex items-center justify-center gap-1.5"
                >
                  <Package className="w-3.5 h-3.5" />
                  <span>Inspect Session Packets</span>
                </Link>
                <Link
                  to={`/timeline/${analysisId}?filter=${selectedEdge.source}`}
                  className="btn btn-secondary w-full text-xs py-1.5 flex items-center justify-center gap-1.5"
                >
                  <Clock className="w-3.5 h-3.5" />
                  <span>View Timeline for Pair</span>
                </Link>
              </div>
            </div>
          ) : selectedNode ? (
            /* Selected Node Inspector */
            <div className="space-y-4">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-dark-400 font-semibold">
                    {selectedNode.type ? selectedNode.type.toUpperCase() : 'HOST'} INSPECTION
                  </span>
                  <button
                    type="button"
                    onClick={() => togglePinHost(selectedNode.id)}
                    className={`p-1 rounded text-xs transition-colors ${
                      pinnedNodes.has(selectedNode.id)
                        ? 'text-amber-500 bg-amber-500/10'
                        : 'text-dark-400 hover:text-white'
                    }`}
                    title={pinnedNodes.has(selectedNode.id) ? 'Pinned to Workspace' : 'Pin to Workspace'}
                  >
                    <Pin className="w-3.5 h-3.5" />
                  </button>
                </div>

                <h3 className="font-mono text-sm font-bold text-white break-all">
                  {selectedNode.label}
                </h3>

                <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
                  {selectedNode.type === 'domain' ? (
                    <span className="badge badge-info text-[10px] flex items-center gap-1">
                      <Globe className="w-3 h-3" />
                      Domain
                    </span>
                  ) : selectedNode.type === 'finding' ? (
                    <span className={`badge badge-${selectedNode.severity || 'high'} text-[10px] uppercase font-bold`}>
                      {selectedNode.severity} Alert
                    </span>
                  ) : (
                    <>
                      {selectedNode.is_multicast ? (
                        <span className="badge text-[10px] flex items-center gap-1 bg-teal-950/80 text-teal-300 border border-teal-700/80">
                          <Radio className="w-3 h-3 text-teal-400" />
                          Multicast Group
                        </span>
                      ) : (
                        <span className={`badge ${selectedNode.is_internal ? 'badge-low' : 'badge-info'} text-[10px] flex items-center gap-1`}>
                          <Server className="w-3 h-3" />
                          {selectedNode.is_internal ? 'Internal Host' : 'External Host'}
                        </span>
                      )}
                      {selectedNode.is_ipv6 && (
                        <span className="badge text-[10px] flex items-center gap-1 bg-sky-950/60 text-sky-300 border border-sky-700/60 font-mono">
                          IPv6
                        </span>
                      )}
                    </>
                  )}
                </div>
              </div>

              {/* Host Details */}
              {(!selectedNode.type || selectedNode.type === 'host') && (
                <div className="card p-3 space-y-2 text-xs font-mono">
                  <div className="flex justify-between">
                    <span className="text-dark-400">Packets Sent:</span>
                    <span className="text-white">{selectedNode.packets_sent?.toLocaleString() || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-dark-400">Packets Recv:</span>
                    <span className="text-white">{selectedNode.packets_received?.toLocaleString() || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-dark-400">Total Volume:</span>
                    <span className="text-white font-bold">{formatBytes(selectedNode.total_bytes)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-dark-400">Detections:</span>
                    <span className={`font-bold ${selectedNode.findings_count > 0 ? 'text-rose-400' : 'text-dark-400'}`}>
                      {selectedNode.findings_count || 0}
                    </span>
                  </div>
                </div>
              )}

              {/* Domain Details */}
              {selectedNode.type === 'domain' && (
                <div className="card p-3 space-y-2 text-xs font-mono">
                  <div className="flex justify-between">
                    <span className="text-dark-400">Query Count:</span>
                    <span className="text-white font-bold">{selectedNode.query_count || 1}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-dark-400">Risk Assessment:</span>
                    <span className={`font-bold ${selectedNode.severity === 'high' ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {selectedNode.severity === 'high' ? 'Flagged / Suspicious' : 'Standard Baseline'}
                    </span>
                  </div>
                </div>
              )}

              {/* Finding Details */}
              {selectedNode.type === 'finding' && (
                <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded text-xs space-y-1.5 font-mono">
                  <div className="flex items-center gap-1.5 text-rose-400 font-semibold">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Security Detection</span>
                  </div>
                  <p className="text-dark-300 font-sans">
                    {selectedNode.description || 'Security anomaly detected on this host.'}
                  </p>
                </div>
              )}

              {/* Action Pivot Buttons for Selected Node */}
              <div className="pt-3 border-t border-dark-800 space-y-2">
                {(!selectedNode.type || selectedNode.type === 'host') && (
                  <>
                    <Link
                      to={`/packets/${analysisId}?ip=${selectedNode.id}`}
                      className="btn btn-primary w-full text-xs py-1.5 flex items-center justify-center gap-1.5"
                    >
                      <span>Inspect Packets for Host</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </Link>
                    <Link
                      to={`/storyline/${analysisId}?ip=${selectedNode.id}`}
                      className="btn btn-secondary w-full text-xs py-1.5 flex items-center justify-center gap-1.5"
                    >
                      <span>View in Storyline</span>
                    </Link>
                  </>
                )}

                {selectedNode.type === 'domain' && (
                  <Link
                    to={`/packets/${analysisId}?search=${encodeURIComponent(selectedNode.domain || selectedNode.label)}`}
                    className="btn btn-primary w-full text-xs py-1.5 flex items-center justify-center gap-1.5"
                  >
                    <span>Search Domain Traffic</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                )}

                {selectedNode.type === 'finding' && (
                  <Link
                    to={`/findings/${analysisId}`}
                    className="btn btn-primary w-full text-xs py-1.5 flex items-center justify-center gap-1.5"
                  >
                    <span>View Full Finding Details</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                )}
              </div>
            </div>
          ) : (
            <div className="text-center py-12 text-dark-500 text-xs font-mono">
              Select any host, domain, finding, or directional edge connection to view forensic telemetry.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
