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
  Activity,
  X,
  Network,
  Laptop,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  Minimize2,
  Cpu
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

// Generate SVG points string for regular hexagon
function getHexagonPoints(cx, cy, r) {
  const points = []
  for (let i = 0; i < 6; i++) {
    const angle = (Math.PI / 3) * i - Math.PI / 6
    points.push(`${Math.round(cx + r * Math.cos(angle))},${Math.round(cy + r * Math.sin(angle))}`)
  }
  return points.join(' ')
}

export default function NetworkGraph() {
  const { analysisId } = useParams()
  const navigate = useNavigate()
  const { mode, isFreeBird, isBlue, isRed, themeColors } = useMode()

  const [loading, setLoading] = useState(true)
  const [graphMode, setGraphMode] = useState('topology') // 'topology' | 'evidence'
  const [graphData, setGraphData] = useState({ nodes: [], edges: [], subnets: [] })
  const [positions, setPositions] = useState({})

  // Selection states (mutually coordinated)
  const [selectedNode, setSelectedNode] = useState(null)
  const [selectedEdge, setSelectedEdge] = useState(null)
  const [selectedSubnet, setSelectedSubnet] = useState(null)
  const [mobileInspectorOpen, setMobileInspectorOpen] = useState(false)

  // Floating hover tooltips state (coordinates & content)
  const [hoveredNode, setHoveredNode] = useState(null) // { node, x, y }
  const [hoveredEdge, setHoveredEdge] = useState(null) // { edge, x, y }

  // Subnet & Device Role filtering and collapse state
  const [subnetFilter, setSubnetFilter] = useState('')
  const [roleFilter, setRoleFilter] = useState('')
  const [collapsedSubnets, setCollapsedSubnets] = useState(new Set())

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

  // Group / Subnet Dragging state
  const [draggedGroupId, setDraggedGroupId] = useState(null)
  const groupDragStartMouseRef = useRef({ x: 0, y: 0 })
  const groupDragStartPositionsRef = useRef({})
  const hasDraggedGroupRef = useRef(false)

  useEffect(() => {
    loadGraph(false)
  }, [analysisId, graphMode])

  useEffect(() => {
    if (analysisId !== 'live') return
    const timer = setInterval(() => {
      if (document.hidden) return
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

      const data = response.data || { nodes: [], edges: [], subnets: [] }
      setGraphData(data)

      if (isIncremental) {
        updateIncrementalLayout(data.nodes, data.subnets || [])
      } else {
        computeInitialLayout(data.nodes, data.subnets || [])
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

  // Derive subnets if not present from backend response
  const availableSubnets = useMemo(() => {
    if (graphData.subnets && graphData.subnets.length > 0) {
      return graphData.subnets
    }
    const map = new Map()
    ;(graphData.nodes || []).forEach((n) => {
      const subId = n.subnet || (n.is_internal ? '192.168.1.0/24' : n.is_multicast ? '224.0.0.0/4' : 'public_wan')
      const subLabel = n.subnet_label || (n.is_internal ? 'Local Network (192.168.1.0/24)' : n.is_multicast ? 'Multicast Group' : 'External / Public WAN')
      if (!map.has(subId)) {
        map.set(subId, {
          id: subId,
          label: subLabel,
          category: n.subnet_category || (n.is_internal ? 'private' : n.is_multicast ? 'multicast' : 'public'),
          is_internal: !!n.is_internal,
          is_inferred_prefix: n.is_inferred_prefix ?? true,
          prefix_length: n.prefix_length ?? (n.is_internal ? 24 : null),
          host_count: 0,
          total_bytes: 0,
          hosts: [],
          gateway: null,
        })
      }
      const entry = map.get(subId)
      entry.host_count += 1
      entry.total_bytes += (n.total_bytes || 0)
      entry.hosts.push(n.id)
      if (n.device_role === 'gateway') entry.gateway = n.id
    })
    return Array.from(map.values())
  }, [graphData])

  const toggleCollapseSubnet = (subnetId) => {
    setCollapsedSubnets((prev) => {
      const next = new Set(prev)
      if (next.has(subnetId)) {
        next.delete(subnetId)
      } else {
        next.add(subnetId)
      }
      return next
    })
  }

  const updateIncrementalLayout = (nodes, subnets = []) => {
    setPositions((prev) => {
      const unplaced = nodes.filter((n) => !prev[n.id])
      if (unplaced.length === 0) return prev
      const allPos = calculateStaticPositions(nodes, subnets)
      const nextPos = { ...prev }
      unplaced.forEach((n) => {
        if (allPos[n.id]) {
          const subId = n.subnet
          const siblingIds = nodes
            .filter(
              (sibling) =>
                sibling.id !== n.id &&
                (sibling.subnet === subId || (sibling.hosts && sibling.hosts.includes(sibling.id)))
            )
            .map((s) => s.id)
            .filter((id) => prev[id])

          if (siblingIds.length > 0) {
            let curSumX = 0, curSumY = 0
            siblingIds.forEach((id) => {
              curSumX += prev[id].x
              curSumY += prev[id].y
            })
            const curCenterX = curSumX / siblingIds.length
            const curCenterY = curSumY / siblingIds.length

            let staticSumX = 0, staticSumY = 0
            siblingIds.forEach((id) => {
              staticSumX += allPos[id]?.x || curCenterX
              staticSumY += allPos[id]?.y || curCenterY
            })
            const staticCenterX = staticSumX / siblingIds.length
            const staticCenterY = staticSumY / siblingIds.length

            const offsetX = curCenterX - staticCenterX
            const offsetY = curCenterY - staticCenterY
            nextPos[n.id] = {
              x: Math.round(allPos[n.id].x + offsetX),
              y: Math.round(allPos[n.id].y + offsetY),
            }
          } else {
            nextPos[n.id] = allPos[n.id]
          }
        }
      })
      return nextPos
    })
  }

  // Calculate stable static initial positions clustering by subnet bays
  const calculateStaticPositions = (nodes, subnets = []) => {
    const width = 960
    const height = 660
    const centerX = width / 2
    const centerY = height / 2
    const initialPositions = {}

    if (graphMode === 'evidence') {
      const hosts = nodes.filter((n) => n.type === 'host' || !n.type)
      const domains = nodes.filter((n) => n.type === 'domain')
      const findings = nodes.filter((n) => n.type === 'finding')

      // Inner ring: Hosts
      hosts.forEach((node, i) => {
        const radius = hosts.length > 8 ? (i % 2 === 0 ? 140 : 185) : 150
        const angle = (2 * Math.PI * i) / (hosts.length || 1)
        initialPositions[node.id] = {
          x: Math.round(centerX + radius * Math.cos(angle)),
          y: Math.round(centerY + radius * Math.sin(angle)),
        }
      })

      // Outer ring: Domains
      domains.forEach((node, i) => {
        const radius = domains.length > 10 ? (i % 2 === 0 ? 255 : 305) : 265
        const angle = (2 * Math.PI * i) / (domains.length || 1) + 0.3
        initialPositions[node.id] = {
          x: Math.round(centerX + radius * Math.cos(angle)),
          y: Math.round(centerY + radius * Math.sin(angle)),
        }
      })

      // Top arc: Findings
      const findingRadius = 265
      findings.forEach((node, i) => {
        const angle = Math.PI + ((i + 0.5) * Math.PI) / (findings.length || 1)
        initialPositions[node.id] = {
          x: Math.round(centerX + findingRadius * Math.cos(angle)),
          y: Math.round(centerY + (findingRadius * 0.7) * Math.sin(angle)),
        }
      })
    } else {
      // Subnet Cluster Topology Layout
      const subs = subnets.length > 0 ? subnets : availableSubnets
      const internalSubnets = subs.filter((s) => s.is_internal && s.category !== 'multicast' && s.category !== 'loopback')
      const externalSubnets = subs.filter((s) => !s.is_internal)
      const multicastSubnets = subs.filter((s) => s.category === 'multicast')

      // 1. Position Internal Subnets in dedicated left/center clusters
      const numInt = internalSubnets.length || 1
      internalSubnets.forEach((sub, sIdx) => {
        const subCenterY = centerY + (sIdx - (numInt - 1) / 2) * 230
        const subCenterX = numInt > 1 ? 230 + (sIdx % 2) * 160 : 280
        const subNodes = nodes.filter((n) => n.subnet === sub.id || (sub.hosts && sub.hosts.includes(n.id)))

        // Position cluster capsule proxy
        initialPositions[`subnet_cluster:${sub.id}`] = {
          x: subCenterX,
          y: subCenterY,
        }

        // Identify Gateway node vs clients/servers
        const gwNode = subNodes.find((n) => n.device_role === 'gateway' || n.id === sub.gateway)
        const nonGwNodes = subNodes.filter((n) => n !== gwNode)

        if (gwNode) {
          initialPositions[gwNode.id] = {
            x: subCenterX,
            y: subCenterY - (nonGwNodes.length > 0 ? 55 : 0),
          }
        }

        nonGwNodes.forEach((node, idx) => {
          const r = nonGwNodes.length > 5 ? (idx % 2 === 0 ? 80 : 115) : 80
          const angle = (2 * Math.PI * idx) / (nonGwNodes.length || 1) + (gwNode ? 0.3 : 0)
          initialPositions[node.id] = {
            x: Math.round(subCenterX + r * Math.cos(angle)),
            y: Math.round(subCenterY + (gwNode ? 20 : 0) + r * Math.sin(angle)),
          }
        })
      })

      // 2. Position External / Public WAN Subnets on the Right Arc
      const extNodes = nodes.filter((n) => !n.is_internal && !n.is_multicast)
      const extCenterX = 680
      const extCenterY = centerY
      externalSubnets.forEach((sub) => {
        initialPositions[`subnet_cluster:${sub.id}`] = {
          x: extCenterX,
          y: extCenterY,
        }
      })
      extNodes.forEach((node, idx) => {
        const tier = idx % 3
        const r = 160 + tier * 50
        const angle = -Math.PI * 0.45 + (idx * 0.35)
        initialPositions[node.id] = {
          x: Math.round(extCenterX + r * Math.cos(angle)),
          y: Math.round(extCenterY + r * Math.sin(angle)),
        }
      })

      // 3. Position Multicast in Lower Arc
      const mcastNodes = nodes.filter((n) => n.is_multicast)
      multicastSubnets.forEach((sub) => {
        initialPositions[`subnet_cluster:${sub.id}`] = {
          x: centerX,
          y: height - 100,
        }
      })
      mcastNodes.forEach((node, idx) => {
        const angle = Math.PI * 0.5 + ((idx - (mcastNodes.length - 1) / 2) * 0.4)
        const r = 240
        initialPositions[node.id] = {
          x: Math.round(centerX + r * Math.cos(angle)),
          y: Math.round(centerY + 80 + r * Math.sin(angle) * 0.6),
        }
      })

      // Catch-all for any unplaced nodes
      nodes.forEach((n, idx) => {
        if (!initialPositions[n.id]) {
          const angle = (2 * Math.PI * idx) / nodes.length
          initialPositions[n.id] = {
            x: Math.round(centerX + 180 * Math.cos(angle)),
            y: Math.round(centerY + 180 * Math.sin(angle)),
          }
        }
      })
    }

    // Deterministic relaxation loop (20 iterations) to avoid overlaps
    const nodeIds = Object.keys(initialPositions)
    const minDistance = 74
    for (let iter = 0; iter < 20; iter++) {
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

  // Persist custom user-dragged node and group coordinates
  const persistCustomPositions = (newPositions) => {
    try {
      const storageKey = `beacon_workspace_${analysisId}`
      const saved = localStorage.getItem(storageKey)
      const data = saved ? JSON.parse(saved) : { pinned_hosts: [], pinned_findings: [], notes: '' }
      data.custom_positions = { ...(data.custom_positions || {}), ...newPositions }
      localStorage.setItem(storageKey, JSON.stringify(data))
    } catch (e) {
      console.error('Failed to save custom positions:', e)
    }
  }

  // Reset custom layout positions and restore default static layout
  const handleResetLayout = () => {
    try {
      const storageKey = `beacon_workspace_${analysisId}`
      const saved = localStorage.getItem(storageKey)
      if (saved) {
        const data = JSON.parse(saved)
        delete data.custom_positions
        localStorage.setItem(storageKey, JSON.stringify(data))
      }
    } catch (e) {
      // ignore
    }
    loadGraph(false)
  }

  const computeInitialLayout = (nodes, subnets = []) => {
    const width = 960
    const height = 660
    const staticPositions = calculateStaticPositions(nodes, subnets)

    // Load any saved custom positions from workspace storage
    let customPositions = {}
    try {
      const saved = localStorage.getItem(`beacon_workspace_${analysisId}`)
      if (saved) {
        const parsed = JSON.parse(saved)
        if (parsed.custom_positions && typeof parsed.custom_positions === 'object') {
          customPositions = parsed.custom_positions
        }
      }
    } catch (e) {
      // ignore
    }

    const initialPositions = { ...staticPositions, ...customPositions }
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
    const viewW = 960
    const viewH = 660

    const scale = Math.min(1.4, Math.max(0.4, Math.min(viewW / graphW, viewH / graphH)))
    const midX = (minX + maxX) / 2
    const midY = (minY + maxY) / 2

    setZoom(scale)
    setPan({
      x: Math.round(viewW / 2 - midX * scale),
      y: Math.round(viewH / 2 - midY * scale),
    })
  }

  // Select node and smoothly focus
  const handleSelectNode = (node) => {
    if (hasDraggedRef.current || hasDraggedGroupRef.current) return
    setSelectedNode(node)
    setSelectedEdge(null)
    setSelectedSubnet(null)
    setMobileInspectorOpen(true)

    const pos = positions[node.id]
    if (pos) {
      const targetZoom = Math.max(zoom, 1.25)
      setZoom(targetZoom)
      setPan({
        x: Math.round(480 - pos.x * targetZoom),
        y: Math.round(330 - pos.y * targetZoom),
      })
    }
  }

  // Filter nodes & edges, accounting for collapsed subnets
  const filteredData = useMemo(() => {
    let nodes = graphData.nodes

    if (internalOnly && graphMode === 'topology') {
      nodes = nodes.filter((n) => n.is_internal)
    }

    if (subnetFilter && graphMode === 'topology') {
      nodes = nodes.filter((n) => n.subnet === subnetFilter)
    }

    if (roleFilter && graphMode === 'topology') {
      if (roleFilter === 'gateway') {
        nodes = nodes.filter((n) => n.device_role === 'gateway')
      } else if (roleFilter === 'server') {
        nodes = nodes.filter((n) => ['server', 'web_server', 'dns_server'].includes(n.device_role))
      } else if (roleFilter === 'workstation') {
        nodes = nodes.filter((n) => n.device_role === 'workstation')
      } else if (roleFilter === 'external') {
        nodes = nodes.filter((n) => n.device_role === 'external' || !n.is_internal)
      } else if (roleFilter === 'multicast') {
        nodes = nodes.filter((n) => n.is_multicast || n.device_role === 'multicast')
      }
    }

    if (findingsOnly) {
      nodes = nodes.filter(
        (n) => (n.findings_count && n.findings_count > 0) || n.type === 'finding' || n.severity === 'critical' || n.severity === 'high'
      )
    }

    // Handle Collapsed Subnets:
    // If a subnet is collapsed, hide its member nodes and insert a proxy cluster node
    const finalNodes = []
    const hostToClusterMap = new Map()

    if (graphMode === 'topology' && collapsedSubnets.size > 0) {
      availableSubnets.forEach((sub) => {
        if (collapsedSubnets.has(sub.id)) {
          finalNodes.push({
            id: `subnet_cluster:${sub.id}`,
            label: `${sub.label} (${sub.host_count} hosts)`,
            subnet_id: sub.id,
            type: 'subnet_cluster',
            is_collapsed: true,
            host_count: sub.host_count,
            total_bytes: sub.total_bytes,
            is_internal: sub.is_internal,
            category: sub.category,
            gateway: sub.gateway,
            hosts: sub.hosts,
          })
          ;(sub.hosts || []).forEach((h) => {
            hostToClusterMap.set(h, `subnet_cluster:${sub.id}`)
          })
        }
      })

      nodes.forEach((n) => {
        if (!hostToClusterMap.has(n.id)) {
          finalNodes.push(n)
        }
      })
    } else {
      nodes.forEach((n) => finalNodes.push(n))
    }

    const nodeIds = new Set(finalNodes.map((n) => n.id))

    // Process Edges (reroute to cluster proxy if endpoint is collapsed)
    let edges = []
    const seenEdges = new Set()

    graphData.edges.forEach((e) => {
      let s = hostToClusterMap.get(e.source) || e.source
      let t = hostToClusterMap.get(e.target) || e.target

      // Avoid self-loop inside collapsed cluster
      if (s === t) return

      if (nodeIds.has(s) && nodeIds.has(t)) {
        const edgeKey = `${s}_${t}_${e.protocol}`
        if (!seenEdges.has(edgeKey)) {
          seenEdges.add(edgeKey)
          edges.push({
            ...e,
            source: s,
            target: t,
          })
        }
      }
    })

    if (protocolFilter) {
      edges = edges.filter((e) => (e.protocol || '').toLowerCase() === protocolFilter.toLowerCase())
    }

    if (timeFilter !== 'all' && edges.length > 0) {
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

    return { nodes: finalNodes, edges }
  }, [graphData, internalOnly, subnetFilter, roleFilter, findingsOnly, collapsedSubnets, protocolFilter, timeFilter, graphMode, availableSubnets])

  // Direct neighbors for 1-Hop focus
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

  const handleGroupMouseDown = (e, sub) => {
    e.stopPropagation()
    setDraggedGroupId(sub.id)
    groupDragStartMouseRef.current = { x: e.clientX, y: e.clientY }
    hasDraggedGroupRef.current = false

    // Snapshot starting positions of all member nodes and cluster proxy
    const startPositions = {}
    const memberNodes = (graphData.nodes || []).filter(
      (n) => n.subnet === sub.id || (sub.hosts && sub.hosts.includes(n.id))
    )
    memberNodes.forEach((n) => {
      if (positions[n.id]) {
        startPositions[n.id] = { ...positions[n.id] }
      }
    })
    ;(sub.hosts || []).forEach((hId) => {
      if (positions[hId] && !startPositions[hId]) {
        startPositions[hId] = { ...positions[hId] }
      }
    })
    const clusterProxyId = `subnet_cluster:${sub.id}`
    if (positions[clusterProxyId]) {
      startPositions[clusterProxyId] = { ...positions[clusterProxyId] }
    }

    groupDragStartPositionsRef.current = startPositions
  }

  const handleGroupTouchStart = (e, sub) => {
    if (e.touches.length === 1) {
      e.stopPropagation()
      setDraggedGroupId(sub.id)
      const touch = e.touches[0]
      groupDragStartMouseRef.current = { x: touch.clientX, y: touch.clientY }
      hasDraggedGroupRef.current = false

      const startPositions = {}
      const memberNodes = (graphData.nodes || []).filter(
        (n) => n.subnet === sub.id || (sub.hosts && sub.hosts.includes(n.id))
      )
      memberNodes.forEach((n) => {
        if (positions[n.id]) {
          startPositions[n.id] = { ...positions[n.id] }
        }
      })
      ;(sub.hosts || []).forEach((hId) => {
        if (positions[hId] && !startPositions[hId]) {
          startPositions[hId] = { ...positions[hId] }
        }
      })
      const clusterProxyId = `subnet_cluster:${sub.id}`
      if (positions[clusterProxyId]) {
        startPositions[clusterProxyId] = { ...positions[clusterProxyId] }
      }

      groupDragStartPositionsRef.current = startPositions
    }
  }

  const handleNodeMouseDown = (e, node) => {
    e.stopPropagation()
    setDraggedNodeId(node.id)
    dragStartRef.current = { x: e.clientX, y: e.clientY }
    hasDraggedRef.current = false
  }

  const handleNodeTouchStart = (e, node) => {
    if (e.touches.length === 1) {
      e.stopPropagation()
      setDraggedNodeId(node.id)
      const touch = e.touches[0]
      dragStartRef.current = { x: touch.clientX, y: touch.clientY }
      hasDraggedRef.current = false
    }
  }

  const handleMouseMove = (e) => {
    if (isPanning) {
      setPan({
        x: e.clientX - panStartRef.current.x,
        y: e.clientY - panStartRef.current.y,
      })
    } else if (draggedNodeId) {
      const deltaX = Math.abs(e.clientX - dragStartRef.current.x)
      const deltaY = Math.abs(e.clientY - dragStartRef.current.y)
      if (deltaX > 3 || deltaY > 3) {
        hasDraggedRef.current = true
      }
      const svg = svgRef.current
      if (!svg) return

      const rect = svg.getBoundingClientRect()
      const clientX = e.clientX - rect.left
      const clientY = e.clientY - rect.top

      const graphX = Math.round((clientX - pan.x) / zoom)
      const graphY = Math.round((clientY - pan.y) / zoom)

      setPositions((prev) => ({
        ...prev,
        [draggedNodeId]: { x: graphX, y: graphY },
      }))
    } else if (draggedGroupId) {
      const deltaScreenX = e.clientX - groupDragStartMouseRef.current.x
      const deltaScreenY = e.clientY - groupDragStartMouseRef.current.y

      if (Math.hypot(deltaScreenX, deltaScreenY) > 3) {
        hasDraggedGroupRef.current = true
      }

      const deltaGraphX = Math.round(deltaScreenX / zoom)
      const deltaGraphY = Math.round(deltaScreenY / zoom)

      const startPosMap = groupDragStartPositionsRef.current
      setPositions((prev) => {
        const next = { ...prev }
        Object.keys(startPosMap).forEach((id) => {
          next[id] = {
            x: startPosMap[id].x + deltaGraphX,
            y: startPosMap[id].y + deltaGraphY,
          }
        })
        return next
      })
    }
  }

  const handleMouseUp = () => {
    setIsPanning(false)

    if (draggedNodeId && hasDraggedRef.current) {
      setPositions((current) => {
        if (current[draggedNodeId]) {
          persistCustomPositions({ [draggedNodeId]: current[draggedNodeId] })
        }
        return current
      })
    }

    if (draggedGroupId) {
      if (hasDraggedGroupRef.current) {
        setPositions((current) => {
          const toSave = {}
          Object.keys(groupDragStartPositionsRef.current).forEach((id) => {
            if (current[id]) toSave[id] = current[id]
          })
          persistCustomPositions(toSave)
          return current
        })
      } else {
        const sub = availableSubnets.find((s) => s.id === draggedGroupId)
        if (sub) {
          setSelectedSubnet(sub)
          setSelectedNode(null)
          setSelectedEdge(null)
          setMobileInspectorOpen(true)
        }
      }
    }

    setDraggedNodeId(null)
    setDraggedGroupId(null)
    setTimeout(() => {
      hasDraggedRef.current = false
      hasDraggedGroupRef.current = false
    }, 50)
  }

  // Touch Support
  const handleTouchStart = (e) => {
    if (e.touches.length === 1) {
      setIsPanning(true)
      const touch = e.touches[0]
      panStartRef.current = { x: touch.clientX - pan.x, y: touch.clientY - pan.y }
    }
  }

  const handleTouchMove = (e) => {
    if (isPanning && e.touches.length === 1) {
      const touch = e.touches[0]
      setPan({
        x: touch.clientX - panStartRef.current.x,
        y: touch.clientY - panStartRef.current.y,
      })
    } else if (draggedNodeId && e.touches.length === 1) {
      const touch = e.touches[0]
      const deltaX = Math.abs(touch.clientX - dragStartRef.current.x)
      const deltaY = Math.abs(touch.clientY - dragStartRef.current.y)
      if (deltaX > 3 || deltaY > 3) {
        hasDraggedRef.current = true
      }
      const svg = svgRef.current
      if (!svg) return

      const rect = svg.getBoundingClientRect()
      const clientX = touch.clientX - rect.left
      const clientY = touch.clientY - rect.top

      const graphX = Math.round((clientX - pan.x) / zoom)
      const graphY = Math.round((clientY - pan.y) / zoom)

      setPositions((prev) => ({
        ...prev,
        [draggedNodeId]: { x: graphX, y: graphY },
      }))
    } else if (draggedGroupId && e.touches.length === 1) {
      const touch = e.touches[0]
      const deltaScreenX = touch.clientX - groupDragStartMouseRef.current.x
      const deltaScreenY = touch.clientY - groupDragStartMouseRef.current.y

      if (Math.hypot(deltaScreenX, deltaScreenY) > 3) {
        hasDraggedGroupRef.current = true
      }

      const deltaGraphX = Math.round(deltaScreenX / zoom)
      const deltaGraphY = Math.round(deltaScreenY / zoom)

      const startPosMap = groupDragStartPositionsRef.current
      setPositions((prev) => {
        const next = { ...prev }
        Object.keys(startPosMap).forEach((id) => {
          next[id] = {
            x: startPosMap[id].x + deltaGraphX,
            y: startPosMap[id].y + deltaGraphY,
          }
        })
        return next
      })
    }
  }

  // Node Hover Tooltip
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

  // Edge Hover Tooltip
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

  // Node Base Color honoring Blue, Red, and Free Bird modes
  const getNodeColor = (node) => {
    if (node.type === 'subnet_cluster') {
      return node.is_internal ? '#0369a1' : '#334155'
    }
    if (node.type === 'domain') {
      return '#06b6d4'
    }
    if (node.type === 'finding') {
      if (node.severity === 'critical') return '#ef4444'
      if (node.severity === 'high') return '#f43f5e'
      return '#eab308'
    }

    if (node.device_role === 'gateway') {
      return isRed ? '#f43f5e' : '#0284c7'
    }

    if (node.is_multicast) {
      return '#0d9488'
    }

    if (isFreeBird) {
      return node.is_internal ? '#38bdf8' : '#0284c7'
    }
    if (isRed) {
      return node.is_internal ? '#f43f5e' : '#78716c'
    }
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
        subnets: availableSubnets,
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
                {graphMode === 'evidence' ? 'Investigation Evidence Graph' : 'Forensic Network Map & Subnets'}
              </h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-dark-900 border-slate-700/80 text-dark-300">
                {filteredData.nodes.length} nodes • {filteredData.edges.length} links • {availableSubnets.length} subnets
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
                  Topology & Subnets
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

              {/* Subnet Selector (when in Topology mode) */}
              {graphMode === 'topology' && (
                <select
                  value={subnetFilter}
                  onChange={(e) => setSubnetFilter(e.target.value)}
                  className="py-1 px-2 text-xs bg-dark-900 border border-slate-700/80 rounded-md text-white font-mono focus:outline-none"
                  title="Filter by network segment / subnet"
                >
                  <option value="">All Subnets ({availableSubnets.length})</option>
                  {availableSubnets.map((sub) => (
                    <option key={sub.id} value={sub.id}>
                      {sub.label} ({sub.host_count})
                    </option>
                  ))}
                </select>
              )}

              {/* Device Role Selector (when in Topology mode) */}
              {graphMode === 'topology' && (
                <select
                  value={roleFilter}
                  onChange={(e) => setRoleFilter(e.target.value)}
                  className="py-1 px-2 text-xs bg-dark-900 border border-slate-700/80 rounded-md text-white font-mono focus:outline-none"
                  title="Filter by device role / classification"
                >
                  <option value="">All Roles</option>
                  <option value="gateway">Gateways / Routers [GW]</option>
                  <option value="server">Servers / Services [SRV]</option>
                  <option value="workstation">Workstations / Clients [CLI]</option>
                  <option value="external">External Endpoints [EXT]</option>
                  <option value="multicast">Multicast Groups [MC]</option>
                </select>
              )}

              {/* Search Filter */}
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-dark-400" />
                <input
                  type="text"
                  placeholder="Filter host/IP/domain..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="input pl-8 pr-2.5 py-1 text-xs w-36 font-mono"
                />
              </div>

              {/* Protocol Selector */}
              <select
                value={protocolFilter}
                onChange={(e) => setProtocolFilter(e.target.value)}
                className="py-1 px-2 text-xs bg-dark-900 border border-slate-700/80 rounded-md text-white font-mono focus:outline-none"
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
                className="py-1 px-2 text-xs bg-dark-900 border border-slate-700/80 rounded-md text-white font-mono focus:outline-none"
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
                  <span>1-Hop</span>
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
                onClick={handleResetLayout}
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
                <span className="text-xs font-mono text-dark-400">Rendering forensic map & subnets...</span>
              </div>
            ) : filteredData.nodes.length === 0 ? (
              <div className="text-dark-400 text-xs font-mono p-8 text-center">
                No communicating entities found with active filter criteria.
              </div>
            ) : (
              <svg
                ref={svgRef}
                viewBox="0 0 960 660"
                className="w-full h-full select-none cursor-grab active:cursor-grabbing touch-none"
                onMouseDown={handleSvgMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={handleMouseUp}
                onTouchStart={handleTouchStart}
                onTouchMove={handleTouchMove}
                onTouchEnd={handleMouseUp}
                onTouchCancel={handleMouseUp}
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
                  {/* Subnet Container Boundary Boxes (rendered in Topology mode for expanded subnets) */}
                  {graphMode === 'topology' &&
                    availableSubnets.map((sub) => {
                      if (collapsedSubnets.has(sub.id)) return null
                      const memberNodes = filteredData.nodes.filter(
                        (n) => n.type !== 'subnet_cluster' && (n.subnet === sub.id || (sub.hosts && sub.hosts.includes(n.id)))
                      )
                      if (memberNodes.length === 0) return null

                      let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity
                      let hasValidCoords = false
                      memberNodes.forEach((n) => {
                        const p = positions[n.id]
                        if (p) {
                          hasValidCoords = true
                          if (p.x < minX) minX = p.x
                          if (p.x > maxX) maxX = p.x
                          if (p.y < minY) minY = p.y
                          if (p.y > maxY) maxY = p.y
                        }
                      })

                      if (!hasValidCoords) return null

                      const boxPadX = 46
                      const boxPadY = 44
                      const bX = minX - boxPadX
                      const bY = minY - boxPadY - 14
                      const bW = Math.max(160, maxX - minX + boxPadX * 2)
                      const bH = Math.max(90, maxY - minY + boxPadY * 2 + 14)

                      const isSelectedSub = selectedSubnet && selectedSubnet.id === sub.id
                      const isDraggedSub = draggedGroupId === sub.id

                      return (
                        <g key={`subnet-box-${sub.id}`} className="subnet-container">
                          {/* Subnet Enclosure Rectangle */}
                          <rect
                            x={bX}
                            y={bY}
                            width={bW}
                            height={bH}
                            rx={14}
                            fill={sub.is_internal ? 'rgba(15, 23, 42, 0.45)' : 'rgba(2, 6, 23, 0.35)'}
                            stroke={
                              isDraggedSub
                                ? (isRed ? '#f43f5e' : '#38bdf8')
                                : isSelectedSub
                                ? '#38bdf8'
                                : sub.is_internal
                                ? (isFreeBird ? '#0284c7' : isRed ? '#f43f5e' : '#1e3a8a')
                                : '#334155'
                            }
                            strokeWidth={isDraggedSub ? 2.4 : isSelectedSub ? 2 : 1.2}
                            strokeDasharray={isDraggedSub ? '6 3' : sub.is_internal ? undefined : '6 4'}
                            strokeOpacity={isDraggedSub ? 1 : 0.8}
                            pointerEvents="stroke"
                            className="cursor-grab active:cursor-grabbing"
                            onMouseDown={(e) => handleGroupMouseDown(e, sub)}
                            onTouchStart={(e) => handleGroupTouchStart(e, sub)}
                          />

                          {/* Subnet Header Banner */}
                          <g transform={`translate(${bX + 10}, ${bY + 8})`}>
                            {/* Banner Pill Container */}
                            <rect
                              x={0}
                              y={0}
                              width={Math.min(bW - 20, 280)}
                              height={22}
                              rx={5}
                              fill={isDraggedSub ? '#0f1d38' : '#0b1120'}
                              stroke={isDraggedSub ? (isRed ? '#f43f5e' : '#38bdf8') : isSelectedSub ? '#38bdf8' : '#1e293b'}
                              strokeWidth={isDraggedSub || isSelectedSub ? 1.5 : 1}
                              className="cursor-grab active:cursor-grabbing hover:stroke-sky-500 transition-colors"
                              onMouseDown={(e) => handleGroupMouseDown(e, sub)}
                              onTouchStart={(e) => handleGroupTouchStart(e, sub)}
                              onClick={() => {
                                if (!hasDraggedGroupRef.current) {
                                  setSelectedSubnet(sub)
                                  setSelectedNode(null)
                                  setSelectedEdge(null)
                                  setMobileInspectorOpen(true)
                                }
                              }}
                            />

                            {/* 6-dot Drag Grip Handle */}
                            <g
                              className="cursor-grab active:cursor-grabbing"
                              onMouseDown={(e) => handleGroupMouseDown(e, sub)}
                              onTouchStart={(e) => handleGroupTouchStart(e, sub)}
                            >
                              <circle cx={7} cy={7} r={1} fill={isDraggedSub ? '#38bdf8' : '#64748b'} />
                              <circle cx={7} cy={11} r={1} fill={isDraggedSub ? '#38bdf8' : '#64748b'} />
                              <circle cx={7} cy={15} r={1} fill={isDraggedSub ? '#38bdf8' : '#64748b'} />
                              <circle cx={11} cy={7} r={1} fill={isDraggedSub ? '#38bdf8' : '#64748b'} />
                              <circle cx={11} cy={11} r={1} fill={isDraggedSub ? '#38bdf8' : '#64748b'} />
                              <circle cx={11} cy={15} r={1} fill={isDraggedSub ? '#38bdf8' : '#64748b'} />
                            </g>

                            <text x={18} y={15} fill="#38bdf8" fontSize={10} fontFamily="monospace" fontWeight="bold" pointerEvents="none">
                              ⌗
                            </text>

                            <text
                              x={30}
                              y={15}
                              fill="#f8fafc"
                              fontSize={9.5}
                              fontFamily="monospace"
                              fontWeight="bold"
                              className="select-none pointer-events-none"
                            >
                              {sub.label.length > 24 ? sub.label.slice(0, 22) + '…' : sub.label}
                            </text>

                            {/* Host Count Badge */}
                            <rect
                              x={Math.min(bW - 20, 280) - 56}
                              y={3}
                              width={30}
                              height={16}
                              rx={3}
                              fill="#1e293b"
                              pointerEvents="none"
                            />
                            <text
                              x={Math.min(bW - 20, 280) - 41}
                              y={14}
                              fill="#94a3b8"
                              fontSize={8.5}
                              fontFamily="monospace"
                              fontWeight="bold"
                              textAnchor="middle"
                              pointerEvents="none"
                            >
                              {memberNodes.length}h
                            </text>

                            {/* Collapse Toggle Button */}
                            <rect
                              x={Math.min(bW - 20, 280) - 22}
                              y={3}
                              width={16}
                              height={16}
                              rx={3}
                              fill="#0f172a"
                              stroke="#334155"
                              strokeWidth={1}
                              className="cursor-pointer hover:fill-slate-800"
                              onMouseDown={(e) => e.stopPropagation()}
                              onTouchStart={(e) => e.stopPropagation()}
                              onClick={(e) => {
                                e.stopPropagation()
                                toggleCollapseSubnet(sub.id)
                              }}
                            />
                            <text
                              x={Math.min(bW - 20, 280) - 14}
                              y={14}
                              fill="#38bdf8"
                              fontSize={11}
                              fontFamily="monospace"
                              fontWeight="bold"
                              textAnchor="middle"
                              className="cursor-pointer select-none"
                              onMouseDown={(e) => e.stopPropagation()}
                              onTouchStart={(e) => e.stopPropagation()}
                              onClick={(e) => {
                                e.stopPropagation()
                                toggleCollapseSubnet(sub.id)
                              }}
                            >
                              −
                            </text>
                          </g>
                        </g>
                      )
                    })}

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
                        {/* Invisible Wide Hit-Target for Edge Hover & Selection */}
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
                            setSelectedSubnet(null)
                            setMobileInspectorOpen(true)
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

                    // 1. Collapsed Subnet Cluster Capsule Node
                    if (node.type === 'subnet_cluster') {
                      const isDraggedCluster = draggedGroupId === node.subnet_id
                      return (
                        <g
                          key={node.id}
                          transform={`translate(${pos.x}, ${pos.y})`}
                          className="cursor-grab active:cursor-grabbing"
                          onMouseDown={(e) => {
                            const sub = availableSubnets.find((s) => s.id === node.subnet_id)
                            if (sub) handleGroupMouseDown(e, sub)
                          }}
                          onTouchStart={(e) => {
                            const sub = availableSubnets.find((s) => s.id === node.subnet_id)
                            if (sub) handleGroupTouchStart(e, sub)
                          }}
                          onClick={() => {
                            if (!hasDraggedGroupRef.current) {
                              toggleCollapseSubnet(node.subnet_id)
                            }
                          }}
                        >
                          <rect
                            x={-75}
                            y={-22}
                            width={150}
                            height={44}
                            rx={8}
                            fill={isDraggedCluster ? '#0f1d38' : '#0b1329'}
                            stroke={isDraggedCluster ? (isRed ? '#f43f5e' : '#38bdf8') : node.is_internal ? '#0284c7' : '#475569'}
                            strokeWidth={isDraggedCluster ? 2.4 : 2}
                            strokeDasharray={isDraggedCluster ? '6 3' : node.is_internal ? undefined : '4 2'}
                            className="hover:stroke-sky-400 transition-colors shadow-lg"
                          />
                          {/* 6-dot Drag Handle on Left of Capsule */}
                          <g opacity={0.6}>
                            <circle cx={-66} cy={-5} r={1} fill={isDraggedCluster ? '#38bdf8' : '#64748b'} />
                            <circle cx={-66} cy={0} r={1} fill={isDraggedCluster ? '#38bdf8' : '#64748b'} />
                            <circle cx={-66} cy={5} r={1} fill={isDraggedCluster ? '#38bdf8' : '#64748b'} />
                            <circle cx={-62} cy={-5} r={1} fill={isDraggedCluster ? '#38bdf8' : '#64748b'} />
                            <circle cx={-62} cy={0} r={1} fill={isDraggedCluster ? '#38bdf8' : '#64748b'} />
                            <circle cx={-62} cy={5} r={1} fill={isDraggedCluster ? '#38bdf8' : '#64748b'} />
                          </g>
                          <text x={-54} y={-3} fill="#38bdf8" fontSize={11} fontFamily="monospace" fontWeight="bold">
                            ⌗ {node.subnet_id}
                          </text>
                          <text x={-54} y={13} fill="#94a3b8" fontSize={9} fontFamily="monospace">
                            {node.host_count} hosts • Click to Expand [+]
                          </text>
                        </g>
                      )
                    }

                    // 2. Standard Individual Entity Nodes
                    const isSelected = selectedNode && selectedNode.id === node.id
                    const isHovered = hoveredNode && hoveredNode.node.id === node.id
                    const isMatch = searchQuery && node.label.toLowerCase().includes(searchQuery.toLowerCase())
                    const isPinned = pinnedNodes.has(node.id)

                    let isDimmed = false
                    if (neighborhoodFocus && selectedNode) {
                      isDimmed = !directNeighborIds.has(node.id)
                    }

                    const nodeColor = getNodeColor(node)
                    let radius = 14
                    if (node.type === 'finding') radius = 13
                    else if (node.type === 'domain') radius = 13
                    else if (node.device_role === 'gateway') radius = 17
                    else {
                      radius = Math.min(20, Math.max(13, Math.log10(node.total_bytes || 10) * 3.1))
                    }

                    return (
                      <g
                        key={node.id}
                        className="cursor-pointer"
                        opacity={isDimmed ? 0.12 : 1}
                        style={{ transition: 'opacity 0.2s ease' }}
                      >
                        {/* Outer Selection / Match Halo */}
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

                        {/* Finding Warning Beacon Halo (Only when evidence findings exist) */}
                        {node.findings_count > 0 && (
                          <circle
                            cx={pos.x}
                            cy={pos.y}
                            r={radius + 4}
                            fill="none"
                            stroke="#f43f5e"
                            strokeWidth={1.8}
                            strokeDasharray="3 2"
                            opacity={0.9}
                            pointerEvents="none"
                          />
                        )}

                        {/* Distinct Shape Geometry by Device Role */}
                        {node.device_role === 'gateway' ? (
                          /* Hexagon for Default Gateways & Routers */
                          <polygon
                            points={getHexagonPoints(pos.x, pos.y, radius + 2)}
                            fill={nodeColor}
                            stroke="#f59e0b"
                            strokeWidth={2.2}
                            pointerEvents="none"
                          />
                        ) : ['server', 'web_server', 'dns_server'].includes(node.device_role) ? (
                          /* Rounded Square for Network Servers */
                          <rect
                            x={pos.x - radius}
                            y={pos.y - radius}
                            width={radius * 2}
                            height={radius * 2}
                            rx={4}
                            fill={nodeColor}
                            stroke="#60a5fa"
                            strokeWidth={1.8}
                            pointerEvents="none"
                          />
                        ) : node.is_multicast ? (
                          /* Diamond for Multicast Broadcast Groups */
                          <polygon
                            points={`${pos.x},${pos.y - radius - 2} ${pos.x + radius + 2},${pos.y} ${pos.x},${pos.y + radius + 2} ${pos.x - radius - 2},${pos.y}`}
                            fill={nodeColor}
                            stroke="#14b8a6"
                            strokeWidth={1.8}
                            pointerEvents="none"
                          />
                        ) : !node.is_internal ? (
                          /* Dashed Circle for Public WAN Endpoints */
                          <circle
                            cx={pos.x}
                            cy={pos.y}
                            r={radius}
                            fill={nodeColor}
                            stroke="#94a3b8"
                            strokeWidth={1.6}
                            strokeDasharray="4 2"
                            pointerEvents="none"
                          />
                        ) : (
                          /* Solid Circle for Standard Internal Workstations & Endpoints */
                          <circle
                            cx={pos.x}
                            cy={pos.y}
                            r={radius}
                            fill={nodeColor}
                            stroke="#070a12"
                            strokeWidth={1}
                            pointerEvents="none"
                          />
                        )}

                        {/* Mini Role Text Badge (GW, SRV, DNS, WEB, CLI, EXT, MC) for Colorblind Clarity */}
                        <g pointerEvents="none" transform={`translate(${pos.x}, ${pos.y - radius - 5})`}>
                          <rect
                            x={-11}
                            y={-7}
                            width={22}
                            height={11}
                            rx={2.5}
                            fill="#020617"
                            stroke={node.device_role === 'gateway' ? '#f59e0b' : node.is_internal ? '#0284c7' : '#64748b'}
                            strokeWidth={0.8}
                          />
                          <text
                            x={0}
                            y={1.5}
                            textAnchor="middle"
                            fontSize="7"
                            fontFamily="monospace"
                            fontWeight="bold"
                            fill={node.device_role === 'gateway' ? '#f59e0b' : '#38bdf8'}
                          >
                            {node.role_badge || (node.device_role === 'gateway' ? 'GW' : node.is_internal ? 'CLI' : 'EXT')}
                          </text>
                        </g>

                        {/* Pinned Marker Indicator */}
                        {isPinned && (
                          <circle
                            cx={pos.x + radius - 2}
                            cy={pos.y - radius + 2}
                            r={4}
                            fill="#f59e0b"
                            stroke="#ffffff"
                            strokeWidth={1}
                            pointerEvents="none"
                          />
                        )}

                        {/* Invisible Fixed-Size Hit Target (Prevents Hover Vibration/Jitter) */}
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
                          onTouchStart={(e) => handleNodeTouchStart(e, node)}
                          onClick={() => handleSelectNode(node)}
                        />

                        {/* Node Label Text with High-Contrast Background Stroke & Two-Line Wrapping */}
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
                                  : node.device_role === 'gateway'
                                  ? 'fill-amber-300 font-bold'
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

            {/* Contextual Floating Hover Tooltip */}
            {hoveredNode && (
              <div
                className="absolute z-40 bg-[#090d19] border border-slate-700/90 rounded-lg p-3 shadow-2xl text-xs font-mono backdrop-blur-md pointer-events-none min-w-[220px]"
                style={{
                  left: `${Math.min(hoveredNode.x, 680)}px`,
                  top: `${Math.max(15, hoveredNode.y)}px`,
                }}
              >
                <div className="flex items-center gap-2 mb-1.5 pb-1 border-b border-slate-800">
                  <span
                    className="w-2.5 h-2.5 rounded-full shrink-0"
                    style={{ backgroundColor: getNodeColor(hoveredNode.node) }}
                  />
                  <span className="font-bold text-white text-xs truncate max-w-[200px]">
                    {hoveredNode.node.label}
                  </span>
                  {hoveredNode.node.role_badge && (
                    <span className="ml-auto text-[9px] px-1 rounded bg-slate-800 text-sky-400 border border-slate-700">
                      {hoveredNode.node.role_badge}
                    </span>
                  )}
                </div>
                <div className="space-y-1 text-slate-300 text-[11px]">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Subnet:</span>
                    <span className="text-white font-mono">{hoveredNode.node.subnet || 'Unassigned'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Device Role:</span>
                    <span className="text-white capitalize">{hoveredNode.node.device_role || 'Host'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Total Volume:</span>
                    <span className="text-white font-bold">{formatBytes(hoveredNode.node.total_bytes)}</span>
                  </div>
                  {hoveredNode.node.findings_count > 0 && (
                    <div className="flex justify-between text-rose-400 font-bold">
                      <span>Detections:</span>
                      <span>{hoveredNode.node.findings_count} Flagged</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Floating Canvas Controls */}
            <div
              className="absolute top-3 right-3 flex flex-col gap-1 p-1 rounded-md border shadow-xl backdrop-blur-md z-10"
              style={{
                backgroundColor: 'rgba(9, 13, 24, 0.9)',
                borderColor: 'var(--border-subtle)',
              }}
            >
              <button
                type="button"
                onClick={() => setZoom((z) => Math.min(3.5, z * 1.25))}
                className="p-1.5 text-dark-300 hover:text-white hover:bg-white/10 rounded transition-colors min-h-[38px] min-w-[38px] flex items-center justify-center"
                title="Zoom In"
              >
                <ZoomIn className="w-4 h-4" />
              </button>
              <button
                type="button"
                onClick={() => setZoom((z) => Math.max(0.3, z * 0.8))}
                className="p-1.5 text-dark-300 hover:text-white hover:bg-white/10 rounded transition-colors min-h-[38px] min-w-[38px] flex items-center justify-center"
                title="Zoom Out"
              >
                <ZoomOut className="w-4 h-4" />
              </button>
              <button
                type="button"
                onClick={fitToView}
                className="p-1.5 text-dark-300 hover:text-white hover:bg-white/10 rounded transition-colors min-h-[38px] min-w-[38px] flex items-center justify-center"
                title="Fit to View"
              >
                <Maximize2 className="w-4 h-4" />
              </button>
              <button
                type="button"
                onClick={() => {
                  setZoom(1)
                  setPan({ x: 0, y: 0 })
                }}
                className="p-1.5 text-dark-300 hover:text-white hover:bg-white/10 rounded transition-colors min-h-[38px] min-w-[38px] flex items-center justify-center"
                title="Reset View (1:1)"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            </div>

            {/* Forensic Legend with Shape, Badge & Subnet Guide */}
            <div
              className="absolute bottom-3 left-3 flex flex-wrap items-center gap-3 text-[10.5px] font-mono p-2.5 rounded-md border backdrop-blur-md"
              style={{
                backgroundColor: 'rgba(9, 13, 24, 0.92)',
                borderColor: 'var(--border-subtle)',
              }}
            >
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 border border-amber-400 bg-amber-500/30 rotate-45 inline-block" />
                <span className="text-dark-200">[GW] Gateway</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-xs border border-blue-400 bg-blue-500/30 inline-block" />
                <span className="text-dark-200">[SRV] Server</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-sky-500 inline-block" />
                <span className="text-dark-200">[CLI] Client</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full border border-dashed border-slate-400 inline-block" />
                <span className="text-dark-200">[EXT] Public WAN</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rotate-45 bg-teal-500 inline-block" />
                <span className="text-dark-200">[MC] Multicast</span>
              </div>
              <div className="flex items-center gap-1.5 border-l border-slate-700 pl-2">
                <span className="w-2.5 h-2.5 rounded-full border border-rose-500 border-dashed inline-block" />
                <span className="text-rose-400">Flagged Finding</span>
              </div>
            </div>

            {/* Mobile Floating Inspector Trigger */}
            {(selectedNode || selectedEdge || selectedSubnet) && !mobileInspectorOpen && (
              <button
                type="button"
                onClick={() => setMobileInspectorOpen(true)}
                className="lg:hidden absolute bottom-4 left-1/2 -translate-x-1/2 z-30 px-3.5 py-2 rounded-full bg-primary-600/95 hover:bg-primary-500 text-white text-xs font-mono font-medium shadow-2xl backdrop-blur-md flex items-center gap-2 border border-primary-400/50"
              >
                <Eye className="w-3.5 h-3.5" />
                <span>Inspect Selected</span>
              </button>
            )}
          </div>
        </div>

        {/* Mobile Backdrop */}
        {mobileInspectorOpen && (selectedNode || selectedEdge || selectedSubnet) && (
          <div
            className="fixed inset-0 bg-black/60 backdrop-blur-xs z-30 lg:hidden"
            onClick={() => setMobileInspectorOpen(false)}
          />
        )}

        {/* Right Drawer: Selected Entity, Edge, or Subnet Inspector */}
        <div
          className={`border-t lg:border-t-0 lg:border-l p-4 flex flex-col justify-between overflow-y-auto transition-transform duration-200 z-40 ${
            mobileInspectorOpen
              ? 'fixed inset-x-0 bottom-0 max-h-[75vh] lg:static lg:inset-auto lg:w-80 lg:max-h-none lg:h-[calc(100vh-57px)] flex'
              : 'hidden lg:flex lg:w-80 lg:h-[calc(100vh-57px)]'
          }`}
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-subtle)',
          }}
        >
          {/* Mobile Drawer Header */}
          <div className="flex items-center justify-between pb-3 mb-2 border-b border-dark-800 lg:hidden">
            <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
              {selectedSubnet ? 'Subnet Details' : selectedEdge ? 'Connection Details' : 'Host Telemetry'}
            </span>
            <button
              type="button"
              onClick={() => setMobileInspectorOpen(false)}
              className="p-1.5 text-dark-400 hover:text-white rounded min-h-[36px] min-w-[36px] flex items-center justify-center"
              title="Close panel"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* 1. Subnet Inspector */}
          {selectedSubnet ? (
            <div className="space-y-4">
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-primary-400 font-bold block mb-1">
                  NETWORK SEGMENT & SUBNET
                </span>
                <h3 className="font-mono text-sm font-bold text-white break-all">
                  {selectedSubnet.label}
                </h3>
                <div className="flex items-center gap-1.5 mt-1.5">
                  <span className={`badge ${selectedSubnet.is_internal ? 'badge-low' : 'badge-info'} text-[10px]`}>
                    {selectedSubnet.category.toUpperCase()}
                  </span>
                  <span className="badge text-[10px] font-mono bg-dark-800 text-dark-300">
                    CIDR: {selectedSubnet.id}
                  </span>
                </div>
              </div>

              <div className="card p-3 space-y-2 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-dark-400">Prefix Inference:</span>
                  <span className="text-white">
                    {selectedSubnet.is_inferred_prefix ? 'Inferred (/24 Heuristic)' : 'Observed Address'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-dark-400">Active Member Hosts:</span>
                  <span className="text-white font-bold">{selectedSubnet.host_count}</span>
                </div>
                {selectedSubnet.gateway && (
                  <div className="flex justify-between">
                    <span className="text-dark-400">Identified Gateway:</span>
                    <span className="text-amber-400 font-bold">{selectedSubnet.gateway}</span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-dark-400">Aggregate Traffic:</span>
                  <span className="text-white font-bold">{formatBytes(selectedSubnet.total_bytes)}</span>
                </div>
              </div>

              {/* Member Hosts List */}
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-dark-400 font-bold block mb-2">
                  CONSTITUENT HOSTS ({selectedSubnet.hosts?.length || 0})
                </span>
                <div className="space-y-1.5 max-h-48 overflow-y-auto">
                  {(selectedSubnet.hosts || []).map((hIp) => (
                    <div
                      key={hIp}
                      className="p-2 rounded bg-dark-900 border border-dark-800 text-xs font-mono flex items-center justify-between cursor-pointer hover:border-slate-600"
                      onClick={() => {
                        const targetNode = filteredData.nodes.find((n) => n.id === hIp)
                        if (targetNode) handleSelectNode(targetNode)
                      }}
                    >
                      <span className="text-white truncate">{hIp}</span>
                      <ArrowRight className="w-3 h-3 text-dark-400" />
                    </div>
                  ))}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-2 border-t border-dark-800 space-y-2">
                <button
                  type="button"
                  onClick={() => toggleCollapseSubnet(selectedSubnet.id)}
                  className="btn btn-secondary w-full text-xs py-1.5 flex items-center justify-center gap-1.5"
                >
                  <Minimize2 className="w-3.5 h-3.5" />
                  <span>
                    {collapsedSubnets.has(selectedSubnet.id) ? 'Expand Subnet Container' : 'Collapse into Cluster'}
                  </span>
                </button>
              </div>
            </div>
          ) : selectedEdge ? (
            /* 2. Socket Edge Inspector */
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

              {/* Action Buttons */}
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
            /* 3. Selected Node Inspector */
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
                  {selectedNode.device_role && (
                    <span className={`badge text-[10px] font-mono ${selectedNode.device_role === 'gateway' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'bg-primary-950/70 text-primary-300 border border-primary-700/60'}`}>
                      {selectedNode.device_role.toUpperCase()}
                    </span>
                  )}
                  {selectedNode.subnet && (
                    <span className="badge text-[10px] font-mono bg-dark-800 text-dark-300 border border-dark-700">
                      {selectedNode.subnet}
                    </span>
                  )}
                  {selectedNode.is_ipv6 && (
                    <span className="badge text-[10px] bg-sky-950/60 text-sky-300 border border-sky-700/60 font-mono">
                      IPv6
                    </span>
                  )}
                </div>
              </div>

              {/* Host Telemetry & Device Classification */}
              {(!selectedNode.type || selectedNode.type === 'host') && (
                <div className="card p-3 space-y-2 text-xs font-mono">
                  <div className="flex justify-between">
                    <span className="text-dark-400">Role Inferred:</span>
                    <span className="text-white capitalize font-bold">{selectedNode.device_role || 'Client'}</span>
                  </div>
                  {selectedNode.role_evidence && (
                    <p className="text-[10px] text-dark-400 bg-dark-900/80 p-1.5 rounded border border-dark-800">
                      {selectedNode.role_evidence}
                    </p>
                  )}
                  <div className="flex justify-between">
                    <span className="text-dark-400">Subnet Prefix:</span>
                    <span className="text-slate-300">
                      {selectedNode.is_inferred_prefix ? 'Inferred (/24 LAN)' : 'Observed Address'}
                    </span>
                  </div>
                  {selectedNode.observed_ports && selectedNode.observed_ports.length > 0 && (
                    <div className="flex justify-between">
                      <span className="text-dark-400">Observed Ports:</span>
                      <span className="text-sky-400 truncate max-w-[140px]">
                        {selectedNode.observed_ports.join(', ')}
                      </span>
                    </div>
                  )}
                  {selectedNode.dns_names && selectedNode.dns_names.length > 0 && (
                    <div className="flex justify-between">
                      <span className="text-dark-400">Queried Domain:</span>
                      <span className="text-sky-300 truncate max-w-[140px]">
                        {selectedNode.dns_names[0]}
                      </span>
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span className="text-dark-400">Packets Sent / Recv:</span>
                    <span className="text-white">
                      {(selectedNode.packets_sent || 0).toLocaleString()} / {(selectedNode.packets_received || 0).toLocaleString()}
                    </span>
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
              </div>
            </div>
          ) : (
            <div className="text-xs font-mono text-dark-500 text-center py-8">
              Select any host, subnet container, or socket link to inspect forensic evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
