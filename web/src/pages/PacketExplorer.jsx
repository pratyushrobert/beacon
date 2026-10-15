import { useState, useEffect } from 'react'
import { useParams, useSearchParams, Link } from 'react-router-dom'
import axios from 'axios'
import {
  Package,
  Search,
  Filter,
  Loader2,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Layers,
  ArrowRight,
  ExternalLink,
  X,
  Code,
  Terminal,
  MessageSquare,
  FileCode,
  Pin,
  Check
} from 'lucide-react'
import CaptureHeader from '../components/CaptureHeader'

export default function PacketExplorer() {
  const { analysisId } = useParams()
  const [searchParams] = useSearchParams()

  const [loading, setLoading] = useState(true)
  const [packets, setPackets] = useState([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const limit = 30

  // Filters
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedProtocol, setSelectedProtocol] = useState('')
  const [selectedDirection, setSelectedDirection] = useState('')
  const [selectedIp, setSelectedIp] = useState(searchParams.get('ip') || '')

  // Selected Packet Details
  const [selectedPacketNumber, setSelectedPacketNumber] = useState(
    searchParams.get('packet') ? parseInt(searchParams.get('packet')) : null
  )
  const [detailLoading, setDetailLoading] = useState(false)
  const [packetDetail, setPacketDetail] = useState(null)
  const [detailError, setDetailError] = useState(null)
  const [activeTab, setActiveTab] = useState('layers') // 'layers' | 'hex' | 'findings'
  const [showRawJson, setShowRawJson] = useState(false)

  // Stream Modal State
  const [streamModalOpen, setStreamModalOpen] = useState(false)
  const [streamData, setStreamData] = useState(null)
  const [streamLoading, setStreamLoading] = useState(false)

  useEffect(() => {
    loadPackets(false)
    if (analysisId === 'live' && offset === 0 && !searchQuery && !selectedIp) {
      const interval = setInterval(() => {
        loadPackets(true)
      }, 2500)
      return () => clearInterval(interval)
    }
  }, [analysisId, offset, selectedProtocol, selectedDirection, selectedIp, searchQuery])

  useEffect(() => {
    if (selectedPacketNumber) {
      loadPacketDetail(selectedPacketNumber)
    } else {
      setPacketDetail(null)
      setDetailError(null)
    }
  }, [selectedPacketNumber])

  const loadPackets = async (isBackground = false) => {
    if (!isBackground) setLoading(true)
    try {
      const params = {
        offset,
        limit,
        search: searchQuery || undefined,
        protocol: selectedProtocol || undefined,
        direction: selectedDirection || undefined,
        ip: selectedIp || undefined,
      }
      const response = await axios.get(`/api/analysis/${analysisId}/packets`, { params })
      setPackets(response.data.packets || [])
      setTotal(response.data.total || 0)
    } catch (err) {
      console.error('Failed to load packets:', err)
    } finally {
      if (!isBackground) setLoading(false)
    }
  }

  const handleSearchSubmit = (e) => {
    e.preventDefault()
    setOffset(0)
    loadPackets(false)
  }

  const loadPacketDetail = async (num) => {
    setDetailLoading(true)
    setShowRawJson(false)
    setDetailError(null)
    setActiveTab('layers')
    try {
      const response = await axios.get(`/api/analysis/${analysisId}/packet/${num}`)
      setPacketDetail(response.data)
    } catch (err) {
      console.error('Failed to load packet detail:', err)
      setPacketDetail(null)
      setDetailError(err.response?.data?.detail || `Failed to load details for packet #${num}`)
    } finally {
      setDetailLoading(false)
    }
  }

  const openStreamViewer = async (convKey) => {
    if (!convKey) return
    setStreamModalOpen(true)
    setStreamLoading(true)
    try {
      const res = await axios.get(`/api/analysis/${analysisId}/stream/${encodeURIComponent(convKey)}`)
      setStreamData(res.data)
    } catch (err) {
      console.error('Failed to load conversation stream:', err)
    } finally {
      setStreamLoading(false)
    }
  }

  // Format hex dump for individual packet
  const generatePacketHexDump = (detail) => {
    if (!detail) return ''
    let textPayload = ''
    if (detail.http?.method || detail.http?.uri) {
      textPayload = `${detail.http.method || 'GET'} ${detail.http.uri || '/'} HTTP/1.1\r\nHost: ${detail.http.host || detail.destination}\r\nUser-Agent: ${detail.http.user_agent || 'Client'}\r\n\r\n`
    } else if (detail.dns?.query_name) {
      textPayload = `DNS Query: ${detail.dns.query_name} (Type: ${detail.dns.query_type || 'A'})`
    } else if (detail.tls?.server_name) {
      textPayload = `TLS Handshake SNI: ${detail.tls.server_name}`
    } else {
      textPayload = `Raw packet #${detail.packet_number} (${detail.length} bytes, protocol: ${detail.application_protocol || detail.transport_protocol})`
    }

    const bytes = new TextEncoder().encode(textPayload)
    const lines = []
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16)
      const hexPart = Array.from(chunk)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ')
        .padEnd(48, ' ')
      const asciiPart = Array.from(chunk)
        .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
        .join('')
      lines.push(`${i.toString(16).padStart(4, '0')}  ${hexPart}  |${asciiPart}|`)
    }
    return lines.join('\n')
  }

  const currentPage = Math.floor(offset / limit) + 1
  const totalPages = Math.ceil(total / limit) || 1

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-canvas text-dark-100">
      <CaptureHeader onModeChange={loadPackets} />

      <div className="flex flex-1 overflow-hidden">
        {/* Left: Packet Table Area */}
        <div className={`flex-1 flex flex-col min-w-0 p-6 overflow-y-auto ${selectedPacketNumber ? 'pr-2' : ''}`}>
          {/* Header */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
            <div>
              <h1 className="text-2xl font-bold text-dark-900 dark:text-white flex items-center gap-2">
                <Package className="w-6 h-6 text-primary-500" />
                Packet Explorer
                {analysisId === 'live' && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 self-center">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    LIVE STREAM
                  </span>
                )}
              </h1>
              <p className="text-xs text-dark-500 dark:text-dark-400">
                {total.toLocaleString()} total packets captured
              </p>
            </div>

            {/* Quick Filters */}
            <form onSubmit={handleSearchSubmit} className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-dark-400" />
                <input
                  type="text"
                  placeholder="Search IP, port, host, URI..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 pr-3 py-1.5 text-xs bg-white dark:bg-dark-900 border border-dark-200 dark:border-dark-700 rounded-lg text-dark-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-primary-500 w-52 md:w-60 font-mono"
                />
              </div>

              <select
                value={selectedProtocol}
                onChange={(e) => { setSelectedProtocol(e.target.value); setOffset(0); }}
                className="py-1.5 px-2.5 text-xs bg-white dark:bg-dark-900 border border-dark-200 dark:border-dark-700 rounded-lg text-dark-900 dark:text-white focus:outline-none"
              >
                <option value="">All Protocols</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="http">HTTP</option>
                <option value="dns">DNS</option>
                <option value="https">HTTPS / TLS</option>
                <option value="ssh">SSH</option>
              </select>

              {selectedIp && (
                <button
                  type="button"
                  onClick={() => setSelectedIp('')}
                  className="px-2 py-1 bg-dark-200 dark:bg-dark-800 text-dark-700 dark:text-dark-300 rounded text-xs flex items-center gap-1 font-mono"
                >
                  <span>IP: {selectedIp}</span>
                  <span className="font-bold">×</span>
                </button>
              )}
            </form>
          </div>

          {/* Packet Table */}
          <div className="card p-0 overflow-hidden flex-1 flex flex-col">
            <div className="overflow-x-auto flex-1">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-dark-50 dark:bg-dark-800/80 border-b border-dark-200 dark:border-dark-700 text-xs font-semibold uppercase text-dark-500 dark:text-dark-400">
                    <th className="py-2.5 px-3 w-16">#</th>
                    <th className="py-2.5 px-3 w-28">Time</th>
                    <th className="py-2.5 px-3">Source</th>
                    <th className="py-2.5 px-3">Destination</th>
                    <th className="py-2.5 px-3 w-20">Protocol</th>
                    <th className="py-2.5 px-3 w-20 text-right">Length</th>
                    <th className="py-2.5 px-3">Info / Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-100 dark:divide-dark-800 text-xs font-mono">
                  {loading ? (
                    <tr>
                      <td colSpan="7" className="py-12 text-center text-dark-400">
                        <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2 text-primary-500" />
                        Loading packets...
                      </td>
                    </tr>
                  ) : packets.length === 0 ? (
                    <tr>
                      <td colSpan="7" className="py-12 text-center text-dark-400">
                        No packets found matching your filter criteria.
                      </td>
                    </tr>
                  ) : (
                    packets.map((pkt) => {
                      const isSelected = selectedPacketNumber === pkt.number
                      let infoSummary = ''
                      if (pkt.dns_query_name) {
                        infoSummary = `DNS Query: ${pkt.dns_query_name}`
                      } else if (pkt.http_method) {
                        infoSummary = `HTTP ${pkt.http_method} ${pkt.http_host || ''}${pkt.http_uri || ''}`
                      } else if (pkt.tls_server_name) {
                        infoSummary = `TLS SNI: ${pkt.tls_server_name}`
                      } else if (pkt.transport_proto === 'tcp') {
                        infoSummary = `TCP Port ${pkt.src_port} → ${pkt.dst_port}`
                      } else {
                        infoSummary = (pkt.protocols || []).slice(-2).join(' / ')
                      }

                      return (
                        <tr
                          key={pkt.number}
                          onClick={() => setSelectedPacketNumber(pkt.number)}
                          className={`cursor-pointer transition-colors ${
                            isSelected
                              ? 'bg-primary-50 dark:bg-primary-950/40 text-primary-900 dark:text-primary-100 font-semibold'
                              : 'hover:bg-dark-50 dark:hover:bg-dark-800/40 text-dark-800 dark:text-dark-200'
                          }`}
                        >
                          <td className="py-2 px-3 text-dark-400">{pkt.number}</td>
                          <td className="py-2 px-3 text-dark-500">
                            {pkt.timestamp ? pkt.timestamp.split('T')[1]?.slice(0, 12) : '-'}
                          </td>
                          <td className="py-2 px-3 truncate max-w-[140px]">
                            {pkt.ip_src || '-'}{pkt.src_port !== null ? `:${pkt.src_port}` : ''}
                          </td>
                          <td className="py-2 px-3 truncate max-w-[140px]">
                            {pkt.ip_dst || '-'}{pkt.dst_port !== null ? `:${pkt.dst_port}` : ''}
                          </td>
                          <td className="py-2 px-3">
                            <span className="badge badge-info uppercase text-[10px]">
                              {pkt.app_proto || pkt.transport_proto || 'unknown'}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-right text-dark-500">{pkt.length}</td>
                          <td className="py-2 px-3 truncate max-w-xs text-dark-600 dark:text-dark-400">
                            {infoSummary}
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div className="flex items-center justify-between px-4 py-3 border-t border-dark-200 dark:border-dark-700 bg-dark-50 dark:bg-dark-800/50 text-xs">
              <span className="text-dark-500 dark:text-dark-400">
                Showing {total > 0 ? offset + 1 : 0} to {Math.min(offset + limit, total)} of {total.toLocaleString()} packets
              </span>
              <div className="flex items-center gap-2">
                <button
                  disabled={offset === 0 || loading}
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  className="btn btn-secondary py-1 px-2.5 text-xs flex items-center gap-1 disabled:opacity-40"
                >
                  <ChevronLeft className="w-3.5 h-3.5" /> Previous
                </button>
                <span className="text-dark-700 dark:text-dark-300 font-medium">
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  disabled={offset + limit >= total || loading}
                  onClick={() => setOffset(offset + limit)}
                  className="btn btn-secondary py-1 px-2.5 text-xs flex items-center gap-1 disabled:opacity-40"
                >
                  Next <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Deep Packet Inspection Panel */}
        {selectedPacketNumber && (
          <div className="w-[500px] border-l border-dark-200 dark:border-dark-800 bg-white dark:bg-dark-900 flex flex-col h-[calc(100vh-57px)] overflow-hidden shadow-xl z-20">
            {/* Inspector Header */}
            <div className="p-4 border-b border-dark-200 dark:border-dark-800 bg-dark-50 dark:bg-dark-800/50 flex flex-col gap-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Layers className="w-5 h-5 text-primary-500" />
                  <h2 className="font-semibold text-sm text-dark-900 dark:text-white">
                    Packet #{selectedPacketNumber} Inspection
                  </h2>
                </div>
                <div className="flex items-center gap-2">
                  {packetDetail?.conversation_key && (
                    <button
                      onClick={() => openStreamViewer(packetDetail.conversation_key)}
                      className="px-2.5 py-1 rounded bg-primary-600 text-white text-xs font-medium flex items-center gap-1 shadow-sm hover:bg-primary-700 transition-colors"
                      title="Follow reconstructed conversation stream"
                    >
                      <MessageSquare className="w-3 h-3" />
                      <span>Follow Stream</span>
                    </button>
                  )}
                  <button
                    onClick={() => setShowRawJson(!showRawJson)}
                    className="p-1.5 text-dark-400 hover:text-dark-200 rounded"
                    title="Toggle Raw JSON"
                  >
                    <Code className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => setSelectedPacketNumber(null)}
                    className="p-1.5 text-dark-400 hover:text-dark-200 rounded"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Inspector View Tabs */}
              <div className="flex rounded-md p-0.5 bg-dark-100 dark:bg-dark-800 text-xs">
                <button
                  onClick={() => setActiveTab('layers')}
                  className={`flex-1 py-1 rounded font-medium transition-colors ${
                    activeTab === 'layers'
                      ? 'bg-white dark:bg-dark-900 text-dark-900 dark:text-white shadow-sm'
                      : 'text-dark-500 hover:text-dark-200'
                  }`}
                >
                  Protocol Layers
                </button>
                <button
                  onClick={() => setActiveTab('hex')}
                  className={`flex-1 py-1 rounded font-medium transition-colors ${
                    activeTab === 'hex'
                      ? 'bg-white dark:bg-dark-900 text-dark-900 dark:text-white shadow-sm'
                      : 'text-dark-500 hover:text-dark-200'
                  }`}
                >
                  Hex / ASCII
                </button>
                <button
                  onClick={() => setActiveTab('findings')}
                  className={`flex-1 py-1 rounded font-medium transition-colors ${
                    activeTab === 'findings'
                      ? 'bg-white dark:bg-dark-900 text-dark-900 dark:text-white shadow-sm'
                      : 'text-dark-500 hover:text-dark-200'
                  }`}
                >
                  Findings ({packetDetail?.findings?.length || 0})
                </button>
              </div>
            </div>

            {/* Inspector Content */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {detailLoading ? (
                <div className="py-16 text-center text-dark-400">
                  <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2 text-primary-500" />
                  Decoding packet layers...
                </div>
              ) : detailError ? (
                <div className="p-4 rounded-lg bg-red-950/20 border border-red-800/40 text-xs space-y-3">
                  <div className="flex items-center gap-2 text-red-400 font-semibold">
                    <ShieldAlert className="w-4 h-4 shrink-0" />
                    <span>Packet Data Evicted / Unavailable</span>
                  </div>
                  <p className="text-dark-300 font-mono text-xs leading-relaxed">
                    {detailError}
                  </p>
                  {analysisId === 'live' && (
                    <div className="pt-2 border-t border-red-800/20 text-dark-400 text-xs space-y-2">
                      <p>
                        In continuous live capture, ordinary non-suspicious packets are evicted from memory once the rolling buffer capacity is exceeded.
                      </p>
                      <p>
                        Packets correlated with high/critical security alerts are automatically preserved with surrounding pre- and post-trigger context.
                      </p>
                      <Link
                        to="/live"
                        className="inline-flex items-center gap-1 text-primary-400 hover:underline font-medium"
                      >
                        <span>Open Live Incident Console</span>
                        <ArrowRight className="w-3 h-3" />
                      </Link>
                    </div>
                  )}
                </div>
              ) : packetDetail ? (
                <>
                  {showRawJson ? (
                    <pre className="p-3 bg-dark-950 rounded-lg text-xs font-mono text-dark-300 overflow-x-auto">
                      {JSON.stringify(packetDetail, null, 2)}
                    </pre>
                  ) : activeTab === 'hex' ? (
                    /* Hex / ASCII Dump Tab */
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs text-dark-400 font-mono">
                        <span>Offset (h)</span>
                        <span>Hexadecimal Bytes</span>
                        <span>ASCII Text</span>
                      </div>
                      <pre className="p-3.5 bg-dark-950 rounded-lg text-[11px] font-mono text-emerald-400 overflow-x-auto leading-relaxed border border-dark-800">
                        {generatePacketHexDump(packetDetail)}
                      </pre>
                    </div>
                  ) : activeTab === 'findings' ? (
                    /* Findings Tab */
                    <div className="space-y-3">
                      {!packetDetail.findings || packetDetail.findings.length === 0 ? (
                        <div className="text-xs text-dark-400 text-center py-8">
                          No direct security findings associated with packet #{selectedPacketNumber}.
                        </div>
                      ) : (
                        packetDetail.findings.map((f, i) => (
                          <div
                            key={i}
                            className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs space-y-1.5"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-red-500">{f.title}</span>
                              <span className="badge badge-critical uppercase text-[10px]">{f.severity}</span>
                            </div>
                            <p className="text-dark-700 dark:text-dark-300">{f.description}</p>
                            <Link
                              to={`/findings/${analysisId}`}
                              className="text-primary-600 dark:text-primary-400 hover:underline flex items-center gap-1 text-[11px] pt-1"
                            >
                              <span>View in Findings Page</span>
                              <ArrowRight className="w-3 h-3" />
                            </Link>
                          </div>
                        ))
                      )}
                    </div>
                  ) : (
                    /* Protocol Layers Tab */
                    <div className="space-y-3">
                      {/* Frame */}
                      <div className="card p-3 space-y-2">
                        <div className="text-xs font-semibold text-primary-600 dark:text-primary-400 uppercase tracking-wider">
                          Frame & Metadata
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                          <div>
                            <span className="text-dark-400">Timestamp: </span>
                            <span className="text-dark-900 dark:text-dark-100">{packetDetail.timestamp || '-'}</span>
                          </div>
                          <div>
                            <span className="text-dark-400">Wire Length: </span>
                            <span className="text-dark-900 dark:text-dark-100">{packetDetail.length} bytes</span>
                          </div>
                          <div>
                            <span className="text-dark-400">Direction: </span>
                            <span className="badge badge-info text-[10px] uppercase">{packetDetail.direction || 'unknown'}</span>
                          </div>
                          <div>
                            <span className="text-dark-400">Stack: </span>
                            <span className="text-dark-900 dark:text-dark-100 truncate">{(packetDetail.protocols || []).join(' → ')}</span>
                          </div>
                        </div>
                      </div>

                      {/* Network (IP) */}
                      <div className="card p-3 space-y-2">
                        <div className="text-xs font-semibold text-primary-600 dark:text-primary-400 uppercase tracking-wider">
                          Network Layer (IP)
                        </div>
                        <div className="text-xs font-mono space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="text-dark-400">Source IP:</span>
                            <span className="text-dark-900 dark:text-white font-bold">{packetDetail.source || '-'}</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-dark-400">Destination IP:</span>
                            <span className="text-dark-900 dark:text-white font-bold">{packetDetail.destination || '-'}</span>
                          </div>
                        </div>
                      </div>

                      {/* Transport (TCP / UDP) */}
                      <div className="card p-3 space-y-2">
                        <div className="text-xs font-semibold text-primary-600 dark:text-primary-400 uppercase tracking-wider">
                          Transport Layer ({packetDetail.transport_protocol?.toUpperCase() || 'Transport'})
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                          <div>
                            <span className="text-dark-400">Source Port: </span>
                            <span className="text-dark-900 dark:text-white">{packetDetail.source_port !== null ? packetDetail.source_port : '-'}</span>
                          </div>
                          <div>
                            <span className="text-dark-400">Dest Port: </span>
                            <span className="text-dark-900 dark:text-white">{packetDetail.destination_port !== null ? packetDetail.destination_port : '-'}</span>
                          </div>
                          {packetDetail.tcp && (
                            <>
                              <div className="col-span-2">
                                <span className="text-dark-400">TCP Flags: </span>
                                <span className="badge badge-low text-[10px]">{packetDetail.tcp.flags_text || packetDetail.tcp.flags || 'None'}</span>
                              </div>
                              <div>
                                <span className="text-dark-400">Stream: </span>
                                <span>{packetDetail.tcp.stream ?? '-'}</span>
                              </div>
                              <div>
                                <span className="text-dark-400">Retransmission: </span>
                                <span>{packetDetail.tcp.retransmission ? 'Yes' : 'No'}</span>
                              </div>
                            </>
                          )}
                        </div>
                      </div>

                      {/* HTTP Details */}
                      {packetDetail.http && (packetDetail.http.method || packetDetail.http.uri) && (
                        <div className="card p-3 space-y-2">
                          <div className="text-xs font-semibold text-primary-600 dark:text-primary-400 uppercase tracking-wider">
                            HTTP Details
                          </div>
                          <div className="text-xs font-mono space-y-1">
                            <div>
                              <span className="text-dark-400">Method: </span>
                              <span className="font-bold text-dark-900 dark:text-white">{packetDetail.http.method}</span>
                            </div>
                            <div>
                              <span className="text-dark-400">Host: </span>
                              <span className="text-dark-900 dark:text-white">{packetDetail.http.host || '-'}</span>
                            </div>
                            <div>
                              <span className="text-dark-400">URI: </span>
                              <span className="text-dark-900 dark:text-white break-all">{packetDetail.http.uri}</span>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* DNS Details */}
                      {packetDetail.dns && packetDetail.dns.query_name && (
                        <div className="card p-3 space-y-2">
                          <div className="text-xs font-semibold text-primary-600 dark:text-primary-400 uppercase tracking-wider">
                            DNS Query Details
                          </div>
                          <div className="text-xs font-mono space-y-1">
                            <div>
                              <span className="text-dark-400">Query Name: </span>
                              <span className="font-bold text-dark-900 dark:text-white">{packetDetail.dns.query_name}</span>
                            </div>
                            <div>
                              <span className="text-dark-400">Record Type: </span>
                              <span className="text-dark-900 dark:text-white">{packetDetail.dns.query_type || 'A'}</span>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </>
              ) : (
                <div className="py-12 text-center text-dark-400 text-xs">
                  Unable to load packet details.
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Reconstructed Stream Viewer Modal */}
      {streamModalOpen && (
        <div className="fixed inset-0 bg-dark-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-dark-900 border border-dark-200 dark:border-dark-800 rounded-xl shadow-2xl max-w-4xl w-full max-h-[85vh] flex flex-col overflow-hidden">
            <div className="p-4 border-b border-dark-200 dark:border-dark-800 flex items-center justify-between bg-dark-50 dark:bg-dark-800/60">
              <div className="flex items-center gap-2">
                <MessageSquare className="w-5 h-5 text-primary-500" />
                <h3 className="font-bold text-sm text-dark-900 dark:text-white font-mono">
                  Conversation Stream: {streamData?.conversation_key}
                </h3>
              </div>
              <button
                onClick={() => setStreamModalOpen(false)}
                className="p-1.5 rounded hover:bg-dark-200 dark:hover:bg-dark-700 text-dark-400"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs">
              {streamLoading ? (
                <div className="py-16 text-center text-dark-400">
                  <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2 text-primary-500" />
                  Reconstructing dialogue stream...
                </div>
              ) : streamData?.turns && streamData.turns.length > 0 ? (
                streamData.turns.map((turn, i) => {
                  const isClient = turn.direction === 'client_to_server'
                  return (
                    <div
                      key={i}
                      className={`p-3 rounded-lg border ${
                        isClient
                          ? 'bg-sky-500/10 border-sky-500/30 ml-4'
                          : 'bg-emerald-500/10 border-emerald-500/30 mr-4'
                      }`}
                    >
                      <div className="flex items-center justify-between text-[11px] text-dark-400 mb-1.5 border-b border-dark-200/50 dark:border-dark-700/50 pb-1">
                        <span className="font-bold text-dark-900 dark:text-white">
                          #{turn.number} • {turn.sender} → {turn.receiver}
                        </span>
                        <span>{turn.protocol} • {turn.length} bytes</span>
                      </div>
                      <div className="font-bold text-dark-800 dark:text-dark-100 mb-1">
                        {turn.summary}
                      </div>
                      {turn.hex_dump && (
                        <pre className="p-2 bg-dark-950 rounded text-[10px] text-dark-300 overflow-x-auto mt-2 leading-relaxed">
                          {turn.hex_dump}
                        </pre>
                      )}
                    </div>
                  )
                })
              ) : (
                <div className="py-12 text-center text-dark-400">
                  No reconstructed messages found for this conversation.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
