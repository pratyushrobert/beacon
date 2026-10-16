import { useState, useEffect } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import axios from 'axios'
import {
  Loader2,
  Network,
  Search,
  Package,
  Clock,
  ArrowRight,
  Terminal
} from 'lucide-react'
import CaptureHeader from '../components/CaptureHeader'

export default function Conversations() {
  const { analysisId } = useParams()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [conversations, setConversations] = useState([])
  const [search, setSearch] = useState('')
  const [error, setError] = useState(null)

  useEffect(() => {
    loadConversations(false)
    if (analysisId === 'live') {
      const interval = setInterval(() => {
        if (document.hidden) return
        loadConversations(true)
      }, 2500)
      return () => clearInterval(interval)
    }
  }, [analysisId])

  const loadConversations = async (isBackground = false) => {
    if (!isBackground) setLoading(true)
    try {
      const response = await axios.get(`/api/analysis/${analysisId}/conversations`, {
        params: { top: 100 }
      })
      setConversations(response.data.conversations || [])
    } catch (err) {
      if (!isBackground) setError(err.response?.data?.detail || 'Failed to load conversations')
    } finally {
      if (!isBackground) setLoading(false)
    }
  }

  const filteredConversations = conversations.filter((c) => {
    if (!search.trim()) return true
    const q = search.toLowerCase()
    return (
      c.host1?.toLowerCase().includes(q) ||
      c.host2?.toLowerCase().includes(q) ||
      c.protocol?.toLowerCase().includes(q) ||
      c.port1?.toString().includes(q) ||
      c.port2?.toString().includes(q)
    )
  })

  return (
    <div className="min-h-screen bg-canvas flex flex-col">
      <CaptureHeader />

      <div className="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Network className="w-6 h-6 text-primary-500" />
              <h1 className="text-2xl font-bold text-dark-900 dark:text-white">
                Network Conversations
              </h1>
              {analysisId === 'live' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  LIVE STREAMS
                </span>
              )}
            </div>
            <p className="text-xs text-dark-500 dark:text-dark-400 mt-1">
              Bidirectional socket sessions and talker pairs ({filteredConversations.length} of {conversations.length} conversation pairs displayed)
            </p>
          </div>

          {/* Filter */}
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-dark-400" />
            <input
              type="text"
              placeholder="Search host, port, protocol..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input pl-9 text-xs py-1.5 w-72"
            />
          </div>
        </div>

        {/* Conversations Table */}
        {loading ? (
          <div className="flex items-center justify-center py-24">
            <Loader2 className="w-8 h-8 text-primary-500 animate-spin" />
          </div>
        ) : error ? (
          <div className="card p-6 text-center text-red-400">
            {error}
          </div>
        ) : (
          <div className="card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-dark-100/40 dark:bg-dark-900/60 border-b border-subtle text-[11px] font-semibold text-dark-400 uppercase tracking-wider">
                    <th className="text-left py-2.5 px-3.5">#</th>
                    <th className="text-left py-2.5 px-3.5">Endpoint 1</th>
                    <th className="text-center py-2.5 px-3.5">↔</th>
                    <th className="text-left py-2.5 px-3.5">Endpoint 2</th>
                    <th className="text-center py-2.5 px-3.5">Protocol</th>
                    <th className="text-right py-2.5 px-3.5">Packets</th>
                    <th className="text-right py-2.5 px-3.5">Volume</th>
                    <th className="text-right py-2.5 px-3.5">Duration</th>
                    <th className="text-right py-2.5 px-3.5">Investigate</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-subtle">
                  {filteredConversations.length === 0 ? (
                    <tr>
                      <td colSpan={9} className="py-12 text-center text-dark-400 text-xs">
                        No conversations match your search filter.
                      </td>
                    </tr>
                  ) : (
                    filteredConversations.map((conv, index) => {
                      const convKey = `${conv.host1}:${conv.port1 || 0}-${conv.host2}:${conv.port2 || 0}`
                      return (
                        <tr
                          key={convKey || index}
                          className="hover:bg-surface-elevated/40 transition-colors text-xs"
                        >
                          <td className="py-2.5 px-3.5 text-dark-400 font-mono text-[11px]">
                            {index + 1}
                          </td>
                          <td className="py-2.5 px-3.5">
                            <div className="font-mono text-xs font-semibold text-dark-900 dark:text-white">
                              {conv.host1}
                              {conv.port1 && (
                                <span className="text-primary-400 font-normal">:{conv.port1}</span>
                              )}
                            </div>
                          </td>
                          <td className="py-2.5 px-3.5 text-center text-dark-500">
                            ↔
                          </td>
                          <td className="py-2.5 px-3.5">
                            <div className="font-mono text-xs font-semibold text-dark-900 dark:text-white">
                              {conv.host2}
                              {conv.port2 && (
                                <span className="text-primary-400 font-normal">:{conv.port2}</span>
                              )}
                            </div>
                          </td>
                          <td className="py-2.5 px-3.5 text-center">
                            <div className="flex flex-col items-center gap-1">
                              <span className="badge bg-slate-800/80 text-slate-300 border border-slate-700/60 uppercase text-[10px] font-mono">
                                {conv.protocol}
                              </span>
                              {analysisId === 'live' && (
                                <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium ${
                                  conv.is_active
                                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                                    : 'bg-dark-800/40 text-dark-400 border border-dark-700/40'
                                }`}>
                                  {conv.is_active && <span className="w-1 h-1 rounded-full bg-emerald-400 animate-pulse" />}
                                  {conv.is_active ? 'ACTIVE' : 'IDLE'}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-2.5 px-3.5 text-right font-mono text-dark-800 dark:text-dark-200">
                            {conv.packet_count?.toLocaleString() || '0'}
                          </td>
                          <td className="py-2.5 px-3.5 text-right font-mono font-medium text-dark-900 dark:text-white">
                            {formatBytes(conv.byte_count)}
                          </td>
                          <td className="py-2.5 px-3.5 text-right text-xs text-dark-400 font-mono">
                            {formatDuration(conv.last_seen - conv.first_seen)}
                          </td>
                          <td className="py-2.5 px-3.5 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                onClick={() => navigate(`/packets/${analysisId}?conv=${convKey}`)}
                                className="px-2 py-1 text-[11px] font-medium rounded bg-surface border border-subtle text-dark-300 hover:text-white hover:border-primary-500/50 flex items-center gap-1 transition-colors"
                                title="Inspect socket session packets"
                              >
                                <Package className="w-3 h-3" />
                                <span>Packets</span>
                              </button>
                              <button
                                onClick={() => navigate(`/timeline/${analysisId}?filter=${conv.host1}`)}
                                className="px-2 py-1 text-[11px] font-medium rounded bg-surface border border-subtle text-dark-300 hover:text-white hover:border-primary-500/50 flex items-center gap-1 transition-colors"
                                title="View timeline events"
                              >
                                <Clock className="w-3 h-3" />
                                <span>Timeline</span>
                              </button>
                            </div>
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function formatBytes(bytes) {
  if (!bytes) return '0 B'
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`
}

function formatDuration(seconds) {
  if (!seconds || seconds < 0) return '0s'
  if (seconds < 60) return `${seconds.toFixed(1)}s`
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)}m`
  return `${(seconds / 3600).toFixed(1)}h`
}
