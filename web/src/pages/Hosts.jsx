import { useState, useEffect } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import axios from 'axios'
import {
  Loader2,
  Users,
  Search,
  Package,
  Clock,
  ExternalLink,
  ShieldAlert,
  Server,
  Pin
} from 'lucide-react'
import CaptureHeader from '../components/CaptureHeader'

export default function Hosts() {
  const { analysisId } = useParams()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [hosts, setHosts] = useState([])
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all') // all, internal, external
  const [error, setError] = useState(null)
  const [pinnedHosts, setPinnedHosts] = useState(() => {
    try {
      const saved = localStorage.getItem(`beacon_workspace_${analysisId}`)
      if (saved) {
        const data = JSON.parse(saved)
        return new Set(data.pinned_hosts || [])
      }
    } catch (e) {}
    return new Set()
  })

  useEffect(() => {
    loadHosts(false)
    if (analysisId === 'live') {
      const interval = setInterval(() => {
        loadHosts(true)
      }, 2500)
      return () => clearInterval(interval)
    }
  }, [analysisId])

  const loadHosts = async (isBackground = false) => {
    if (!isBackground) setLoading(true)
    try {
      const response = await axios.get(`/api/analysis/${analysisId}/hosts`, {
        params: { top: 100 }
      })
      setHosts(response.data.hosts || [])
    } catch (err) {
      if (!isBackground) setError(err.response?.data?.detail || 'Failed to load hosts')
    } finally {
      if (!isBackground) setLoading(false)
    }
  }

  const togglePinHost = (ip) => {
    const updated = new Set(pinnedHosts)
    if (updated.has(ip)) {
      updated.delete(ip)
    } else {
      updated.add(ip)
    }
    setPinnedHosts(updated)

    try {
      const storageKey = `beacon_workspace_${analysisId}`
      const saved = localStorage.getItem(storageKey)
      const data = saved ? JSON.parse(saved) : { pinned_hosts: [], pinned_findings: [], notes: '' }
      data.pinned_hosts = Array.from(updated)
      localStorage.setItem(storageKey, JSON.stringify(data))
    } catch (e) {
      console.error('Failed to update workspace pinned hosts:', e)
    }
  }

  const filteredHosts = hosts.filter((host) => {
    if (typeFilter === 'internal' && !host.is_internal) return false
    if (typeFilter === 'external' && host.is_internal) return false
    if (search.trim()) {
      const q = search.toLowerCase()
      const matchIp = host.ip.toLowerCase().includes(q)
      const matchProto = host.protocols?.some((p) => p.toLowerCase().includes(q))
      if (!matchIp && !matchProto) return false
    }
    return true
  })

  return (
    <div className="min-h-screen bg-canvas flex flex-col">
      <CaptureHeader />

      <div className="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
        {/* Header & Controls */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Server className="w-6 h-6 text-primary-500" />
              <h1 className="text-2xl font-bold text-dark-900 dark:text-white">
                Host Inventory
              </h1>
              {analysisId === 'live' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  LIVE INVENTORY
                </span>
              )}
            </div>
            <p className="text-xs text-dark-500 dark:text-dark-400 mt-1">
              Active endpoint inventory across private and public subnets ({filteredHosts.length} of {hosts.length} hosts shown)
            </p>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-dark-400" />
              <input
                type="text"
                placeholder="Filter IP or protocol..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="input pl-9 text-xs py-1.5 w-60"
              />
            </div>

            <div className="flex bg-surface p-1 rounded-lg border border-subtle">
              {['all', 'internal', 'external'].map((t) => (
                <button
                  key={t}
                  onClick={() => setTypeFilter(t)}
                  className={`
                    px-2.5 py-1 rounded text-xs font-medium capitalize transition-all
                    ${typeFilter === t
                      ? 'bg-primary-600 text-white shadow-sm'
                      : 'text-dark-400 hover:text-white'
                    }
                  `}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Hosts Table */}
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
                    <th className="text-left py-2.5 px-3.5">IP Address</th>
                    <th className="text-center py-2.5 px-3.5">Scope</th>
                    <th className="text-right py-2.5 px-3.5">Sent Pkts</th>
                    <th className="text-right py-2.5 px-3.5">Recv Pkts</th>
                    <th className="text-right py-2.5 px-3.5">Volume</th>
                    <th className="text-left py-2.5 px-3.5">Protocols</th>
                    <th className="text-right py-2.5 px-3.5">Investigate</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-subtle">
                  {filteredHosts.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-12 text-center text-dark-400 text-xs">
                        No hosts match your filter criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredHosts.map((host, index) => {
                      const isPinned = pinnedHosts.has(host.ip)
                      return (
                        <tr
                          key={host.ip || index}
                          className="hover:bg-surface-elevated/40 transition-colors text-xs"
                        >
                          <td className="py-2.5 px-3.5 text-dark-400 font-mono text-[11px]">
                            {index + 1}
                          </td>
                          <td className="py-2.5 px-3.5">
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => togglePinHost(host.ip)}
                                className={`p-1 rounded transition-colors ${
                                  isPinned
                                    ? 'text-amber-400 bg-amber-400/10'
                                    : 'text-dark-500 hover:text-dark-300'
                                }`}
                                title={isPinned ? 'Pinned to Workspace' : 'Pin to Workspace'}
                              >
                                <Pin className="w-3.5 h-3.5" />
                              </button>
                              <span className="font-mono font-bold text-dark-900 dark:text-white">
                                {host.ip}
                              </span>
                              {analysisId === 'live' && host.is_active && (
                                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30" title="Active communication observed recently">
                                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                                  ACTIVE
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-2.5 px-3.5 text-center">
                            {host.is_internal ? (
                              <span className="badge bg-blue-950/40 text-blue-300 border border-blue-800/60 text-[10px]">
                                Internal
                              </span>
                            ) : (
                              <span className="badge bg-slate-800/60 text-slate-300 border border-slate-700/60 text-[10px]">
                                External
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-3.5 text-right font-mono text-dark-800 dark:text-dark-200">
                            {host.packets_sent?.toLocaleString() || '0'}
                          </td>
                          <td className="py-2.5 px-3.5 text-right font-mono text-dark-800 dark:text-dark-200">
                            {host.packets_received?.toLocaleString() || '0'}
                          </td>
                          <td className="py-2.5 px-3.5 text-right font-mono font-medium text-dark-900 dark:text-white">
                            {formatBytes(host.total_bytes)}
                          </td>
                          <td className="py-2.5 px-3.5">
                            <div className="flex flex-wrap gap-1">
                              {host.protocols?.slice(0, 4).map((protocol, i) => (
                                <span
                                  key={i}
                                  className="badge bg-slate-800/80 text-slate-300 border border-slate-700/60 text-[10px] uppercase font-mono"
                                >
                                  {protocol}
                                </span>
                              ))}
                              {host.protocols?.length > 4 && (
                                <span className="text-[10px] text-dark-400 self-center font-mono">
                                  +{host.protocols.length - 4}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-2.5 px-3.5 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                onClick={() => navigate(`/packets/${analysisId}?ip=${host.ip}`)}
                                className="px-2 py-1 text-[11px] font-medium rounded bg-surface border border-subtle text-dark-300 hover:text-white hover:border-primary-500/50 flex items-center gap-1 transition-colors"
                                title="Inspect all packets for this host"
                              >
                                <Package className="w-3 h-3" />
                                <span>Packets</span>
                              </button>
                              <button
                                onClick={() => navigate(`/timeline/${analysisId}?filter=${host.ip}`)}
                                className="px-2 py-1 text-[11px] font-medium rounded bg-surface border border-subtle text-dark-300 hover:text-white hover:border-primary-500/50 flex items-center gap-1 transition-colors"
                                title="View timeline events involving this host"
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
