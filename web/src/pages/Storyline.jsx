import { useState, useEffect } from 'react'
import { useParams, Link, useNavigate, useSearchParams } from 'react-router-dom'
import axios from 'axios'
import {
  Compass,
  Loader2,
  Filter,
  Package,
  ArrowRight,
  ShieldAlert,
  Globe,
  Radio,
  Lock,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Pin,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Terminal
} from 'lucide-react'
import CaptureHeader from '../components/CaptureHeader'

export default function Storyline() {
  const { analysisId } = useParams()
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()

  const [loading, setLoading] = useState(true)
  const [storyline, setStoryline] = useState([])
  const [filterPhase, setFilterPhase] = useState('ALL')
  const [filterSeverity, setFilterSeverity] = useState('ALL')
  const [filterIp, setFilterIp] = useState(searchParams.get('ip') || '')
  const [expandedItems, setExpandedItems] = useState(new Set([0])) // First item expanded
  const [pinnedItems, setPinnedItems] = useState(() => {
    try {
      const saved = localStorage.getItem(`beacon_workspace_${analysisId}`)
      if (saved) {
        const data = JSON.parse(saved)
        return new Set(data.pinned_findings || [])
      }
    } catch (e) {
      // ignore
    }
    return new Set()
  })

  useEffect(() => {
    loadStoryline(false)
    if (analysisId === 'live') {
      const interval = setInterval(() => {
        if (document.hidden) return
        loadStoryline(true)
      }, 2500)
      return () => clearInterval(interval)
    }
  }, [analysisId])

  const loadStoryline = async (isBackground = false) => {
    if (!isBackground) setLoading(true)
    try {
      const res = await axios.get(`/api/analysis/${analysisId}/storyline`)
      setStoryline(res.data.storyline || [])
    } catch (err) {
      console.error('Failed to load storyline:', err)
    } finally {
      if (!isBackground) setLoading(false)
    }
  }

  const toggleExpand = (idx) => {
    const updated = new Set(expandedItems)
    if (updated.has(idx)) updated.delete(idx)
    else updated.add(idx)
    setExpandedItems(updated)
  }

  const togglePinStoryItem = (item) => {
    const key = item.id
    const updated = new Set(pinnedItems)
    if (updated.has(key)) {
      updated.delete(key)
    } else {
      updated.add(key)
    }
    setPinnedItems(updated)

    try {
      const storageKey = `beacon_workspace_${analysisId}`
      const saved = localStorage.getItem(storageKey)
      const data = saved ? JSON.parse(saved) : { pinned_hosts: [], pinned_findings: [], notes: '' }
      data.pinned_findings = Array.from(updated)
      localStorage.setItem(storageKey, JSON.stringify(data))
    } catch (e) {
      console.error('Failed to pin storyline item:', e)
    }
  }

  const filteredStory = storyline.filter((item) => {
    if (filterPhase !== 'ALL' && item.phase !== filterPhase) return false
    if (filterSeverity !== 'ALL' && (item.severity || 'info').toLowerCase() !== filterSeverity.toLowerCase()) return false
    if (filterIp && item.source_ip !== filterIp && item.destination_ip !== filterIp) return false
    return true
  })

  const getPhaseBadge = (phase) => {
    switch (phase) {
      case 'RECONNAISSANCE':
        return { label: 'Reconnaissance', color: 'bg-amber-100 text-amber-800 dark:bg-amber-950/40 dark:text-amber-400 border-amber-300 dark:border-amber-700' }
      case 'RESOLUTION':
        return { label: 'DNS Resolution', color: 'bg-cyan-950/40 text-cyan-300 border-cyan-800/60' }
      case 'EXPOSURE':
        return { label: 'Exposure', color: 'bg-rose-950/40 text-rose-300 border-rose-800/60' }
      case 'COMMAND_AND_CONTROL':
        return { label: 'Command & Control', color: 'bg-red-950/40 text-red-300 border-red-800/60' }
      case 'LATERAL_MOVEMENT':
        return { label: 'Lateral Movement', color: 'bg-sky-950/40 text-sky-300 border-sky-800/60' }
      default:
        return { label: phase, color: 'bg-slate-800/60 text-slate-300 border-slate-700/60' }
    }
  }

  const getSeverityBadge = (severity) => {
    const sev = (severity || 'info').toLowerCase()
    switch (sev) {
      case 'critical':
        return 'badge-critical'
      case 'high':
        return 'badge-high'
      case 'medium':
        return 'badge-medium'
      case 'low':
        return 'badge-low'
      default:
        return 'badge-info'
    }
  }

  return (
    <div className="min-h-screen bg-canvas flex flex-col">
      <CaptureHeader onModeChange={loadStoryline} />

      <div className="flex-1 p-6 max-w-7xl mx-auto w-full">
        {/* Title & Introduction */}
        <div className="mb-6">
          <div className="flex items-center gap-2">
            <Compass className="w-6 h-6 text-primary-500" />
            <h1 className="text-2xl font-bold text-dark-900 dark:text-white">
              Investigation Storyline
            </h1>
            {analysisId === 'live' && (
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 self-center">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                LIVE STREAM
              </span>
            )}
          </div>
          <p className="text-xs text-dark-500 dark:text-dark-400 mt-1">
            Chronological reconstruction of notable capture events—linking host reconnaissance, domain resolutions, authentication exchanges, and security findings into an end-to-end incident narrative.
          </p>
        </div>

        {/* Filter Toolbar */}
        <div className="card p-3 mb-6 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold text-dark-400 uppercase tracking-wider text-[11px] mr-1">
              Phase:
            </span>
            {['ALL', 'RECONNAISSANCE', 'RESOLUTION', 'EXPOSURE', 'COMMAND_AND_CONTROL', 'LATERAL_MOVEMENT'].map((p) => (
              <button
                key={p}
                onClick={() => setFilterPhase(p)}
                className={`px-2.5 py-1 rounded font-medium transition-colors ${
                  filterPhase === p
                    ? 'bg-primary-600 text-white shadow-sm'
                    : 'bg-dark-100 dark:bg-dark-800 text-dark-600 dark:text-dark-300 hover:bg-dark-200 dark:hover:bg-dark-700'
                }`}
              >
                {p === 'ALL' ? 'All Phases' : p.replace(/_/g, ' ')}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-3">
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="py-1 px-2.5 bg-white dark:bg-dark-900 border border-dark-200 dark:border-dark-700 rounded text-dark-800 dark:text-white text-xs"
            >
              <option value="ALL">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Informational</option>
            </select>

            {filterIp && (
              <button
                onClick={() => setFilterIp('')}
                className="px-2 py-1 rounded bg-dark-200 dark:bg-dark-800 text-dark-600 dark:text-dark-300 text-xs flex items-center gap-1"
              >
                <span>Filter IP: {filterIp}</span>
                <span className="font-bold">×</span>
              </button>
            )}
          </div>
        </div>

        {/* Storyline Timeline Container */}
        {loading ? (
          <div className="flex items-center justify-center py-24">
            <Loader2 className="w-8 h-8 text-primary-500 animate-spin" />
          </div>
        ) : filteredStory.length === 0 ? (
          <div className="card text-center py-16 text-dark-400">
            <AlertTriangle className="w-10 h-10 mx-auto mb-2 text-dark-400" />
            <p>No storyline milestones found for selected filters.</p>
          </div>
        ) : (
          <div className="relative pl-6 border-l-2 border-dark-200 dark:border-dark-800 space-y-6 my-4">
            {filteredStory.map((item, idx) => {
              const isExpanded = expandedItems.has(idx)
              const phaseBadge = getPhaseBadge(item.phase)
              const isPinned = pinnedItems.has(item.id)

              return (
                <div key={item.id || idx} className="relative group">
                  {/* Timeline Node Pip */}
                  <div
                    className={`absolute -left-[31px] top-4 w-4 h-4 rounded-full border-2 bg-slate-900 ${
                      item.severity === 'critical' || item.severity === 'high'
                        ? 'border-red-500 text-red-500'
                        : item.phase === 'RESOLUTION'
                        ? 'border-cyan-400 text-cyan-400'
                        : 'border-primary-500 text-primary-500'
                    }`}
                  />

                  {/* Narrative Milestone Card */}
                  <div
                    className={`card p-4 transition-all ${
                      item.is_finding
                        ? 'border-l-4 border-l-red-500 dark:border-l-red-500'
                        : 'border-l-4 border-l-primary-500 dark:border-l-primary-500'
                    } ${isPinned ? 'ring-1 ring-amber-500/50' : ''}`}
                  >
                    <div
                      className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 cursor-pointer"
                      onClick={() => toggleExpand(idx)}
                    >
                      <div className="space-y-1.5 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${phaseBadge.color}`}
                          >
                            {phaseBadge.label}
                          </span>

                          <span className={`badge ${getSeverityBadge(item.severity)} text-[10px] uppercase font-bold`}>
                            {item.severity || 'info'}
                          </span>

                          {item.protocol && (
                            <span className="badge bg-slate-800/80 text-slate-300 border border-slate-700/60 text-[10px] uppercase font-mono">
                              {item.protocol}
                            </span>
                          )}

                          <span className="text-xs text-dark-400 font-mono">
                            {item.timestamp}
                          </span>
                        </div>

                        <h3 className="text-base font-bold text-dark-900 dark:text-white flex items-center gap-2">
                          {item.title}
                        </h3>

                        <p className="text-xs text-dark-600 dark:text-dark-300 leading-relaxed">
                          {item.summary}
                        </p>
                      </div>

                      {/* Right controls */}
                      <div className="flex items-center gap-2 self-start sm:self-auto">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation()
                            togglePinStoryItem(item)
                          }}
                          className={`p-1.5 rounded text-xs transition-colors ${
                            isPinned
                              ? 'text-amber-500 bg-amber-500/10'
                              : 'text-dark-400 hover:text-dark-200'
                          }`}
                          title={isPinned ? 'Pinned to Workspace' : 'Pin to Workspace'}
                        >
                          <Pin className="w-4 h-4" />
                        </button>

                        <button
                          type="button"
                          className="p-1.5 rounded text-dark-400 hover:text-dark-200"
                        >
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>

                    {/* Detailed Expanded View */}
                    {isExpanded && (
                      <div className="mt-4 pt-4 border-t border-dark-100 dark:border-dark-800 space-y-3.5">
                        {/* Communicating Endpoints */}
                        {(item.source_ip || item.destination_ip) && (
                          <div className="flex flex-wrap items-center gap-4 p-2.5 rounded bg-dark-50 dark:bg-dark-900/60 font-mono text-xs border border-dark-200 dark:border-dark-800">
                            {item.source_ip && (
                              <div className="flex items-center gap-2">
                                <span className="text-dark-400">Source:</span>
                                <span className="text-dark-900 dark:text-white font-bold">{item.source_ip}</span>
                                <Link
                                  to={`/packets/${analysisId}?ip=${item.source_ip}`}
                                  className="text-primary-600 dark:text-primary-400 hover:underline flex items-center text-[11px]"
                                >
                                  Packets
                                </Link>
                              </div>
                            )}

                            {item.destination_ip && (
                              <div className="flex items-center gap-2">
                                <span className="text-dark-400">Target:</span>
                                <span className="text-dark-900 dark:text-white font-bold">{item.destination_ip}</span>
                                <Link
                                  to={`/packets/${analysisId}?ip=${item.destination_ip}`}
                                  className="text-primary-600 dark:text-primary-400 hover:underline flex items-center text-[11px]"
                                >
                                  Packets
                                </Link>
                              </div>
                            )}
                          </div>
                        )}

                        {/* Evidence Points */}
                        {item.evidence && item.evidence.length > 0 && (
                          <div>
                            <span className="text-[11px] font-semibold uppercase tracking-wider text-dark-400 block mb-1.5">
                              Observed Evidence:
                            </span>
                            <div className="space-y-1">
                              {item.evidence.map((ev, i) => (
                                <div
                                  key={i}
                                  className="text-xs font-mono bg-dark-100 dark:bg-dark-900 p-2 rounded text-dark-800 dark:text-dark-200 border-l-2 border-primary-500"
                                >
                                  {ev}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Exact Packet Jumps */}
                        {item.packet_numbers && item.packet_numbers.length > 0 && (
                          <div>
                            <span className="text-[11px] font-semibold uppercase tracking-wider text-dark-400 block mb-1.5">
                              Exact Correlated Packets ({item.packet_numbers.length}):
                            </span>
                            <div className="flex flex-wrap gap-1.5">
                              {item.packet_numbers.slice(0, 15).map((num) => (
                                <button
                                  key={num}
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    navigate(`/packets/${analysisId}?packet=${num}`)
                                  }}
                                  className="px-2 py-0.5 rounded bg-dark-200 hover:bg-primary-100 text-dark-800 hover:text-primary-700 dark:bg-dark-800 dark:hover:bg-primary-950/50 dark:text-dark-200 dark:hover:text-primary-300 text-xs font-mono transition-colors border border-dark-300 dark:border-dark-700"
                                  title={`Inspect packet #${num}`}
                                >
                                  #{num}
                                </button>
                              ))}
                              {item.packet_numbers.length > 15 && (
                                <span className="text-xs text-dark-400 self-center">
                                  +{item.packet_numbers.length - 15} more
                                </span>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Next Step Confirmation */}
                        {item.next_step && (
                          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded text-xs text-dark-700 dark:text-dark-300 flex items-start gap-2">
                            <Compass className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" />
                            <div>
                              <span className="font-semibold text-emerald-600 dark:text-emerald-400 block mb-0.5">
                                Recommended Confirmation Step:
                              </span>
                              {item.next_step}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
