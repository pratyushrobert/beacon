import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import axios from 'axios'
import {
  Clock,
  Filter,
  Search,
  Loader2,
  ExternalLink,
  Radio,
  Globe,
  Lock,
  Network
} from 'lucide-react'
import CaptureHeader from '../components/CaptureHeader'

export default function Timeline() {
  const { analysisId } = useParams()
  const [loading, setLoading] = useState(true)
  const [events, setEvents] = useState([])
  const [filterType, setFilterType] = useState('all')
  const [search, setSearch] = useState('')
  const [error, setError] = useState(null)

  useEffect(() => {
    loadTimeline(false)
    if (analysisId === 'live') {
      const interval = setInterval(() => {
        if (document.hidden) return
        loadTimeline(true)
      }, 2500)
      return () => clearInterval(interval)
    }
  }, [analysisId])

  const loadTimeline = async (isBackground = false) => {
    if (!isBackground) setLoading(true)
    try {
      const response = await axios.get(`/api/analysis/${analysisId}/timeline`, {
        params: { limit: 500 }
      })
      setEvents(response.data.timeline || [])
    } catch (err) {
      if (!isBackground) setError(err.response?.data?.detail || 'Failed to load timeline')
    } finally {
      if (!isBackground) setLoading(false)
    }
  }

  const filteredEvents = events.filter((ev) => {
    if (filterType !== 'all') {
      if (filterType === 'tcp' && !ev.event_type.startsWith('TCP')) return false
      if (filterType === 'dns' && !ev.event_type.startsWith('DNS')) return false
      if (filterType === 'http' && !ev.event_type.startsWith('HTTP')) return false
      if (filterType === 'tls' && !ev.event_type.startsWith('TLS')) return false
    }
    if (search) {
      const q = search.toLowerCase()
      return (
        (ev.message && ev.message.toLowerCase().includes(q)) ||
        (ev.source && ev.source.toLowerCase().includes(q)) ||
        (ev.destination && ev.destination.toLowerCase().includes(q))
      )
    }
    return true
  })

  const getEventIcon = (type) => {
    if (type.startsWith('DNS')) return Globe
    if (type.startsWith('HTTP')) return Network
    if (type.startsWith('TLS')) return Lock
    return Radio
  }

  const getEventColor = (type) => {
    if (type.includes('RST') || type.includes('FAIL')) return 'bg-red-950/40 text-red-300 border-red-800/60'
    if (type.startsWith('DNS')) return 'bg-cyan-950/40 text-cyan-300 border-cyan-800/60'
    if (type.startsWith('HTTP')) return 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60'
    if (type.startsWith('TLS')) return 'bg-amber-950/40 text-amber-300 border-amber-800/60'
    return 'bg-sky-950/40 text-sky-300 border-sky-800/60'
  }

  return (
    <div className="min-h-screen bg-canvas flex flex-col">
      <CaptureHeader />

      <div className="flex-1 p-6 max-w-6xl mx-auto w-full space-y-6">
        {/* Header & Controls */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Clock className="w-6 h-6 text-primary-500" />
              <h1 className="text-2xl font-bold text-dark-900 dark:text-white">
                Capture Event Timeline
              </h1>
              {analysisId === 'live' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  LIVE STREAM
                </span>
              )}
            </div>
            <p className="text-xs text-dark-500 dark:text-dark-400 mt-1">
              Chronological sequence of key connection handshakes, DNS lookups, and protocol exchanges ({filteredEvents.length} events)
            </p>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-dark-400" />
              <input
                type="text"
                placeholder="Search timeline..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="input pl-9 text-xs py-1.5 w-48"
              />
            </div>

            <div className="flex gap-1 bg-surface p-1 rounded-lg border border-subtle text-xs font-medium">
              {['all', 'tcp', 'dns', 'http', 'tls'].map((t) => (
                <button
                  key={t}
                  onClick={() => setFilterType(t)}
                  className={`px-2.5 py-1 rounded uppercase text-[11px] font-semibold transition-colors ${
                    filterType === t
                      ? 'bg-primary-600 text-white shadow-sm'
                      : 'text-dark-400 hover:text-white'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Live Observation Banner */}
        {analysisId === 'live' && (
          <div className="card p-3 bg-emerald-500/5 border-emerald-500/20 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-medium text-emerald-300">
                Streaming live network events in real time. Connection handshakes, DNS lookups, and resets appear as observed.
              </span>
            </div>
            <Link
              to="/live"
              className="text-xs text-emerald-400 hover:text-emerald-300 font-mono font-medium underline flex items-center gap-1"
            >
              Live Console →
            </Link>
          </div>
        )}

        {/* Timeline Stream */}
        {loading ? (
          <div className="flex items-center justify-center py-24">
            <Loader2 className="w-8 h-8 text-primary-500 animate-spin" />
          </div>
        ) : error ? (
          <div className="card p-6 text-center text-red-400">
            {error}
          </div>
        ) : (
          <div className="relative border-l-2 border-subtle ml-3 pl-6 space-y-4 my-4">
            {filteredEvents.length === 0 ? (
              <div className="card py-12 text-center text-dark-400 text-xs">
                No events found matching current criteria.
              </div>
            ) : (
              filteredEvents.map((ev, i) => {
                const Icon = getEventIcon(ev.event_type)
                const colorClass = getEventColor(ev.event_type)

                return (
                  <div key={i} className="relative group">
                    {/* Timeline node dot */}
                    <div className="absolute -left-[31px] top-4 w-3.5 h-3.5 rounded-full border-2 border-slate-900 bg-primary-500 group-hover:scale-125 transition-transform" />

                    <div className="card p-4 hover:border-primary-500/50 transition-colors">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase border ${colorClass}`}>
                            {ev.event_type}
                          </span>
                          <span className="text-xs font-mono text-dark-400">
                            {ev.timestamp ? ev.timestamp.replace('T', ' ').slice(0, 23) : ''}
                          </span>
                        </div>

                        {ev.packet_number && (
                          <Link
                            to={`/packets/${analysisId}?packet=${ev.packet_number}`}
                            className="text-xs font-mono text-primary-400 hover:underline flex items-center gap-1 self-start sm:self-auto"
                          >
                            Inspect Packet #{ev.packet_number}
                            <ExternalLink className="w-3 h-3" />
                          </Link>
                        )}
                      </div>

                      <div className="font-mono text-xs text-dark-900 dark:text-dark-100 mb-2">
                        {ev.message}
                      </div>

                      <div className="text-[11px] text-dark-400 flex flex-wrap items-center gap-2 font-mono">
                        <span>From: <strong className="text-dark-200">{ev.source || 'N/A'}</strong></span>
                        <span>→</span>
                        <span>To: <strong className="text-dark-200">{ev.destination || 'N/A'}</strong></span>
                      </div>
                    </div>
                  </div>
                )
              })
            )}
          </div>
        )}
      </div>
    </div>
  )
}
