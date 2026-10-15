import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import axios from 'axios'
import {
  KeyRound,
  Search,
  Filter,
  Copy,
  Check,
  ExternalLink,
  Loader2,
  Globe,
  Hash,
  Link2,
  Server
} from 'lucide-react'
import CaptureHeader from '../components/CaptureHeader'

export default function IOCs() {
  const { analysisId } = useParams()
  const [loading, setLoading] = useState(true)
  const [iocs, setIocs] = useState([])
  const [filterType, setFilterType] = useState('all')
  const [search, setSearch] = useState('')
  const [copiedValue, setCopiedValue] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    loadIOCs(false)
    if (analysisId === 'live') {
      const interval = setInterval(() => {
        loadIOCs(true)
      }, 2500)
      return () => clearInterval(interval)
    }
  }, [analysisId])

  const loadIOCs = async (isBackground = false) => {
    if (!isBackground) setLoading(true)
    try {
      const response = await axios.get(`/api/analysis/${analysisId}/iocs`)
      setIocs(response.data.iocs || [])
    } catch (err) {
      if (!isBackground) setError(err.response?.data?.detail || 'Failed to load IOCs')
    } finally {
      if (!isBackground) setLoading(false)
    }
  }

  const handleCopy = (val) => {
    navigator.clipboard.writeText(val)
    setCopiedValue(val)
    setTimeout(() => setCopiedValue(null), 2000)
  }

  const filteredIOCs = iocs.filter((ioc) => {
    if (filterType !== 'all' && ioc.type !== filterType) return false
    if (search) {
      const q = search.toLowerCase()
      return ioc.value.toLowerCase().includes(q)
    }
    return true
  })

  const getTypeIcon = (type) => {
    switch (type) {
      case 'ip': return Server
      case 'domain': return Globe
      case 'url': return Link2
      case 'hash': return Hash
      default: return KeyRound
    }
  }

  const getTypeBadge = (type) => {
    switch (type) {
      case 'ip': return 'bg-blue-950/40 text-blue-300 border-blue-800/60'
      case 'domain': return 'bg-cyan-950/40 text-cyan-300 border-cyan-800/60'
      case 'url': return 'bg-amber-950/40 text-amber-300 border-amber-800/60'
      case 'hash': return 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60'
      default: return 'bg-slate-800/60 text-slate-300 border-slate-700/60'
    }
  }

  return (
    <div className="min-h-screen bg-canvas flex flex-col">
      <CaptureHeader />

      <div className="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
        {/* Header & Controls */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <KeyRound className="w-6 h-6 text-primary-500" />
              <h1 className="text-2xl font-bold text-dark-900 dark:text-white">
                Network Indicators of Interest (IOCs)
              </h1>
              {analysisId === 'live' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 self-center">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  LIVE STREAM
                </span>
              )}
            </div>
            <p className="text-xs text-dark-500 dark:text-dark-400 mt-1">
              Extracted IP addresses, domains, URLs, and cryptographic hashes discovered across capture payloads ({filteredIOCs.length} indicators)
            </p>
          </div>

          {/* Search & Filter */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-dark-400" />
              <input
                type="text"
                placeholder="Search IOC value..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="input pl-9 text-xs py-1.5 w-52"
              />
            </div>

            <div className="flex gap-1 bg-surface p-1 rounded-lg border border-subtle text-xs font-medium">
              {['all', 'ip', 'domain', 'url', 'hash'].map((t) => (
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

        {/* Table */}
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
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-dark-100/40 dark:bg-dark-900/60 border-b border-subtle text-[11px] font-semibold text-dark-400 uppercase tracking-wider">
                    <th className="py-2.5 px-3.5 w-28">Type</th>
                    <th className="py-2.5 px-3.5">Indicator Value</th>
                    <th className="py-2.5 px-3.5 w-24 text-right">Occurrences</th>
                    <th className="py-2.5 px-3.5 w-44">First Seen</th>
                    <th className="py-2.5 px-3.5 w-44">Last Seen</th>
                    <th className="py-2.5 px-3.5">Context & Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-subtle text-xs font-mono">
                  {filteredIOCs.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="py-12 text-center text-dark-400 text-xs font-sans">
                        No IOCs found matching query.
                      </td>
                    </tr>
                  ) : (
                    filteredIOCs.map((ioc, idx) => {
                      const Icon = getTypeIcon(ioc.type)
                      const badgeClass = getTypeBadge(ioc.type)

                      return (
                        <tr key={idx} className="hover:bg-surface-elevated/40 transition-colors">
                          <td className="py-2.5 px-3.5">
                            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold uppercase border ${badgeClass}`}>
                              <Icon className="w-3 h-3" />
                              {ioc.type}
                            </span>
                          </td>
                          <td className="py-2.5 px-3.5">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-dark-900 dark:text-white break-all max-w-lg">
                                {ioc.value}
                              </span>
                              <button
                                onClick={() => handleCopy(ioc.value)}
                                className="p-1 text-dark-400 hover:text-primary-400 rounded transition-colors"
                                title="Copy to clipboard"
                              >
                                {copiedValue === ioc.value ? (
                                  <Check className="w-3.5 h-3.5 text-green-400" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5" />
                                )}
                              </button>
                            </div>
                          </td>
                          <td className="py-2.5 px-3.5 text-right font-bold text-dark-800 dark:text-dark-200">
                            {ioc.count?.toLocaleString() || 1}
                          </td>
                          <td className="py-2.5 px-3.5 text-dark-400 text-[11px]">
                            {ioc.first_seen ? ioc.first_seen.replace('T', ' ').slice(0, 19) : '-'}
                          </td>
                          <td className="py-2.5 px-3.5 text-dark-400 text-[11px]">
                            {ioc.last_seen ? ioc.last_seen.replace('T', ' ').slice(0, 19) : '-'}
                          </td>
                          <td className="py-2.5 px-3.5 font-sans">
                            <div className="flex flex-wrap gap-1">
                              {(ioc.context || []).map((ctx, ci) => {
                                const pktMatch = ctx.match(/packet\s+(\d+)/i)
                                if (pktMatch) {
                                  return (
                                    <Link
                                      key={ci}
                                      to={`/packets/${analysisId}?packet=${pktMatch[1]}`}
                                      className="text-[11px] font-mono text-primary-400 hover:underline flex items-center gap-0.5"
                                    >
                                      {ctx} <ExternalLink className="w-2.5 h-2.5" />
                                    </Link>
                                  )
                                }
                                return (
                                  <span key={ci} className="text-dark-400 text-[11px] font-mono">
                                    {ctx}
                                  </span>
                                )
                              })}
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
