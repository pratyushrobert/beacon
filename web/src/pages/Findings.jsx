import { useState, useEffect } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import axios from 'axios'
import {
  Loader2,
  AlertTriangle,
  Filter,
  ChevronDown,
  ChevronUp,
  Package,
  Compass,
  Lightbulb,
  Info,
  ArrowRight,
  Pin,
  CheckCircle,
  ShieldAlert,
  HelpCircle,
  Share2
} from 'lucide-react'
import CaptureHeader from '../components/CaptureHeader'
import { useMode } from '../context/ModeContext'

export default function Findings() {
  const { analysisId } = useParams()
  const navigate = useNavigate()
  const { mode, isFreeBird, isBlue, isRed } = useMode()
  const [loading, setLoading] = useState(true)
  const [findings, setFindings] = useState([])
  const [error, setError] = useState(null)
  const [selectedSeverity, setSelectedSeverity] = useState('all')
  const [expandedFindings, setExpandedFindings] = useState(new Set([0])) // expand first by default
  const [pinnedFindings, setPinnedFindings] = useState(() => {
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
    loadFindings(false)
    if (analysisId === 'live') {
      const interval = setInterval(() => {
        if (document.hidden) return
        loadFindings(true)
      }, 2500)
      return () => clearInterval(interval)
    }
  }, [analysisId, selectedSeverity])

  const loadFindings = async (isBackground = false) => {
    if (!isBackground) setLoading(true)
    try {
      const params = selectedSeverity !== 'all' ? { severity: selectedSeverity } : {}
      const response = await axios.get(`/api/analysis/${analysisId}/findings`, { params })
      setFindings(response.data.findings || [])
    } catch (err) {
      if (!isBackground) setError(err.response?.data?.detail || 'Failed to load findings')
    } finally {
      if (!isBackground) setLoading(false)
    }
  }

  const toggleExpanded = (index) => {
    const newExpanded = new Set(expandedFindings)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedFindings(newExpanded)
  }

  const togglePin = (finding) => {
    const key = finding.title || finding.id
    const updated = new Set(pinnedFindings)
    if (updated.has(key)) {
      updated.delete(key)
    } else {
      updated.add(key)
    }
    setPinnedFindings(updated)

    try {
      const storageKey = `beacon_workspace_${analysisId}`
      const saved = localStorage.getItem(storageKey)
      const data = saved ? JSON.parse(saved) : { pinned_hosts: [], pinned_findings: [], notes: '' }
      data.pinned_findings = Array.from(updated)
      localStorage.setItem(storageKey, JSON.stringify(data))
    } catch (e) {
      console.error('Failed to pin finding:', e)
    }
  }

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info']
  const sortedFindings = [...findings].sort((a, b) => {
    return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  })

  // Generate benign hypothesis scenario based on category
  const getBenignExplanation = (finding) => {
    const cat = (finding.category || '').toLowerCase()
    const title = (finding.title || '').toLowerCase()
    if (cat.includes('scan') || title.includes('scan')) {
      return 'Legitimate vulnerability vulnerability assessment scanners (e.g. Nessus, Qualys), network inventory crawlers, or local monitoring probes.'
    }
    if (cat.includes('credential') || title.includes('cleartext') || title.includes('auth')) {
      return 'Internal development/testing staging endpoints, legacy web services, or local diagnostic tools not yet migrated to HTTPS.'
    }
    if (cat.includes('token') || title.includes('token')) {
      return 'Public telemetry tracking tokens, stateless session identifiers, or public API query keys intended for client-side identification.'
    }
    if (cat.includes('c2') || title.includes('beacon')) {
      return 'Legitimate IoT or software heartbeat telemetry, regular NTP sync, or software update check loops.'
    }
    if (cat.includes('internal') || title.includes('ssh') || title.includes('smb')) {
      return 'Routine systems administration, authorized SSH maintenance session, or internal backup synchronization.'
    }
    return 'Authorized administrative or operational routine matching anomaly signature.'
  }

  return (
    <div className="min-h-screen bg-canvas text-dark-100 flex flex-col">
      <CaptureHeader onModeChange={loadFindings} />

      <div className="flex-1 p-6 max-w-7xl mx-auto w-full">
        {/* Header */}
        <div className="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-dark-900 dark:text-white flex items-center gap-2">
              <ShieldAlert className="w-6 h-6 text-primary-500" />
              <span>Explainable Security Findings</span>
              {analysisId === 'live' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 self-center">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  LIVE STREAM
                </span>
              )}
            </h1>
            <p className="text-xs text-dark-500 dark:text-dark-400 mt-1">
              Structured breakdown of observed network evidence, detection logic, benign alternative explanations, and confirmation steps.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Link
              to={`/storyline/${analysisId}`}
              className="btn btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5"
            >
              <span>View Storyline</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
            <Link
              to={`/graph/${analysisId}`}
              className="btn btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5"
            >
              <Share2 className="w-3.5 h-3.5" />
              <span>Evidence Graph</span>
            </Link>
          </div>
        </div>

        {/* Live Incident Retention Banner */}
        {analysisId === 'live' && (
          <div className="card p-3 mb-6 bg-emerald-500/5 border-emerald-500/20 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-medium text-emerald-300">
                Evaluating streaming detection rules continuously. High and critical detections trigger automated packet retention and incident capture.
              </span>
            </div>
            <Link
              to="/live"
              className="text-xs text-emerald-400 hover:text-emerald-300 font-mono font-medium underline flex items-center gap-1 shrink-0"
            >
              Export Incident PCAPs (/live) →
            </Link>
          </div>
        )}

        {/* Severity Filters */}
        <div className="card p-3 mb-6 flex flex-wrap items-center gap-2 text-xs">
          <Filter className="w-4 h-4 text-dark-400 mr-2" />
          {['all', 'critical', 'high', 'medium', 'low', 'info'].map((severity) => (
            <button
              key={severity}
              onClick={() => setSelectedSeverity(severity)}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                selectedSeverity === severity
                  ? 'bg-primary-600 text-white shadow-sm'
                  : 'bg-dark-100 dark:bg-dark-800 text-dark-600 dark:text-dark-300 hover:bg-dark-200 dark:hover:bg-dark-700'
              }`}
            >
              {severity.charAt(0).toUpperCase() + severity.slice(1)}
            </button>
          ))}
        </div>

        {/* Findings List */}
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-8 h-8 text-primary-500 animate-spin" />
          </div>
        ) : error ? (
          <div className="card p-4 text-red-600 dark:text-red-400 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 shrink-0" />
            <span>{error}</span>
          </div>
        ) : sortedFindings.length === 0 ? (
          <div className="card text-center py-16 text-dark-400">
            <AlertTriangle className="w-10 h-10 mx-auto mb-2 text-dark-400" />
            <p>No security findings detected for the selected filter.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {sortedFindings.map((finding, index) => {
              const isExpanded = expandedFindings.has(index)
              const isPinned = pinnedFindings.has(finding.title || finding.id)
              const benignExplanation = getBenignExplanation(finding)

              return (
                <div
                  key={index}
                  className={`card p-5 border-l-4 transition-all ${
                    finding.severity === 'critical'
                      ? 'border-l-red-600'
                      : finding.severity === 'high'
                      ? 'border-l-orange-500'
                      : finding.severity === 'medium'
                      ? 'border-l-yellow-500'
                      : finding.severity === 'low'
                      ? 'border-l-blue-500'
                      : 'border-l-slate-500'
                  } ${isPinned ? 'ring-1 ring-amber-500/50' : ''}`}
                >
                  {/* Card Header */}
                  <div
                    className="flex items-start justify-between cursor-pointer gap-4"
                    onClick={() => toggleExpanded(index)}
                  >
                    <div className="flex-1 space-y-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`badge badge-${finding.severity} uppercase text-[10px] font-bold`}>
                          {finding.severity}
                        </span>
                        <span className="badge badge-info uppercase text-[10px] font-mono">
                          Confidence: {finding.confidence}
                        </span>
                        <span className="text-xs text-dark-400 font-semibold uppercase tracking-wider">
                          {(finding.category || 'DETECTION').replace(/_/g, ' ')}
                        </span>
                        {finding.protocol && (
                          <span className="badge bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300 uppercase text-[10px] font-mono">
                            {finding.protocol}
                          </span>
                        )}
                      </div>

                      <h3 className="text-base font-bold text-dark-900 dark:text-white">
                        {finding.title}
                      </h3>

                      <p className="text-xs text-dark-600 dark:text-dark-300">
                        {finding.description}
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation()
                          togglePin(finding)
                        }}
                        className={`p-1.5 rounded transition-colors ${
                          isPinned ? 'text-amber-500 bg-amber-500/10' : 'text-dark-400 hover:text-dark-200'
                        }`}
                        title={isPinned ? 'Pinned to Workspace' : 'Pin to Workspace'}
                      >
                        <Pin className="w-4 h-4" />
                      </button>

                      <button
                        type="button"
                        className="p-1.5 hover:bg-dark-100 dark:hover:bg-dark-800 rounded text-dark-400"
                      >
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Expanded Explainability Details */}
                  {isExpanded && (
                    <div className="mt-5 pt-4 border-t border-dark-200 dark:border-dark-800 space-y-4">
                      {/* Grid: Endpoints Involved */}
                      {(finding.source_ip || finding.destination_ip) && (
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3 rounded-lg bg-dark-50 dark:bg-dark-900/70 border border-dark-200 dark:border-dark-800 font-mono text-xs">
                          {finding.source_ip && (
                            <div>
                              <div className="text-[11px] text-dark-400 font-semibold uppercase mb-0.5">
                                Originating Host:
                              </div>
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-dark-900 dark:text-white">{finding.source_ip}</span>
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    navigate(`/packets/${analysisId}?ip=${finding.source_ip}`)
                                  }}
                                  className="text-primary-600 dark:text-primary-400 hover:underline text-[11px]"
                                >
                                  Explore Packets
                                </button>
                              </div>
                            </div>
                          )}

                          {finding.destination_ip && (
                            <div>
                              <div className="text-[11px] text-dark-400 font-semibold uppercase mb-0.5">
                                Target Host:
                              </div>
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-dark-900 dark:text-white">{finding.destination_ip}</span>
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    navigate(`/packets/${analysisId}?ip=${finding.destination_ip}`)
                                  }}
                                  className="text-primary-600 dark:text-primary-400 hover:underline text-[11px]"
                                >
                                  Explore Packets
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Section 1: Observed Evidence (Concrete signals) */}
                      {finding.evidence && finding.evidence.length > 0 && (
                        <div>
                          <div className="text-[11px] font-bold uppercase tracking-wider text-dark-400 mb-1.5 flex items-center gap-1.5">
                            <CheckCircle className="w-3.5 h-3.5 text-primary-500" />
                            <span>1. Observed Network Evidence</span>
                          </div>
                          <ul className="space-y-1">
                            {finding.evidence.map((item, i) => (
                              <li
                                key={i}
                                className="text-xs font-mono bg-dark-50 dark:bg-dark-900 p-2.5 rounded text-dark-800 dark:text-dark-200 border-l-2 border-primary-500"
                              >
                                {item}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Section 2: Detection Rationale & Baseline Rule */}
                      {finding.detection_rationale && (
                        <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs">
                          <div className="flex items-center gap-1.5 font-bold text-amber-700 dark:text-amber-400 mb-1">
                            <Info className="w-3.5 h-3.5" />
                            <span>2. Detection Rule Logic & Thresholds</span>
                          </div>
                          <p className="text-dark-700 dark:text-dark-300 leading-relaxed">
                            {finding.detection_rationale}
                          </p>
                        </div>
                      )}

                      {/* Section 3: Benign Alternative Explanations / False Positive Scenarios */}
                      <div className="p-3 rounded-lg bg-slate-100 dark:bg-dark-900 border border-slate-300 dark:border-dark-700 text-xs">
                        <div className="flex items-center gap-1.5 font-bold text-slate-700 dark:text-slate-300 mb-1">
                          <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
                          <span>3. Benign Explanations & False Positive Scenarios</span>
                        </div>
                        <p className="text-dark-600 dark:text-dark-400 leading-relaxed">
                          {benignExplanation}
                        </p>
                      </div>

                      {/* Section 4: Recommended Next Steps */}
                      {finding.next_step && (
                        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs">
                          <div className="flex items-center gap-1.5 font-bold text-emerald-700 dark:text-emerald-400 mb-1">
                            <Compass className="w-3.5 h-3.5" />
                            <span>4. Recommended Confirmation & Pivot Step</span>
                          </div>
                          <p className="text-dark-700 dark:text-dark-300 leading-relaxed">
                            {finding.next_step}
                          </p>
                        </div>
                      )}

                      {/* Section 5: Exact Correlated Packets */}
                      {finding.related_packets && finding.related_packets.length > 0 && (
                        <div>
                          <div className="text-[11px] font-bold uppercase tracking-wider text-dark-400 mb-1.5">
                            Exact Correlated Packets ({finding.related_packets.length}):
                          </div>
                          <div className="flex flex-wrap gap-1.5">
                            {finding.related_packets.slice(0, 25).map((pktNum) => (
                              <button
                                key={pktNum}
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  navigate(`/packets/${analysisId}?packet=${pktNum}`)
                                }}
                                className="px-2 py-0.5 rounded bg-dark-100 hover:bg-primary-100 text-dark-800 hover:text-primary-700 dark:bg-dark-800 dark:hover:bg-primary-950/40 dark:text-dark-300 dark:hover:text-primary-300 text-xs font-mono transition-colors border border-dark-200 dark:border-dark-700"
                                title={`Inspect packet #${pktNum}`}
                              >
                                #{pktNum}
                              </button>
                            ))}
                            {finding.related_packets.length > 25 && (
                              <span className="text-xs text-dark-400 self-center">
                                +{finding.related_packets.length - 25} more
                              </span>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Section 6: Remediation Recommendation */}
                      {finding.recommendation && (
                        <div className="p-3 rounded-lg bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-900/30 text-xs">
                          <div className="flex items-center gap-1.5 font-bold text-blue-900 dark:text-blue-300 mb-1">
                            <Lightbulb className="w-3.5 h-3.5 text-blue-500" />
                            <span>Remediation Recommendation</span>
                          </div>
                          <p className="text-blue-800 dark:text-blue-300 leading-relaxed">
                            {finding.recommendation}
                          </p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
