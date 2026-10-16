import { useState, useEffect } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import axios from 'axios'
import {
  History,
  Shield,
  ShieldAlert,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  CheckCircle2,
  HelpCircle,
  ExternalLink,
  Search,
  Filter,
  Check,
  X,
  MessageSquare,
  Sparkles,
  Layers,
  Server,
  Network,
  Clock,
  ArrowRight,
  Database,
  RefreshCw,
  Eye,
  Sliders,
  AlertOctagon,
  FileText
} from 'lucide-react'
import CaptureHeader from '../components/CaptureHeader'
import { useMode } from '../context/ModeContext'

export default function MemoryView() {
  const { analysisId: routeAnalysisId } = useParams()
  const navigate = useNavigate()
  const { isFreeBird, isBlue, isRed } = useMode()

  const [analysisId, setAnalysisId] = useState(routeAnalysisId || '')
  const [loading, setLoading] = useState(true)
  const [briefing, setBriefing] = useState(null)
  const [baselineStatus, setBaselineStatus] = useState(null)
  const [recurringAnomalies, setRecurringAnomalies] = useState([])
  const [historyCaptures, setHistoryCaptures] = useState([])
  const [availableAnalyses, setAvailableAnalyses] = useState([])
  const [error, setError] = useState(null)

  // Navigation & Filtering
  const [activeTab, setActiveTab] = useState('changes') // 'changes' | 'recurring' | 'catalog'
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [confidenceFilter, setConfidenceFilter] = useState('all')
  const [hideExpected, setHideExpected] = useState(false)

  // Analyst Feedback Modal
  const [feedbackModalItem, setFeedbackModalItem] = useState(null)
  const [feedbackStatus, setFeedbackStatus] = useState('expected')
  const [feedbackNote, setFeedbackNote] = useState('')
  const [feedbackSubmitting, setFeedbackSubmitting] = useState(false)

  // Initial load
  useEffect(() => {
    loadGlobalCatalog()
  }, [])

  useEffect(() => {
    if (routeAnalysisId) {
      setAnalysisId(routeAnalysisId)
      loadMemoryData(routeAnalysisId)
    } else if (availableAnalyses.length > 0 && !analysisId) {
      const first = availableAnalyses[0].id
      setAnalysisId(first)
      loadMemoryData(first)
    }
  }, [routeAnalysisId, availableAnalyses])

  const loadGlobalCatalog = async () => {
    try {
      const [analysesRes, statusRes, recurringRes, historyRes] = await Promise.all([
        axios.get('/api/analyses').catch(() => ({ data: { analyses: [] } })),
        axios.get('/api/memory/status').catch(() => ({ data: null })),
        axios.get('/api/memory/recurring').catch(() => ({ data: { recurring_anomalies: [] } })),
        axios.get('/api/memory/history').catch(() => ({ data: { captures: [] } })),
      ])

      const completed = (analysesRes.data.analyses || []).filter((a) => a.status === 'complete' || a.id === 'live')
      setAvailableAnalyses(completed)
      setBaselineStatus(statusRes.data)
      setRecurringAnomalies(recurringRes.data.recurring_anomalies || [])
      setHistoryCaptures(historyRes.data.captures || [])

      if (!routeAnalysisId && completed.length > 0) {
        setAnalysisId(completed[0].id)
        loadMemoryData(completed[0].id)
      } else if (!routeAnalysisId && completed.length === 0) {
        setLoading(false)
      }
    } catch (err) {
      console.error('Failed to load global memory catalog:', err)
      setLoading(false)
    }
  }

  useEffect(() => {
    if (analysisId === 'live') {
      const interval = setInterval(() => {
        if (document.hidden) return
        loadMemoryData('live', true)
      }, 3500)
      return () => clearInterval(interval)
    }
  }, [analysisId])

  const loadMemoryData = async (targetId, isBackground = false) => {
    if (!targetId) return
    if (!isBackground) setLoading(true)
    setError(null)
    try {
      const res = await axios.get(`/api/analysis/${targetId}/memory`)
      setBriefing(res.data)
      // Also refresh baseline status
      const statusRes = await axios.get('/api/memory/status')
      setBaselineStatus(statusRes.data)
    } catch (err) {
      console.error('Failed to load memory briefing:', err)
      if (!isBackground) setError(err.response?.data?.detail || 'Failed to generate memory change briefing for this capture.')
    } finally {
      if (!isBackground) setLoading(false)
    }
  }

  const handleCaptureSwitch = (newId) => {
    if (newId === analysisId) return
    navigate(`/memory/${newId}`)
    setAnalysisId(newId)
    loadMemoryData(newId)
  }

  const openFeedbackModal = (item) => {
    setFeedbackModalItem(item)
    setFeedbackStatus(item.analyst_feedback?.status || 'expected')
    setFeedbackNote(item.analyst_feedback?.analyst_note || '')
  }

  const closeFeedbackModal = () => {
    setFeedbackModalItem(null)
    setFeedbackNote('')
    setFeedbackSubmitting(false)
  }

  const submitFeedback = async (e) => {
    e.preventDefault()
    if (!feedbackModalItem) return
    setFeedbackSubmitting(true)
    try {
      const isExp = feedbackStatus === 'expected'
      await axios.post('/api/memory/feedback', {
        target_key: feedbackModalItem.entity,
        target_type: feedbackModalItem.entity_type || 'host',
        status: feedbackStatus,
        is_expected: isExp,
        note: feedbackNote,
      })
      // Refresh memory data to reflect new priority scores and feedback badges
      await loadMemoryData(analysisId)
      closeFeedbackModal()
    } catch (err) {
      console.error('Failed to save feedback:', err)
      alert(err.response?.data?.detail || 'Failed to submit analyst feedback.')
      setFeedbackSubmitting(false)
    }
  }

  const formatDuration = (seconds) => {
    if (!seconds && seconds !== 0) return '0s'
    if (seconds < 60) return `${seconds.toFixed(0)}s`
    const mins = Math.floor(seconds / 60)
    const secs = (seconds % 60).toFixed(0)
    if (mins < 60) return `${mins}m ${secs}s`
    const hours = (mins / 60).toFixed(1)
    return `${hours} hrs`
  }

  // Filter items
  const filteredItems = (briefing?.items || []).filter((item) => {
    // Category filter
    if (selectedCategory !== 'all' && item.category !== selectedCategory) {
      return false
    }
    // Confidence filter
    if (confidenceFilter !== 'all' && item.confidence !== confidenceFilter) {
      return false
    }
    // Hide expected filter
    if (hideExpected && item.analyst_feedback?.is_expected) {
      return false
    }
    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      const matchTitle = item.title?.toLowerCase().includes(q)
      const matchEntity = item.entity?.toLowerCase().includes(q)
      const matchFact = item.observed_fact?.toLowerCase().includes(q)
      const matchHypo = item.inferred_hypothesis?.toLowerCase().includes(q)
      const matchBenign = item.alternative_benign_explanation?.toLowerCase().includes(q)
      if (!matchTitle && !matchEntity && !matchFact && !matchHypo && !matchBenign) {
        return false
      }
    }
    return true
  })

  // Health Badge Helper
  const renderHealthBadge = (health) => {
    switch (health) {
      case 'established':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-emerald-950/60 text-emerald-400 border border-emerald-800/60 shadow-sm">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            ESTABLISHED BASELINE (HEALTHY)
          </span>
        )
      case 'limited':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-sky-950/60 text-sky-400 border border-sky-800/60">
            <span className="w-2 h-2 rounded-full bg-sky-400" />
            LIMITED BASELINE DEPTH
          </span>
        )
      case 'incompatible':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-amber-950/60 text-amber-400 border border-amber-800/60">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            SUBNET DISPARITY DETECTED
          </span>
        )
      case 'insufficient':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-slate-800/60 text-slate-300 border border-slate-700/60">
            <span className="w-2 h-2 rounded-full bg-slate-400" />
            INITIAL BASELINE FORMATION
          </span>
        )
    }
  }

  // Confidence Badge Helper
  const renderConfidenceBadge = (confidence) => {
    switch (confidence) {
      case 'high':
        return <span className="badge badge-critical text-[10px] uppercase font-mono">High Confidence</span>
      case 'medium':
        return <span className="badge badge-medium text-[10px] uppercase font-mono">Medium Confidence</span>
      case 'low':
        return <span className="badge badge-low text-[10px] uppercase font-mono">Low Confidence</span>
      case 'baseline_formation':
      default:
        return <span className="badge badge-info text-[10px] uppercase font-mono">Baseline Formation</span>
    }
  }

  // Category Badge Helper
  const getCategoryDetails = (cat) => {
    switch (cat) {
      case 'first_seen_destination':
        return { label: 'New Destination', color: 'text-purple-400', bg: 'bg-purple-950/40 border-purple-800/50' }
      case 'new_relationship':
        return { label: 'New Relationship', color: 'text-sky-400', bg: 'bg-sky-950/40 border-sky-800/50' }
      case 'unusual_service':
        return { label: 'Service Shift', color: 'text-amber-400', bg: 'bg-amber-950/40 border-amber-800/50' }
      case 'volume_deviation':
        return { label: 'Volume Surge', color: 'text-rose-400', bg: 'bg-rose-950/40 border-rose-800/50' }
      case 'recurring_anomaly':
        return { label: 'Recurring Anomaly', color: 'text-red-400', bg: 'bg-red-950/40 border-red-800/50' }
      default:
        return { label: 'Behavioral Drift', color: 'text-slate-400', bg: 'bg-slate-900 border-slate-700' }
    }
  }

  return (
    <div className="flex flex-col min-h-screen bg-canvas text-dark-100">
      {analysisId && <CaptureHeader onModeChange={() => loadMemoryData(analysisId)} />}

      <div className="flex-1 p-5 max-w-7xl mx-auto w-full space-y-5">
        {/* Top Header & Capture Context Switcher */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase tracking-wider text-dark-400 flex items-center gap-1.5">
                <History className="w-3.5 h-3.5 text-primary-400" />
                BEACON MEMORY & HISTORICAL BASELINE ENGINE
              </span>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            </div>
            <h1 className="text-xl font-bold text-white font-sans tracking-tight mt-0.5 flex items-center gap-2">
              <span>Explainable Change Detection & Network Evolution</span>
              {analysisId === 'live' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 inline-flex items-center gap-1.5 align-middle">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  LIVE STREAM
                </span>
              )}
            </h1>
          </div>

          {/* Context Capture Selector */}
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-dark-400 hidden sm:inline">Active Target:</span>
            <select
              value={analysisId}
              onChange={(e) => handleCaptureSwitch(e.target.value)}
              className="input text-xs font-mono py-1 px-3 bg-dark-900 border-slate-700 max-w-xs"
            >
              {availableAnalyses.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.filename} ({a.id.slice(0, 8)})
                </option>
              ))}
            </select>
            <button
              onClick={() => loadMemoryData(analysisId)}
              className="btn btn-secondary p-1.5 text-xs text-dark-300 hover:text-white"
              title="Refresh Memory Briefing"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Global Memory Baseline Executive Summary Banner */}
        <div
          className="rounded-lg border p-4 space-y-4 shadow-lg backdrop-blur-sm"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-subtle)',
          }}
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-dark-800">
            <div className="space-y-1">
              <div className="flex items-center gap-2.5">
                <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-white">
                  Baseline Intelligence Status
                </h2>
                {briefing && renderHealthBadge(briefing.baseline_health)}
              </div>
              <p className="text-xs text-dark-400 max-w-2xl">
                Comparing current capture <span className="font-mono text-white font-semibold">{briefing?.filename || analysisId}</span> against compact local-first historical metadata.
              </p>
            </div>

            {/* Quick Metrics Counter */}
            <div className="flex items-center gap-4 text-xs font-mono">
              <div className="text-right">
                <span className="text-dark-500 text-[10px] uppercase block">Indexed History</span>
                <span className="text-white font-bold text-sm">
                  {briefing?.baseline_captures_count || 0} PCAPs ({formatDuration(briefing?.baseline_duration_seconds)})
                </span>
              </div>
              <div className="h-7 w-[1px] bg-dark-800" />
              <div className="text-right">
                <span className="text-dark-500 text-[10px] uppercase block">Changes Detected</span>
                <span className="text-sky-400 font-bold text-sm">
                  {briefing?.total_changes_detected || 0} items
                </span>
              </div>
            </div>
          </div>

          {/* Context Warning Banner if subnet disparity or brief duration */}
          {briefing?.baseline_warning && (
            <div className="flex items-start gap-3 p-3 rounded-md bg-amber-950/40 border border-amber-800/60 text-xs">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div className="space-y-0.5">
                <span className="font-bold text-amber-300 font-mono">Baseline Compatibility Notice:</span>
                <p className="text-amber-200/90 leading-relaxed font-sans">
                  {briefing.baseline_warning}
                </p>
              </div>
            </div>
          )}

          {/* Category Metric Badges Strip */}
          {briefing && (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5 pt-1">
              <button
                type="button"
                onClick={() => setSelectedCategory('first_seen_destination')}
                className={`p-2 rounded border text-left font-mono transition-all ${
                  selectedCategory === 'first_seen_destination'
                    ? 'bg-purple-950/60 border-purple-500 ring-1 ring-purple-500'
                    : 'bg-dark-950/40 border-dark-800 hover:border-dark-700'
                }`}
              >
                <div className="text-[10px] text-purple-400 uppercase font-semibold">New Destinations</div>
                <div className="text-base font-bold text-white mt-0.5">{briefing.new_destinations_count || 0}</div>
              </button>

              <button
                type="button"
                onClick={() => setSelectedCategory('new_relationship')}
                className={`p-2 rounded border text-left font-mono transition-all ${
                  selectedCategory === 'new_relationship'
                    ? 'bg-sky-950/60 border-sky-500 ring-1 ring-sky-500'
                    : 'bg-dark-950/40 border-dark-800 hover:border-dark-700'
                }`}
              >
                <div className="text-[10px] text-sky-400 uppercase font-semibold">New Relationships</div>
                <div className="text-base font-bold text-white mt-0.5">{briefing.new_relationships_count || 0}</div>
              </button>

              <button
                type="button"
                onClick={() => setSelectedCategory('unusual_service')}
                className={`p-2 rounded border text-left font-mono transition-all ${
                  selectedCategory === 'unusual_service'
                    ? 'bg-amber-950/60 border-amber-500 ring-1 ring-amber-500'
                    : 'bg-dark-950/40 border-dark-800 hover:border-dark-700'
                }`}
              >
                <div className="text-[10px] text-amber-400 uppercase font-semibold">Service Shifts</div>
                <div className="text-base font-bold text-white mt-0.5">{briefing.service_shifts_count || 0}</div>
              </button>

              <button
                type="button"
                onClick={() => setSelectedCategory('volume_deviation')}
                className={`p-2 rounded border text-left font-mono transition-all ${
                  selectedCategory === 'volume_deviation'
                    ? 'bg-rose-950/60 border-rose-500 ring-1 ring-rose-500'
                    : 'bg-dark-950/40 border-dark-800 hover:border-dark-700'
                }`}
              >
                <div className="text-[10px] text-rose-400 uppercase font-semibold">Volume Surges</div>
                <div className="text-base font-bold text-white mt-0.5">{briefing.volume_deviations_count || 0}</div>
              </button>

              <button
                type="button"
                onClick={() => setSelectedCategory('recurring_anomaly')}
                className={`p-2 rounded border text-left font-mono transition-all ${
                  selectedCategory === 'recurring_anomaly'
                    ? 'bg-red-950/60 border-red-500 ring-1 ring-red-500'
                    : 'bg-dark-950/40 border-dark-800 hover:border-dark-700'
                }`}
              >
                <div className="text-[10px] text-red-400 uppercase font-semibold">Recurring Anomalies</div>
                <div className="text-base font-bold text-white mt-0.5">{briefing.recurring_anomalies_count || 0}</div>
              </button>
            </div>
          )}
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center justify-between border-b border-dark-800 pb-2">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('changes')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-bold transition-all ${
                activeTab === 'changes'
                  ? 'bg-primary-600 text-white shadow-sm'
                  : 'text-dark-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Ranked Changes ({briefing?.items?.length || 0})</span>
            </button>

            <button
              onClick={() => setActiveTab('recurring')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-bold transition-all ${
                activeTab === 'recurring'
                  ? 'bg-primary-600 text-white shadow-sm'
                  : 'text-dark-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Recurring Across Captures ({recurringAnomalies.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('catalog')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-bold transition-all ${
                activeTab === 'catalog'
                  ? 'bg-primary-600 text-white shadow-sm'
                  : 'text-dark-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <Database className="w-3.5 h-3.5" />
              <span>Baseline Catalog ({historyCaptures.length})</span>
            </button>
          </div>

          {activeTab === 'changes' && (
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-1.5 text-xs font-mono text-dark-400 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={hideExpected}
                  onChange={(e) => setHideExpected(e.target.checked)}
                  className="rounded border-dark-700 bg-dark-900 text-primary-500 focus:ring-0"
                />
                <span>Hide Acknowledged</span>
              </label>
            </div>
          )}
        </div>

        {/* Tab 1: Explainable Ranked Changes View */}
        {activeTab === 'changes' && (
          <div className="space-y-4">
            {/* Filter Bar */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
              {/* Category Pills */}
              <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
                <button
                  onClick={() => setSelectedCategory('all')}
                  className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-all ${
                    selectedCategory === 'all'
                      ? 'bg-white/10 text-white border border-white/20'
                      : 'text-dark-400 hover:text-white'
                  }`}
                >
                  All ({briefing?.items?.length || 0})
                </button>
                <button
                  onClick={() => setSelectedCategory('first_seen_destination')}
                  className={`px-2.5 py-1 rounded text-[11px] transition-all ${
                    selectedCategory === 'first_seen_destination'
                      ? 'bg-purple-950 text-purple-300 border border-purple-800'
                      : 'text-dark-400 hover:text-purple-300'
                  }`}
                >
                  Destinations
                </button>
                <button
                  onClick={() => setSelectedCategory('new_relationship')}
                  className={`px-2.5 py-1 rounded text-[11px] transition-all ${
                    selectedCategory === 'new_relationship'
                      ? 'bg-sky-950 text-sky-300 border border-sky-800'
                      : 'text-dark-400 hover:text-sky-300'
                  }`}
                >
                  Relationships
                </button>
                <button
                  onClick={() => setSelectedCategory('unusual_service')}
                  className={`px-2.5 py-1 rounded text-[11px] transition-all ${
                    selectedCategory === 'unusual_service'
                      ? 'bg-amber-950 text-amber-300 border border-amber-800'
                      : 'text-dark-400 hover:text-amber-300'
                  }`}
                >
                  Services
                </button>
                <button
                  onClick={() => setSelectedCategory('volume_deviation')}
                  className={`px-2.5 py-1 rounded text-[11px] transition-all ${
                    selectedCategory === 'volume_deviation'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : 'text-dark-400 hover:text-rose-300'
                  }`}
                >
                  Volumes
                </button>
                <button
                  onClick={() => setSelectedCategory('recurring_anomaly')}
                  className={`px-2.5 py-1 rounded text-[11px] transition-all ${
                    selectedCategory === 'recurring_anomaly'
                      ? 'bg-red-950 text-red-300 border border-red-800'
                      : 'text-dark-400 hover:text-red-300'
                  }`}
                >
                  Recurring
                </button>
              </div>

              {/* Search & Confidence Filter */}
              <div className="flex items-center gap-2 w-full sm:w-auto">
                <div className="relative flex-1 sm:w-56">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-dark-500" />
                  <input
                    type="text"
                    placeholder="Search candidate, IP, fact..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="input pl-8 pr-6 py-1 text-xs font-mono w-full"
                  />
                  {searchQuery && (
                    <button
                      onClick={() => setSearchQuery('')}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-dark-400 hover:text-white"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  )}
                </div>

                <select
                  value={confidenceFilter}
                  onChange={(e) => setConfidenceFilter(e.target.value)}
                  className="input py-1 px-2.5 text-xs font-mono bg-dark-900 border-slate-700"
                >
                  <option value="all">All Confidences</option>
                  <option value="high">High Confidence</option>
                  <option value="medium">Medium Confidence</option>
                  <option value="low">Low Confidence</option>
                </select>
              </div>
            </div>

            {/* Top Investigation Candidate Hero Card */}
            {briefing?.top_investigation_candidate && selectedCategory === 'all' && !searchQuery && (
              <div className="p-4 rounded-lg border border-amber-500/40 bg-gradient-to-r from-amber-950/30 via-dark-900/80 to-dark-900 border-l-4 border-l-amber-500 space-y-3 shadow-md">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40">
                      ★ TOP INVESTIGATION CANDIDATE
                    </span>
                    <span className="text-xs font-mono font-bold text-white">
                      {briefing.top_investigation_candidate.title}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono text-dark-400">
                      Priority Score: <span className="text-amber-400 font-bold">{briefing.top_investigation_candidate.priority_score.toFixed(1)}</span>
                    </span>
                    {renderConfidenceBadge(briefing.top_investigation_candidate.confidence)}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div className="p-2.5 rounded bg-dark-950/60 border border-dark-800 space-y-1">
                    <div className="text-[10px] uppercase font-mono text-dark-500 flex items-center gap-1">
                      <Eye className="w-3 h-3 text-sky-400" />
                      Observed Fact (Packet Telemetry)
                    </div>
                    <div className="font-mono text-dark-200 leading-snug">
                      {briefing.top_investigation_candidate.observed_fact}
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-amber-950/20 border border-amber-900/40 space-y-1">
                    <div className="text-[10px] uppercase font-mono text-amber-400 flex items-center gap-1">
                      <ShieldAlert className="w-3 h-3 text-amber-400" />
                      Inferred Threat Hypothesis
                    </div>
                    <div className="text-amber-200/90 leading-snug">
                      {briefing.top_investigation_candidate.inferred_hypothesis}
                    </div>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <span className="text-[11px] font-mono text-dark-500">
                    Entity: <span className="text-primary-400 font-bold">{briefing.top_investigation_candidate.entity}</span>
                  </span>

                  <div className="flex items-center gap-2">
                    <Link
                      to={`/packets/${analysisId}?ip=${briefing.top_investigation_candidate.evidence_links?.ip || briefing.top_investigation_candidate.entity}`}
                      className="btn btn-secondary text-xs font-mono py-1 px-2.5 flex items-center gap-1 text-sky-400 hover:text-white"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>Inspect Packet Evidence</span>
                    </Link>

                    <button
                      onClick={() => openFeedbackModal(briefing.top_investigation_candidate)}
                      className="btn btn-primary text-xs font-mono py-1 px-2.5 flex items-center gap-1"
                    >
                      <Check className="w-3.5 h-3.5" />
                      <span>Review Candidate</span>
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* List of Ranked Candidates */}
            {filteredItems.length === 0 ? (
              <div className="card p-12 text-center space-y-3 font-mono">
                <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
                <h3 className="text-sm font-bold text-white uppercase">No Changes Matching Filter</h3>
                <p className="text-xs text-dark-400 max-w-md mx-auto">
                  {searchQuery
                    ? `No items found matching "${searchQuery}". Try clearing filters.`
                    : 'Current capture behavior conforms completely with established historical baseline expectations.'}
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredItems.map((item) => {
                  const catDetails = getCategoryDetails(item.category)
                  const isExpected = item.analyst_feedback?.is_expected

                  return (
                    <div
                      key={item.id}
                      className={`card p-4 transition-all space-y-3.5 ${
                        isExpected ? 'opacity-60 bg-dark-950/40 border-dark-800' : 'hover:border-dark-700'
                      }`}
                    >
                      {/* Top Bar: Category, Priority, Severity, Title */}
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${catDetails.bg} ${catDetails.color}`}
                          >
                            {catDetails.label}
                          </span>

                          <span className={`badge badge-${item.severity} text-[9px] uppercase font-mono`}>
                            {item.severity}
                          </span>

                          {renderConfidenceBadge(item.confidence)}

                          {isExpected && (
                            <span className="badge badge-low text-[9px] uppercase font-mono bg-emerald-950/80 text-emerald-300 border-emerald-700/60">
                              [EXPECTED / BENIGN]
                            </span>
                          )}

                          <h3 className="text-xs font-bold font-mono text-white ml-1">
                            {item.title}
                          </h3>
                        </div>

                        {/* Priority Score Bar */}
                        <div className="flex items-center gap-2 text-xs font-mono shrink-0">
                          <span className="text-dark-500 text-[11px]">Score:</span>
                          <span className="font-bold text-white w-8 text-right">
                            {item.priority_score.toFixed(1)}
                          </span>
                          <div className="w-16 h-1.5 rounded-full bg-dark-800 overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                item.priority_score > 70
                                  ? 'bg-rose-500'
                                  : item.priority_score > 40
                                  ? 'bg-amber-500'
                                  : 'bg-sky-500'
                              }`}
                              style={{ width: `${Math.min(100, Math.max(5, item.priority_score))}%` }}
                            />
                          </div>
                        </div>
                      </div>

                      {/* Tripartite Explainability Box */}
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                        {/* 1. Concrete Packet Fact */}
                        <div className="p-2.5 rounded bg-dark-950/70 border border-dark-800/90 space-y-1">
                          <div className="text-[10px] uppercase font-mono text-sky-400 flex items-center justify-between">
                            <span className="flex items-center gap-1 font-bold">
                              <Eye className="w-3 h-3 text-sky-400" />
                              Observed Fact
                            </span>
                            <span className="text-[9px] text-dark-500">Packet Evidence</span>
                          </div>
                          <p className="font-mono text-dark-200 text-[11px] leading-snug">
                            {item.observed_fact}
                          </p>
                          <div className="text-[10px] text-dark-500 font-mono pt-1">
                            {item.statistical_context}
                          </div>
                        </div>

                        {/* 2. Security Threat Hypothesis */}
                        <div className="p-2.5 rounded bg-rose-950/20 border border-rose-900/40 space-y-1">
                          <div className="text-[10px] uppercase font-mono text-rose-400 flex items-center justify-between">
                            <span className="flex items-center gap-1 font-bold">
                              <ShieldAlert className="w-3 h-3 text-rose-400" />
                              Security Hypothesis
                            </span>
                            <span className="text-[9px] text-rose-400/80">Inferred</span>
                          </div>
                          <p className="text-rose-200/90 text-[11px] leading-snug">
                            {item.inferred_hypothesis}
                          </p>
                        </div>

                        {/* 3. Alternative Benign Explanation */}
                        <div className="p-2.5 rounded bg-emerald-950/20 border border-emerald-900/40 space-y-1">
                          <div className="text-[10px] uppercase font-mono text-emerald-400 flex items-center justify-between">
                            <span className="flex items-center gap-1 font-bold">
                              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                              Benign Explanation
                            </span>
                            <span className="text-[9px] text-emerald-400/80">Plausible</span>
                          </div>
                          <p className="text-emerald-200/90 text-[11px] leading-snug">
                            {item.alternative_benign_explanation}
                          </p>
                        </div>
                      </div>

                      {/* If analyst note is attached */}
                      {item.analyst_feedback?.analyst_note && (
                        <div className="p-2 rounded bg-dark-900 border border-dark-800 text-xs font-mono text-dark-300 flex items-center gap-2">
                          <MessageSquare className="w-3.5 h-3.5 text-primary-400 shrink-0" />
                          <span className="text-[11px]">
                            <strong className="text-white">Analyst Annotation:</strong> {item.analyst_feedback.analyst_note}
                          </span>
                        </div>
                      )}

                      {/* Footer Actions: Evidence Pivots & Review */}
                      <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-dark-800/60">
                        <div className="flex items-center gap-2 font-mono text-[11px] text-dark-400">
                          <span>Target: <span className="text-white font-bold">{item.entity}</span></span>
                          <span>•</span>
                          <span>{item.comparison_context}</span>
                        </div>

                        <div className="flex items-center gap-2">
                          {/* Pivot to Packet Explorer */}
                          <Link
                            to={`/packets/${analysisId}?ip=${item.evidence_links?.ip || item.evidence_links?.host1 || item.entity}`}
                            className="btn btn-secondary text-xs font-mono py-1 px-2.5 flex items-center gap-1 text-sky-400 hover:text-white"
                            title="Direct verification against raw packet stream"
                          >
                            <Eye className="w-3 h-3" />
                            <span>View Packets</span>
                          </Link>

                          {/* Pivot to Hosts */}
                          {item.evidence_links?.ip && (
                            <Link
                              to={`/hosts/${analysisId}`}
                              className="btn btn-secondary text-xs font-mono py-1 px-2.5 flex items-center gap-1 text-dark-300 hover:text-white"
                            >
                              <Server className="w-3 h-3" />
                              <span>Host Profile</span>
                            </Link>
                          )}

                          {/* Analyst Review Modal Button */}
                          <button
                            onClick={() => openFeedbackModal(item)}
                            className="btn btn-secondary text-xs font-mono py-1 px-2.5 flex items-center gap-1 text-amber-400 hover:text-white"
                          >
                            <Sliders className="w-3 h-3" />
                            <span>{isExpected ? 'Edit Review' : 'Mark Expected'}</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Recurring Anomalies Across Captures */}
        {activeTab === 'recurring' && (
          <div className="space-y-4">
            <div className="card p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold font-mono text-white uppercase">
                    Recurring Anomalies Across Multiple Captures
                  </h3>
                  <p className="text-xs text-dark-400 mt-0.5">
                    Signatures and behavioral deviations observed persistently or periodically across historical PCAPs.
                  </p>
                </div>
                <span className="badge badge-medium text-xs font-mono">
                  {recurringAnomalies.length} Tracked
                </span>
              </div>

              {recurringAnomalies.length === 0 ? (
                <div className="py-12 text-center text-dark-500 text-xs font-mono">
                  No recurring anomalies tracked across historical captures yet.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs">
                    <thead>
                      <tr className="border-b border-dark-800 text-[10px] text-dark-500 uppercase tracking-wider">
                        <th className="py-2.5 px-3">Anomaly Title</th>
                        <th className="py-2.5 px-3">Category</th>
                        <th className="py-2.5 px-3">Severity</th>
                        <th className="py-2.5 px-3">Entity</th>
                        <th className="py-2.5 px-3 text-center">Occurrences</th>
                        <th className="py-2.5 px-3 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-dark-800/60">
                      {recurringAnomalies.map((rec) => (
                        <tr key={rec.signature} className="hover:bg-white/5 transition-colors">
                          <td className="py-2.5 px-3 font-bold text-white">
                            {rec.title}
                          </td>
                          <td className="py-2.5 px-3 text-dark-400 uppercase text-[11px]">
                            {rec.category}
                          </td>
                          <td className="py-2.5 px-3">
                            <span className={`badge badge-${rec.severity} text-[9px] uppercase`}>
                              {rec.severity}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-sky-400 font-bold">
                            {rec.entity}
                          </td>
                          <td className="py-2.5 px-3 text-center">
                            <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-amber-950/60 text-amber-300 border border-amber-800/50">
                              {rec.occurrences}x captures
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <button
                              onClick={() =>
                                openFeedbackModal({
                                  entity: rec.signature,
                                  title: rec.title,
                                  entity_type: 'anomaly',
                                  analyst_feedback: rec.analyst_feedback,
                                })
                              }
                              className="btn btn-secondary text-[11px] font-mono py-1 px-2 text-dark-300 hover:text-white"
                            >
                              Review
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 3: Historical Baseline Catalog */}
        {activeTab === 'catalog' && (
          <div className="space-y-4">
            <div className="card p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold font-mono text-white uppercase">
                    Indexed Historical Baseline Captures
                  </h3>
                  <p className="text-xs text-dark-400 mt-0.5">
                    Local-first compact profiles stored in <code className="text-primary-400">cache/beacon_memory.db</code>. Raw PCAPs are not duplicated.
                  </p>
                </div>
                <span className="text-xs font-mono text-dark-400">
                  Total Baselines: <strong className="text-white">{historyCaptures.length}</strong>
                </span>
              </div>

              {historyCaptures.length === 0 ? (
                <div className="py-12 text-center text-dark-500 text-xs font-mono">
                  No captures currently indexed in memory. Run analysis on a PCAP to begin baseline formation.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs">
                    <thead>
                      <tr className="border-b border-dark-800 text-[10px] text-dark-500 uppercase tracking-wider">
                        <th className="py-2.5 px-3">Capture ID</th>
                        <th className="py-2.5 px-3">Filename</th>
                        <th className="py-2.5 px-3 text-right">Duration</th>
                        <th className="py-2.5 px-3 text-right">Total Packets</th>
                        <th className="py-2.5 px-3 text-right">Hosts</th>
                        <th className="py-2.5 px-3 text-right">Switch Target</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-dark-800/60">
                      {historyCaptures.map((cap) => {
                        const isCurrent = cap.id === analysisId
                        return (
                          <tr
                            key={cap.id}
                            className={`hover:bg-white/5 transition-colors ${
                              isCurrent ? 'bg-primary-950/20' : ''
                            }`}
                          >
                            <td className="py-2.5 px-3 font-bold text-white">
                              {cap.id.slice(0, 12)}...
                            </td>
                            <td className="py-2.5 px-3 text-dark-200">
                              {cap.filename}
                            </td>
                            <td className="py-2.5 px-3 text-right text-dark-300">
                              {formatDuration(cap.duration_seconds)}
                            </td>
                            <td className="py-2.5 px-3 text-right text-dark-300">
                              {cap.total_packets?.toLocaleString() || 0}
                            </td>
                            <td className="py-2.5 px-3 text-right text-white font-bold">
                              {cap.unique_hosts || 0}
                            </td>
                            <td className="py-2.5 px-3 text-right">
                              {isCurrent ? (
                                <span className="text-primary-400 font-bold text-[11px]">Active</span>
                              ) : (
                                <button
                                  onClick={() => handleCaptureSwitch(cap.id)}
                                  className="btn btn-secondary text-[11px] font-mono py-0.5 px-2 text-dark-300 hover:text-white"
                                >
                                  Inspect →
                                </button>
                              )}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Analyst Feedback / Mark Expected Modal */}
      {feedbackModalItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="card p-5 max-w-lg w-full space-y-4 border border-dark-700 shadow-2xl">
            <div className="flex items-center justify-between pb-2 border-b border-dark-800">
              <div className="flex items-center gap-2">
                <Sliders className="w-4 h-4 text-primary-400" />
                <h3 className="text-sm font-bold font-mono text-white">
                  Analyst Baseline Review
                </h3>
              </div>
              <button onClick={closeFeedbackModal} className="text-dark-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={submitFeedback} className="space-y-4 font-mono text-xs">
              <div className="p-2.5 rounded bg-dark-950 border border-dark-800 space-y-1">
                <div className="text-[10px] text-dark-500 uppercase">Target Entity Key</div>
                <div className="text-primary-400 font-bold text-xs truncate">
                  {feedbackModalItem.entity || feedbackModalItem.title}
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-[11px] text-dark-300 font-bold uppercase block">
                  Review Assessment Status
                </label>
                <div className="grid grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => setFeedbackStatus('expected')}
                    className={`p-2 rounded border text-center transition-all ${
                      feedbackStatus === 'expected'
                        ? 'bg-emerald-950 border-emerald-500 text-emerald-300 font-bold'
                        : 'bg-dark-900 border-dark-800 text-dark-400 hover:text-white'
                    }`}
                  >
                    Expected / Benign
                  </button>

                  <button
                    type="button"
                    onClick={() => setFeedbackStatus('acknowledged')}
                    className={`p-2 rounded border text-center transition-all ${
                      feedbackStatus === 'acknowledged'
                        ? 'bg-sky-950 border-sky-500 text-sky-300 font-bold'
                        : 'bg-dark-900 border-dark-800 text-dark-400 hover:text-white'
                    }`}
                  >
                    Acknowledged
                  </button>

                  <button
                    type="button"
                    onClick={() => setFeedbackStatus('investigating')}
                    className={`p-2 rounded border text-center transition-all ${
                      feedbackStatus === 'investigating'
                        ? 'bg-amber-950 border-amber-500 text-amber-300 font-bold'
                        : 'bg-dark-900 border-dark-800 text-dark-400 hover:text-white'
                    }`}
                  >
                    Investigating
                  </button>
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-[11px] text-dark-300 font-bold uppercase block">
                  Analyst Annotation & Justification Note
                </label>
                <textarea
                  rows={3}
                  value={feedbackNote}
                  onChange={(e) => setFeedbackNote(e.target.value)}
                  placeholder="E.g., Authorized corporate backup host; planned DNS migration endpoint..."
                  className="input w-full p-2.5 text-xs text-white"
                />
              </div>

              <div className="text-[10px] text-dark-500 font-sans">
                Marking an item as expected adjusts its priority ranking score without removing or erasing the verifiable packet evidence.
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-dark-800">
                <button
                  type="button"
                  onClick={closeFeedbackModal}
                  className="btn btn-secondary text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={feedbackSubmitting}
                  className="btn btn-primary text-xs flex items-center gap-1.5"
                >
                  {feedbackSubmitting ? 'Saving...' : 'Save Assessment'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
