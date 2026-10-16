import { useState, useEffect } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import axios from 'axios'
import {
  GitCompare,
  Loader2,
  AlertTriangle,
  ArrowRight,
  TrendingUp,
  TrendingDown,
  ShieldAlert,
  Server,
  Layers,
  CheckCircle,
  Activity
} from 'lucide-react'

export default function CaptureComparison() {
  const [searchParams] = useSearchParams()
  const [analyses, setAnalyses] = useState([])
  const [baselineId, setBaselineId] = useState(searchParams.get('baseline') || '')
  const [targetId, setTargetId] = useState(searchParams.get('target') || '')
  const [loadingAnalyses, setLoadingAnalyses] = useState(true)
  const [comparing, setComparing] = useState(false)
  const [comparisonResult, setComparisonResult] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    loadAnalysesList()
  }, [])

  useEffect(() => {
    if (baselineId && targetId && baselineId !== targetId) {
      runComparison(false)
    }
  }, [baselineId, targetId])

  useEffect(() => {
    if (baselineId === 'live' || targetId === 'live') {
      const interval = setInterval(() => {
        if (document.hidden) return
        if (baselineId && targetId && baselineId !== targetId) {
          runComparison(true)
        }
      }, 3500)
      return () => clearInterval(interval)
    }
  }, [baselineId, targetId])

  const loadAnalysesList = async () => {
    setLoadingAnalyses(true)
    try {
      const res = await axios.get('/api/analyses')
      const completed = (res.data.analyses || []).filter((a) => a.status === 'complete' || a.id === 'live')
      setAnalyses(completed)

      if (completed.length >= 2 && !baselineId && !targetId) {
        setBaselineId(completed[1].id)
        setTargetId(completed[0].id)
      }
    } catch (err) {
      console.error('Failed to load analyses:', err)
    } finally {
      setLoadingAnalyses(false)
    }
  }

  const runComparison = async (isBackground = false) => {
    if (!baselineId || !targetId || baselineId === targetId) return
    if (!isBackground) setComparing(true)
    setError(null)
    try {
      const res = await axios.get('/api/analysis/compare', {
        params: { baseline_id: baselineId, target_id: targetId },
      })
      setComparisonResult(res.data)
    } catch (err) {
      if (!isBackground) {
        setError(err.response?.data?.detail || 'Comparison failed')
        setComparisonResult(null)
      }
    } finally {
      if (!isBackground) setComparing(false)
    }
  }

  const formatBytes = (bytes) => {
    if (!bytes && bytes !== 0) return '0 B'
    const sign = bytes < 0 ? '-' : ''
    const abs = Math.abs(bytes)
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(abs || 1) / Math.log(k))
    return `${sign}${(abs / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
  }

  return (
    <div className="min-h-screen bg-canvas flex flex-col">
      <div className="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
        {/* Title */}
        <div>
          <div className="flex items-center gap-2">
            <GitCompare className="w-6 h-6 text-primary-500" />
            <h1 className="text-2xl font-bold text-dark-900 dark:text-white">
              Capture Diff & Drift Comparison
            </h1>
            {(baselineId === 'live' || targetId === 'live') && (
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 self-center">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                LIVE STREAM COMPARISON
              </span>
            )}
          </div>
          <p className="text-xs text-dark-500 dark:text-dark-400 mt-1">
            Compare two network captures to identify anomalous traffic drift, newly introduced hosts, new security findings, and protocol changes against a known baseline.
          </p>
        </div>

        {/* Selection Card */}
        <div className="card p-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold uppercase text-dark-400 mb-1.5">
                Baseline Capture (Reference):
              </label>
              <select
                value={baselineId}
                onChange={(e) => setBaselineId(e.target.value)}
                disabled={loadingAnalyses}
                className="w-full py-2 px-3 text-xs bg-white dark:bg-dark-900 border border-dark-200 dark:border-dark-700 rounded-lg text-dark-900 dark:text-white font-mono"
              >
                <option value="">Select baseline capture...</option>
                {analyses.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.filename} ({a.packet_count} pkts, {a.mode} mode)
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase text-dark-400 mb-1.5">
                Target Capture (Investigation):
              </label>
              <select
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                disabled={loadingAnalyses}
                className="w-full py-2 px-3 text-xs bg-white dark:bg-dark-900 border border-dark-200 dark:border-dark-700 rounded-lg text-dark-900 dark:text-white font-mono"
              >
                <option value="">Select target capture...</option>
                {analyses.map((a) => (
                  <option key={a.id} value={a.id} disabled={a.id === baselineId}>
                    {a.filename} ({a.packet_count} pkts, {a.mode} mode)
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Comparison Output */}
        {comparing ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-8 h-8 text-primary-500 animate-spin" />
          </div>
        ) : error ? (
          <div className="card p-4 text-red-600 dark:text-red-400 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 shrink-0" />
            <span>{error}</span>
          </div>
        ) : comparisonResult ? (
          <div className="space-y-6">
            {/* Metric Delta Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="card p-4">
                <span className="text-[11px] font-semibold uppercase text-dark-400 block mb-1">
                  Packet Volume Delta
                </span>
                <div className="text-xl font-bold font-mono text-dark-900 dark:text-white flex items-center gap-1.5">
                  {comparisonResult.metrics_delta.packets_delta >= 0 ? (
                    <TrendingUp className="w-4 h-4 text-emerald-500" />
                  ) : (
                    <TrendingDown className="w-4 h-4 text-slate-400" />
                  )}
                  <span>{comparisonResult.metrics_delta.packets_delta > 0 ? '+' : ''}{comparisonResult.metrics_delta.packets_delta.toLocaleString()}</span>
                </div>
                <span className="text-[11px] text-dark-400 font-mono mt-1 block">
                  {comparisonResult.baseline_summary.total_packets.toLocaleString()} → {comparisonResult.target_summary.total_packets.toLocaleString()}
                </span>
              </div>

              <div className="card p-4">
                <span className="text-[11px] font-semibold uppercase text-dark-400 block mb-1">
                  Bytes Delta
                </span>
                <div className="text-xl font-bold font-mono text-dark-900 dark:text-white flex items-center gap-1.5">
                  <span>{formatBytes(comparisonResult.metrics_delta.bytes_delta)}</span>
                </div>
                <span className="text-[11px] text-dark-400 font-mono mt-1 block">
                  {formatBytes(comparisonResult.baseline_summary.total_bytes)} → {formatBytes(comparisonResult.target_summary.total_bytes)}
                </span>
              </div>

              <div className="card p-4">
                <span className="text-[11px] font-semibold uppercase text-dark-400 block mb-1">
                  Unique Hosts Delta
                </span>
                <div className="text-xl font-bold font-mono text-dark-900 dark:text-white">
                  <span>{comparisonResult.metrics_delta.hosts_delta > 0 ? '+' : ''}{comparisonResult.metrics_delta.hosts_delta}</span>
                </div>
                <span className="text-[11px] text-dark-400 font-mono mt-1 block">
                  {comparisonResult.baseline_summary.unique_hosts} → {comparisonResult.target_summary.unique_hosts} hosts
                </span>
              </div>

              <div className="card p-4">
                <span className="text-[11px] font-semibold uppercase text-dark-400 block mb-1">
                  New Security Findings
                </span>
                <div className="text-xl font-bold font-mono text-red-500">
                  <span>+{comparisonResult.new_findings.length}</span>
                </div>
                <span className="text-[11px] text-dark-400 font-mono mt-1 block">
                  {comparisonResult.resolved_findings.length} findings resolved
                </span>
              </div>
            </div>

            {/* Findings Differences */}
            {comparisonResult.new_findings.length > 0 && (
              <div className="card p-5 border-l-4 border-l-red-500">
                <h3 className="text-sm font-bold text-dark-900 dark:text-white flex items-center gap-2 mb-3">
                  <ShieldAlert className="w-4 h-4 text-red-500" />
                  <span>New Security Findings In Target Capture ({comparisonResult.new_findings.length})</span>
                </h3>
                <div className="space-y-2">
                  {comparisonResult.new_findings.map((f, i) => (
                    <div
                      key={i}
                      className="p-3 rounded bg-red-500/10 border border-red-500/20 text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-red-600 dark:text-red-400">{f.title}</span>
                        <span className="badge badge-high uppercase text-[10px]">{f.severity || 'high'}</span>
                      </div>
                      <p className="text-dark-700 dark:text-dark-300">{f.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Host Inventory Drift */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* New Hosts Card */}
              <div className="card p-4">
                <h3 className="text-sm font-bold text-dark-900 dark:text-white flex items-center gap-2 mb-3">
                  <Server className="w-4 h-4 text-emerald-500" />
                  <span>Newly Introduced Hosts ({comparisonResult.new_hosts.length})</span>
                </h3>
                {comparisonResult.new_hosts.length === 0 ? (
                  <div className="text-xs text-dark-400 py-4 text-center">No new hosts detected.</div>
                ) : (
                  <div className="space-y-1.5 font-mono text-xs">
                    {comparisonResult.new_hosts.map((h) => (
                      <div
                        key={h.ip}
                        className="p-2 rounded bg-dark-50 dark:bg-dark-900 flex justify-between items-center"
                      >
                        <span className="font-bold text-dark-900 dark:text-white">{h.ip}</span>
                        <span className="badge badge-low text-[10px]">{h.is_internal ? 'Internal' : 'External'}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Removed Hosts Card */}
              <div className="card p-4">
                <h3 className="text-sm font-bold text-dark-900 dark:text-white flex items-center gap-2 mb-3">
                  <Server className="w-4 h-4 text-slate-400" />
                  <span>Disappeared Hosts ({comparisonResult.removed_hosts.length})</span>
                </h3>
                {comparisonResult.removed_hosts.length === 0 ? (
                  <div className="text-xs text-dark-400 py-4 text-center">No missing hosts from baseline.</div>
                ) : (
                  <div className="space-y-1.5 font-mono text-xs">
                    {comparisonResult.removed_hosts.map((h) => (
                      <div
                        key={h.ip}
                        className="p-2 rounded bg-dark-50 dark:bg-dark-900 flex justify-between items-center text-dark-500"
                      >
                        <span>{h.ip}</span>
                        <span className="text-[10px]">Inactive</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* New Protocols */}
            {comparisonResult.new_protocols.length > 0 && (
              <div className="card p-4">
                <h3 className="text-sm font-bold text-dark-900 dark:text-white flex items-center gap-2 mb-2">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <span>New Application / Transport Protocols Observed</span>
                </h3>
                <div className="flex flex-wrap gap-2">
                  {comparisonResult.new_protocols.map((p) => (
                    <span
                      key={p}
                      className="px-2.5 py-1 rounded bg-slate-800 text-cyan-300 border border-slate-700 font-mono text-xs font-bold uppercase"
                    >
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="card text-center py-20 text-dark-400">
            <GitCompare className="w-12 h-12 mx-auto mb-3 opacity-40" />
            <p className="text-sm">Select baseline and target captures above to compute side-by-side differences.</p>
          </div>
        )}
      </div>
    </div>
  )
}
