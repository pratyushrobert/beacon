import { useState, useEffect } from 'react'
import axios from 'axios'
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  AlertTriangle,
  Clock,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Plus,
  Trash2,
  Info,
  Radio,
  FileText
} from 'lucide-react'

export default function PreventionPanel({ onRuleChange }) {
  const [status, setStatus] = useState(null)
  const [policy, setPolicy] = useState(null)
  const [rules, setRules] = useState([])
  const [auditLog, setAuditLog] = useState([])
  const [activeSubTab, setActiveSubTab] = useState('rules') // 'rules' | 'pending' | 'audit'
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Manual Block Form State
  const [manualIp, setManualIp] = useState('')
  const [manualDuration, setManualDuration] = useState(900)
  const [manualReason, setManualReason] = useState('')
  const [submittingBlock, setSubmittingBlock] = useState(false)

  // Auto-protect confirmation modal
  const [confirmAutoModal, setConfirmAutoModal] = useState(false)

  const fetchData = async () => {
    try {
      setLoading(true)
      const [statusRes, policyRes, rulesRes, auditRes] = await Promise.all([
        axios.get('/api/prevention/status'),
        axios.get('/api/prevention/policy'),
        axios.get('/api/prevention/rules'),
        axios.get('/api/prevention/audit?limit=30'),
      ])
      setStatus(statusRes.data)
      setPolicy(policyRes.data)
      setRules(rulesRes.data?.rules || [])
      setAuditLog(auditRes.data?.audit_log || [])
      setError(null)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load threat prevention state')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    const timer = setInterval(() => {
      // Periodic refresh of rules for live countdowns
      axios.get('/api/prevention/rules')
        .then((res) => setRules(res.data?.rules || []))
        .catch(() => {})
    }, 5000)
    return () => clearInterval(timer)
  }, [])

  const handleModeChange = async (newMode) => {
    if (newMode === 'auto' && !policy?.auto_protect_enabled) {
      setConfirmAutoModal(true)
      return
    }
    try {
      const res = await axios.post('/api/prevention/policy', { mode: newMode })
      setPolicy(res.data)
      if (onRuleChange) onRuleChange()
      fetchData()
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update policy mode')
    }
  }

  const handleEnableAutoProtect = async () => {
    try {
      const res = await axios.post('/api/prevention/policy', {
        mode: 'auto',
        auto_protect_enabled: true,
      })
      setPolicy(res.data)
      setConfirmAutoModal(false)
      if (onRuleChange) onRuleChange()
      fetchData()
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to enable auto protection')
    }
  }

  const handleManualBlock = async (e) => {
    if (e) e.preventDefault()
    if (!manualIp.trim()) return
    setSubmittingBlock(true)
    setError(null)

    try {
      await axios.post('/api/prevention/block', {
        destination_ip: manualIp.trim(),
        duration_seconds: parseInt(manualDuration, 10),
        reason: manualReason.trim() || 'Manual operator block',
      })
      setManualIp('')
      setManualReason('')
      if (onRuleChange) onRuleChange()
      fetchData()
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to apply block rule')
    } finally {
      setSubmittingBlock(false)
    }
  }

  const handleApprove = async (ruleId) => {
    try {
      await axios.post(`/api/prevention/rules/${ruleId}/approve`)
      if (onRuleChange) onRuleChange()
      fetchData()
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to approve rule')
    }
  }

  const handleRevoke = async (ruleId) => {
    try {
      await axios.post(`/api/prevention/rules/${ruleId}/revoke`, { reason: 'Operator revoked via web dashboard' })
      if (onRuleChange) onRuleChange()
      fetchData()
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to revoke rule')
    }
  }

  const activeRules = rules.filter((r) => r.is_active && r.status === 'active')
  const pendingRules = rules.filter((r) => r.status === 'pending_approval')

  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-dark-950 font-sans">
      {/* 1. STATUS & POLICY CONTROLS HEADER */}
      <div className="flex-none p-4 border-b border-dark-800 bg-dark-900/40">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Policy Mode Selector */}
          <div className="card p-3 bg-dark-900 border-dark-800">
            <span className="text-[10px] font-mono text-dark-400 uppercase tracking-wider block mb-1.5">
              Enforcement Mode
            </span>
            <div className="flex rounded bg-dark-950 p-1 border border-dark-800 text-xs">
              <button
                onClick={() => handleModeChange('monitor')}
                className={`flex-1 py-1 px-2 rounded font-mono font-medium transition-colors ${
                  policy?.mode === 'monitor'
                    ? 'bg-primary-500/20 text-primary-300 border border-primary-500/30'
                    : 'text-dark-400 hover:text-white'
                }`}
                title="Observe only; never block traffic"
              >
                Monitor
              </button>
              <button
                onClick={() => handleModeChange('ask')}
                className={`flex-1 py-1 px-2 rounded font-mono font-medium transition-colors ${
                  policy?.mode === 'ask'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    : 'text-dark-400 hover:text-white'
                }`}
                title="Require explicit approval before blocking"
              >
                Ask First
              </button>
              <button
                onClick={() => handleModeChange('auto')}
                className={`flex-1 py-1 px-2 rounded font-mono font-medium transition-colors ${
                  policy?.mode === 'auto' && policy?.auto_protect_enabled
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : 'text-dark-400 hover:text-white'
                }`}
                title="Autonomous high-confidence blocking"
              >
                Auto
              </button>
            </div>
          </div>

          {/* Firewall Adapter Status */}
          <div className="card p-3 bg-dark-900 border-dark-800">
            <span className="text-[10px] font-mono text-dark-400 uppercase tracking-wider block mb-1">
              Firewall Adapter
            </span>
            <div className="flex items-center gap-2 mt-1">
              <div className={`w-2 h-2 rounded-full ${status?.adapter_available ? 'bg-emerald-400' : 'bg-rose-400 animate-pulse'}`} />
              <span className="font-mono text-xs font-bold text-white uppercase">
                {status?.adapter_name || 'Checking...'}
              </span>
              <span className="text-[11px] text-dark-400 font-mono">
                ({status?.adapter_available ? 'Active' : 'Unavailable'})
              </span>
            </div>
            <p className="text-[10px] text-dark-500 truncate mt-1" title={status?.adapter_status_message}>
              {status?.adapter_status_message}
            </p>
          </div>

          {/* Active Rules Capacity */}
          <div className="card p-3 bg-dark-900 border-dark-800">
            <span className="text-[10px] font-mono text-dark-400 uppercase tracking-wider block mb-1">
              Active Dropped Destinations
            </span>
            <div className="flex items-baseline gap-2 mt-0.5">
              <span className="text-xl font-bold font-mono text-emerald-400">
                {activeRules.length}
              </span>
              <span className="text-xs text-dark-400 font-mono">
                / {status?.max_active_rules || 100} max bounded
              </span>
            </div>
            <p className="text-[10px] text-dark-500 mt-1">
              Default expiry: {Math.round((status?.default_duration_seconds || 900) / 60)}m temporary window
            </p>
          </div>

          {/* Autonomous Status */}
          <div className="card p-3 bg-dark-900 border-dark-800">
            <span className="text-[10px] font-mono text-dark-400 uppercase tracking-wider block mb-1">
              Autonomous Protection
            </span>
            <div className="flex items-center justify-between mt-1">
              <div className="flex items-center gap-1.5">
                {policy?.auto_protect_enabled ? (
                  <ShieldAlert className="w-4 h-4 text-emerald-400" />
                ) : (
                  <ShieldCheck className="w-4 h-4 text-dark-500" />
                )}
                <span className={`text-xs font-mono font-bold ${policy?.auto_protect_enabled ? 'text-emerald-400' : 'text-dark-400'}`}>
                  {policy?.auto_protect_enabled ? 'ACTIVE' : 'OPT-IN REQUIRED'}
                </span>
              </div>
              {policy?.auto_protect_enabled && (
                <button
                  onClick={() => axios.post('/api/prevention/policy', { auto_protect_enabled: false, mode: 'monitor' }).then(fetchData)}
                  className="text-[10px] text-rose-400 hover:text-rose-300 font-mono underline"
                >
                  Disable
                </button>
              )}
            </div>
            <p className="text-[10px] text-dark-500 mt-1">
              {policy?.auto_protect_enabled ? 'Blocks HIGH confidence destination threats' : 'Manual approval required'}
            </p>
          </div>
        </div>

        {/* Action Error Banner */}
        {error && (
          <div className="mt-3 p-2.5 rounded bg-rose-500/10 border border-rose-500/30 flex items-center justify-between text-xs text-rose-300 font-mono">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 flex-none" />
              <span>{error}</span>
            </div>
            <button onClick={() => setError(null)} className="text-rose-400 hover:text-white">✕</button>
          </div>
        )}

        {/* Quick Manual Block Input */}
        <form onSubmit={handleManualBlock} className="mt-3 flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[200px]">
            <input
              type="text"
              value={manualIp}
              onChange={(e) => setManualIp(e.target.value)}
              placeholder="Enter suspicious destination IP (e.g. 198.51.100.42)..."
              className="w-full bg-dark-950 border border-dark-800 rounded px-3 py-1.5 text-xs text-white font-mono placeholder-dark-500 focus:outline-none focus:border-primary-500"
            />
          </div>
          <select
            value={manualDuration}
            onChange={(e) => setManualDuration(e.target.value)}
            className="bg-dark-950 border border-dark-800 rounded px-2.5 py-1.5 text-xs text-white font-mono focus:outline-none"
          >
            <option value={300}>5 minutes</option>
            <option value={900}>15 minutes (Default)</option>
            <option value={3600}>1 hour</option>
            <option value={14400}>4 hours</option>
            <option value={86400}>24 hours</option>
          </select>
          <input
            type="text"
            value={manualReason}
            onChange={(e) => setManualReason(e.target.value)}
            placeholder="Reason (optional)..."
            className="w-48 bg-dark-950 border border-dark-800 rounded px-3 py-1.5 text-xs text-white font-mono placeholder-dark-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={submittingBlock || !manualIp.trim()}
            className="btn bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs py-1.5 px-3 rounded flex items-center gap-1.5 font-mono font-medium transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Block Destination</span>
          </button>
        </form>
      </div>

      {/* 2. SUB-TABS NAVIGATION */}
      <div className="flex-none px-4 py-2 border-b border-dark-800 bg-dark-900/60 flex items-center justify-between text-xs">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveSubTab('rules')}
            className={`px-3 py-1 rounded font-medium transition-colors ${
              activeSubTab === 'rules'
                ? 'bg-dark-800 text-white shadow-sm'
                : 'text-dark-400 hover:text-dark-200'
            }`}
          >
            Active Blocks ({activeRules.length})
          </button>
          <button
            onClick={() => setActiveSubTab('pending')}
            className={`px-3 py-1 rounded font-medium flex items-center gap-1.5 transition-colors ${
              activeSubTab === 'pending'
                ? 'bg-dark-800 text-white shadow-sm'
                : 'text-dark-400 hover:text-dark-200'
            }`}
          >
            <span>Pending Approvals</span>
            {pendingRules.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold bg-amber-500/30 text-amber-300">
                {pendingRules.length}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveSubTab('audit')}
            className={`px-3 py-1 rounded font-medium transition-colors ${
              activeSubTab === 'audit'
                ? 'bg-dark-800 text-white shadow-sm'
                : 'text-dark-400 hover:text-dark-200'
            }`}
          >
            Audit Trail
          </button>
        </div>

        <button
          onClick={fetchData}
          className="p-1 rounded text-dark-400 hover:text-white transition-colors"
          title="Refresh Prevention Rules"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* 3. SUB-TAB CONTENT PANELS */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono">
        {/* SUB-TAB A: ACTIVE BLOCKS */}
        {activeSubTab === 'rules' && (
          <div>
            {activeRules.length === 0 ? (
              <div className="p-12 text-center text-dark-500 text-xs">
                <ShieldCheck className="w-8 h-8 text-dark-600 mx-auto mb-2" />
                <p className="font-bold text-dark-300">No Active Destination Blocks</p>
                <p className="text-[11px] text-dark-500 mt-1 max-w-sm mx-auto">
                  When suspicious destinations are blocked either manually or autonomously, they will appear here with active countdown timers.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {activeRules.map((r) => (
                  <div key={r.id} className="card p-3.5 bg-dark-900 border-dark-800 hover:border-dark-700 transition-all flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-bold font-mono text-rose-400 flex items-center gap-1.5">
                          <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                          {r.destination_ip}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                          ACTIVE ({Math.ceil(r.remaining_seconds)}s)
                        </span>
                      </div>
                      <p className="text-xs text-white font-medium mb-1 truncate" title={r.finding_title}>
                        {r.finding_title}
                      </p>
                      <div className="text-[10px] text-dark-400 space-y-0.5">
                        <p>Adapter: <span className="text-dark-300">{r.adapter_name}</span> (Verified: ✓)</p>
                        <p>Applied by: <span className="text-dark-300">{r.applied_by}</span></p>
                        <p>Expires in: <span className="text-white font-bold">{Math.ceil(r.remaining_seconds / 60)} minutes</span></p>
                      </div>

                      {/* Collateral Impact Notice */}
                      {r.collateral_warning && (
                        <div className="mt-2 p-2 rounded bg-amber-500/10 border border-amber-500/20 text-[10px] text-amber-300 leading-relaxed">
                          {r.collateral_warning}
                        </div>
                      )}
                    </div>

                    <div className="mt-3 pt-2 border-t border-dark-800/80 flex items-center justify-end">
                      <button
                        onClick={() => handleRevoke(r.id)}
                        className="btn bg-dark-800 hover:bg-rose-500/20 text-rose-300 text-xs py-1 px-2.5 rounded flex items-center gap-1 font-mono transition-colors"
                      >
                        <Trash2 className="w-3 h-3" />
                        <span>Revoke Block</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* SUB-TAB B: PENDING APPROVALS */}
        {activeSubTab === 'pending' && (
          <div>
            {pendingRules.length === 0 ? (
              <div className="p-12 text-center text-dark-500 text-xs">
                <CheckCircle2 className="w-8 h-8 text-dark-600 mx-auto mb-2" />
                <p className="font-bold text-dark-300">No Block Proposals Awaiting Review</p>
                <p className="text-[11px] text-dark-500 mt-1 max-w-sm mx-auto">
                  Under the "Ask Before Blocking" policy, detected threats targeting destination IPs will wait here for human review before any firewall rule is modified.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {pendingRules.map((r) => (
                  <div key={r.id} className="card p-4 bg-dark-900 border-amber-500/30">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-bold font-mono text-amber-300 flex items-center gap-1.5">
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                        Target: {r.destination_ip}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-300 font-bold border border-amber-500/30">
                        AWAITING SIGN-OFF
                      </span>
                    </div>

                    <p className="text-xs text-white font-medium mb-1.5">
                      {r.finding_title}
                    </p>

                    <div className="grid grid-cols-2 gap-2 text-[11px] text-dark-300 mb-2">
                      <div>Severity: <span className="font-bold uppercase text-rose-400">{r.severity}</span></div>
                      <div>Confidence: <span className="font-bold uppercase text-white">{r.confidence}</span></div>
                      <div>Proposed Expiry: <span className="text-white">{Math.round(r.duration_seconds / 60)} minutes</span></div>
                      <div>Firewall Target: <span className="text-white">{r.adapter_name}</span></div>
                    </div>

                    {r.collateral_warning && (
                      <div className="p-2.5 rounded bg-amber-500/10 border border-amber-500/30 text-[10px] text-amber-200 leading-relaxed mb-3">
                        {r.collateral_warning}
                      </div>
                    )}

                    <div className="flex items-center justify-end gap-2 pt-2 border-t border-dark-800">
                      <button
                        onClick={() => handleRevoke(r.id)}
                        className="btn bg-dark-800 hover:bg-dark-700 text-dark-300 text-xs py-1 px-3 rounded font-mono"
                      >
                        Dismiss
                      </button>
                      <button
                        onClick={() => handleApprove(r.id)}
                        className="btn bg-rose-600 hover:bg-rose-500 text-white text-xs py-1 px-3 rounded font-mono font-medium flex items-center gap-1"
                      >
                        <ShieldAlert className="w-3.5 h-3.5" />
                        <span>Approve Drop ({Math.round(r.duration_seconds / 60)}m)</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* SUB-TAB C: AUDIT TRAIL */}
        {activeSubTab === 'audit' && (
          <div className="card overflow-hidden bg-dark-900 border-dark-800">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-dark-800 bg-dark-950/60 text-dark-400 font-mono text-[10px] uppercase tracking-wider">
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Action</th>
                  <th className="py-2.5 px-3">Target IP</th>
                  <th className="py-2.5 px-3">Details</th>
                  <th className="py-2.5 px-3">User</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-800/60 font-mono text-[11px]">
                {auditLog.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-6 text-center text-dark-500">
                      No audit events logged yet.
                    </td>
                  </tr>
                ) : (
                  auditLog.map((log) => {
                    const ts = new Date(log.timestamp * 1000).toLocaleString()
                    const actColor = log.action === 'APPLIED' || log.action === 'APPROVED'
                      ? 'text-emerald-400'
                      : log.action.includes('FAIL') || log.action.includes('REJECT')
                      ? 'text-rose-400'
                      : 'text-amber-300'

                    return (
                      <tr key={log.id} className="hover:bg-dark-800/30">
                        <td className="py-2 px-3 text-dark-400 whitespace-nowrap">{ts}</td>
                        <td className={`py-2 px-3 font-bold ${actColor}`}>{log.action}</td>
                        <td className="py-2 px-3 text-white">{log.destination_ip || '-'}</td>
                        <td className="py-2 px-3 text-dark-300 max-w-md truncate" title={log.details}>
                          {log.details}
                        </td>
                        <td className="py-2 px-3 text-dark-400">{log.user}</td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* CONFIRM AUTOMATIC PROTECTION MODAL */}
      {confirmAutoModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in font-mono">
          <div className="card max-w-md w-full p-5 bg-dark-900 border-rose-500/40 shadow-2xl space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-rose-500/20 border border-rose-500/40 text-rose-400">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-sm text-white uppercase tracking-wider">
                  Enable Autonomous Threat Protection?
                </h3>
                <p className="text-[11px] text-dark-400 mt-0.5">
                  Explicit confirmation required
                </p>
              </div>
            </div>

            <div className="p-3 rounded bg-dark-950 border border-dark-800 text-xs text-dark-300 space-y-2 leading-relaxed">
              <p>
                When autonomous protection is enabled, Beacon will automatically apply temporary egress drop rules (15m default)
                for any <strong className="text-white">HIGH-CONFIDENCE</strong> threats detected on live network traffic.
              </p>
              <ul className="list-disc pl-4 space-y-1 text-dark-400 text-[11px]">
                <li>Only the suspicious destination IP is blocked.</li>
                <li>Offline PCAP analysis is never affected.</li>
                <li>All actions are independently verified and logged.</li>
                <li>Active rules are capped at 100 to prevent state exhaustion.</li>
              </ul>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-dark-800">
              <button
                type="button"
                onClick={() => setConfirmAutoModal(false)}
                className="btn bg-dark-800 hover:bg-dark-700 text-dark-300 text-xs py-1.5 px-3 rounded"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleEnableAutoProtect}
                className="btn bg-rose-600 hover:bg-rose-500 text-white text-xs py-1.5 px-4 rounded font-bold shadow-lg shadow-rose-900/30"
              >
                Confirm & Enable
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
