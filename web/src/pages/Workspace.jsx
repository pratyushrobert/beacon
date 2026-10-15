import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import axios from 'axios'
import {
  Pin,
  FileText,
  Trash2,
  Download,
  Share2,
  Package,
  ShieldAlert,
  Server,
  ArrowRight,
  Save,
  Check
} from 'lucide-react'
import CaptureHeader from '../components/CaptureHeader'

export default function Workspace() {
  const { analysisId } = useParams()
  const storageKey = `beacon_workspace_${analysisId}`

  const [pinnedHosts, setPinnedHosts] = useState([])
  const [pinnedFindings, setPinnedFindings] = useState([])
  const [notes, setNotes] = useState('')
  const [previewMode, setPreviewMode] = useState(false)
  const [saveStatus, setSaveStatus] = useState('Saved')

  useEffect(() => {
    loadWorkspace()
  }, [analysisId])

  const loadWorkspace = () => {
    try {
      const saved = localStorage.getItem(storageKey)
      if (saved) {
        const data = JSON.parse(saved)
        setPinnedHosts(data.pinned_hosts || [])
        setPinnedFindings(data.pinned_findings || [])
        setNotes(data.notes || '')
      }
    } catch (e) {
      console.error('Failed to load workspace:', e)
    }
  }

  const saveWorkspace = (newHosts, newFindings, newNotes) => {
    try {
      const data = {
        pinned_hosts: newHosts !== undefined ? newHosts : pinnedHosts,
        pinned_findings: newFindings !== undefined ? newFindings : pinnedFindings,
        notes: newNotes !== undefined ? newNotes : notes,
        updated_at: new Date().toISOString(),
      }
      localStorage.setItem(storageKey, JSON.stringify(data))
      setSaveStatus('Saved')
    } catch (e) {
      console.error('Failed to save workspace:', e)
      setSaveStatus('Error saving')
    }
  }

  const handleNotesChange = (e) => {
    const val = e.target.value
    setNotes(val)
    setSaveStatus('Saving...')
    // Debounce save
    saveWorkspace(undefined, undefined, val)
  }

  const removePinnedHost = (ip) => {
    const updated = pinnedHosts.filter((h) => h !== ip)
    setPinnedHosts(updated)
    saveWorkspace(updated, undefined, undefined)
  }

  const removePinnedFinding = (findingTitle) => {
    const updated = pinnedFindings.filter((f) => f !== findingTitle)
    setPinnedFindings(updated)
    saveWorkspace(undefined, updated, undefined)
  }

  const clearWorkspace = () => {
    if (window.confirm('Clear all pinned items and notes for this investigation?')) {
      setPinnedHosts([])
      setPinnedFindings([])
      setNotes('')
      localStorage.removeItem(storageKey)
    }
  }

  const exportWorkspaceMarkdown = () => {
    const md = [
      `# Beacon Investigation Workspace Report`,
      `**Capture Analysis ID**: ${analysisId}`,
      `**Exported**: ${new Date().toUTCString()}`,
      ``,
      `## Pinned Key Hosts (${pinnedHosts.length})`,
      pinnedHosts.length > 0 ? pinnedHosts.map((h) => `- \`${h}\``).join('\n') : `*None pinned*`,
      ``,
      `## Flagged Security Findings (${pinnedFindings.length})`,
      pinnedFindings.length > 0 ? pinnedFindings.map((f) => `- **${f}**`).join('\n') : `*None pinned*`,
      ``,
      `## Analyst Investigation Notes`,
      notes || `*No analyst notes recorded.*`,
    ].join('\n')

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `beacon_workspace_${analysisId.slice(0, 8)}.md`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="min-h-screen bg-canvas flex flex-col">
      <CaptureHeader />

      <div className="flex-1 p-6 max-w-7xl mx-auto w-full">
        {/* Workspace Title & Toolbar */}
        <div className="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-dark-900 dark:text-white flex items-center gap-2">
              <Pin className="w-6 h-6 text-amber-500" />
              <span>Analyst Investigation Workspace</span>
              {analysisId === 'live' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 self-center">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  LIVE SESSION
                </span>
              )}
            </h1>
            <p className="text-xs text-dark-500 dark:text-dark-400 mt-1">
              Active working canvas for pinned suspects, flagged findings, and incident hypothesis notes.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={exportWorkspaceMarkdown}
              className="btn btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Markdown</span>
            </button>

            <button
              onClick={clearWorkspace}
              className="px-3 py-1.5 rounded-lg border border-red-300 dark:border-red-900/50 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 text-xs flex items-center gap-1.5 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear Workspace</span>
            </button>
          </div>
        </div>

        {/* Workspace Layout Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Pinned Entities Column */}
          <div className="space-y-6">
            {/* Pinned Hosts Card */}
            <div className="card p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-sky-500" />
                  <h2 className="text-sm font-bold text-dark-900 dark:text-white">
                    Pinned Suspect Hosts ({pinnedHosts.length})
                  </h2>
                </div>
                <Link
                  to={`/hosts/${analysisId}`}
                  className="text-[11px] text-primary-600 dark:text-primary-400 hover:underline"
                >
                  All Hosts
                </Link>
              </div>

              {pinnedHosts.length === 0 ? (
                <div className="text-xs text-dark-400 text-center py-6 border border-dashed border-dark-200 dark:border-dark-800 rounded-lg">
                  No hosts pinned yet. Pin hosts from Network Graph or Host Inventory.
                </div>
              ) : (
                <div className="space-y-2">
                  {pinnedHosts.map((host) => (
                    <div
                      key={host}
                      className="flex items-center justify-between p-2.5 rounded bg-dark-50 dark:bg-dark-900 border border-dark-200 dark:border-dark-800 text-xs font-mono"
                    >
                      <span className="font-bold text-dark-900 dark:text-white">{host}</span>
                      <div className="flex items-center gap-2">
                        <Link
                          to={`/packets/${analysisId}?ip=${host}`}
                          className="text-primary-600 dark:text-primary-400 hover:underline text-[11px]"
                          title="Inspect packets"
                        >
                          Packets
                        </Link>
                        <button
                          onClick={() => removePinnedHost(host)}
                          className="text-dark-400 hover:text-red-500 text-base leading-none p-1"
                          title="Unpin host"
                        >
                          ×
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Pinned Findings Card */}
            <div className="card p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-500" />
                  <h2 className="text-sm font-bold text-dark-900 dark:text-white">
                    Flagged Findings ({pinnedFindings.length})
                  </h2>
                </div>
                <Link
                  to={`/findings/${analysisId}`}
                  className="text-[11px] text-primary-600 dark:text-primary-400 hover:underline"
                >
                  All Findings
                </Link>
              </div>

              {pinnedFindings.length === 0 ? (
                <div className="text-xs text-dark-400 text-center py-6 border border-dashed border-dark-200 dark:border-dark-800 rounded-lg">
                  No findings pinned yet. Pin findings from the Findings or Storyline pages.
                </div>
              ) : (
                <div className="space-y-2">
                  {pinnedFindings.map((finding) => (
                    <div
                      key={finding}
                      className="flex items-start justify-between p-2.5 rounded bg-dark-50 dark:bg-dark-900 border border-dark-200 dark:border-dark-800 text-xs"
                    >
                      <span className="font-medium text-dark-800 dark:text-dark-200 line-clamp-2 pr-2">
                        {finding}
                      </span>
                      <button
                        onClick={() => removePinnedFinding(finding)}
                        className="text-dark-400 hover:text-red-500 text-base leading-none p-1 shrink-0"
                        title="Unpin finding"
                      >
                        ×
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Right 2 Columns: Analyst Investigation Notes */}
          <div className="lg:col-span-2">
            <div className="card p-5 h-full flex flex-col">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-primary-500" />
                  <h2 className="text-sm font-bold text-dark-900 dark:text-white">
                    Analyst Investigation Log & Hypothesis
                  </h2>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-[11px] text-dark-400 font-mono">
                    {saveStatus}
                  </span>
                  <div className="flex rounded p-0.5 bg-dark-100 dark:bg-dark-800 text-xs">
                    <button
                      onClick={() => setPreviewMode(false)}
                      className={`px-2.5 py-1 rounded transition-colors ${
                        !previewMode
                          ? 'bg-white dark:bg-dark-900 text-dark-900 dark:text-white shadow-sm'
                          : 'text-dark-500 hover:text-dark-200'
                      }`}
                    >
                      Editor
                    </button>
                    <button
                      onClick={() => setPreviewMode(true)}
                      className={`px-2.5 py-1 rounded transition-colors ${
                        previewMode
                          ? 'bg-white dark:bg-dark-900 text-dark-900 dark:text-white shadow-sm'
                          : 'text-dark-500 hover:text-dark-200'
                      }`}
                    >
                      Preview
                    </button>
                  </div>
                </div>
              </div>

              {previewMode ? (
                <div className="flex-1 p-4 rounded-lg bg-dark-50 dark:bg-dark-900/60 border border-dark-200 dark:border-dark-800 text-xs font-mono text-dark-800 dark:text-dark-200 whitespace-pre-wrap overflow-y-auto min-h-[350px]">
                  {notes || '*No notes written yet. Switch to Editor to log findings, hypotheses, and next steps.*'}
                </div>
              ) : (
                <textarea
                  value={notes}
                  onChange={handleNotesChange}
                  placeholder="Record your investigation steps, key observations, IOC pivots, hypotheses, and root cause notes here... (Auto-saved locally)"
                  className="flex-1 p-4 rounded-lg bg-dark-50 dark:bg-dark-900/80 border border-dark-200 dark:border-dark-800 text-xs font-mono text-dark-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-primary-500 min-h-[350px] resize-none leading-relaxed"
                />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
