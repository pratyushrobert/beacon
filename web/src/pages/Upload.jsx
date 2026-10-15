import { useState, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useDropzone } from 'react-dropzone'
import axios from 'axios'
import {
  Upload as UploadIcon,
  FileUp,
  Loader2,
  AlertCircle,
  CheckCircle2,
  Trash2,
  ArrowRight,
  RefreshCw,
  Clock,
  Shield,
  X
} from 'lucide-react'

export default function Upload({ setCurrentAnalysis }) {
  const navigate = useNavigate()
  const [uploading, setUploading] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState(null)
  const [selectedMode, setSelectedMode] = useState('blue')
  const [uploadedFile, setUploadedFile] = useState(null)
  const [history, setHistory] = useState([])
  const [loadingHistory, setLoadingHistory] = useState(true)

  useEffect(() => {
    loadHistory()
  }, [])

  const loadHistory = async () => {
    try {
      setLoadingHistory(true)
      const res = await axios.get('/api/analyses')
      setHistory(res.data.analyses || [])
    } catch (e) {
      console.error('Failed to load history', e)
    } finally {
      setLoadingHistory(false)
    }
  }

  const handleDelete = async (e, id) => {
    e.stopPropagation()
    if (!window.confirm('Delete this analysis and its cached data?')) return
    try {
      await axios.delete(`/api/analysis/${id}`)
      loadHistory()
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to delete analysis')
    }
  }

  const openAnalysis = (item) => {
    setCurrentAnalysis({
      id: item.id,
      filename: item.filename,
      mode: item.mode
    })
    navigate(`/dashboard/${item.id}`)
  }

  const onDrop = useCallback(async (acceptedFiles) => {
    const file = acceptedFiles[0]
    if (!file) return

    setError(null)
    setUploading(true)

    try {
      // Upload file
      const formData = new FormData()
      formData.append('file', file)

      const uploadResponse = await axios.post('/api/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })

      setUploadedFile({
        id: uploadResponse.data.id,
        filename: uploadResponse.data.filename,
        size: uploadResponse.data.size
      })

      setUploading(false)
    } catch (err) {
      setError(err.response?.data?.detail || 'Upload failed')
      setUploading(false)
    }
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.tcpdump.pcap': ['.pcap', '.pcapng']
    },
    maxFiles: 1
  })

  const startAnalysis = async () => {
    if (!uploadedFile) return

    setAnalyzing(true)
    setError(null)

    try {
      // Start analysis
      await axios.post(`/api/analyze/${uploadedFile.id}`, {
        mode: selectedMode,
        packet_limit: null
      })

      // Poll for completion
      const pollInterval = setInterval(async () => {
        try {
          const statusResponse = await axios.get(`/api/analysis/${uploadedFile.id}/status`)
          const status = statusResponse.data

          if (status.status === 'complete') {
            clearInterval(pollInterval)
            setAnalyzing(false)
            setCurrentAnalysis({
              id: uploadedFile.id,
              filename: uploadedFile.filename,
              mode: selectedMode
            })
            navigate(`/dashboard/${uploadedFile.id}`)
          } else if (status.status === 'error') {
            clearInterval(pollInterval)
            setError(status.error || 'Analysis failed')
            setAnalyzing(false)
          }
        } catch (err) {
          clearInterval(pollInterval)
          setError('Failed to check analysis status')
          setAnalyzing(false)
        }
      }, 2000)

    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to start analysis')
      setAnalyzing(false)
    }
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-screen p-8 bg-canvas">
      <div className="w-full max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-surface border border-subtle mb-4 shadow-sm">
            <UploadIcon className="w-8 h-8 text-primary-400" />
          </div>
          <h1 className="text-3xl font-bold text-dark-900 dark:text-white mb-2">
            Upload PCAP Capture
          </h1>
          <p className="text-dark-400 text-sm">
            Upload a network capture file to begin deep cybersecurity investigation with TShark
          </p>
        </div>

        {/* Upload Area */}
        <div className="card mb-6">
          <div
            {...getRootProps()}
            className={`
              border-2 border-dashed rounded-lg p-10 text-center cursor-pointer transition-colors relative
              ${isDragActive
                ? 'border-primary-500 bg-primary-500/10'
                : 'border-subtle hover:border-primary-500/50'
              }
              ${uploading || analyzing ? 'pointer-events-none opacity-50' : ''}
            `}
          >
            <input {...getInputProps()} />

            {uploading ? (
              <div className="flex flex-col items-center">
                <Loader2 className="w-12 h-12 text-primary-400 animate-spin mb-4" />
                <p className="text-lg font-medium text-dark-900 dark:text-white">
                  Uploading capture to server...
                </p>
              </div>
            ) : uploadedFile ? (
              <div className="flex flex-col items-center">
                <CheckCircle2 className="w-12 h-12 text-emerald-400 mb-4" />
                <p className="text-lg font-medium text-dark-900 dark:text-white mb-1">
                  {uploadedFile.filename}
                </p>
                <p className="text-sm text-dark-400 mb-3">
                  {formatBytes(uploadedFile.size)}
                </p>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation()
                    setUploadedFile(null)
                  }}
                  className="text-xs text-rose-400 hover:text-rose-300 underline"
                >
                  Choose a different capture
                </button>
              </div>
            ) : (
              <div className="flex flex-col items-center">
                <FileUp className="w-12 h-12 text-dark-500 mb-4" />
                <p className="text-lg font-medium text-dark-900 dark:text-white mb-1">
                  {isDragActive ? 'Drop PCAP file here' : 'Drag & drop PCAP or PCAPNG file'}
                </p>
                <p className="text-sm text-dark-400">
                  or click to browse your local filesystem
                </p>
                <p className="text-xs text-dark-500 mt-4">
                  Supports Wireshark .pcap and .pcapng captures
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Mode Selection */}
        {uploadedFile && !analyzing && (
          <div className="card mb-6">
            <h3 className="text-sm font-bold uppercase tracking-wider text-dark-400 mb-3">
              Select Analysis Mode
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                {
                  value: 'blue',
                  label: 'Blue Mode',
                  tag: 'Defensive SOC',
                  desc: 'Port scans, host sweeps, DNS exfiltration, beacons, and suspicious connections',
                  activeBorder: 'border-sky-500',
                  activeBg: 'bg-sky-950/30'
                },
                {
                  value: 'red',
                  label: 'Red Mode',
                  tag: 'Offensive Posture',
                  desc: 'Cleartext credentials, API tokens, internal IP leaks, banners, and deprecated TLS',
                  activeBorder: 'border-rose-500',
                  activeBg: 'bg-rose-950/30'
                },
                {
                  value: 'white',
                  label: 'Free Bird',
                  tag: 'Red + Blue Unified',
                  desc: 'Unified cybersecurity investigation: Red + Blue dual analysis, full telemetry & threat correlation',
                  activeBorder: 'border-sky-400',
                  activeBg: 'bg-gradient-to-br from-sky-950/30 to-rose-950/30'
                }
              ].map((m) => {
                const isSelected = selectedMode === m.value
                return (
                  <button
                    key={m.value}
                    type="button"
                    onClick={() => setSelectedMode(m.value)}
                    className={`
                      p-4 rounded-xl border text-left transition-all relative
                      ${isSelected
                        ? `${m.activeBorder} ${m.activeBg} ring-1 ring-primary-500/50 shadow-md`
                        : 'border-subtle bg-surface hover:border-dark-600'
                      }
                    `}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-bold text-sm text-dark-900 dark:text-white">
                        {m.label}
                      </span>
                      {isSelected ? (
                        <CheckCircle2 className="w-4 h-4 text-primary-400" />
                      ) : (
                        <span className="text-[10px] uppercase font-mono text-dark-500 border border-subtle px-1.5 py-0.5 rounded">
                          {m.tag}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-dark-400 leading-relaxed">
                      {m.desc}
                    </div>
                  </button>
                )
              })}
            </div>
          </div>
        )}

        {/* Error Display */}
        {error && (
          <div className="mb-6 p-4 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
            <div className="flex items-start">
              <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 mr-3 mt-0.5" />
              <div className="flex-1">
                <h4 className="text-sm font-medium text-red-900 dark:text-red-200 mb-1">
                  Analysis Error
                </h4>
                <p className="text-sm text-red-800 dark:text-red-300">
                  {error}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Analyze Button */}
        {uploadedFile && (
          <button
            onClick={startAnalysis}
            disabled={analyzing}
            className="btn btn-primary w-full h-12 text-base mb-10"
          >
            {analyzing ? (
              <>
                <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                Analyzing with TShark pipeline...
              </>
            ) : (
              <>
                Run {selectedMode.toUpperCase()} Mode Investigation
              </>
            )}
          </button>
        )}

        {/* Capture History */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-bold text-dark-900 dark:text-white">
                Investigation History
              </h2>
              <p className="text-xs text-dark-500">
                Previously analyzed PCAP/PCAPNG captures stored in local SQLite cache
              </p>
            </div>
            <button
              onClick={loadHistory}
              disabled={loadingHistory}
              className="text-xs text-primary-600 dark:text-primary-400 hover:underline flex items-center gap-1.5"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingHistory ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>

          {loadingHistory ? (
            <div className="flex justify-center py-8">
              <Loader2 className="w-6 h-6 text-primary-500 animate-spin" />
            </div>
          ) : history.length === 0 ? (
            <div className="text-center py-8 text-dark-500 text-sm">
              No previous captures found. Upload a PCAP above to begin investigation.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-dark-200 dark:border-dark-800 text-xs font-medium text-dark-500 dark:text-dark-400 uppercase">
                    <th className="py-3 px-3">Capture File</th>
                    <th className="py-3 px-3">Mode</th>
                    <th className="py-3 px-3 text-right">Packets</th>
                    <th className="py-3 px-3 text-right">Findings</th>
                    <th className="py-3 px-3">Analyzed</th>
                    <th className="py-3 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-100 dark:divide-dark-800">
                  {history.map((item) => (
                    <tr
                      key={item.id}
                      className="hover:bg-dark-50 dark:hover:bg-dark-800/50 cursor-pointer transition-colors"
                      onClick={() => openAnalysis(item)}
                    >
                      <td className="py-3 px-3 font-medium text-dark-900 dark:text-white">
                        <div className="truncate max-w-xs" title={item.filename}>
                          {item.filename}
                        </div>
                        <div className="text-xs text-dark-500 font-mono">
                          {formatBytes(item.size)}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`badge ${
                            item.mode === 'blue'
                              ? 'bg-blue-950/40 text-blue-300 border border-blue-800/60'
                              : item.mode === 'red'
                              ? 'bg-rose-950/40 text-rose-300 border border-rose-800/60'
                              : 'bg-slate-800 text-sky-300 border border-slate-700'
                          } uppercase text-[11px] font-mono`}
                        >
                          {item.mode === 'white' ? 'Free Bird' : item.mode}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right font-mono text-dark-700 dark:text-dark-300">
                        {item.packet_count?.toLocaleString() || '—'}
                      </td>
                      <td className="py-3 px-3 text-right">
                        {item.findings_count > 0 ? (
                          <span className="badge badge-warning text-xs">
                            {item.findings_count}
                          </span>
                        ) : (
                          <span className="text-dark-400 text-xs">—</span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-xs text-dark-500">
                        {formatDate(item.updated_at || item.created_at)}
                      </td>
                      <td className="py-3 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => openAnalysis(item)}
                            className="px-2.5 py-1 text-xs font-medium rounded bg-primary-50 text-primary-700 hover:bg-primary-100 dark:bg-primary-900/20 dark:text-primary-400 dark:hover:bg-primary-900/40 flex items-center gap-1"
                            title="Open investigation dashboard"
                          >
                            <span>Open</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>
                          <button
                            onClick={(e) => handleDelete(e, item.id)}
                            className="p-1 text-dark-400 hover:text-red-600 dark:hover:text-red-400 rounded transition-colors"
                            title="Delete capture analysis"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
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

function formatDate(isoStr) {
  if (!isoStr) return '—'
  try {
    const d = new Date(isoStr)
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  } catch {
    return isoStr
  }
}
