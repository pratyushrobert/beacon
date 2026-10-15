import { Link, useLocation } from 'react-router-dom'
import {
  Upload,
  LayoutDashboard,
  AlertTriangle,
  Users,
  Network,
  Clock,
  Package,
  Fingerprint,
  Share2,
  Compass,
  Pin,
  GitCompare,
  Radio,
  Shield,
  Zap,
  Flame,
  CheckCircle2,
  History
} from 'lucide-react'
import { useMode } from '../context/ModeContext'
import axios from 'axios'

export default function Sidebar({ currentAnalysis }) {
  const location = useLocation()
  const { mode, setMode, isFreeBird, isBlue, isRed, themeColors } = useMode()

  const routeAnalysisId = location.pathname.match(
    /\/(?:dashboard|findings|hosts|conversations|timeline|packets|iocs|graph|storyline|workspace|memory)\/([^/?#]+)/
  )?.[1]
  const isLivePath = location.pathname.startsWith('/live')
  const analysisId = currentAnalysis?.id || routeAnalysisId || (isLivePath ? 'live' : 'live')
  const isLiveActive = analysisId === 'live'

  const navigation = [
    { name: 'Upload Capture', href: '/upload', icon: Upload, disabled: false },
    { name: 'Live Capture', href: '/live', icon: Radio, disabled: false },
    { name: 'Dashboard', href: `/dashboard/${analysisId}`, icon: LayoutDashboard, disabled: false },

    { name: 'Storyline', href: `/storyline/${analysisId}`, icon: Compass, disabled: false },
    { name: "Memory / Changes", href: `/memory/${analysisId}`, icon: History, disabled: false },
    { name: 'Security Findings', href: `/findings/${analysisId}`, icon: AlertTriangle, disabled: false },
    { name: 'Evidence Graph', href: `/graph/${analysisId}`, icon: Share2, disabled: false },
    { name: 'Workspace', href: `/workspace/${analysisId}`, icon: Pin, disabled: false },
    { name: 'Packet Explorer', href: `/packets/${analysisId}`, icon: Package, disabled: false },
    { name: 'Conversations', href: `/conversations/${analysisId}`, icon: Network, disabled: false },
    { name: 'Host Inventory', href: `/hosts/${analysisId}`, icon: Users, disabled: false },
    { name: 'Timeline', href: `/timeline/${analysisId}`, icon: Clock, disabled: false },
    { name: 'Extracted IOCs', href: `/iocs/${analysisId}`, icon: Fingerprint, disabled: false },
    { name: 'Capture Comparison', href: '/compare', icon: GitCompare, disabled: false },
  ]

  const handleModeSwitch = async (newMode) => {
    setMode(newMode)
    if (analysisId) {
      try {
        await axios.post(`/api/analysis/${analysisId}/mode`, { mode: newMode })
        window.dispatchEvent(new CustomEvent('beacon_mode_changed', { detail: newMode }))
      } catch (err) {
        console.error('Failed to sync mode with analysis:', err)
      }
    }
  }

  return (
    <aside
      className="flex flex-col w-60 border-r select-none h-screen transition-colors duration-200"
      style={{
        backgroundColor: 'var(--bg-sidebar)',
        borderColor: 'var(--border-subtle)',
      }}
    >
      {/* Brand Header */}
      <div
        className="flex items-center justify-between h-14 px-4 border-b"
        style={{ borderColor: 'var(--border-subtle)' }}
      >
        <Link to="/upload" className="flex items-center gap-2.5 group">
          {/* Custom Dual/Single Identity Glyph */}
          <div className="relative flex items-center justify-center w-7 h-7 rounded-md bg-dark-900 border border-dark-800 shadow-sm overflow-hidden">
            {isFreeBird ? (
              /* DUAL GLYPH: RED + BLUE (Free Bird) */
              <div className="flex w-full h-full">
                <div className="w-1/2 h-full bg-blue-500/80 flex items-center justify-center">
                  <div className="w-1.5 h-1.5 rounded-full bg-white shadow-sm" />
                </div>
                <div className="w-1/2 h-full bg-rose-500/80 flex items-center justify-center">
                  <div className="w-1.5 h-1.5 rounded-full bg-white shadow-sm" />
                </div>
              </div>
            ) : isBlue ? (
              /* BLUE DEFENSIVE GLYPH */
              <div className="flex items-center justify-center w-full h-full bg-sky-500/20 text-sky-400">
                <Shield className="w-4 h-4" />
              </div>
            ) : (
              /* RED OFFENSIVE GLYPH */
              <div className="flex items-center justify-center w-full h-full bg-rose-500/20 text-rose-400">
                <Flame className="w-4 h-4" />
              </div>
            )}
          </div>

          <div>
            <div className="flex items-center gap-1.5 leading-none">
              <span className="text-sm font-bold tracking-tight text-white font-sans">
                BEACON
              </span>
              <span
                className="text-[9px] font-mono px-1 py-0.2 rounded font-semibold uppercase tracking-wider"
                style={{
                  backgroundColor: isFreeBird
                    ? 'rgba(56, 189, 248, 0.15)'
                    : isBlue
                    ? 'rgba(56, 189, 248, 0.15)'
                    : 'rgba(244, 63, 94, 0.15)',
                  color: isFreeBird ? '#38bdf8' : isBlue ? '#38bdf8' : '#f43f5e',
                  border: `1px solid ${isFreeBird ? 'rgba(244, 63, 94, 0.3)' : 'currentColor'}`,
                }}
              >
                {isFreeBird ? 'FREE BIRD' : isBlue ? 'BLUE' : 'RED'}
              </span>
            </div>
            <span className="text-[10px] text-dark-400 font-mono tracking-wider block mt-0.5">
              PCAP WORKSTATION
            </span>
          </div>
        </Link>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 px-2.5 py-3 space-y-0.5 overflow-y-auto">
        {navigation.map((item) => {
          const isActive = location.pathname === item.href
          const Icon = item.icon

          return (
            <Link
              key={item.name}
              to={item.href}
              className={`
                flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-all duration-150
                ${item.disabled ? 'pointer-events-none opacity-30 text-dark-600' : ''}
                ${
                  isActive
                    ? 'text-white shadow-sm font-semibold'
                    : 'text-dark-400 hover:text-dark-200 hover:bg-white/5'
                }
              `}
              style={
                isActive
                  ? {
                      backgroundColor: 'var(--bg-elevated)',
                      borderLeft: `2px solid ${
                        isFreeBird
                          ? '#38bdf8'
                          : isBlue
                          ? '#38bdf8'
                          : '#f43f5e'
                      }`,
                    }
                  : {}
              }
            >
              <div className="flex items-center gap-2.5 truncate">
                <Icon
                  className="w-4 h-4 shrink-0 transition-colors"
                  style={{
                    color: isActive
                      ? isFreeBird
                        ? '#38bdf8'
                        : isBlue
                        ? '#38bdf8'
                        : '#f43f5e'
                      : undefined,
                  }}
                />
                <span className="truncate">{item.name}</span>
              </div>

              {item.name === 'Storyline' && analysisId && (
                <span className="w-1.5 h-1.5 rounded-full bg-primary-400 animate-pulse" />
              )}
              {item.name === 'Live Capture' && (
                <span className="px-1 py-0.2 rounded text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  LIVE
                </span>
              )}
            </Link>

          )
        })}
      </nav>

      {/* Sidebar Footer: Mode Selector & Capture Info */}
      <div
        className="p-3 border-t space-y-3"
        style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-subtle)' }}
      >
        {/* Active Analysis Indicator */}
        {(currentAnalysis || analysisId) && (
          <div className="px-2.5 py-2 rounded border bg-dark-950/60 border-dark-800/80">
            <div className="text-[10px] font-mono text-dark-500 uppercase tracking-wider mb-0.5 flex items-center justify-between">
              <span>TARGET CAPTURE</span>
              <span className={`w-1.5 h-1.5 rounded-full ${isLiveActive ? 'bg-emerald-400 animate-pulse' : 'bg-emerald-500'}`} />
            </div>
            <div
              className="text-xs font-mono font-bold text-dark-200 truncate flex items-center gap-1.5"
              title={currentAnalysis?.filename || (isLiveActive ? 'Live Continuous Stream' : analysisId)}
            >
              {isLiveActive && (
                <span className="px-1 py-0.2 rounded text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  LIVE
                </span>
              )}
              <span className="truncate">
                {currentAnalysis?.filename || (isLiveActive ? 'Live Continuous Stream' : analysisId)}
              </span>
            </div>
          </div>
        )}

        {/* Identity / Mode Switcher Pill */}
        <div>
          <div className="text-[10px] font-mono uppercase tracking-wider text-dark-400 mb-1.5 px-1 flex items-center justify-between">
            <span>ANALYSIS IDENTITY</span>
            <span
              className="text-[9px] font-semibold"
              style={{ color: isFreeBird ? '#38bdf8' : isBlue ? '#38bdf8' : '#f43f5e' }}
            >
              {themeColors.modeLabel}
            </span>
          </div>

          <div
            className="grid grid-cols-3 p-0.5 rounded-md border text-[11px] font-mono"
            style={{
              backgroundColor: 'var(--bg-app)',
              borderColor: 'var(--border-subtle)',
            }}
          >
            <button
              onClick={() => handleModeSwitch('blue')}
              className={`py-1 text-center font-semibold rounded transition-all ${
                isBlue
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-dark-400 hover:text-dark-200'
              }`}
              title="Blue Mode: Defensive Analysis & Threat Detection"
            >
              Blue
            </button>

            <button
              onClick={() => handleModeSwitch('red')}
              className={`py-1 text-center font-semibold rounded transition-all ${
                isRed
                  ? 'bg-rose-600 text-white shadow-sm'
                  : 'text-dark-400 hover:text-dark-200'
              }`}
              title="Red Mode: Offensive Security & Vulnerability Exposure"
            >
              Red
            </button>

            <button
              onClick={() => handleModeSwitch('white')}
              className={`py-1 text-center font-semibold rounded transition-all relative ${
                isFreeBird
                  ? 'text-white shadow-sm font-bold'
                  : 'text-dark-400 hover:text-dark-200'
              }`}
              style={
                isFreeBird
                  ? {
                      background: 'linear-gradient(90deg, #1e3a8a 0%, #881337 100%)',
                      border: '1px solid rgba(255, 255, 255, 0.2)',
                    }
                  : {}
              }
              title="Free Bird: Unified Red + Blue Duality Identity"
            >
              Free Bird
            </button>
          </div>
        </div>
      </div>
    </aside>
  )
}
