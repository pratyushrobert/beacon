import { createContext, useContext, useState, useEffect } from 'react'

const ModeContext = createContext()

// Deterministic, colorblind-safe protocol color mapping to prevent monochromatic washouts
export const PROTOCOL_COLOR_PALETTE = {
  SSH: '#38bdf8',      // Cobalt / Sky Blue
  TCP: '#f59e0b',      // Amber / Gold
  UDP: '#10b981',      // Emerald Green
  DNS: '#06b6d4',      // Cyan
  HTTP: '#f43f5e',     // Rose / Crimson
  HTTPS: '#8b5cf6',    // Violet / Purple
  TLS: '#8b5cf6',      // Violet / Purple
  ICMP: '#ec4899',     // Pink
  ARP: '#d946ef',      // Fuchsia
  DHCP: '#eab308',     // Yellow
  NTP: '#14b8a6',      // Teal
  MDNS: '#6366f1',     // Indigo
  SSDP: '#fb923c',     // Tangerine
  SMB: '#a855f7',      // Purple
  FTP: '#ef4444',      // Red
  OTHER: '#64748b',    // Slate
}

export const FALLBACK_CHART_COLORS = [
  '#38bdf8', '#f59e0b', '#10b981', '#8b5cf6', '#f43f5e',
  '#06b6d4', '#ec4899', '#14b8a6', '#6366f1', '#eab308'
]

export function getProtocolColor(protocolName, index = 0) {
  if (!protocolName) return FALLBACK_CHART_COLORS[index % FALLBACK_CHART_COLORS.length]
  const upper = protocolName.toString().toUpperCase().trim()
  if (PROTOCOL_COLOR_PALETTE[upper]) {
    return PROTOCOL_COLOR_PALETTE[upper]
  }
  return FALLBACK_CHART_COLORS[index % FALLBACK_CHART_COLORS.length]
}

export function ModeProvider({ children }) {
  // Modes: 'blue' (Defensive), 'red' (Offensive), 'white' (Free Bird: Unified Red + Blue)
  const [mode, setModeState] = useState(() => {
    return localStorage.getItem('beacon_active_mode') || 'white'
  })

  const setMode = (newMode) => {
    const validMode = ['blue', 'red', 'white'].includes(newMode?.toLowerCase())
      ? newMode.toLowerCase()
      : 'white'
    setModeState(validMode)
    localStorage.setItem('beacon_active_mode', validMode)
    document.documentElement.setAttribute('data-mode', validMode)
  }

  useEffect(() => {
    // Ensure document reflects initial mode and dark theme
    document.documentElement.classList.add('dark')
    document.documentElement.setAttribute('data-mode', mode)

    const handleExternalModeChange = (e) => {
      if (e.detail) {
        setMode(e.detail)
      }
    }
    window.addEventListener('beacon_mode_changed', handleExternalModeChange)
    return () => window.removeEventListener('beacon_mode_changed', handleExternalModeChange)
  }, [mode])

  const isFreeBird = mode === 'white'
  const isBlue = mode === 'blue'
  const isRed = mode === 'red'

  // Dynamic colors for Recharts and Canvas visualizations
  const themeColors = {
    mode,
    modeLabel: isFreeBird ? 'Free Bird' : isBlue ? 'Blue Mode' : 'Red Mode',
    modeDescription: isFreeBird
      ? 'Unified Duality (Red + Blue)'
      : isBlue
      ? 'Defensive Security'
      : 'Offensive Security',
    primary: isFreeBird ? '#38bdf8' : isBlue ? '#38bdf8' : '#f43f5e',
    secondary: isFreeBird ? '#f43f5e' : isBlue ? '#0284c7' : '#e11d48',
    surface: isFreeBird ? '#111827' : isBlue ? '#0f172a' : '#181414',
    bg: isFreeBird ? '#090c14' : isBlue ? '#080d1a' : '#0c0a0a',
    border: isFreeBird ? '#1e293b' : isBlue ? '#172544' : '#2d1a1a',
    // Distinct categorical palette for general multi-series charts:
    chartColors: FALLBACK_CHART_COLORS,
    protocolPalette: PROTOCOL_COLOR_PALETTE,
  }

  return (
    <ModeContext.Provider value={{ mode, setMode, isFreeBird, isBlue, isRed, themeColors, getProtocolColor }}>
      {children}
    </ModeContext.Provider>
  )
}

export function useMode() {
  const context = useContext(ModeContext)
  if (!context) {
    throw new Error('useMode must be used within a ModeProvider')
  }
  return context
}
