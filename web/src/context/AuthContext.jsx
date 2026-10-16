import { createContext, useContext, useState, useEffect } from 'react'
import axios from 'axios'
import { KeyRound, ShieldAlert, Lock, CheckCircle2, Loader2, ArrowRight } from 'lucide-react'

const AuthContext = createContext({
  authRequired: false,
  isAuthenticated: true,
  verifyPin: async () => {},
  logout: () => {},
})

export function AuthProvider({ children }) {
  const [authRequired, setAuthRequired] = useState(false)
  const [isAuthenticated, setIsAuthenticated] = useState(true)
  const [checking, setChecking] = useState(true)
  const [pinInput, setPinInput] = useState('')
  const [pinError, setPinError] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  // Configure axios interceptor for PIN header
  useEffect(() => {
    const savedPin = sessionStorage.getItem('beacon_pin')
    if (savedPin) {
      axios.defaults.headers.common['X-Beacon-PIN'] = savedPin
    }

    const interceptor = axios.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401 && error.response?.data?.detail?.includes('PIN')) {
          setIsAuthenticated(false)
        }
        return Promise.reject(error)
      }
    )

    checkAuthStatus(savedPin)

    return () => {
      axios.interceptors.response.eject(interceptor)
    }
  }, [])

  const checkAuthStatus = async (pin) => {
    try {
      const headers = pin ? { 'X-Beacon-PIN': pin } : {}
      const res = await axios.get('/api/auth/status', { headers })
      setAuthRequired(res.data.auth_required)
      setIsAuthenticated(res.data.authenticated)
    } catch (err) {
      console.error('Failed to query auth status:', err)
    } finally {
      setChecking(false)
    }
  }

  const handleVerify = async (e) => {
    if (e) e.preventDefault()
    if (!pinInput.trim()) return
    setSubmitting(true)
    setPinError(null)

    try {
      await axios.post('/api/auth/verify', { pin: pinInput.trim() })
      sessionStorage.setItem('beacon_pin', pinInput.trim())
      axios.defaults.headers.common['X-Beacon-PIN'] = pinInput.trim()
      setIsAuthenticated(true)
      setPinError(null)
      // Notify active WebSocket or live components
      window.dispatchEvent(new CustomEvent('beacon_auth_success'))
    } catch (err) {
      setPinError(err.response?.data?.detail || 'Invalid access PIN. Access denied.')
    } finally {
      setSubmitting(false)
    }
  }

  const logout = () => {
    sessionStorage.removeItem('beacon_pin')
    delete axios.defaults.headers.common['X-Beacon-PIN']
    setIsAuthenticated(false)
    setPinInput('')
  }

  return (
    <AuthContext.Provider value={{ authRequired, isAuthenticated, verifyPin: handleVerify, logout }}>
      {children}

      {/* Access Protection Modal if PIN is required but unauthenticated */}
      {authRequired && !isAuthenticated && !checking && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
          <div className="card max-w-sm w-full p-6 border-slate-700 bg-[#090d19] shadow-2xl space-y-4">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-md bg-amber-500/10 border border-amber-500/30 text-amber-400">
                <Lock className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-sm text-white font-mono uppercase tracking-wider">
                  Authentication Required
                </h3>
                <p className="text-[11px] text-dark-400">
                  This Beacon server is running on a private network with access protection.
                </p>
              </div>
            </div>

            <form onSubmit={handleVerify} className="space-y-3 pt-1">
              <div>
                <label className="block text-[11px] font-mono text-dark-300 uppercase tracking-wider mb-1.5">
                  Enter Server Access PIN:
                </label>
                <div className="relative">
                  <KeyRound className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-dark-400" />
                  <input
                    type="password"
                    autoFocus
                    placeholder="PIN / Token..."
                    value={pinInput}
                    onChange={(e) => setPinInput(e.target.value)}
                    className="input pl-9 w-full text-xs font-mono py-2 bg-dark-950 border-slate-700 text-white"
                  />
                </div>
              </div>

              {pinError && (
                <div className="p-2 rounded bg-rose-950/40 border border-rose-800/60 text-[11px] font-mono text-rose-300 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                  <span>{pinError}</span>
                </div>
              )}

              <button
                type="submit"
                disabled={submitting || !pinInput.trim()}
                className="btn btn-primary w-full text-xs py-2 flex items-center justify-center gap-1.5 font-medium disabled:opacity-50"
              >
                {submitting ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Verifying Credentials...</span>
                  </>
                ) : (
                  <>
                    <span>Unlock Workstation</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            </form>

            <p className="text-[10px] text-dark-500 font-mono text-center">
              The PIN is configured on the host machine running <code className="text-dark-300">beacon serve --pin &lt;PIN&gt;</code>
            </p>
          </div>
        </div>
      )}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
