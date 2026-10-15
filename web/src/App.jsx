import { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Upload from './pages/Upload'
import Findings from './pages/Findings'
import Hosts from './pages/Hosts'
import Conversations from './pages/Conversations'
import Timeline from './pages/Timeline'
import PacketExplorer from './pages/PacketExplorer'
import IOCs from './pages/IOCs'
import NetworkGraph from './pages/NetworkGraph'
import Storyline from './pages/Storyline'
import Workspace from './pages/Workspace'
import CaptureComparison from './pages/CaptureComparison'
import MemoryView from './pages/MemoryView'
import LiveCapture from './pages/LiveCapture'
import { ModeProvider } from './context/ModeContext'


function App() {
  const [currentAnalysis, setCurrentAnalysis] = useState(null)

  return (
    <ModeProvider>
      <Router>
        <div className="flex h-screen overflow-hidden bg-canvas text-dark-100">
          <Sidebar
            currentAnalysis={currentAnalysis}
          />

        <main className="flex-1 overflow-y-auto">
          <Routes>
            <Route path="/" element={<Navigate to="/upload" replace />} />
            <Route
              path="/upload"
              element={<Upload setCurrentAnalysis={setCurrentAnalysis} />}
            />
            <Route
              path="/dashboard/:analysisId"
              element={<Dashboard />}
            />
            <Route
              path="/storyline/:analysisId"
              element={<Storyline />}
            />
            <Route
              path="/findings/:analysisId"
              element={<Findings />}
            />
            <Route
              path="/hosts/:analysisId"
              element={<Hosts />}
            />
            <Route
              path="/conversations/:analysisId"
              element={<Conversations />}
            />
            <Route
              path="/timeline/:analysisId"
              element={<Timeline />}
            />
            <Route
              path="/packets/:analysisId"
              element={<PacketExplorer />}
            />
            <Route
              path="/iocs/:analysisId"
              element={<IOCs />}
            />
            <Route
              path="/graph/:analysisId"
              element={<NetworkGraph />}
            />
            <Route
              path="/workspace/:analysisId"
              element={<Workspace />}
            />
            <Route
              path="/compare"
              element={<CaptureComparison />}
            />
            <Route
              path="/memory/:analysisId"
              element={<MemoryView />}
            />
            <Route
              path="/memory"
              element={<MemoryView />}
            />
            <Route
              path="/live"
              element={<LiveCapture />}
            />
          </Routes>

        </main>
      </div>
    </Router>
  </ModeProvider>
  )
}

export default App
