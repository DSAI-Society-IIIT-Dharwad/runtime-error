import { useEffect, useState } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import Dashboard from './components/Dashboard'
import DeviceTable from './components/DeviceTable'
import FlowGraph from './components/FlowGraph'
import AlertList from './components/AlertList'
import Settings from './components/Settings'
import Navigation from './components/Navigation'
import { useWebSocket } from './lib/ws'
import { useStore } from './lib/store'

function App() {
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('darkMode')
    return saved ? JSON.parse(saved) : true
  })

  const { connect, disconnect } = useWebSocket()
  const isConnected = useStore((state) => state.isConnected)

  useEffect(() => {
    // Apply dark mode
    if (darkMode) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
    localStorage.setItem('darkMode', JSON.stringify(darkMode))
  }, [darkMode])

  useEffect(() => {
    // Connect to WebSocket
    connect()

    return () => {
      disconnect()
    }
  }, [connect, disconnect])

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors">
      <Navigation darkMode={darkMode} setDarkMode={setDarkMode} />
      
      {/* Connection Status */}
      <AnimatePresence>
        {!isConnected && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="fixed top-16 right-4 z-50"
          >
            <div className="bg-warning-100 dark:bg-warning-900 text-warning-800 dark:text-warning-200 px-4 py-2 rounded-lg shadow-lg flex items-center space-x-2">
              <div className="w-2 h-2 bg-warning-500 rounded-full animate-pulse" />
              <span className="text-sm font-medium">Reconnecting...</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <main className="container mx-auto px-4 py-8 mt-16">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/devices" element={<DeviceTable />} />
          <Route path="/flows" element={<FlowGraph />} />
          <Route path="/alerts" element={<AlertList />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
