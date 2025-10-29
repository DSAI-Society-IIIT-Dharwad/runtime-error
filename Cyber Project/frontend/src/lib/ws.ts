import { useRef, useCallback } from 'react'
import toast from 'react-hot-toast'
import { useStore } from './store'

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/stream'

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const pingIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  
  const setIsConnected = useStore((state) => state.setIsConnected)
  const updateDevices = useStore((state) => state.updateDevices)
  const updateFlows = useStore((state) => state.updateFlows)
  const updateAlerts = useStore((state) => state.updateAlerts)

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return
    }

    // Close existing connection if any
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }

    try {
      console.log('Attempting WebSocket connection to:', WS_URL)
      const ws = new WebSocket(WS_URL)
      wsRef.current = ws

      // Set connection timeout
      const connectionTimeout = setTimeout(() => {
        if (ws.readyState === WebSocket.CONNECTING) {
          console.log('WebSocket connection timeout')
          ws.close()
        }
      }, 10000) // 10 second timeout

      ws.onopen = () => {
        clearTimeout(connectionTimeout)
        console.log('WebSocket connected successfully')
        setIsConnected(true)
        toast.success('Connected to monitoring system')
        
        // Clear reconnect timeout
        if (reconnectTimeoutRef.current) {
          clearTimeout(reconnectTimeoutRef.current)
          reconnectTimeoutRef.current = null
        }

        // Start ping interval with shorter interval for better connection monitoring
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping')
          }
        }, 15000) // Ping every 15 seconds
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          
          if (data === 'pong') {
            return // Pong response
          }

          if (data.type === 'initial') {
            // Initial data load
            if (data.data.devices) {
              updateDevices(data.data.devices)
            }
          } else if (data.type === 'update') {
            // Incremental updates
            if (data.data.devices) {
              updateDevices(data.data.devices)
            }
            if (data.data.flows) {
              updateFlows(data.data.flows)
            }
            if (data.data.alerts) {
              updateAlerts(data.data.alerts)
            }
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error)
        }
      }

      ws.onclose = (event) => {
        clearTimeout(connectionTimeout)
        console.log('WebSocket disconnected:', event.code, event.reason)
        setIsConnected(false)
        wsRef.current = null
        
        // Clear ping interval
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current)
          pingIntervalRef.current = null
        }

        // Only show error toast if it wasn't a clean close
        if (event.code !== 1000) {
          toast.error('Connection lost, attempting to reconnect...')
        }

        // Attempt to reconnect with exponential backoff
        const delay = event.code === 1006 ? 2000 : 5000 // Faster reconnect for network issues
        reconnectTimeoutRef.current = setTimeout(() => {
          console.log('Attempting to reconnect...')
          connect()
        }, delay)
      }

      ws.onerror = (error) => {
        clearTimeout(connectionTimeout)
        console.error('WebSocket error:', error)
        // Don't show error toast here as onclose will handle it
      }
    } catch (error) {
      console.error('Failed to connect WebSocket:', error)
      setIsConnected(false)
      toast.error('Failed to establish connection')
      
      // Retry connection with delay
      reconnectTimeoutRef.current = setTimeout(() => {
        console.log('Retrying connection after error...')
        connect()
      }, 5000)
    }
  }, [setIsConnected, updateDevices, updateFlows, updateAlerts])

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
    
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
    
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current)
      pingIntervalRef.current = null
    }
    
    setIsConnected(false)
  }, [setIsConnected])

  const send = useCallback((message: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message))
    } else {
      console.warn('WebSocket is not connected')
    }
  }, [])

  return { connect, disconnect, send }
}
