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

    try {
      const ws = new WebSocket(WS_URL)
      wsRef.current = ws

      ws.onopen = () => {
        console.log('WebSocket connected')
        setIsConnected(true)
        toast.success('Connected to monitoring system')
        
        // Clear reconnect timeout
        if (reconnectTimeoutRef.current) {
          clearTimeout(reconnectTimeoutRef.current)
          reconnectTimeoutRef.current = null
        }

        // Start ping interval
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping')
          }
        }, 30000) // Ping every 30 seconds
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

      ws.onclose = () => {
        console.log('WebSocket disconnected')
        setIsConnected(false)
        wsRef.current = null
        
        // Clear ping interval
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current)
          pingIntervalRef.current = null
        }

        // Attempt to reconnect after 5 seconds
        reconnectTimeoutRef.current = setTimeout(() => {
          console.log('Attempting to reconnect...')
          connect()
        }, 5000)
      }

      ws.onerror = (error) => {
        console.error('WebSocket error:', error)
        toast.error('Connection error')
      }
    } catch (error) {
      console.error('Failed to connect WebSocket:', error)
      setIsConnected(false)
      
      // Retry connection
      reconnectTimeoutRef.current = setTimeout(() => {
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
