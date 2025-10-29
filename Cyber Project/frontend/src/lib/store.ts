import { create } from 'zustand'

export interface Device {
  id: number
  mac: string
  ip?: string
  vendor?: string
  hostname?: string
  role?: string
  score: number
  first_seen: string
  last_seen: string
}

export interface Flow {
  id: number
  timestamp: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  bytes_total: number
  packets_total: number
}

export interface Alert {
  id: number
  timestamp: string
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  category: string
  title: string
  description: string
  status: string
  device_mac?: string
}

interface AppState {
  // Connection state
  isConnected: boolean
  setIsConnected: (connected: boolean) => void

  // Devices
  devices: Device[]
  updateDevices: (devices: Device[]) => void
  addDevice: (device: Device) => void
  removeDevice: (mac: string) => void

  // Flows
  flows: Flow[]
  updateFlows: (flows: Flow[]) => void
  addFlows: (flows: Flow[]) => void
  clearFlows: () => void

  // Alerts
  alerts: Alert[]
  updateAlerts: (alerts: Alert[]) => void
  addAlert: (alert: Alert) => void
  updateAlertStatus: (id: number, status: string) => void
  clearAlerts: () => void

  // Capture state
  captureMode: 'live' | 'pcap'
  setCaptureMode: (mode: 'live' | 'pcap') => void
  clearModeData: () => void
  captureStatus: {
    isRunning: boolean
    interface?: string
    pcapPath?: string
    packetsCaptured: number
    devicesDiscovered: number
    activeFlows: number
  }
  setCaptureStatus: (status: any) => void

  // Filters
  alertFilter: {
    severity?: string
    status?: string
    deviceMac?: string
  }
  setAlertFilter: (filter: any) => void

  // Statistics
  statistics: {
    totalDevices: number
    activeDevices: number
    totalAlerts: number
    criticalAlerts: number
    totalFlows: number
    externalFlows: number
  }
  updateStatistics: () => void
}

export const useStore = create<AppState>((set, get) => ({
  // Connection state
  isConnected: false,
  setIsConnected: (connected) => set({ isConnected: connected }),

  // Devices
  devices: [],
  updateDevices: (devices) => set({ devices }),
  addDevice: (device) => set((state) => ({
    devices: [...state.devices.filter(d => d.mac !== device.mac), device]
  })),
  removeDevice: (mac) => set((state) => ({
    devices: state.devices.filter(d => d.mac !== mac)
  })),

  // Flows
  flows: [],
  updateFlows: (flows) => set((state) => ({
    flows: [...flows, ...state.flows].slice(0, 1000) // Keep last 1000 flows
  })),
  addFlows: (flows) => set((state) => ({
    flows: [...flows, ...state.flows].slice(0, 1000)
  })),
  clearFlows: () => set({ flows: [] }),

  // Alerts
  alerts: [],
  updateAlerts: (alerts) => set((state) => ({
    alerts: [...alerts, ...state.alerts.filter(a => !alerts.find(na => na.id === a.id))].slice(0, 500)
  })),
  addAlert: (alert) => set((state) => ({
    alerts: [alert, ...state.alerts].slice(0, 500)
  })),
  updateAlertStatus: (id, status) => set((state) => ({
    alerts: state.alerts.map(a => a.id === id ? { ...a, status } : a)
  })),
  clearAlerts: () => set({ alerts: [] }),

  // Capture state
  captureMode: 'pcap',
  setCaptureMode: (mode) => {
    // Clear existing data when switching modes
    set({ 
      captureMode: mode,
      devices: [],
      flows: [],
      alerts: []
    })
  },
  clearModeData: () => set({ devices: [], flows: [], alerts: [] }),
  captureStatus: {
    isRunning: false,
    packetsCaptured: 0,
    devicesDiscovered: 0,
    activeFlows: 0
  },
  setCaptureStatus: (status) => set({ captureStatus: status }),

  // Filters
  alertFilter: {},
  setAlertFilter: (filter) => set({ alertFilter: filter }),

  // Statistics
  statistics: {
    totalDevices: 0,
    activeDevices: 0,
    totalAlerts: 0,
    criticalAlerts: 0,
    totalFlows: 0,
    externalFlows: 0
  },
  updateStatistics: () => {
    const state = get()
    const now = new Date()
    const fifteenMinutesAgo = new Date(now.getTime() - 15 * 60000)
    
    set({
      statistics: {
        totalDevices: state.devices.length,
        activeDevices: state.devices.filter(d => 
          new Date(d.last_seen) > fifteenMinutesAgo
        ).length,
        totalAlerts: state.alerts.length,
        criticalAlerts: state.alerts.filter(a => a.severity === 'CRITICAL').length,
        totalFlows: state.flows.length,
        externalFlows: 0 // Would need to calculate based on IP ranges
      }
    })
  }
}))
