import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { format } from 'date-fns'
import clsx from 'clsx'
import { deviceApi } from '../lib/api'
import { useStore } from '../lib/store'

export default function DeviceTable() {
  const devices = useStore((state) => state.devices)
  const captureMode = useStore((state) => state.captureMode)
  const [searchTerm, setSearchTerm] = useState('')
  const [sortField, setSortField] = useState<'mac' | 'ip' | 'vendor' | 'score' | 'last_seen'>('last_seen')
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc')
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null)

  // Fetch device details
  const { data: deviceActivity } = useQuery({
    queryKey: ['deviceActivity', selectedDevice],
    queryFn: () => selectedDevice ? deviceApi.getActivity(selectedDevice) : null,
    enabled: !!selectedDevice,
  })

  const { data: deviceRisk } = useQuery({
    queryKey: ['deviceRisk', selectedDevice],
    queryFn: () => selectedDevice ? deviceApi.getRisk(selectedDevice) : null,
    enabled: !!selectedDevice,
  })

  // Filter and sort devices
  const filteredDevices = useMemo(() => {
    let filtered = devices.filter(device => {
      // In PCAP mode, only show devices that are NOT Docker or infrastructure
      if (captureMode === 'pcap') {
        if (
          device.role === 'container' ||
          device.role === 'infrastructure' ||
          (device.vendor && device.vendor.toLowerCase().includes('docker'))
        ) {
          return false
        }
      }
      const search = searchTerm.toLowerCase()
      return (
        device.mac.toLowerCase().includes(search) ||
        (device.ip?.toLowerCase().includes(search) || '') ||
        (device.vendor?.toLowerCase().includes(search) || '') ||
        (device.hostname?.toLowerCase().includes(search) || '')
      )
    })

    // Sort
    filtered.sort((a, b) => {
      let aValue: any = a[sortField]
      let bValue: any = b[sortField]

      if (sortField === 'last_seen') {
        aValue = new Date(a.last_seen).getTime()
        bValue = new Date(b.last_seen).getTime()
      }

      if (aValue < bValue) return sortDirection === 'asc' ? -1 : 1
      if (aValue > bValue) return sortDirection === 'asc' ? 1 : -1
      return 0
    })

    return filtered
  }, [devices, searchTerm, sortField, sortDirection, captureMode])

  const handleSort = (field: typeof sortField) => {
    if (field === sortField) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDirection('asc')
    }
  }

  const getRiskBadge = (score: number) => {
    if (score >= 70) return { label: 'Critical', color: 'danger' }
    if (score >= 50) return { label: 'High', color: 'warning' }
    if (score >= 30) return { label: 'Medium', color: 'primary' }
    return { label: 'Low', color: 'success' }
  }

  const isDeviceActive = (lastSeen: string) => {
    const lastSeenDate = new Date(lastSeen)
    const now = new Date()
    return (now.getTime() - lastSeenDate.getTime()) < 15 * 60 * 1000 // 15 minutes
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Devices</h1>
          <p className="text-gray-600 dark:text-gray-400">
            {filteredDevices.length} devices found • {filteredDevices.filter(d => isDeviceActive(d.last_seen)).length} active
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex items-center space-x-2">
          <input
            type="text"
            placeholder="Search devices..."
            className="input"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="table">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th scope="col" className="px-6 py-3">
                  <div className="flex items-center">
                    <div className="w-2 h-2 rounded-full mr-2" />
                    Status
                  </div>
                </th>
                <th scope="col" className="px-6 py-3 cursor-pointer" onClick={() => handleSort('mac')}>
                  <div className="flex items-center">
                    MAC Address
                    {sortField === 'mac' && (
                      <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th scope="col" className="px-6 py-3 cursor-pointer" onClick={() => handleSort('ip')}>
                  <div className="flex items-center">
                    IP Address
                    {sortField === 'ip' && (
                      <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th scope="col" className="px-6 py-3 cursor-pointer" onClick={() => handleSort('vendor')}>
                  <div className="flex items-center">
                    Vendor
                    {sortField === 'vendor' && (
                      <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th scope="col" className="px-6 py-3">Role</th>
                <th scope="col" className="px-6 py-3 cursor-pointer" onClick={() => handleSort('score')}>
                  <div className="flex items-center">
                    Risk
                    {sortField === 'score' && (
                      <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th scope="col" className="px-6 py-3 cursor-pointer" onClick={() => handleSort('last_seen')}>
                  <div className="flex items-center">
                    Last Seen
                    {sortField === 'last_seen' && (
                      <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th scope="col" className="px-6 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {filteredDevices.map((device, index) => {
                const active = isDeviceActive(device.last_seen)
                const risk = getRiskBadge(device.score)

                return (
                  <motion.tr
                    key={device.mac}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.05 }}
                    className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
                    onClick={() => setSelectedDevice(device.mac === selectedDevice ? null : device.mac)}
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <div className={clsx(
                          'w-2 h-2 rounded-full mr-2',
                          active ? 'bg-success-500 animate-pulse' : 'bg-gray-400'
                        )} />
                        <span className="text-sm text-gray-600 dark:text-gray-400">
                          {active ? 'Online' : 'Offline'}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 font-mono text-sm">{device.mac}</td>
                    <td className="px-6 py-4 font-mono text-sm">{device.ip || '-'}</td>
                    <td className="px-6 py-4 text-sm">{device.vendor || 'Unknown'}</td>
                    <td className="px-6 py-4">
                      <span className="badge badge-info">{device.role || 'Unknown'}</span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={clsx(
                        'badge',
                        {
                          'badge-danger': risk.color === 'danger',
                          'badge-warning': risk.color === 'warning',
                          'badge-info': risk.color === 'primary',
                          'badge-success': risk.color === 'success',
                        }
                      )}>
                        {risk.label}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                      {format(new Date(device.last_seen), 'MMM d, HH:mm')}
                    </td>
                    <td className="px-6 py-4">
                      <button
                        className="text-primary-600 hover:text-primary-700 text-sm font-medium"
                        onClick={(e) => {
                          e.stopPropagation()
                          setSelectedDevice(device.mac === selectedDevice ? null : device.mac)
                        }}
                      >
                        {device.mac === selectedDevice ? 'Hide' : 'Details'}
                      </button>
                    </td>
                  </motion.tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {filteredDevices.length === 0 && (
          <div className="text-center py-8 text-gray-500 dark:text-gray-400">
            No devices found
          </div>
        )}
      </div>

      {/* Device Details Panel */}
      {selectedDevice && deviceActivity?.data && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="card"
        >
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Device Details: {selectedDevice}
            </h3>
          </div>
          <div className="card-body">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Total Traffic</p>
                <p className="text-xl font-semibold">
                  {((deviceActivity.data.bytes_sent + deviceActivity.data.bytes_received) / 1024 / 1024).toFixed(2)} MB
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Flows</p>
                <p className="text-xl font-semibold">{deviceActivity.data.flows_count}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Unique Destinations</p>
                <p className="text-xl font-semibold">{deviceActivity.data.unique_destinations.length}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Alerts</p>
                <p className="text-xl font-semibold">{deviceActivity.data.alerts_count}</p>
              </div>
            </div>

            {deviceRisk?.data && (
              <div className="mt-6">
                <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Risk Assessment</h4>
                <div className="space-y-2">
                  {deviceRisk.data.risk_factors.map((factor: any, index: number) => (
                    <div key={index} className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700 rounded">
                      <span className="text-sm">{factor.factor}</span>
                      <span className="text-sm font-medium">{factor.severity || factor.count}</span>
                    </div>
                  ))}
                </div>
                {deviceRisk.data.recommendations.length > 0 && (
                  <div className="mt-4">
                    <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Recommendations</h4>
                    <ul className="list-disc list-inside space-y-1">
                      {deviceRisk.data.recommendations.map((rec: string, index: number) => (
                        <li key={index} className="text-sm text-gray-600 dark:text-gray-400">{rec}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            <div className="mt-6">
              <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Top Ports</h4>
              <div className="flex flex-wrap gap-2">
                {deviceActivity.data.top_ports.map((port: number) => (
                  <span key={port} className="badge badge-info">{port}</span>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  )
}
