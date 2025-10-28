import { ReactNode, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { format } from 'date-fns'
import clsx from 'clsx'
import { deviceApi } from '../lib/api'
import { useStore } from '../lib/store'
import { glossaryTitle } from '../lib/glossary'

type SortField = 'hostname' | 'ip' | 'mac' | 'vendor' | 'score' | 'last_seen'

export default function DeviceTable() {
  const devices = useStore((state) => state.devices)
  const [searchTerm, setSearchTerm] = useState('')
  const [sortField, setSortField] = useState<SortField>('last_seen')
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc')
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null)

  const { data: deviceActivity } = useQuery({
    queryKey: ['deviceActivity', selectedDevice],
    queryFn: () => (selectedDevice ? deviceApi.getActivity(selectedDevice) : null),
    enabled: !!selectedDevice,
  })

  const { data: deviceRisk } = useQuery({
    queryKey: ['deviceRisk', selectedDevice],
    queryFn: () => (selectedDevice ? deviceApi.getRisk(selectedDevice) : null),
    enabled: !!selectedDevice,
  })

  const filteredDevices = useMemo(() => {
    const search = searchTerm.trim().toLowerCase()

    const matchesSearch = (value?: string) =>
      value ? value.toLowerCase().includes(search) : false

    const filtered = devices.filter((device) => {
      if (!search) return true
      return (
        device.mac.toLowerCase().includes(search) ||
        matchesSearch(device.ip) ||
        matchesSearch(device.vendor) ||
        matchesSearch(device.hostname)
      )
    })

    const sorted = [...filtered].sort((a, b) => {
      let aValue: number | string = ''
      let bValue: number | string = ''

      switch (sortField) {
        case 'hostname':
          aValue = (a.hostname || a.vendor || '').toLowerCase()
          bValue = (b.hostname || b.vendor || '').toLowerCase()
          break
        case 'ip':
          aValue = (a.ip || '').toLowerCase()
          bValue = (b.ip || '').toLowerCase()
          break
        case 'mac':
          aValue = a.mac.toLowerCase()
          bValue = b.mac.toLowerCase()
          break
        case 'vendor':
          aValue = (a.vendor || '').toLowerCase()
          bValue = (b.vendor || '').toLowerCase()
          break
        case 'score':
          aValue = a.score
          bValue = b.score
          break
        case 'last_seen':
        default:
          aValue = new Date(a.last_seen).getTime()
          bValue = new Date(b.last_seen).getTime()
          break
      }

      if (aValue < bValue) return sortDirection === 'asc' ? -1 : 1
      if (aValue > bValue) return sortDirection === 'asc' ? 1 : -1
      return 0
    })

    return sorted
  }, [devices, searchTerm, sortField, sortDirection])

  const handleSort = (field: SortField) => {
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
    const lastSeenTime = new Date(lastSeen).getTime()
    const now = Date.now()
    return now - lastSeenTime < 15 * 60 * 1000
  }

  const activeCount = filteredDevices.filter((device) => isDeviceActive(device.last_seen)).length

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Devices</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Devices: {filteredDevices.length} • Active: {activeCount}
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex items-center space-x-2">
          <input
            type="text"
            placeholder="Search devices..."
            className="input"
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
          />
        </div>
      </div>

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
                <SortableHeader
                  label="Device"
                  active={sortField === 'hostname'}
                  direction={sortDirection}
                  onClick={() => handleSort('hostname')}
                />
                <SortableHeader
                  label="IP Address"
                  active={sortField === 'ip'}
                  direction={sortDirection}
                  onClick={() => handleSort('ip')}
                />
                <SortableHeader
                  label={<span title={glossaryTitle('hardwareId')}>Hardware ID (MAC)</span>}
                  active={sortField === 'mac'}
                  direction={sortDirection}
                  onClick={() => handleSort('mac')}
                />
                <SortableHeader
                  label="Vendor"
                  active={sortField === 'vendor'}
                  direction={sortDirection}
                  onClick={() => handleSort('vendor')}
                />
                <th scope="col" className="px-6 py-3">
                  <span title="Device purpose if defined.">Role</span>
                </th>
                <SortableHeader
                  label={<span title="Current risk assessment based on observed behaviour.">Threat Level</span>}
                  active={sortField === 'score'}
                  direction={sortDirection}
                  onClick={() => handleSort('score')}
                />
                <SortableHeader
                  label="Last Seen"
                  active={sortField === 'last_seen'}
                  direction={sortDirection}
                  onClick={() => handleSort('last_seen')}
                />
                <th scope="col" className="px-6 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {filteredDevices.map((device, index) => {
                const active = isDeviceActive(device.last_seen)
                const risk = getRiskBadge(device.score)
                const displayName = device.hostname || device.vendor || 'Not identified'
                const ipAddress = device.ip || 'Not identified'
                const vendorName = device.vendor || 'Not identified'
                const roleLabel = device.role || 'Not identified'

                return (
                  <motion.tr
                    key={device.mac}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.05 }}
                    className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
                    onClick={() => setSelectedDevice((prev) => (prev === device.mac ? null : device.mac))}
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <div
                          className={clsx(
                            'w-2 h-2 rounded-full mr-2',
                            active ? 'bg-success-500 animate-pulse' : 'bg-gray-400'
                          )}
                        />
                        <span className="text-sm text-gray-600 dark:text-gray-400">
                          {active ? 'Online' : 'Offline'}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">{displayName}</td>
                    <td className="px-6 py-4 font-mono text-sm">{ipAddress}</td>
                    <td className="px-6 py-4 font-mono text-sm" title={glossaryTitle('hardwareId')}>{device.mac}</td>
                    <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">{vendorName}</td>
                    <td className="px-6 py-4">
                      <span className="badge badge-info" title="Device purpose if defined.">{roleLabel}</span>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        title="Current risk assessment based on observed behaviour."
                        className={clsx('badge', {
                          'badge-danger': risk.color === 'danger',
                          'badge-warning': risk.color === 'warning',
                          'badge-info': risk.color === 'primary',
                          'badge-success': risk.color === 'success',
                        })}
                      >
                        {risk.label}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                      {format(new Date(device.last_seen), 'MMM d, HH:mm')}
                    </td>
                    <td className="px-6 py-4">
                      <button
                        className="text-primary-600 hover:text-primary-700 text-sm font-medium"
                        onClick={(event) => {
                          event.stopPropagation()
                          setSelectedDevice((prev) => (prev === device.mac ? null : device.mac))
                        }}
                      >
                        {selectedDevice === device.mac ? 'Hide' : 'Details'}
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
            No devices match the current filters.
          </div>
        )}
      </div>

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
              <DetailMetric
                label="Total Traffic"
                value={`${((deviceActivity.data.bytes_sent + deviceActivity.data.bytes_received) / 1024 / 1024).toFixed(2)} MB`}
              />
              <DetailMetric
                label="Connections"
                value={deviceActivity.data.flows_count}
                tooltip={glossaryTitle('connection')}
              />
              <DetailMetric
                label="Unique Destinations"
                value={deviceActivity.data.unique_destinations.length}
              />
              <DetailMetric
                label="Threats"
                value={deviceActivity.data.alerts_count}
              />
            </div>

            {deviceRisk?.data && (
              <div className="mt-6">
                <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Threat Assessment</h4>
                <div className="space-y-2">
                  {deviceRisk.data.risk_factors.map((factor: any, index: number) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700 rounded"
                    >
                      <span className="text-sm text-gray-700 dark:text-gray-300">{factor.factor}</span>
                      <span className="text-sm font-medium text-gray-900 dark:text-white">
                        {factor.severity || factor.count}
                      </span>
                    </div>
                  ))}
                </div>
                {deviceRisk.data.recommendations.length > 0 && (
                  <div className="mt-4">
                    <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Recommendations</h4>
                    <ul className="list-disc list-inside space-y-1">
                      {deviceRisk.data.recommendations.map((recommendation: string, index: number) => (
                        <li key={index} className="text-sm text-gray-600 dark:text-gray-400">
                          {recommendation}
                        </li>
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
                  <span key={port} className="badge badge-info">
                    {port}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  )
}

function SortableHeader({
  label,
  active,
  direction,
  onClick,
}: {
  label: ReactNode
  active: boolean
  direction: 'asc' | 'desc'
  onClick: () => void
}) {
  return (
    <th scope="col" className="px-6 py-3 cursor-pointer" onClick={onClick}>
      <div className="flex items-center">
        {label}
        {active && <span className="ml-1">{direction === 'asc' ? '^' : 'v'}</span>}
      </div>
    </th>
  )
}

function DetailMetric({ label, value, tooltip }: { label: string; value: string | number; tooltip?: string }) {
  return (
    <div>
      <p className="text-sm text-gray-600 dark:text-gray-400" title={tooltip}>{label}</p>
      <p className="text-xl font-semibold text-gray-900 dark:text-white">{value}</p>
    </div>
  )
}





