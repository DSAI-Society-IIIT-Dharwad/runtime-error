import { useEffect, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import { format } from 'date-fns'
import { useStore } from '../lib/store'
import { glossaryTitle } from '../lib/glossary'
import { deviceApi, flowApi, alertApi } from '../lib/api'
import clsx from 'clsx'

export default function Dashboard() {
  const devices = useStore((state) => state.devices)
  const alerts = useStore((state) => state.alerts)
  const flows = useStore((state) => state.flows)
  const updateStatistics = useStore((state) => state.updateStatistics)

  useQuery({
    queryKey: ['devices'],
    queryFn: () => deviceApi.getAll(),
  })

  useQuery({
    queryKey: ['alertStats'],
    queryFn: () => alertApi.getStatistics(),
  })

  const { data: flowStats } = useQuery({
    queryKey: ['flowStats'],
    queryFn: () => flowApi.getStatistics(),
  })

  const { data: topTalkers } = useQuery({
    queryKey: ['topTalkers'],
    queryFn: () => flowApi.getTopTalkers(),
  })

  useEffect(() => {
    updateStatistics()
  }, [devices, alerts, flows, updateStatistics])

  const alertTrendData = useMemo(() => {
    return alerts
      .slice(0, 24)
      .reverse()
      .reduce((acc: any[], alert) => {
        const timestamp = new Date(alert.timestamp)
        const hourLabel = Number.isNaN(timestamp.getTime())
          ? 'Not identified'
          : `${timestamp.getHours()}:00`
        const existing = acc.find((item) => item.hour === hourLabel)
        if (existing) {
          existing[alert.severity] = (existing[alert.severity] || 0) + 1
        } else {
          acc.push({
            hour: hourLabel,
            [alert.severity]: 1,
          })
        }
        return acc
      }, [])
  }, [alerts])

  const flowTrendData = useMemo(() => {
    return flows.slice(0, 100).reduce((acc: any[], flow, index) => {
      if (index % 10 === 0) {
        acc.push({
          time: format(new Date(flow.timestamp), 'HH:mm'),
          packets: flow.packets_total,
          bytes: flow.bytes_total / 1024,
        })
      }
      return acc
    }, [])
  }, [flows])

  const totalDevices = devices.length
  const activeDevices = useMemo(() => {
    const now = Date.now()
    const windowMs = 15 * 60 * 1000
    return devices.filter((device) => {
      const lastSeen = new Date(device.last_seen).getTime()
      return !Number.isNaN(lastSeen) && now - lastSeen < windowMs
    }).length
  }, [devices])

  const { recentAlerts, severityCounts } = useMemo(() => {
    const now = Date.now()
    const windowStart = now - 24 * 60 * 60 * 1000
    const recent = alerts.filter((alert) => {
      const timestamp = new Date(alert.timestamp).getTime()
      return !Number.isNaN(timestamp) && timestamp >= windowStart
    })
    const counts = {
      CRITICAL: recent.filter((alert) => alert.severity === 'CRITICAL').length,
      HIGH: recent.filter((alert) => alert.severity === 'HIGH').length,
      MEDIUM: recent.filter((alert) => alert.severity === 'MEDIUM').length,
      LOW: recent.filter((alert) => alert.severity === 'LOW').length,
    }
    return { recentAlerts: recent, severityCounts: counts }
  }, [alerts])

  const networkStatusMessage =
    severityCounts.CRITICAL > 0 || severityCounts.HIGH > 0
      ? 'Attention required. At least one device shows high-severity indicators.'
      : severityCounts.MEDIUM > 0
        ? 'Review recommended. Some activity requires verification.'
        : 'No significant issues detected.'

  const stats = [
    {
      label: 'Active devices',
      value: activeDevices,
      total: totalDevices,
      color: 'primary',
      context: '15-minute window',
    },
    {
      label: 'Critical threats',
      value: severityCounts.CRITICAL,
      total: recentAlerts.length,
      color: 'danger',
      context: 'Last 24 hours',
    },
    {
      label: 'Connections per hour',
      value: flowStats?.data?.total_flows || 0,
      suffix: 'connections/hr',
      color: 'success',
      context: 'Rolling hour',
      tooltip: glossaryTitle('connection'),
    },
    {
      label: 'Potential threats',
      value: severityCounts.CRITICAL + severityCounts.HIGH,
      color: 'warning',
      context: 'High or critical',
    },
  ]

  const lastUpdated = format(new Date(), 'PPpp')

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Overview</h1>
          <p className="text-gray-600 dark:text-gray-400">Combined view of network activity and threat posture.</p>
        </div>
        <div className="mt-4 sm:mt-0 text-sm text-gray-500 dark:text-gray-400">
          Last updated: {lastUpdated}
        </div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="card border border-gray-200 dark:border-gray-700"
      >
        <div className="card-body space-y-2">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Network Health</h2>
          <p className="text-sm text-gray-700 dark:text-gray-300">
            Devices: {totalDevices} • Active: {activeDevices}
          </p>
          <p className="text-sm text-gray-700 dark:text-gray-300">
            Threats (last 24h): Critical {severityCounts.CRITICAL} • High {severityCounts.HIGH} • Medium {severityCounts.MEDIUM} • Low {severityCounts.LOW}
          </p>
          <p className="text-sm text-gray-600 dark:text-gray-400">{networkStatusMessage}</p>
        </div>
      </motion.div>

  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className="card"
          >
            <div className="card-body">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400" title={stat.tooltip}>{stat.label}</p>
                  <div className="mt-2 flex items-baseline">
                    <p className="text-3xl font-semibold text-gray-900 dark:text-white">
                      {stat.value}
                    </p>
                    {typeof stat.total === 'number' && (
                      <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">
                        / {stat.total}
                      </span>
                    )}
                    {stat.suffix && (
                      <span className="ml-1 text-sm text-gray-500 dark:text-gray-400">
                        {stat.suffix}
                      </span>
                    )}
                  </div>
                </div>
                <div
                  className={clsx(
                    'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                    {
                      'bg-primary-100 text-primary-800 dark:bg-primary-900 dark:text-primary-200': stat.color === 'primary',
                      'bg-danger-100 text-danger-800 dark:bg-danger-900 dark:text-danger-200': stat.color === 'danger',
                      'bg-success-100 text-success-800 dark:bg-success-900 dark:text-success-200': stat.color === 'success',
                      'bg-warning-100 text-warning-800 dark:bg-warning-900 dark:text-warning-200': stat.color === 'warning',
                    }
                  )}
                >
                  {stat.context}
                </div>
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2 }}
          className="card"
        >
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Threat Trends</h3>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={alertTrendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="hour" stroke="#9CA3AF" />
                <YAxis stroke="#9CA3AF" />
                <RechartsTooltip
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: 'none',
                    borderRadius: '8px',
                  }}
                />
                <Legend />
                <Area type="monotone" dataKey="CRITICAL" stackId="1" stroke="#DC2626" fill="#DC2626" fillOpacity={0.6} />
                <Area type="monotone" dataKey="HIGH" stackId="1" stroke="#F59E0B" fill="#F59E0B" fillOpacity={0.6} />
                <Area type="monotone" dataKey="MEDIUM" stackId="1" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.6} />
                <Area type="monotone" dataKey="LOW" stackId="1" stroke="#10B981" fill="#10B981" fillOpacity={0.6} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.3 }}
          className="card"
        >
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Connection Volume</h3>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={flowTrendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9CA3AF" />
                <YAxis stroke="#9CA3AF" />
                <RechartsTooltip
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: 'none',
                    borderRadius: '8px',
                  }}
                />
                <Legend />
                <Line type="monotone" dataKey="packets" stroke="#3B82F6" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="bytes" stroke="#10B981" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.4 }}
          className="card"
        >
          <div className="card-header flex justify-between items-center">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Recent Threats</h3>
            <a href="/alerts" className="text-sm text-primary-600 hover:text-primary-700">
              View all threats
            </a>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {alerts.slice(0, 5).map((alert) => (
              <div key={alert.id} className="px-6 py-3 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      {alert.title}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      {alert.description}
                    </p>
                  </div>
                  <span
                    className={clsx(
                      'ml-2 inline-flex items-center px-2 py-1 rounded-full text-xs font-medium',
                      {
                        'bg-danger-100 text-danger-700 dark:bg-danger-900 dark:text-danger-300': alert.severity === 'CRITICAL',
                        'bg-warning-100 text-warning-700 dark:bg-warning-900 dark:text-warning-300': alert.severity === 'HIGH',
                        'bg-primary-100 text-primary-700 dark:bg-primary-900 dark:text-primary-300': alert.severity === 'MEDIUM',
                        'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300': alert.severity === 'LOW',
                      }
                    )}
                  >
                    {alert.severity}
                  </span>
                </div>
                <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                  {format(new Date(alert.timestamp), 'MMM d, HH:mm')}
                </p>
              </div>
            ))}
            {alerts.length === 0 && (
              <div className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">
                No threats to display
              </div>
            )}
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
          className="card"
        >
          <div className="card-header flex justify-between items-center">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Top Devices by Traffic</h3>
            <a href="/devices" className="text-sm text-primary-600 hover:text-primary-700">
              View all devices
            </a>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {topTalkers?.data?.slice(0, 5).map((device: any) => (
              <div key={device.mac} className="px-6 py-3 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                <div className="flex justify-between items-center">
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      {device.vendor || 'Not identified'}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {device.mac}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      {(device.total_bytes / 1024 / 1024).toFixed(2)} MB
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {device.flow_count} connections
                    </p>
                  </div>
                </div>
                <div className="mt-2">
                  <div className="bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div
                      className="bg-primary-500 h-2 rounded-full"
                      style={{ width: `${device.percentage || 0}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
            {(!topTalkers?.data || topTalkers.data.length === 0) && (
              <div className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">
                No connection data available
              </div>
            )}
          </div>
        </motion.div>
      </div>
    </div>
  )
}



