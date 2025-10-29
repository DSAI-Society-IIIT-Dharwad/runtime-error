import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import {
  LineChart, Line, AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts'
import { format } from 'date-fns'
import { useStore } from '../lib/store'
import { deviceApi, flowApi, alertApi } from '../lib/api'
import DockerStatus from './DockerStatus'
import ModeIndicator from './ModeIndicator'
import PcapAnalysis from './PcapAnalysis'
import clsx from 'clsx'

export default function Dashboard() {
  const devices = useStore((state) => state.devices)
  const alerts = useStore((state) => state.alerts)
  const flows = useStore((state) => state.flows)
  const captureMode = useStore((state) => state.captureMode)
  const updateStatistics = useStore((state) => state.updateStatistics)

  // Fetch initial data
  const { data: _devicesData } = useQuery({
    queryKey: ['devices'],
    queryFn: () => deviceApi.getAll(),
  })

  const { data: _alertStats } = useQuery({
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

  // Prepare chart data
  const alertTrendData = alerts.slice(0, 24).reverse().reduce((acc: any[], alert, _index) => {
    const hour = new Date(alert.timestamp).getHours()
    const existing = acc.find(item => item.hour === hour)
    if (existing) {
      existing[alert.severity] = (existing[alert.severity] || 0) + 1
    } else {
      acc.push({
        hour: `${hour}:00`,
        [alert.severity]: 1,
      })
    }
    return acc
  }, [])

  const flowTrendData = flows.slice(0, 100).reduce((acc: any[], flow, index) => {
    if (index % 10 === 0) {
      acc.push({
        time: format(new Date(flow.timestamp), 'HH:mm'),
        packets: flow.packets_total,
        bytes: flow.bytes_total / 1024, // KB
      })
    }
    return acc
  }, [])

  const stats = [
    {
      label: 'Active Devices',
      value: devices.filter(d => {
        const lastSeen = new Date(d.last_seen)
        const now = new Date()
        return (now.getTime() - lastSeen.getTime()) < 15 * 60 * 1000
      }).length,
      total: devices.length,
      color: 'primary',
      trend: '+2',
    },
    {
      label: 'Critical Alerts',
      value: alerts.filter(a => a.severity === 'CRITICAL').length,
      total: alerts.length,
      color: 'danger',
      trend: alerts.filter(a => a.severity === 'CRITICAL').length > 0 ? `+${alerts.filter(a => a.severity === 'CRITICAL').length}` : '0',
    },
    {
      label: 'Network Flows',
      value: flowStats?.data?.total_flows || 0,
      suffix: '/hr',
      color: 'success',
      trend: '+12%',
    },
    {
      label: 'Suspicious Activity',
      value: alerts.filter(a => a.severity === 'HIGH' || a.severity === 'CRITICAL').length,
      color: 'warning',
      trend: alerts.filter(a => a.severity === 'HIGH' || a.severity === 'CRITICAL').length > 0 ? '⚠️' : '✓',
    },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
          <p className="text-gray-600 dark:text-gray-400">Network security overview</p>
        </div>
        <div className="mt-4 sm:mt-0 flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <ModeIndicator />
          <div className="text-sm text-gray-500 dark:text-gray-400">
            Last updated: {format(new Date(), 'PPpp')}
          </div>
        </div>
      </div>

      {/* Stats Grid */}
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
                  <p className="text-sm text-gray-600 dark:text-gray-400">{stat.label}</p>
                  <div className="mt-2 flex items-baseline">
                    <p className="text-3xl font-semibold text-gray-900 dark:text-white">
                      {stat.value}
                    </p>
                    {stat.total && (
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
                <div className={clsx(
                  'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                  {
                    'bg-primary-100 text-primary-800 dark:bg-primary-900 dark:text-primary-200': stat.color === 'primary',
                    'bg-danger-100 text-danger-800 dark:bg-danger-900 dark:text-danger-200': stat.color === 'danger',
                    'bg-success-100 text-success-800 dark:bg-success-900 dark:text-success-200': stat.color === 'success',
                    'bg-warning-100 text-warning-800 dark:bg-warning-900 dark:text-warning-200': stat.color === 'warning',
                  }
                )}>
                  {stat.trend}
                </div>
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Mode-specific components */}
      {captureMode === 'live' && <DockerStatus />}
      {captureMode === 'pcap' && <PcapAnalysis />}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alert Trend Chart */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2 }}
          className="card"
        >
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Alert Trends</h3>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={alertTrendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="hour" stroke="#9CA3AF" />
                <YAxis stroke="#9CA3AF" />
                <Tooltip
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

        {/* Network Flow Chart */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.3 }}
          className="card"
        >
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Network Activity</h3>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={flowTrendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9CA3AF" />
                <YAxis stroke="#9CA3AF" />
                <Tooltip
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

      {/* Recent Alerts & Top Talkers */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Alerts */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.4 }}
          className="card"
        >
          <div className="card-header flex justify-between items-center">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Recent Alerts</h3>
            <a href="/alerts" className="text-sm text-primary-600 hover:text-primary-700">
              View all →
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
                  <span className={clsx(
                    'ml-2 inline-flex items-center px-2 py-1 rounded-full text-xs font-medium',
                    {
                      'bg-danger-100 text-danger-700 dark:bg-danger-900 dark:text-danger-300': alert.severity === 'CRITICAL',
                      'bg-warning-100 text-warning-700 dark:bg-warning-900 dark:text-warning-300': alert.severity === 'HIGH',
                      'bg-primary-100 text-primary-700 dark:bg-primary-900 dark:text-primary-300': alert.severity === 'MEDIUM',
                      'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300': alert.severity === 'LOW',
                    }
                  )}>
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
                No alerts to display
              </div>
            )}
          </div>
        </motion.div>

        {/* Top Talkers */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
          className="card"
        >
          <div className="card-header flex justify-between items-center">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Top Devices by Traffic</h3>
            <a href="/devices" className="text-sm text-primary-600 hover:text-primary-700">
              View all →
            </a>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {topTalkers?.data?.slice(0, 5).map((device: any) => (
              <div key={device.mac} className="px-6 py-3 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                <div className="flex justify-between items-center">
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      {device.vendor || 'Unknown Device'}
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
                      {device.flow_count} flows
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
                No traffic data available
              </div>
            )}
          </div>
        </motion.div>
      </div>
    </div>
  )
}
