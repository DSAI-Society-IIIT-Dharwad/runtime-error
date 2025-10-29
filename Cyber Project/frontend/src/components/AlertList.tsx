import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { format } from 'date-fns'
import toast from 'react-hot-toast'
import clsx from 'clsx'
import { alertApi } from '../lib/api'
import { useStore } from '../lib/store'

export default function AlertList() {
  const alerts = useStore((state) => state.alerts)
  const queryClient = useQueryClient()
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  
  const { data: _alertStats } = useQuery({
    queryKey: ['alertStats'],
    queryFn: () => alertApi.getStatistics(),
  })

  const updateAlertMutation = useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) =>
      alertApi.update(id, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      toast.success('Alert updated successfully')
    },
  })

  const filteredAlerts = alerts.filter(alert => {
    if (severityFilter !== 'all' && alert.severity !== severityFilter) return false
    if (statusFilter !== 'all' && alert.status !== statusFilter) return false
    return true
  })

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'danger'
      case 'HIGH': return 'warning'
      case 'MEDIUM': return 'primary'
      case 'LOW': return 'success'
      default: return 'gray'
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Security Alerts</h1>
          <p className="text-gray-600 dark:text-gray-400">
            {filteredAlerts.length} alerts • {filteredAlerts.filter(a => a.status === 'new').length} unresolved
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex space-x-2">
          <select
            className="select"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="all">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select
            className="select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="all">All Status</option>
            <option value="new">New</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>
      </div>

      <div className="space-y-4">
        {filteredAlerts.map((alert, index) => (
          <motion.div
            key={alert.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.05 }}
            className="card"
          >
            <div className="p-6">
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-center space-x-2">
                    <span className={clsx(
                      'badge',
                      `badge-${getSeverityColor(alert.severity)}`
                    )}>
                      {alert.severity}
                    </span>
                    <span className="badge badge-info">{alert.category}</span>
                    {alert.device_mac && (
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        Device: {alert.device_mac}
                      </span>
                    )}
                  </div>
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white mt-2">
                    {alert.title}
                  </h3>
                  <p className="text-gray-600 dark:text-gray-400 mt-1">
                    {alert.description}
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-500 mt-2">
                    {format(new Date(alert.timestamp), 'PPpp')}
                  </p>
                </div>
                <div className="ml-4">
                  <select
                    className="select"
                    value={alert.status}
                    onChange={(e) => updateAlertMutation.mutate({
                      id: alert.id,
                      status: e.target.value
                    })}
                  >
                    <option value="new">New</option>
                    <option value="acknowledged">Acknowledged</option>
                    <option value="investigating">Investigating</option>
                    <option value="resolved">Resolved</option>
                    <option value="false_positive">False Positive</option>
                  </select>
                </div>
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      {filteredAlerts.length === 0 && (
        <div className="card">
          <div className="text-center py-12 text-gray-500 dark:text-gray-400">
            <ExclamationTriangleIcon className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <p>No alerts found</p>
          </div>
        </div>
      )}
    </div>
  )
}

function ExclamationTriangleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  )
}
