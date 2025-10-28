import { useMemo, useState, type ReactNode } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { format } from 'date-fns'
import toast from 'react-hot-toast'
import clsx from 'clsx'
import { alertApi } from '../lib/api'
import { useStore } from '../lib/store'
import type { Alert, Device } from '../lib/store'
import { glossaryTitle } from '../lib/glossary'

const DEFAULT_EXPLANATION = 'Anomalous network activity detected.'
const DEFAULT_RECOMMENDATION = 'Review device behaviour and apply network restrictions if necessary.'

export default function AlertList() {
  const alerts = useStore((state) => state.alerts)
  const devices = useStore((state) => state.devices)
  const queryClient = useQueryClient()
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null)
  const [technicalOpen, setTechnicalOpen] = useState(false)

  useQuery({
    queryKey: ['alertStats'],
    queryFn: () => alertApi.getStatistics(),
  })

  const updateAlertMutation = useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) =>
      alertApi.update(id, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      toast.success('Status updated.')
    },
  })

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      if (severityFilter !== 'all' && alert.severity !== severityFilter) return false
      if (statusFilter !== 'all' && alert.status !== statusFilter) return false
      return true
    })
  }, [alerts, severityFilter, statusFilter])

  const unresolvedCount = filteredAlerts.filter((alert) => alert.status !== 'resolved').length

  const selectedAlert = useMemo(() => {
    if (selectedAlertId === null) return null
    return alerts.find((alert) => alert.id === selectedAlertId) || null
  }, [alerts, selectedAlertId])

  const handleSelectAlert = (alertId: number) => {
    setSelectedAlertId((current) => (current === alertId ? null : alertId))
    setTechnicalOpen(false)
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Threats</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Total {filteredAlerts.length} threats • {unresolvedCount} unresolved
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex space-x-2">
          <select
            className="select"
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
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
            onChange={(event) => setStatusFilter(event.target.value)}
          >
            <option value="all">All Status</option>
            <option value="new">New</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>
      </div>

      <div className="grid lg:grid-cols-[minmax(0,1fr)_360px] gap-6">
        <div className="space-y-4">
          {filteredAlerts.map((alert, index) => {
            const isSelected = selectedAlertId === alert.id
            const severityColor = getSeverityColor(alert.severity)
            const deviceLabel = formatDevice(alert.device_mac, devices)

            return (
              <motion.div
                key={alert.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
                className={clsx('card', isSelected && 'ring-2 ring-primary-400 dark:ring-primary-500')}
              >
                <div className="p-6 space-y-3">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-2">
                      <span className={clsx('badge', `badge-${severityColor}`)}>{alert.severity}</span>
                      {deviceLabel && (
                        <span className="text-sm text-gray-500 dark:text-gray-400">{deviceLabel}</span>
                      )}
                    </div>
                    <select
                      className="select"
                      value={alert.status}
                      onClick={(event) => event.stopPropagation()}
                      onChange={(event) =>
                        updateAlertMutation.mutate({
                          id: alert.id,
                          status: event.target.value,
                        })
                      }
                    >
                      <option value="new">New</option>
                      <option value="acknowledged">Acknowledged</option>
                      <option value="investigating">Investigating</option>
                      <option value="resolved">Resolved</option>
                      <option value="false_positive">False Positive</option>
                    </select>
                  </div>

                  <div
                    className="space-y-2 cursor-pointer"
                    onClick={() => handleSelectAlert(alert.id)}
                  >
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">{alert.title}</h3>
                    <p className="text-gray-600 dark:text-gray-400">{alert.description}</p>
                    <p className="text-sm text-gray-500 dark:text-gray-500">
                      {format(new Date(alert.timestamp), 'PPpp')}
                    </p>
                    <button
                      type="button"
                      className="text-sm text-primary-600 hover:text-primary-700"
                    >
                      {isSelected ? 'Hide details' : 'View details'}
                    </button>
                  </div>
                </div>
              </motion.div>
            )
          })}

          {filteredAlerts.length === 0 && (
            <div className="card">
              <div className="text-center py-12 text-gray-500 dark:text-gray-400">
                <ExclamationTriangleIcon className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No threats found</p>
              </div>
            </div>
          )}
        </div>

        {selectedAlert && (
          <motion.aside
            key={selectedAlert.id}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            className="card lg:sticky lg:top-24 h-fit"
          >
            <div className="card-header flex items-start justify-between">
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{selectedAlert.title}</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {format(new Date(selectedAlert.timestamp), 'PPpp')}
                </p>
              </div>
              <button
                type="button"
                className="text-sm text-primary-600 hover:text-primary-700"
                onClick={() => setSelectedAlertId(null)}
              >
                Close
              </button>
            </div>
            <div className="card-body space-y-4">
              <div className="grid grid-cols-1 gap-3 text-sm text-gray-700 dark:text-gray-300">
                <div>
                  <p className="font-medium text-gray-900 dark:text-white">Device</p>
                  <p>{formatDevice(selectedAlert.device_mac, devices) || 'Not identified'}</p>
                </div>
                <div>
                  <p className="font-medium text-gray-900 dark:text-white">Severity</p>
                  <p>{toSentenceCase(selectedAlert.severity)}</p>
                </div>
                <div>
                  <p className="font-medium text-gray-900 dark:text-white">First seen</p>
                  <p>{formatDate(getFirstSeen(selectedAlert))}</p>
                </div>
                <div>
                  <p className="font-medium text-gray-900 dark:text-white">Last seen</p>
                  <p>{formatDate(getLastSeen(selectedAlert))}</p>
                </div>
              </div>

              <section>
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Explanation</h3>
                <p className="mt-1 text-sm text-gray-700 dark:text-gray-300">
                  {selectedAlert.explanation || DEFAULT_EXPLANATION}
                </p>
              </section>

              <section>
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Recommendation</h3>
                <p className="mt-1 text-sm text-gray-700 dark:text-gray-300">
                  {selectedAlert.recommendation || DEFAULT_RECOMMENDATION}
                </p>
              </section>

              <section>
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Technical context</h3>
                  <button
                    type="button"
                    className="text-sm text-primary-600 hover:text-primary-700"
                    onClick={() => setTechnicalOpen((open) => !open)}
                  >
                    {technicalOpen ? 'Collapse' : 'Expand'}
                  </button>
                </div>
                {technicalOpen && (
                  <TechnicalContext details={selectedAlert.details} />
                )}
              </section>
            </div>
          </motion.aside>
        )}
      </div>
    </div>
  )
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'CRITICAL':
      return 'danger'
    case 'HIGH':
      return 'warning'
    case 'MEDIUM':
      return 'primary'
    case 'LOW':
      return 'success'
    default:
      return 'info'
  }
}

function toSentenceCase(value: string) {
  if (!value) {
    return 'Not identified'
  }
  const normalised = value.replace(/_/g, ' ').replace(/-/g, ' ')
  return normalised.charAt(0) + normalised.slice(1).toLowerCase()
}

function formatDate(value: string | null) {
  if (!value) {
    return 'Not identified'
  }
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    return 'Not identified'
  }
  return format(parsed, 'PPpp')
}

function formatDevice(mac: string | undefined, devices: Device[]) {
  if (!mac) return 'Not identified'
  const match = devices.find((device) => device.mac === mac)
  if (!match) return mac
  return match.hostname || match.vendor || mac
}

function getFirstSeen(alert: Alert) {
  const details = (alert.details || {}) as Record<string, any>
  return details.first_seen || details.timestamp_start || alert.timestamp
}

function getLastSeen(alert: Alert) {
  const details = (alert.details || {}) as Record<string, any>
  return details.last_seen || details.timestamp_end || alert.timestamp
}

function TechnicalContext({ details }: { details?: Record<string, any> }) {
  const context = buildTechnicalContext(details)

  if (context.length === 0) {
    return <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">No additional technical indicators were captured.</p>
  }

  return (
    <dl className="mt-2 space-y-2 text-sm text-gray-700 dark:text-gray-300">
      {context.map(({ label, value }) => (
        <div key={label} className="flex justify-between">
          <dt className="font-medium text-gray-900 dark:text-white">{label}</dt>
          <dd className="text-right text-sm text-gray-700 dark:text-gray-300">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

function buildTechnicalContext(details?: Record<string, any>) {
  if (!details || typeof details !== 'object') return [] as Array<{ label: string; value: ReactNode }>

  const context: Array<{ label: string; value: ReactNode }> = []

  if (details.rule) {
    context.push({ label: 'Triggered rule', value: annotateWithGlossary(toSentenceCase(details.rule)) })
  }

  if (details.alert_type) {
    context.push({ label: 'Alert type', value: annotateWithGlossary(toSentenceCase(details.alert_type)) })
  }

  if (details.protocol) {
    context.push({ label: 'Protocol', value: annotateWithGlossary(String(details.protocol)) })
  }

  if (details.port) {
    context.push({ label: 'Port', value: annotateWithGlossary(String(details.port)) })
  }

  if (details.ports) {
    const ports = Array.isArray(details.ports) ? details.ports.join(', ') : String(details.ports)
    context.push({ label: 'Ports', value: annotateWithGlossary(ports) })
  }

  if (details.destination || details.dst_ip) {
    context.push({ label: 'Destination', value: annotateWithGlossary(String(details.destination || details.dst_ip)) })
  }

  if (details.total_count) {
    context.push({ label: 'Sample count', value: String(details.total_count) })
  }

  if (details.anomaly_score) {
    const score = typeof details.anomaly_score === 'number'
      ? details.anomaly_score.toFixed(2)
      : String(details.anomaly_score)
    context.push({ label: 'Anomaly score', value: score })
  }

  if (Array.isArray(details.connections) && details.connections.length > 0) {
    context.push({ label: 'Connection samples', value: annotateWithGlossary(`${details.connections.length}`) })
  }

  if (Array.isArray(details.top_features) && details.top_features.length > 0) {
    context.push({ label: 'Top contributing features', value: annotateWithGlossary(details.top_features.slice(0, 5).join(', ')) })
  }


  return context
}

function annotateWithGlossary(value: string): ReactNode {
  const trimmed = value.trim()
  if (!trimmed) {
    return 'Not identified'
  }
  const lower = trimmed.toLowerCase()
  if (lower.includes('dns')) {
    return <span title={glossaryTitle('dns')}>{trimmed}</span>
  }
  if (lower.includes('connection') || lower.includes('flow')) {
    return <span title={glossaryTitle('connection')}>{trimmed}</span>
  }
  if (lower.includes('mac') || lower.includes('hardware')) {
    return <span title={glossaryTitle('hardwareId')}>{trimmed}</span>
  }
  return trimmed
}

function ExclamationTriangleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
      />
    </svg>
  )
}








