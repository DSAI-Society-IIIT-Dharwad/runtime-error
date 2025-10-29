import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { captureApi, deviceApi, flowApi } from '../lib/api'
import { useStore } from '../lib/store'

export default function PcapAnalysis() {
  const [isExpanded, setIsExpanded] = useState(true)
  const captureMode = useStore((state) => state.captureMode)

  const { data: captureStatus, isLoading } = useQuery({
    queryKey: ['capture-status'],
    queryFn: () => captureApi.getStatus(),
    refetchInterval: 5000,
    select: (response) => response.data
  })

  const { data: devicesData } = useQuery({
    queryKey: ['devices', 'pcap'],
    queryFn: () => deviceApi.getAll(),
    enabled: captureMode === 'pcap',
    select: (response) => response.data
  })

  const { data: flowStats } = useQuery({
    queryKey: ['flow-stats', 'pcap'],
    queryFn: () => flowApi.getStatistics(),
    enabled: captureMode === 'pcap',
    select: (response) => response.data
  })

  if (captureMode !== 'pcap') {
    return null
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="card"
    >
      <div className="card-header cursor-pointer" onClick={() => setIsExpanded(!isExpanded)}>
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            📁 PCAP File Analysis
          </h3>
          <div className="flex items-center gap-2">
            <span className="px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
              {captureStatus?.is_running ? 'Processing' : 'Ready'}
            </span>
            <span className="text-gray-500">
              {isExpanded ? '▼' : '▶'}
            </span>
          </div>
        </div>
      </div>

      {isExpanded && (
        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <div className="space-y-4">
            {/* File Information */}
            {captureStatus?.pcap_file_info && (
              <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
                <h4 className="font-medium text-sm text-gray-700 dark:text-gray-300 mb-2">
                  Current PCAP File
                </h4>
                <div className="text-sm space-y-1">
                  <div>
                    <span className="font-medium">File:</span>
                    <span className="ml-2 font-mono text-xs">{captureStatus.pcap_file_info.filename || 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="font-medium">Size:</span>
                    <span className="ml-2">{captureStatus.pcap_file_info.size_mb ? `${captureStatus.pcap_file_info.size_mb.toFixed(2)} MB` : 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="font-medium">Packets:</span>
                    <span className="ml-2">{captureStatus.pcap_file_info.packet_count || 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="font-medium">Duration:</span>
                    <span className="ml-2">{captureStatus.pcap_file_info.capture_duration ? `${Math.round(captureStatus.pcap_file_info.capture_duration)} sec` : 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="font-medium">First Packet:</span>
                    <span className="ml-2">{captureStatus.pcap_file_info.first_packet || 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="font-medium">Last Packet:</span>
                    <span className="ml-2">{captureStatus.pcap_file_info.last_packet || 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="font-medium">Modified:</span>
                    <span className="ml-2">{captureStatus.pcap_file_info.modified || 'Unknown'}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Analysis Statistics */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                  {(devicesData?.devices?.filter(device =>
                    device.role !== 'container' &&
                    device.role !== 'infrastructure' &&
                    !(device.vendor && device.vendor.toLowerCase().includes('docker'))
                  ).length) || 0}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Devices Found
                </div>
              </div>
              
              <div className="text-center p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
                <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                  {flowStats?.total_flows || 0}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Network Flows
                </div>
              </div>
              
              <div className="text-center p-3 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                  {flowStats?.unique_ips || 0}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Unique IPs
                </div>
              </div>
              
              <div className="text-center p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                  {flowStats?.protocols?.length || 0}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Protocols
                </div>
              </div>
            </div>

            {/* Analysis Status */}
            <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <div className="flex items-center gap-2">
                <div className={`w-3 h-3 rounded-full ${
                  captureStatus?.is_running ? 'bg-blue-500 animate-pulse' : 'bg-green-500'
                }`}></div>
                <span className="text-sm font-medium">
                  {captureStatus?.is_running ? 'Analyzing PCAP file...' : 'Analysis complete'}
                </span>
              </div>
              
              {!captureStatus?.is_running && (
                <div className="text-xs text-gray-500">
                  Data shows historical network activity from the uploaded file
                </div>
              )}
            </div>

            {/* Quick Actions */}
            <div className="flex gap-2 pt-2">
              <button
                onClick={() => window.location.href = '/devices'}
                className="btn btn-primary btn-sm"
              >
                View Devices
              </button>
              <button
                onClick={() => window.location.href = '/flows'}
                className="btn btn-secondary btn-sm"
              >
                View Flows
              </button>
              <button
                onClick={() => window.location.href = '/settings'}
                className="btn btn-secondary btn-sm"
              >
                Upload New File
              </button>
            </div>
          </div>
        </div>
      )}
    </motion.div>
  )
}
