import { useStore } from '../lib/store'
import { useQuery } from '@tanstack/react-query'
import { captureApi } from '../lib/api'

export default function ModeIndicator() {
  const captureMode = useStore((state) => state.captureMode)
  
  const { data: captureStatus } = useQuery({
    queryKey: ['capture-status'],
    queryFn: () => captureApi.getStatus(),
    refetchInterval: 5000,
    select: (response) => response.data
  })

  const getModeIcon = (mode: string) => {
    switch (mode) {
      case 'live':
        return '🔴' // Live indicator
      case 'pcap':
        return '📁' // File indicator
      default:
        return '❓'
    }
  }

  const getModeColor = (mode: string) => {
    switch (mode) {
      case 'live':
        return 'bg-red-100 text-red-800 border-red-200'
      case 'pcap':
        return 'bg-blue-100 text-blue-800 border-blue-200'
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const getModeDescription = (mode: string) => {
    switch (mode) {
      case 'live':
        return 'Monitoring live network traffic and connected devices'
      case 'pcap':
        return 'Analyzing uploaded PCAP file data'
      default:
        return 'Unknown mode'
    }
  }

  return (
    <div className={`inline-flex items-center px-3 py-2 rounded-lg border ${getModeColor(captureMode)} text-sm font-medium`}>
      <span className="mr-2 text-base">{getModeIcon(captureMode)}</span>
      <div className="flex flex-col">
        <span className="font-semibold">
          {captureMode.toUpperCase()} MODE
        </span>
        <span className="text-xs opacity-75">
          {getModeDescription(captureMode)}
        </span>
      </div>
      {captureStatus?.is_running && (
        <div className="ml-3 flex items-center">
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
          <span className="ml-1 text-xs">Active</span>
        </div>
      )}
    </div>
  )
}
