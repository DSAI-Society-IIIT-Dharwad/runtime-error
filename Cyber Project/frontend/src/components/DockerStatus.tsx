import { useState, useEffect } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { dockerApi } from '../lib/api'

interface DockerStatusData {
  status: string
  containers_monitored: number
  last_update: string
  message?: string
}

export default function DockerStatus() {
  const [isExpanded, setIsExpanded] = useState(false)

  const { data: dockerStatus, refetch, isLoading } = useQuery({
    queryKey: ['docker-status'],
    queryFn: () => dockerApi.getStatus(),
    refetchInterval: 5000, // Refetch every 5 seconds
    select: (response) => response.data as DockerStatusData
  })

  const restartMutation = useMutation({
    mutationFn: () => dockerApi.restart(),
    onSuccess: () => {
      toast.success('Docker monitoring restarted')
      refetch()
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.message || 'Failed to restart Docker monitoring')
    }
  })

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'text-green-600 bg-green-100'
      case 'stopped':
        return 'text-red-600 bg-red-100'
      case 'not_initialized':
        return 'text-yellow-600 bg-yellow-100'
      default:
        return 'text-gray-600 bg-gray-100'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return '🟢'
      case 'stopped':
        return '🔴'
      case 'not_initialized':
        return '🟡'
      default:
        return '⚪'
    }
  }

  if (isLoading) {
    return (
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-semibold">Docker Monitoring</h3>
        </div>
        <div className="p-4">
          <div className="animate-pulse">Loading...</div>
        </div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="card-header cursor-pointer" onClick={() => setIsExpanded(!isExpanded)}>
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            {getStatusIcon(dockerStatus?.status || 'unknown')}
            Docker Monitoring
          </h3>
          <div className="flex items-center gap-2">
            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(dockerStatus?.status || 'unknown')}`}>
              {dockerStatus?.status || 'Unknown'}
            </span>
            <span className="text-gray-500">
              {isExpanded ? '▼' : '▶'}
            </span>
          </div>
        </div>
      </div>

      {isExpanded && (
        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="font-medium text-gray-600 dark:text-gray-400">Status:</span>
                <span className="ml-2">{dockerStatus?.status || 'Unknown'}</span>
              </div>
              <div>
                <span className="font-medium text-gray-600 dark:text-gray-400">Containers:</span>
                <span className="ml-2">{dockerStatus?.containers_monitored || 0}</span>
              </div>
            </div>

            {dockerStatus?.last_update && (
              <div className="text-sm">
                <span className="font-medium text-gray-600 dark:text-gray-400">Last Update:</span>
                <span className="ml-2">
                  {new Date(dockerStatus.last_update).toLocaleTimeString()}
                </span>
              </div>
            )}

            {dockerStatus?.message && (
              <div className="text-sm text-gray-600 dark:text-gray-400">
                {dockerStatus.message}
              </div>
            )}

            <div className="flex gap-2 pt-2">
              <button
                onClick={() => refetch()}
                disabled={isLoading}
                className="btn btn-secondary btn-sm"
              >
                Refresh
              </button>
              <button
                onClick={() => restartMutation.mutate()}
                disabled={restartMutation.isPending}
                className="btn btn-primary btn-sm"
              >
                {restartMutation.isPending ? 'Restarting...' : 'Restart'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
