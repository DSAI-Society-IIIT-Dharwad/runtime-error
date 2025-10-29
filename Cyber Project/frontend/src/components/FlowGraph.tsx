import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { flowApi } from '../lib/api'
import { useStore } from '../lib/store'

export default function FlowGraph() {
  const flows = useStore((state) => state.flows)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [_selectedNode, _setSelectedNode] = useState<string | null>(null)
  
  const { data: flowStats } = useQuery({
    queryKey: ['flowStats'],
    queryFn: () => flowApi.getStatistics(),
  })

  const { data: _topTalkers } = useQuery({
    queryKey: ['topTalkers'],
    queryFn: () => flowApi.getTopTalkers(20),
  })

  useEffect(() => {
    // Simple network visualization using canvas
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height)

    // Create nodes from flows
    const nodes = new Map<string, { x: number; y: number; size: number }>()
    const edges: Array<{ from: string; to: string }> = []

    flows.slice(0, 100).forEach(flow => {
      if (!nodes.has(flow.src_ip)) {
        nodes.set(flow.src_ip, {
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          size: 5,
        })
      }
      if (!nodes.has(flow.dst_ip)) {
        nodes.set(flow.dst_ip, {
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          size: 5,
        })
      }
      edges.push({ from: flow.src_ip, to: flow.dst_ip })
    })

    // Draw edges
    ctx.strokeStyle = '#4B5563'
    ctx.globalAlpha = 0.3
    edges.forEach(edge => {
      const fromNode = nodes.get(edge.from)
      const toNode = nodes.get(edge.to)
      if (fromNode && toNode) {
        ctx.beginPath()
        ctx.moveTo(fromNode.x, fromNode.y)
        ctx.lineTo(toNode.x, toNode.y)
        ctx.stroke()
      }
    })

    // Draw nodes
    ctx.globalAlpha = 1
    nodes.forEach((node, ip) => {
      const isPrivate = ip.startsWith('192.168.') || ip.startsWith('10.')
      ctx.fillStyle = isPrivate ? '#3B82F6' : '#EF4444'
      ctx.beginPath()
      ctx.arc(node.x, node.y, node.size, 0, Math.PI * 2)
      ctx.fill()
    })
  }, [flows])

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Network Flows</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Real-time network traffic visualization
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-primary-500 rounded-full"></div>
            <span className="text-sm">Internal</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-danger-500 rounded-full"></div>
            <span className="text-sm">External</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Network Graph */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="lg:col-span-2 card"
        >
          <div className="card-header">
            <h3 className="text-lg font-medium">Network Topology</h3>
          </div>
          <div className="card-body">
            <canvas
              ref={canvasRef}
              width={600}
              height={400}
              className="w-full h-full border border-gray-200 dark:border-gray-700 rounded"
            />
          </div>
        </motion.div>

        {/* Flow Statistics */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="space-y-6"
        >
          <div className="card">
            <div className="card-header">
              <h3 className="text-lg font-medium">Flow Statistics</h3>
            </div>
            <div className="card-body space-y-4">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Total Flows</p>
                <p className="text-2xl font-semibold">{flowStats?.data?.total_flows || 0}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">External Flows</p>
                <p className="text-2xl font-semibold">{flowStats?.data?.external_flows || 0}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Total Bytes</p>
                <p className="text-2xl font-semibold">
                  {((flowStats?.data?.total_bytes || 0) / 1024 / 1024).toFixed(2)} MB
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Unique Sources</p>
                <p className="text-2xl font-semibold">{flowStats?.data?.unique_sources || 0}</p>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h3 className="text-lg font-medium">Top Protocols</h3>
            </div>
            <div className="card-body">
              <div className="space-y-2">
                {['TCP', 'UDP', 'ICMP'].map(proto => (
                  <div key={proto} className="flex justify-between items-center">
                    <span className="text-sm">{proto}</span>
                    <span className="badge badge-info">
                      {flows.filter(f => f.protocol === proto).length}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Recent Flows Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="card"
      >
        <div className="card-header">
          <h3 className="text-lg font-medium">Recent Flows</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Port</th>
                <th>Size</th>
              </tr>
            </thead>
            <tbody>
              {flows.slice(0, 10).map((flow) => (
                <tr key={flow.id}>
                  <td className="text-xs">{new Date(flow.timestamp).toLocaleTimeString()}</td>
                  <td className="font-mono text-xs">{flow.src_ip}</td>
                  <td className="font-mono text-xs">{flow.dst_ip}</td>
                  <td>{flow.protocol}</td>
                  <td>{flow.dst_port}</td>
                  <td>{(flow.bytes_total / 1024).toFixed(2)} KB</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.div>
    </div>
  )
}
