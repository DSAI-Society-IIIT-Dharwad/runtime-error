import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { captureApi, detectionApi } from '../lib/api'
import { useStore } from '../lib/store'

export default function Settings() {
  const captureMode = useStore((state) => state.captureMode)
  const setCaptureMode = useStore((state) => state.setCaptureMode)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [interface_, setInterface] = useState('eth0')

  const switchModeMutation = useMutation({
    mutationFn: (data: any) => captureApi.switchMode(data),
    onSuccess: (response, variables) => {
      toast.dismiss('mode-switch')
      const mode = variables.mode
      if (mode === 'live') {
        toast.success('✅ Switched to Live mode - now monitoring real-time devices')
      } else {
        toast.success('✅ Switched to PCAP mode - ready to analyze uploaded files')
      }
      
      // Force refresh of the page data
      window.location.reload()
    },
    onError: (error: any) => {
      toast.dismiss('mode-switch')
      console.error('Mode switch error:', error)
      toast.error(error.response?.data?.detail || 'Failed to switch mode')
    }
  })

  const uploadPcapMutation = useMutation({
    mutationFn: (file: File) => captureApi.uploadPcap(file),
    onSuccess: (response) => {
      toast.dismiss('upload')
      const data = response.data
      toast.success(`✅ PCAP uploaded! Found ${data.packet_count || 0} packets`)
      console.log('Upload response:', data)
      setSelectedFile(null)
      // Switch to PCAP mode after successful upload
      setCaptureMode('pcap')
      // Force page reload to show PCAP analysis results
      setTimeout(() => {
        window.location.reload()
      }, 1500)
    },
    onError: (error: any) => {
      toast.dismiss('upload')
      console.error('Upload error:', error)
      toast.error(error.response?.data?.detail || 'Upload failed')
    },
  })

  const trainModelMutation = useMutation({
    mutationFn: () => detectionApi.trainModel(),
    onSuccess: () => {
      toast.success('Model training started')
    },
  })

  const handleModeSwitch = (mode: 'live' | 'pcap') => {
    // Clear existing data when switching modes
    setCaptureMode(mode)
    
    // Show appropriate message based on mode
    if (mode === 'live') {
      toast.loading('Switching to Live mode - will show real-time connected devices...', { id: 'mode-switch' })
    } else {
      toast.loading('Switching to PCAP mode - will analyze uploaded file data...', { id: 'mode-switch' })
    }
    
    switchModeMutation.mutate({
      mode,
      interface: mode === 'live' ? interface_ : undefined,
    })
  }

  const handleFileUpload = () => {
    if (selectedFile) {
      console.log('Uploading file:', selectedFile.name, selectedFile.size)
      toast.loading('Uploading PCAP file...', { id: 'upload' })
      uploadPcapMutation.mutate(selectedFile)
    } else {
      toast.error('Please select a file first')
    }
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>
        <p className="text-gray-600 dark:text-gray-400">Configure system settings</p>
      </div>

      {/* Capture Mode */}
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-medium">Capture Mode</h3>
        </div>
        <div className="card-body space-y-4">
          <div className="flex space-x-4">
            <button
              onClick={() => handleModeSwitch('live')}
              className={`flex-1 p-4 rounded-lg border-2 transition-colors ${
                captureMode === 'live'
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900'
                  : 'border-gray-300 dark:border-gray-600'
              }`}
            >
              <h4 className="font-medium">Live Capture</h4>
              <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                Monitor network traffic in real-time
              </p>
            </button>
            <button
              onClick={() => handleModeSwitch('pcap')}
              className={`flex-1 p-4 rounded-lg border-2 transition-colors ${
                captureMode === 'pcap'
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900'
                  : 'border-gray-300 dark:border-gray-600'
              }`}
            >
              <h4 className="font-medium">PCAP Analysis</h4>
              <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                Analyze uploaded PCAP files
              </p>
            </button>
          </div>

          {captureMode === 'live' && (
            <div>
              <label className="block text-sm font-medium mb-2">Network Interface</label>
              <input
                type="text"
                className="input"
                value={interface_}
                onChange={(e) => setInterface(e.target.value)}
                placeholder="eth0"
              />
            </div>
          )}

          {captureMode === 'pcap' && (
            <div>
              <label className="block text-sm font-medium mb-2">Upload PCAP File</label>
              <div className="flex space-x-2">
                <input
                  type="file"
                  accept=".pcap,.pcapng"
                  onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                  className="flex-1"
                />
                <button
                  onClick={handleFileUpload}
                  disabled={!selectedFile || uploadPcapMutation.isPending}
                  className="btn btn-primary disabled:opacity-50"
                >
                  {uploadPcapMutation.isPending ? 'Uploading...' : 'Upload'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Detection Settings */}
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-medium">Detection Settings</h3>
        </div>
        <div className="card-body space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">DNS Query Threshold</label>
            <input
              type="number"
              className="input"
              defaultValue={10}
              min={1}
              max={100}
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Maximum DNS queries per second before flagging as suspicious
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Anomaly Sensitivity</label>
            <input
              type="range"
              className="w-full"
              min={1}
              max={10}
              defaultValue={5}
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Higher values detect more anomalies but may increase false positives
            </p>
          </div>

          <div>
            <button
              onClick={() => trainModelMutation.mutate()}
              className="btn btn-secondary"
            >
              Retrain Detection Model
            </button>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
              Train the ML model with recent network data
            </p>
          </div>
        </div>
      </div>

      {/* Alert Settings */}
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-medium">Alert Settings</h3>
        </div>
        <div className="card-body space-y-4">
          <div>
            <label className="flex items-center space-x-2">
              <input type="checkbox" defaultChecked />
              <span className="text-sm">Enable critical alerts</span>
            </label>
          </div>
          <div>
            <label className="flex items-center space-x-2">
              <input type="checkbox" defaultChecked />
              <span className="text-sm">Enable high severity alerts</span>
            </label>
          </div>
          <div>
            <label className="flex items-center space-x-2">
              <input type="checkbox" />
              <span className="text-sm">Enable medium severity alerts</span>
            </label>
          </div>
          <div>
            <label className="flex items-center space-x-2">
              <input type="checkbox" />
              <span className="text-sm">Enable low severity alerts</span>
            </label>
          </div>
        </div>
      </div>
    </div>
  )
}
