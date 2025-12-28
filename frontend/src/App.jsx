import { useState, useEffect } from 'react'
import ScanForm from './components/ScanForm'
import ScanList from './components/ScanList'
import ScanDetail from './components/ScanDetail'
import VulnerabilityDetail from './components/VulnerabilityDetail'

const API_BASE = '/api'

function App() {
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(null)
  const [selectedVulnerability, setSelectedVulnerability] = useState(null)
  const [loading, setLoading] = useState(false)

  // Fetch scans on mount and periodically
  useEffect(() => {
    fetchScans()
    const interval = setInterval(fetchScans, 5000) // Poll every 5 seconds
    return () => clearInterval(interval)
  }, [])

  const fetchScans = async () => {
    try {
      const response = await fetch(`${API_BASE}/scans/`)
      const data = await response.json()
      setScans(data)
    } catch (error) {
      console.error('Error fetching scans:', error)
    }
  }

  const handleCreateScan = async (targetUrl, scanType) => {
    setLoading(true)
    try {
      const response = await fetch(`${API_BASE}/scans/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target_url: targetUrl,
          scan_type: scanType,
        }),
      })
      const newScan = await response.json()
      setScans([newScan, ...scans])
      setSelectedScan(newScan.id)
    } catch (error) {
      console.error('Error creating scan:', error)
      alert('Failed to create scan. Please check the backend is running.')
    } finally {
      setLoading(false)
    }
  }

  const handleDeleteScan = async (scanId) => {
    if (!confirm('Are you sure you want to delete this scan?')) return

    try {
      await fetch(`${API_BASE}/scans/${scanId}`, {
        method: 'DELETE',
      })
      setScans(scans.filter(s => s.id !== scanId))
      if (selectedScan === scanId) {
        setSelectedScan(null)
        setSelectedVulnerability(null)
      }
    } catch (error) {
      console.error('Error deleting scan:', error)
    }
  }

  const handleSelectScan = (scanId) => {
    setSelectedScan(scanId)
    setSelectedVulnerability(null)
  }

  const handleSelectVulnerability = (vulnerability) => {
    setSelectedVulnerability(vulnerability)
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-gray-900 text-white shadow-lg">
        <div className="container mx-auto px-4 py-6">
          <h1 className="text-3xl font-bold">VulnMaster</h1>
          <p className="text-gray-300 mt-1">Educational Vulnerability Scanner</p>
          <p className="text-red-400 text-sm mt-2 font-semibold">
            ⚠️ EDUCATIONAL USE ONLY - For authorized testing only
          </p>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Scans List */}
          <div className="lg:col-span-1">
            <ScanForm onCreateScan={handleCreateScan} loading={loading} />
            <div className="mt-6">
              <ScanList
                scans={scans}
                selectedScan={selectedScan}
                onSelectScan={handleSelectScan}
                onDeleteScan={handleDeleteScan}
              />
            </div>
          </div>

          {/* Right Column - Scan Details */}
          <div className="lg:col-span-2">
            {selectedVulnerability ? (
              <VulnerabilityDetail
                vulnerability={selectedVulnerability}
                onBack={() => setSelectedVulnerability(null)}
              />
            ) : selectedScan ? (
              <ScanDetail
                scanId={selectedScan}
                onSelectVulnerability={handleSelectVulnerability}
              />
            ) : (
              <div className="bg-white rounded-lg shadow p-8 text-center text-gray-500">
                <p>Select a scan to view details</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default App

