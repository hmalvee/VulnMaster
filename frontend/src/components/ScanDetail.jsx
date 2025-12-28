import { useState, useEffect } from 'react'

const API_BASE = '/api'

function ScanDetail({ scanId, onSelectVulnerability }) {
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchScan()
    const interval = setInterval(fetchScan, 3000) // Poll every 3 seconds
    return () => clearInterval(interval)
  }, [scanId])

  const fetchScan = async () => {
    try {
      const response = await fetch(`${API_BASE}/scans/${scanId}`)
      const data = await response.json()
      setScan(data)
      setLoading(false)
    } catch (error) {
      console.error('Error fetching scan:', error)
      setLoading(false)
    }
  }

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-critical text-white'
      case 'high':
        return 'bg-high text-white'
      case 'medium':
        return 'bg-medium text-white'
      case 'low':
        return 'bg-low text-white'
      default:
        return 'bg-gray-200 text-gray-800'
    }
  }

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow p-8 text-center">
        <p>Loading scan details...</p>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="bg-white rounded-lg shadow p-8 text-center text-red-600">
        <p>Scan not found</p>
      </div>
    )
  }

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-6 border-b border-gray-200">
        <h2 className="text-2xl font-bold mb-2">Scan Details</h2>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="font-medium text-gray-600">Target:</span>
            <p className="text-gray-900">{scan.target_url}</p>
          </div>
          <div>
            <span className="font-medium text-gray-600">Type:</span>
            <p className="text-gray-900">{scan.scan_type}</p>
          </div>
          <div>
            <span className="font-medium text-gray-600">Status:</span>
            <span className={`ml-2 px-2 py-1 text-xs font-semibold rounded ${
              scan.status === 'completed' ? 'bg-green-100 text-green-800' :
              scan.status === 'running' ? 'bg-blue-100 text-blue-800' :
              scan.status === 'failed' ? 'bg-red-100 text-red-800' :
              'bg-gray-100 text-gray-800'
            }`}>
              {scan.status}
            </span>
          </div>
          <div>
            <span className="font-medium text-gray-600">Vulnerabilities Found:</span>
            <p className="text-gray-900 font-semibold">{scan.vulnerabilities?.length || 0}</p>
          </div>
        </div>
      </div>

      <div className="p-6">
        <h3 className="text-lg font-bold mb-4">Vulnerabilities</h3>
        {scan.vulnerabilities && scan.vulnerabilities.length > 0 ? (
          <div className="space-y-4">
            {scan.vulnerabilities.map((vuln) => (
              <div
                key={vuln.id}
                className="border border-gray-200 rounded-lg p-4 hover:shadow-md cursor-pointer transition-shadow"
                onClick={() => onSelectVulnerability(vuln)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <h4 className="text-lg font-semibold">{vuln.name}</h4>
                      <span className={`px-2 py-1 text-xs font-semibold rounded ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity}
                      </span>
                    </div>
                    {vuln.parameter && (
                      <p className="text-sm text-gray-600 mb-1">
                        <span className="font-medium">Parameter:</span> {vuln.parameter}
                      </p>
                    )}
                    {vuln.description && (
                      <p className="text-sm text-gray-700 mt-2">{vuln.description}</p>
                    )}
                  </div>
                  <svg
                    className="w-5 h-5 text-gray-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 5l7 7-7 7"
                    />
                  </svg>
                </div>
              </div>
            ))}
          </div>
        ) : scan.status === 'completed' ? (
          <p className="text-gray-500 text-center py-8">
            No vulnerabilities found. Great job! 🎉
          </p>
        ) : scan.status === 'running' ? (
          <p className="text-gray-500 text-center py-8">
            Scan in progress... Please wait.
          </p>
        ) : (
          <p className="text-gray-500 text-center py-8">
            Scan not completed yet.
          </p>
        )}
      </div>
    </div>
  )
}

export default ScanDetail

