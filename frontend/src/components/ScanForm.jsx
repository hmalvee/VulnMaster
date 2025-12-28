import { useState, useEffect } from 'react'

const API_BASE = '/api'

function ScanForm({ onCreateScan, loading }) {
  const [targetUrl, setTargetUrl] = useState('')
  const [scanType, setScanType] = useState('SQL Injection')
  const [scanTypes, setScanTypes] = useState([])
  const [descriptions, setDescriptions] = useState({})

  useEffect(() => {
    // Fetch available scan types
    fetch(`${API_BASE}/scans/types`)
      .then(res => res.json())
      .then(data => {
        setScanTypes(data.scan_types || [])
        setDescriptions(data.descriptions || {})
        if (data.scan_types && data.scan_types.length > 0) {
          setScanType(data.scan_types[0])
        }
      })
      .catch(err => {
        console.error('Error fetching scan types:', err)
        // Fallback to default
        setScanTypes(['SQL Injection', 'XSS', 'Sensitive File Exposure', 'Infrastructure'])
      })
  }, [])

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!targetUrl.trim()) {
      alert('Please enter a target URL')
      return
    }
    onCreateScan(targetUrl, scanType)
    setTargetUrl('') // Reset form
  }

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-xl font-bold mb-4">New Scan</h2>
      <form onSubmit={handleSubmit}>
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Target URL
          </label>
          <input
            type="url"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example.com"
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Scan Type
          </label>
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {scanTypes.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
          {descriptions[scanType] && (
            <p className="text-xs text-gray-500 mt-1">{descriptions[scanType]}</p>
          )}
        </div>
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Starting Scan...' : 'Start Scan'}
        </button>
      </form>
    </div>
  )
}

export default ScanForm
