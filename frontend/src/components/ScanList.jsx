function ScanList({ scans, selectedScan, onSelectScan, onDeleteScan }) {
  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return 'bg-green-100 text-green-800'
      case 'running':
        return 'bg-blue-100 text-blue-800'
      case 'failed':
        return 'bg-red-100 text-red-800'
      default:
        return 'bg-gray-100 text-gray-800'
    }
  }

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-4 border-b border-gray-200">
        <h2 className="text-xl font-bold">Scans ({scans.length})</h2>
      </div>
      <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
        {scans.length === 0 ? (
          <div className="p-4 text-center text-gray-500">
            No scans yet. Create one to get started.
          </div>
        ) : (
          scans.map((scan) => (
            <div
              key={scan.id}
              className={`p-4 cursor-pointer hover:bg-gray-50 ${
                selectedScan === scan.id ? 'bg-blue-50 border-l-4 border-blue-600' : ''
              }`}
              onClick={() => onSelectScan(scan.id)}
            >
              <div className="flex justify-between items-start">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate">
                    {scan.target_url}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">{scan.scan_type}</p>
                  <div className="flex items-center gap-2 mt-2">
                    <span className={`px-2 py-1 text-xs font-semibold rounded ${getStatusColor(scan.status)}`}>
                      {scan.status}
                    </span>
                    {scan.vulnerability_count > 0 && (
                      <span className="text-xs text-red-600 font-semibold">
                        {scan.vulnerability_count} vulnerability{scan.vulnerability_count !== 1 ? 'ies' : ''}
                      </span>
                    )}
                  </div>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    onDeleteScan(scan.id)
                  }}
                  className="ml-2 text-red-600 hover:text-red-800 text-sm"
                >
                  ×
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

export default ScanList

