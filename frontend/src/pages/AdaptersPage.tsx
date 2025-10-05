import { Wrench } from 'lucide-react'
import AdapterExplorer from '../components/AdapterExplorer'

const AdaptersPage = () => {
  return (
    <div className="p-6 space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <Wrench className="h-8 w-8 text-blue-500" />
            Security Tool Adapters
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-2">
            Browse and configure command builders for security tools with optimized defaults
          </p>
        </div>
      </div>

      {/* Adapter Explorer */}
      <AdapterExplorer />
    </div>
  )
}

export default AdaptersPage
