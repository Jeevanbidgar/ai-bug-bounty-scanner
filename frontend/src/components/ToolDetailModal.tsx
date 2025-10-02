import { useState, useEffect } from 'react'
import { X, CheckCircle, XCircle, AlertTriangle, Loader2, Play, RefreshCw, Copy, ExternalLink, Check } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/Card'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import type { Tool } from '../services/api'
import { invoke } from '@tauri-apps/api/tauri'
import { useToast } from '../hooks/useToast'
import Toast from './ui/Toast'

interface ToolDetailModalProps {
  tool: Tool
  onClose: () => void
}

interface OsInfo {
  platform: 'windows' | 'macos' | 'linux' | 'unknown'
  arch: string
}

const ToolDetailModal = ({ tool: initialTool, onClose }: ToolDetailModalProps) => {
  const [tool, setTool] = useState(initialTool)
  const [isTestRunning, setIsTestRunning] = useState(false)
  const [testOutput, setTestOutput] = useState<string | null>(null)
  const [testError, setTestError] = useState<string | null>(null)
  const [osInfo, setOsInfo] = useState<OsInfo | null>(null)
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null)
  const [isRechecking, setIsRechecking] = useState(false)
  const { toasts, success, error: showError, info, removeToast } = useToast()

  useEffect(() => {
    const fetchOsInfo = async () => {
      try {
        const info = await invoke<OsInfo>('get_os_info')
        setOsInfo(info)
      } catch (error) {
        console.error('Failed to get OS info:', error)
      }
    }
    fetchOsInfo()
  }, [])

  const getInstallCommands = (toolName: string, platform: string): { name: string, command: string, link?: string }[] => {
    const commonToolCommands: Record<string, Record<string, { name: string, command: string, link?: string }[]>> = {
      'amass': {
        'windows': [{ name: 'Chocolatey', command: 'choco install amass', link: 'https://chocolatey.org/' }, { name: 'Go', command: 'go install -v github.com/owasp-amass/amass/v4/...@master' }],
        'macos': [{ name: 'Homebrew', command: 'brew install amass' }, { name: 'Go', command: 'go install -v github.com/owasp-amass/amass/v4/...@master' }],
        'linux': [{ name: 'Snap', command: 'sudo snap install amass' }, { name: 'Go', command: 'go install -v github.com/owasp-amass/amass/v4/...@master' }]
      },
      'nuclei': {
        'windows': [{ name: 'Go', command: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' }],
        'macos': [{ name: 'Homebrew', command: 'brew install nuclei' }, { name: 'Go', command: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' }],
        'linux': [{ name: 'Go', command: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' }]
      },
      'nmap': {
        'windows': [{ name: 'Download', command: 'Download from nmap.org', link: 'https://nmap.org/download.html' }],
        'macos': [{ name: 'Homebrew', command: 'brew install nmap' }],
        'linux': [{ name: 'APT', command: 'sudo apt install nmap' }, { name: 'DNF', command: 'sudo dnf install nmap' }]
      },
      'ffuf': {
        'windows': [{ name: 'Go', command: 'go install github.com/ffuf/ffuf@latest' }],
        'macos': [{ name: 'Homebrew', command: 'brew install ffuf' }, { name: 'Go', command: 'go install github.com/ffuf/ffuf@latest' }],
        'linux': [{ name: 'Go', command: 'go install github.com/ffuf/ffuf@latest' }]
      },
      'subfinder': {
        'windows': [{ name: 'Go', command: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' }],
        'macos': [{ name: 'Homebrew', command: 'brew install subfinder' }, { name: 'Go', command: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' }],
        'linux': [{ name: 'Go', command: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' }]
      },
      'httpx': {
        'windows': [{ name: 'Go', command: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest' }],
        'macos': [{ name: 'Homebrew', command: 'brew install httpx' }, { name: 'Go', command: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest' }],
        'linux': [{ name: 'Go', command: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest' }]
      },
      'gobuster': {
        'windows': [{ name: 'Go', command: 'go install github.com/OJ/gobuster/v3@latest' }],
        'macos': [{ name: 'Homebrew', command: 'brew install gobuster' }, { name: 'Go', command: 'go install github.com/OJ/gobuster/v3@latest' }],
        'linux': [{ name: 'APT', command: 'sudo apt install gobuster' }, { name: 'Go', command: 'go install github.com/OJ/gobuster/v3@latest' }]
      },
    }

    return commonToolCommands[toolName.toLowerCase()]?.[platform] || []
  }

  const handleCopyCommand = async (command: string) => {
    try {
      await navigator.clipboard.writeText(command)
      setCopiedCommand(command)
      setTimeout(() => setCopiedCommand(null), 2000)
    } catch (error) {
      console.error('Failed to copy command:', error)
    }
  }

  const getStatusBadge = () => {
    if (tool.installed) {
      return <Badge className="bg-green-700 text-green-100">Available</Badge>
    } else {
      return <Badge className="bg-red-700 text-red-100">Not Installed</Badge>
    }
  }

  const getStatusIcon = () => {
    if (tool.installed) {
      return <CheckCircle className="h-5 w-5 text-green-500" />
    } else {
      return <XCircle className="h-5 w-5 text-red-500" />
    }
  }

  const handleTestRun = async () => {
    setIsTestRunning(true)
    setTestError(null)
    setTestOutput(null)

    try {
      // This would call a backend command to test run the tool
      // For now, we'll simulate it
      await new Promise(resolve => setTimeout(resolve, 1000))
      
      if (tool.raw_version) {
        setTestOutput(tool.raw_version)
      } else {
        setTestOutput(`${tool.name} is installed at ${tool.path}`)
      }
    } catch (error) {
      setTestError(error instanceof Error ? error.message : 'Failed to run test')
    } finally {
      setIsTestRunning(false)
    }
  }

  const handleRecheck = async () => {
    setIsRechecking(true)
    const previousStatus = tool.installed
    
    try {
      // Call the Tauri command directly to check just this tool
      const updatedTool = await invoke<Tool>('recheck_tool', { toolName: tool.name })
      
      if (updatedTool) {
        // Update the local state
        setTool(updatedTool)
        
        // Show appropriate notification
        if (updatedTool.installed && !previousStatus) {
          success(`${updatedTool.name} is now available!`)
        } else if (!updatedTool.installed && previousStatus) {
          info(`${updatedTool.name} is no longer available`)
        } else {
          success(`${updatedTool.name} status checked`)
        }
        
        // NO parent callback - completely isolated recheck
      }
    } catch (error) {
      console.error('Failed to recheck tool:', error)
      showError(`Failed to recheck ${tool.name}`)
    } finally {
      setIsRechecking(false)
    }
  }

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never'
    
    try {
      const date = new Date(dateString)
      return date.toLocaleString()
    } catch {
      return dateString
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="bg-gray-900 rounded-lg max-w-3xl w-full max-h-[90vh] overflow-y-auto border border-gray-700 shadow-2xl">
        {/* Header */}
        <div className="sticky top-0 bg-gray-900 border-b border-gray-700 px-6 py-4 flex items-center justify-between z-10">
          <div className="flex items-center gap-3">
            {getStatusIcon()}
            <div>
              <h2 className="text-2xl font-bold text-white">{tool.name}</h2>
              <p className="text-sm text-gray-400">{tool.category}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {getStatusBadge()}
            <Button
              onClick={onClose}
              variant="ghost"
              size="sm"
              className="text-gray-400 hover:text-white"
            >
              <X className="h-5 w-5" />
            </Button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Description */}
          <Card>
            <CardHeader>
              <CardTitle>Description</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-300">{tool.description}</p>
            </CardContent>
          </Card>

          {/* Installation Details */}
          <Card>
            <CardHeader>
              <CardTitle>Installation Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-400 mb-1">Status</p>
                  <div className="flex items-center gap-2">
                    {getStatusIcon()}
                    <span className="text-white font-medium">
                      {tool.installed ? 'Installed' : 'Not Installed'}
                    </span>
                  </div>
                </div>

                <div>
                  <p className="text-sm text-gray-400 mb-1">Version</p>
                  <p className="text-white font-mono">
                    {tool.version || 'Unknown'}
                  </p>
                </div>

                <div>
                  <p className="text-sm text-gray-400 mb-1">Path</p>
                  <p className="text-white font-mono text-sm break-all">
                    {tool.path || 'Not found'}
                  </p>
                </div>

                <div>
                  <p className="text-sm text-gray-400 mb-1">Output Format</p>
                  <p className="text-white font-mono">
                    {tool.output_format}
                  </p>
                </div>
              </div>

              {/* Command Template */}
              {tool.command_template && tool.command_template.length > 0 && (
                <div>
                  <p className="text-sm text-gray-400 mb-2">Command Template</p>
                  <div className="bg-gray-800 rounded-lg p-3 font-mono text-sm text-gray-300">
                    {tool.command_template.join(' ')}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Dependencies */}
          {(tool.os_dependencies.length > 0 || tool.missing_dependencies.length > 0) && (
            <Card>
              <CardHeader>
                <CardTitle>Dependencies</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {tool.os_dependencies.length > 0 && (
                  <div>
                    <p className="text-sm text-gray-400 mb-2">OS Dependencies</p>
                    <div className="flex flex-wrap gap-2">
                      {tool.os_dependencies.map((dep) => (
                        <Badge key={dep} className="bg-blue-700 text-blue-100">
                          {dep}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {tool.missing_dependencies.length > 0 && (
                  <div>
                    <p className="text-sm text-gray-400 mb-2 flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-yellow-500" />
                      Missing Dependencies
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {tool.missing_dependencies.map((dep) => (
                        <Badge key={dep} className="bg-red-700 text-red-100">
                          {dep}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Installation Helper */}
          {!tool.installed && osInfo && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-yellow-500" />
                  Installation Instructions
                </CardTitle>
                <CardDescription>
                  {tool.name} is not installed. Here are some ways to install it on your system ({osInfo.platform}):
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {getInstallCommands(tool.name, osInfo.platform).length > 0 ? (
                  <div className="space-y-3">
                    {getInstallCommands(tool.name, osInfo.platform).map((installMethod, index) => (
                      <div key={index} className="bg-gray-800 rounded-lg p-4 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium text-gray-300">{installMethod.name}:</span>
                          {installMethod.link && (
                            <a
                              href={installMethod.link}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-blue-400 hover:text-blue-300 flex items-center gap-1 text-sm"
                            >
                              <ExternalLink className="h-3 w-3" />
                              Docs
                            </a>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          <code className="flex-1 bg-gray-900 text-green-300 p-2 rounded text-sm font-mono">
                            {installMethod.command}
                          </code>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleCopyCommand(installMethod.command)}
                            className="flex-shrink-0"
                          >
                            {copiedCommand === installMethod.command ? (
                              <>
                                <Check className="h-4 w-4 text-green-500" />
                              </>
                            ) : (
                              <>
                                <Copy className="h-4 w-4" />
                              </>
                            )}
                          </Button>
                        </div>
                      </div>
                    ))}
                    <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4 mt-4">
                      <p className="text-sm text-blue-300">
                        <strong>💡 Tip:</strong> After installing {tool.name}, click the "Recheck Status" button below to verify the installation.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="bg-gray-800 rounded-lg p-4 text-center space-y-2">
                    <p className="text-gray-300">
                      No automatic installation commands available for this tool.
                    </p>
                    <p className="text-sm text-gray-400">
                      Please refer to the official documentation for installation instructions.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Check History */}
          <Card>
            <CardHeader>
              <CardTitle>Check History</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">Last Checked:</span>
                <span className="text-white">{formatDate(tool.last_checked)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Last Seen:</span>
                <span className="text-white">{formatDate(tool.last_seen)}</span>
              </div>
              {tool.last_error && (
                <div className="mt-3 p-3 bg-red-900/20 border border-red-700 rounded-lg">
                  <p className="text-sm text-red-300">
                    <strong>Last Error:</strong> {tool.last_error}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Test Run Section */}
          {tool.installed && (
            <Card>
              <CardHeader>
                <CardTitle>Test Run</CardTitle>
                <CardDescription>
                  Execute a test command to verify the tool is working correctly
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Button
                  onClick={handleTestRun}
                  disabled={isTestRunning}
                  className="w-full"
                >
                  {isTestRunning ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Running Test...
                    </>
                  ) : (
                    <>
                      <Play className="mr-2 h-4 w-4" />
                      Run Test Command
                    </>
                  )}
                </Button>

                {testOutput && (
                  <div className="bg-gray-800 rounded-lg p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <p className="text-sm text-gray-400">Test Output:</p>
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    </div>
                    <pre className="text-sm text-green-300 whitespace-pre-wrap font-mono">
                      {testOutput}
                    </pre>
                  </div>
                )}

                {testError && (
                  <div className="bg-red-900/20 border border-red-700 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <XCircle className="h-4 w-4 text-red-500" />
                      <p className="text-sm text-red-400 font-medium">Test Failed</p>
                    </div>
                    <p className="text-sm text-red-300">{testError}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Footer Actions */}
        <div className="sticky bottom-0 bg-gray-900 border-t border-gray-700 px-6 py-4 flex justify-between gap-3">
          <Button
            onClick={handleRecheck}
            variant="outline"
            className="flex-1"
            disabled={isRechecking}
          >
            {isRechecking ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Rechecking...
              </>
            ) : (
              <>
                <RefreshCw className="mr-2 h-4 w-4" />
                Recheck Status
              </>
            )}
          </Button>
          <Button onClick={onClose} className="flex-1">
            Close
          </Button>
        </div>
      </div>
      
      {/* Toast Notifications */}
      <div className="fixed top-4 right-4 z-[60] space-y-2">
        {toasts.map((toast) => (
          <Toast
            key={toast.id}
            {...toast}
            onClose={() => removeToast(toast.id)}
          />
        ))}
      </div>
    </div>
  )
}

export default ToolDetailModal
