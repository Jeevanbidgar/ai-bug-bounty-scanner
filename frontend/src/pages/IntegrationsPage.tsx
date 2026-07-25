import { useMutation, useQuery } from '@tanstack/react-query'
import {
  Bot,
  Check,
  CheckCircle2,
  CircleOff,
  Code2,
  Copy,
  KeyRound,
  PlugZap,
  RefreshCw,
  ShieldCheck,
  TerminalSquare,
} from 'lucide-react'
import { useState } from 'react'
import { appBridge } from '../bridge/appBridge'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { useNotificationStore } from '../stores/notificationStore'
import EngagementAccessPanel from '../components/EngagementAccessPanel'

interface McpHostStatus {
  installed: boolean
  executablePath: string | null
  configured: boolean
}

interface McpIntegrationInfo {
  transport: 'stdio'
  serverName: string
  binaryPath: string
  binaryAvailable: boolean
  providerApiKeyRequired: boolean
  codex: McpHostStatus
  claudeCode: McpHostStatus
  codexAddCommand: string
  claudeAddCommand: string
  codexToml: string
  claudeJson: string
  restartNote: string
}

interface ConfigurationResult {
  client: string
  configured: boolean
  alreadyConfigured: boolean
  message: string
}

const IntegrationsPage = () => {
  const [copied, setCopied] = useState<string | null>(null)
  const addNotification = useNotificationStore((state) => state.addNotification)
  const integrationQuery = useQuery({
    queryKey: ['mcp-integration'],
    queryFn: () => appBridge.invoke<McpIntegrationInfo>('get_mcp_integration_info'),
  })
  const configure = useMutation({
    mutationFn: (client: 'codex' | 'claude_code') =>
      appBridge.invoke<ConfigurationResult>('configure_mcp_client', { client }),
    onSuccess: (result) => {
      addNotification({
        level: 'success',
        title: result.alreadyConfigured ? 'MCP already connected' : 'MCP client connected',
        message: result.message,
        dedupeKey: `mcp:${result.client}`,
      })
      integrationQuery.refetch()
    },
    onError: (error) => addNotification({
      level: 'error',
      title: 'MCP setup failed',
      message: error instanceof Error ? error.message : String(error),
    }),
  })

  const copy = async (label: string, value: string) => {
    await navigator.clipboard.writeText(value)
    setCopied(label)
    window.setTimeout(() => setCopied((current) => current === label ? null : current), 1600)
    addNotification({ level: 'success', title: 'Configuration copied', message: `${label} is ready to paste.` })
  }

  const info = integrationQuery.data
  const error = integrationQuery.error ?? configure.error

  return (
    <div className="space-y-6">
      <section className="relative overflow-hidden rounded-3xl border border-cyan-400/15 bg-[radial-gradient(circle_at_top_right,rgba(34,211,238,0.12),transparent_36%),linear-gradient(135deg,rgba(15,23,42,0.96),rgba(7,12,20,0.98))] p-6 shadow-2xl shadow-black/25 sm:p-8">
        <div className="pointer-events-none absolute right-10 top-0 h-40 w-40 rounded-full bg-violet-500/10 blur-3xl" />
        <div className="relative grid gap-6 xl:grid-cols-[1fr_auto] xl:items-center">
          <div className="max-w-3xl">
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <Badge>No API key</Badge>
              <Badge variant="outline">Local STDIO</Badge>
              <Badge variant="outline">Revocable access</Badge>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">Connect your existing AI coding client</h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">
              Codex CLI or Claude Code launches UniHack locally and uses its own signed-in session. UniHack never asks for that client&apos;s model API key and exposes only typed, audited security operations.
            </p>
          </div>
          <div className="grid min-w-[260px] gap-2 rounded-2xl border border-white/[0.08] bg-black/20 p-4 text-xs">
            <StatusLine icon={<KeyRound className="h-4 w-4" />} label="Provider API key" value="Not required" good />
            <StatusLine icon={<TerminalSquare className="h-4 w-4" />} label="Transport" value="STDIO only" good />
            <StatusLine icon={<ShieldCheck className="h-4 w-4" />} label="Execution" value="Scope-gated" good />
          </div>
        </div>
      </section>

      {error && (
        <div className="rounded-2xl border border-red-400/20 bg-red-400/[0.06] p-4 text-sm text-red-200" role="alert">
          {error instanceof Error ? error.message : String(error)}
        </div>
      )}

      {integrationQuery.isLoading && (
        <div className="grid min-h-56 place-items-center rounded-2xl border border-white/[0.08] bg-white/[0.02]" role="status">
          <div className="text-center text-sm text-slate-400"><RefreshCw className="mx-auto mb-3 h-5 w-5 animate-spin text-cyan-300" />Inspecting local MCP clients…</div>
        </div>
      )}

      {info && (
        <>
          <div className="grid gap-5 xl:grid-cols-2">
            <ClientCard
              icon={<Code2 className="h-5 w-5" />}
              title="Codex CLI"
              description="Global Codex MCP configuration in your normal Codex environment."
              status={info.codex}
              command={info.codexAddCommand}
              config={info.codexToml}
              configLabel="Codex TOML"
              pending={configure.isPending && configure.variables === 'codex'}
              binaryAvailable={info.binaryAvailable}
              onConfigure={() => configure.mutate('codex')}
              onCopy={(label, value) => copy(label, value)}
              copied={copied}
            />
            <ClientCard
              icon={<Bot className="h-5 w-5" />}
              title="Claude Code"
              description="User-scoped Claude Code MCP configuration using the same local binary."
              status={info.claudeCode}
              command={info.claudeAddCommand}
              config={info.claudeJson}
              configLabel="Claude JSON"
              pending={configure.isPending && configure.variables === 'claude_code'}
              binaryAvailable={info.binaryAvailable}
              onConfigure={() => configure.mutate('claude_code')}
              onCopy={(label, value) => copy(label, value)}
              copied={copied}
            />
          </div>

          <div className="grid gap-5 xl:grid-cols-[1.15fr_0.85fr]">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2"><PlugZap className="h-5 w-5 text-cyan-300" />What the connection exposes</CardTitle>
                <CardDescription>One shared UniHack service contract, independent of which AI client is driving it.</CardDescription>
              </CardHeader>
              <CardContent className="mt-5 grid gap-3 sm:grid-cols-2">
                {[
                  ['Discovery', 'Status, installed tools, versions, workflow catalog, and compatibility.'],
                  ['Evidence', 'Bounded scan artifacts, findings, reports, and immutable revision identifiers.'],
                  ['Authorization', 'Desktop-approved engagement scopes with target, workflow, risk, time, and budget limits.'],
                  ['Audit', 'Sanitized arguments, outcomes, scope IDs, request IDs, and chained event hashes.'],
                ].map(([title, text]) => (
                  <div key={title} className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-4">
                    <p className="text-sm font-medium text-slate-100">{title}</p>
                    <p className="mt-1.5 text-xs leading-5 text-slate-500">{text}</p>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2"><TerminalSquare className="h-5 w-5 text-violet-300" />Local server</CardTitle>
                <CardDescription>The AI host starts this process only when it needs UniHack.</CardDescription>
              </CardHeader>
              <CardContent className="mt-5 space-y-4">
                <div className="rounded-xl border border-white/[0.07] bg-black/25 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs font-medium text-slate-400">Binary</span>
                    <Badge variant={info.binaryAvailable ? 'default' : 'destructive'}>{info.binaryAvailable ? 'Ready' : 'Missing'}</Badge>
                  </div>
                  <code className="mt-3 block break-all font-mono text-[11px] leading-5 text-slate-400">{info.binaryPath}</code>
                </div>
                <p className="rounded-xl border border-amber-400/15 bg-amber-400/[0.04] p-3 text-xs leading-5 text-amber-100/75">
                  {info.restartNote}
                </p>
              </CardContent>
            </Card>
          </div>

          <EngagementAccessPanel />
        </>
      )}
    </div>
  )
}

interface ClientCardProps {
  icon: React.ReactNode
  title: string
  description: string
  status: McpHostStatus
  command: string
  config: string
  configLabel: string
  pending: boolean
  binaryAvailable: boolean
  copied: string | null
  onConfigure: () => void
  onCopy: (label: string, value: string) => void
}

const ClientCard = ({ icon, title, description, status, command, config, configLabel, pending, binaryAvailable, copied, onConfigure, onCopy }: ClientCardProps) => (
  <Card className="overflow-hidden">
    <CardHeader>
      <div className="flex items-start justify-between gap-4">
        <div className="flex gap-3">
          <span className="grid h-10 w-10 flex-shrink-0 place-items-center rounded-xl border border-cyan-400/15 bg-cyan-400/[0.07] text-cyan-300">{icon}</span>
          <div>
            <CardTitle>{title}</CardTitle>
            <CardDescription>{description}</CardDescription>
          </div>
        </div>
        <Badge variant={status.configured ? 'default' : status.installed ? 'outline' : 'destructive'}>
          {status.configured ? 'Connected' : status.installed ? 'Detected' : 'Not installed'}
        </Badge>
      </div>
    </CardHeader>
    <CardContent className="mt-5 space-y-4">
      <div className="flex flex-col gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <p className="flex items-center gap-2 text-sm font-medium text-slate-200">
            {status.configured ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : status.installed ? <PlugZap className="h-4 w-4 text-cyan-300" /> : <CircleOff className="h-4 w-4 text-red-300" />}
            {status.configured ? 'UniHack is configured' : status.installed ? 'Client is ready to connect' : `${title} was not found on PATH`}
          </p>
          {status.executablePath && <p className="mt-1 truncate font-mono text-[10px] text-slate-600">{status.executablePath}</p>}
        </div>
        <Button onClick={onConfigure} disabled={!status.installed || !binaryAvailable || pending} size="sm">
          {pending ? <RefreshCw className="mr-2 h-3.5 w-3.5 animate-spin" /> : status.configured ? <Check className="mr-2 h-3.5 w-3.5" /> : <PlugZap className="mr-2 h-3.5 w-3.5" />}
          {status.configured ? 'Verify setup' : 'Connect'}
        </Button>
      </div>

      <ConfigBlock label="CLI command" value={command} copied={copied === `${title} command`} onCopy={() => onCopy(`${title} command`, command)} />
      <ConfigBlock label={configLabel} value={config} copied={copied === `${title} config`} onCopy={() => onCopy(`${title} config`, config)} multiline />
    </CardContent>
  </Card>
)

const ConfigBlock = ({ label, value, copied, onCopy, multiline = false }: { label: string; value: string; copied: boolean; onCopy: () => void; multiline?: boolean }) => (
  <div>
    <div className="mb-2 flex items-center justify-between gap-3">
      <span className="console-label">{label}</span>
      <button type="button" onClick={onCopy} className="flex items-center gap-1.5 rounded-lg px-2 py-1 text-[11px] text-slate-500 hover:bg-white/5 hover:text-cyan-200">
        {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}{copied ? 'Copied' : 'Copy'}
      </button>
    </div>
    <pre className={`overflow-x-auto rounded-xl border border-white/[0.07] bg-black/30 p-3 font-mono text-[11px] leading-5 text-slate-400 ${multiline ? 'max-h-52 whitespace-pre' : 'whitespace-pre-wrap break-all'}`}><code>{value}</code></pre>
  </div>
)

const StatusLine = ({ icon, label, value, good = false }: { icon: React.ReactNode; label: string; value: string; good?: boolean }) => (
  <div className="flex items-center gap-2.5">
    <span className={good ? 'text-emerald-400' : 'text-slate-500'}>{icon}</span>
    <span className="flex-1 text-slate-500">{label}</span>
    <span className="font-medium text-slate-200">{value}</span>
  </div>
)

export default IntegrationsPage
