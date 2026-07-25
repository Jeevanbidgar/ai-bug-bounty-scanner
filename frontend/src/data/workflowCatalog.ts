import type { WorkflowTemplate } from '../services/api'

export type WorkflowActivity = 'passive' | 'balanced' | 'active'
export type WorkflowTargetKind = 'domain' | 'host' | 'url'

export interface WorkflowCatalogEntry {
  intent: string
  targetKind: WorkflowTargetKind
  activity: WorkflowActivity
  duration: string
  evidence: string[]
  bestFor: string
  prerequisites?: string[]
  featured?: boolean
}

const catalog: Record<string, WorkflowCatalogEntry> = {
  'passive-url-discovery': {
    intent: 'Collect archived URLs without touching the target',
    targetKind: 'domain',
    activity: 'passive',
    duration: '2–10 min',
    evidence: ['URL inventory', 'Archive sources'],
    bestFor: 'Starting reconnaissance with the lowest target impact',
    featured: true,
  },
  'discovery-only': {
    intent: 'Map subdomains and exposed ports',
    targetKind: 'domain',
    activity: 'balanced',
    duration: '5–20 min',
    evidence: ['Subdomains', 'Open ports'],
    bestFor: 'Building an initial external attack-surface map',
  },
  'quick-bug-bounty': {
    intent: 'Find high-value web exposures quickly',
    targetKind: 'domain',
    activity: 'active',
    duration: '10–30 min',
    evidence: ['Subdomains', 'Services', 'Nuclei findings'],
    bestFor: 'A first authorized pass over a bug-bounty scope',
    featured: true,
  },
  'full-recon': {
    intent: 'Build a complete discover-to-validate pipeline',
    targetKind: 'domain',
    activity: 'active',
    duration: '20–60 min',
    evidence: ['Subdomains', 'Ports', 'Live URLs', 'Findings'],
    bestFor: 'Broad external reconnaissance with structured evidence',
  },
  'network-recon': {
    intent: 'Enumerate ports, services, and network exposures',
    targetKind: 'host',
    activity: 'active',
    duration: '15–45 min',
    evidence: ['Ports', 'Nmap XML', 'HTTP services', 'Findings'],
    bestFor: 'Authorized infrastructure and host assessments',
    featured: true,
  },
  'nuclei-only': {
    intent: 'Validate a URL with curated Nuclei templates',
    targetKind: 'url',
    activity: 'active',
    duration: '5–30 min',
    evidence: ['JSONL findings', 'Nuclei export'],
    bestFor: 'Fast, repeatable vulnerability checks against a known URL',
  },
  'web-application-scan': {
    intent: 'Discover content and validate web vulnerabilities',
    targetKind: 'domain',
    activity: 'active',
    duration: '30–90 min',
    evidence: ['Live URLs', 'Content paths', 'Findings'],
    bestFor: 'A deeper authorized web-application assessment',
    prerequisites: ['Uses UniHack’s managed web-path wordlist'],
  },
  'content-discovery': {
    intent: 'Compare two content-discovery engines',
    targetKind: 'url',
    activity: 'active',
    duration: '10–40 min',
    evidence: ['Gobuster paths', 'Feroxbuster JSONL'],
    bestFor: 'Finding hidden routes and files on a known web service',
    prerequisites: ['Uses UniHack’s managed web-path wordlist'],
  },
  'nikto-web-audit': {
    intent: 'Audit common web-server exposures and misconfiguration',
    targetKind: 'url',
    activity: 'active',
    duration: '10–30 min',
    evidence: ['Nikto JSON'],
    bestFor: 'A focused web-server configuration review',
  },
  'wordpress-assessment': {
    intent: 'Inspect an authorized WordPress deployment',
    targetKind: 'url',
    activity: 'active',
    duration: '10–30 min',
    evidence: ['WPScan JSON'],
    bestFor: 'WordPress component and exposure assessment',
    prerequisites: ['Vulnerability enrichment needs your WPScan API token'],
  },
  'xss-assessment': {
    intent: 'Validate reflected and DOM cross-site scripting',
    targetKind: 'url',
    activity: 'active',
    duration: '10–30 min',
    evidence: ['Dalfox JSON'],
    bestFor: 'Focused XSS testing of a known, authorized endpoint',
  },
  'api-security-scan': {
    intent: 'Discover API routes and test common API exposures',
    targetKind: 'url',
    activity: 'active',
    duration: '30–90 min',
    evidence: ['Endpoints', 'Service metadata', 'Findings', 'SQLMap results'],
    bestFor: 'Authorized API discovery and vulnerability validation',
  },
  'subdomain-takeover': {
    intent: 'Identify dangling DNS and takeover candidates',
    targetKind: 'domain',
    activity: 'active',
    duration: '15–45 min',
    evidence: ['Subdomains', 'Takeover findings', 'DNS findings'],
    bestFor: 'Validating takeover risk across an owned domain',
  },
  'cloud-security-scan': {
    intent: 'Detect exposed cloud services and misconfiguration',
    targetKind: 'domain',
    activity: 'active',
    duration: '20–60 min',
    evidence: ['Cloud services', 'Storage findings', 'Container findings'],
    bestFor: 'External cloud-exposure triage',
  },
  'comprehensive-audit': {
    intent: 'Run the broadest packaged security assessment',
    targetKind: 'domain',
    activity: 'active',
    duration: '1–3 hours',
    evidence: ['Asset map', 'Network evidence', 'Web evidence', 'Findings'],
    bestFor: 'Planned, explicitly authorized deep assessments',
    prerequisites: ['Highest request volume and longest runtime'],
  },
}

const fallback: WorkflowCatalogEntry = {
  intent: 'Run a packaged, repeatable security procedure',
  targetKind: 'domain',
  activity: 'active',
  duration: 'Varies',
  evidence: ['Workflow artifacts'],
  bestFor: 'Repeatable authorized testing',
}

export const getWorkflowCatalogEntry = (workflow: Pick<WorkflowTemplate, 'id' | 'category'>) => {
  const entry = catalog[workflow.id]
  if (entry) return entry

  return {
    ...fallback,
    activity: workflow.category.toLowerCase().includes('recon') ? 'balanced' as const : fallback.activity,
  }
}

export const workflowActivityStyles: Record<WorkflowActivity, string> = {
  passive: 'border-emerald-400/20 bg-emerald-400/[0.07] text-emerald-200',
  balanced: 'border-cyan-400/20 bg-cyan-400/[0.07] text-cyan-200',
  active: 'border-amber-400/20 bg-amber-400/[0.07] text-amber-200',
}

export const getTargetPlaceholder = (kind: WorkflowTargetKind) => {
  if (kind === 'url') return 'https://app.example.com'
  if (kind === 'host') return '192.0.2.10 or authorized CIDR'
  return 'example.com'
}

export const formatToolName = (tool: string) => {
  if (tool.toLowerCase() === 'httpx') return 'HTTPX'
  if (tool.toLowerCase() === 'gau') return 'GAU'
  return tool.charAt(0).toUpperCase() + tool.slice(1)
}
