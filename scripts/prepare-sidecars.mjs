import { execFileSync, spawnSync } from 'node:child_process'
import { chmodSync, copyFileSync, mkdirSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const repositoryRoot = resolve(scriptDirectory, '..')
const manifestPath = join(repositoryRoot, 'src-tauri', 'Cargo.toml')
const targetDirectory = join(repositoryRoot, 'src-tauri', 'target')
const outputDirectory = join(repositoryRoot, 'src-tauri', 'binaries')

function option(name) {
  const index = process.argv.indexOf(name)
  return index >= 0 ? process.argv[index + 1] : undefined
}

const target = option('--target') ?? execFileSync('rustc', ['--print', 'host-tuple'], {
  cwd: repositoryRoot,
  encoding: 'utf8',
}).trim()

if (!target || !/^[a-zA-Z0-9_.-]+$/.test(target)) {
  throw new Error(`Invalid Rust target triple: ${target || '<empty>'}`)
}

const extension = target.includes('windows') ? '.exe' : ''
const cargoArguments = [
  'build',
  '--manifest-path', manifestPath,
  '--locked',
  '--release',
  '--target', target,
  '--bin', 'unihackd',
  '--bin', 'unihack-mcp',
]
const build = spawnSync('cargo', cargoArguments, {
  cwd: repositoryRoot,
  encoding: 'utf8',
  env: {
    ...process.env,
    // This command produces the sidecars. Disable external-binary validation
    // for this Cargo invocation to avoid requiring its own outputs up front.
    TAURI_CONFIG: JSON.stringify({ bundle: { externalBin: [] } }),
  },
  stdio: 'inherit',
})

if (build.error) throw build.error
if (build.status !== 0) process.exit(build.status ?? 1)

mkdirSync(outputDirectory, { recursive: true })
for (const name of ['unihackd', 'unihack-mcp']) {
  const source = join(targetDirectory, target, 'release', `${name}${extension}`)
  const destination = join(outputDirectory, `${name}-${target}${extension}`)
  const sourceSize = statSync(source).size
  if (sourceSize === 0) throw new Error(`Refusing to bundle empty sidecar: ${source}`)
  copyFileSync(source, destination)
  if (!extension) chmodSync(destination, 0o755)
  process.stdout.write(`Prepared ${destination} (${sourceSize} bytes)\n`)
}
