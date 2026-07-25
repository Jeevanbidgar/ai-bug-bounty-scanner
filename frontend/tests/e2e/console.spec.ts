import { expect, test } from '@playwright/test'

const deterministicPreferences = {
  state: {
    visualQuality: 'low',
    motion: 'reduced',
    immersiveVisuals: false,
    highContrast: false,
    sidebarCollapsed: false,
  },
  version: 0,
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript((preferences) => {
    localStorage.setItem('unihack-ui-preferences', JSON.stringify(preferences))
    localStorage.removeItem('unihack-notifications')
    localStorage.removeItem('unihack-workflow-draft-revisions')
  }, deterministicPreferences)
  await page.goto('/')
})

test('renders the native mission console without horizontal overflow', async ({ page }) => {
  await expect(page.getByRole('heading', { name: /security toolchain/i })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Mission topology' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'VM resource comparison' })).toBeVisible()
  await expect(page.getByText('Preview data active')).toBeVisible()

  const dimensions = await page.evaluate(() => ({
    bodyScrollWidth: document.body.scrollWidth,
    bodyClientWidth: document.body.clientWidth,
    rootScrollWidth: document.documentElement.scrollWidth,
    rootClientWidth: document.documentElement.clientWidth,
  }))
  expect(dimensions.bodyScrollWidth).toBeLessThanOrEqual(dimensions.bodyClientWidth)
  expect(dimensions.rootScrollWidth).toBeLessThanOrEqual(dimensions.rootClientWidth)
})

test('mission workflow selector renders a real label and launches an authorized run', async ({ page }) => {
  await page.getByRole('button', { name: 'Workflow template' }).click()
  await page.getByRole('option', { name: /Quick Bug Bounty/i }).click()
  await expect(page.getByRole('button', { name: 'Workflow template' })).toContainText('Quick Bug Bounty')
  await expect(page.getByRole('button', { name: 'Workflow template' })).not.toContainText('[object Object]')
  await page.getByLabel('Authorized domain').fill('example.com')
  await page.getByRole('checkbox', { name: /I confirm I own this target/i }).check()
  await page.getByRole('button', { name: 'Execute Workflow' }).click()
  await expect(page).toHaveURL(/\/scans$/)
})

test('workflow detail actions route to Studio and authorized launch', async ({ page }) => {
  await page.getByRole('button', { name: /Quick Bug Bounty.*All tools available/i }).click()
  const dialog = page.getByRole('dialog', { name: /Quick Bug Bounty/i })
  await expect(dialog.getByText('Workflow Steps')).toBeVisible()
  await dialog.getByRole('button', { name: 'Open in Workflow Studio' }).click()
  await expect(page).toHaveURL(/\/workflows\?workflow=quick-bug-bounty/)
})

test('command palette supports keyboard navigation', async ({ page }) => {
  await page.keyboard.press(process.platform === 'darwin' ? 'Meta+K' : 'Control+K')
  const dialog = page.getByRole('dialog', { name: 'UniHack command palette' })
  await expect(dialog).toBeVisible()
  await dialog.getByPlaceholder(/navigate or run/i).fill('workflow')
  await dialog.getByRole('button', { name: /open workflow studio/i }).click()
  await expect(page).toHaveURL(/\/workflows(?:\?workflow=[^&]+)?$/)
  await expect(page.getByRole('heading', { name: 'Workflow Studio' })).toBeVisible()
})

test('notification center records, reads, and clears local events', async ({ page }) => {
  const bell = page.getByRole('button', { name: /Notifications, 1 unread/i })
  await expect(bell).toBeVisible()
  await bell.click()

  const dialog = page.getByRole('dialog', { name: 'Notification center' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText('Preview environment active')).toBeVisible()
  await dialog.getByRole('button', { name: 'Mark read' }).click()
  await expect(page.getByRole('button', { name: 'Notifications', exact: true })).toBeVisible()
  await dialog.getByRole('button', { name: 'Clear notification history' }).click()
  await expect(dialog.getByText('All clear')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(dialog).toHaveCount(0)
})

test('command palette exposes adapters and refresh action', async ({ page }) => {
  await page.keyboard.press(process.platform === 'darwin' ? 'Meta+K' : 'Control+K')
  const dialog = page.getByRole('dialog', { name: 'UniHack command palette' })
  await expect(dialog).toBeVisible()
  await dialog.getByPlaceholder(/navigate or run/i).fill('adapter')
  await dialog.getByRole('button', { name: /open adapter contracts/i }).click()
  await expect(page).toHaveURL(/\/adapters$/)

  await page.keyboard.press(process.platform === 'darwin' ? 'Meta+K' : 'Control+K')
  await page.getByRole('dialog', { name: 'UniHack command palette' }).getByRole('button', { name: /refresh local state/i }).click()
  await expect(page.getByRole('dialog', { name: 'UniHack command palette' })).toHaveCount(0)
})

test('workflow studio exposes editable DAG and blocks unsafe draft execution', async ({ page }) => {
  await page.goto('/workflows')
  await expect(page.getByRole('heading', { name: 'Workflow Studio' })).toBeVisible()
  await expect(page.locator('.react-flow')).toBeVisible()
  await expect(page.locator('.react-flow__node')).toHaveCount(3)

  await page.locator('.react-flow__node').first().click()
  const displayName = page.getByLabel('Display name')
  await displayName.fill('Edited discovery step')
  await expect(page.getByText('Unsaved draft')).toBeVisible()
  await expect(page.getByRole('button', { name: /reset draft to run/i })).toBeDisabled()

  await page.getByRole('button', { name: 'Save revision' }).click()
  await expect(page.getByText('Saved local draft')).toBeVisible()
  await expect(page.getByRole('button', { name: /reset draft to run/i })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Restore draft' }).first()).toBeVisible()

  await page.getByRole('button', { name: /^Reset$/ }).click()
  await expect(page.getByText('Unsaved draft')).toHaveCount(0)
  await page.getByRole('button', { name: /3D preview/i }).click()
  await expect(page.locator('canvas')).toBeVisible()
})

test('workflow library supports outcome search and direct workflow links', async ({ page }) => {
  await page.goto('/workflows?workflow=network-recon')
  await expect(page.getByRole('heading', { name: 'Workflow Studio' })).toBeVisible()
  await expect(page.getByText('Enumerate ports, services, and network exposures').first()).toBeVisible()

  const library = page.getByRole('complementary', { name: 'Workflow library' })
  await library.getByRole('textbox', { name: 'Search workflow library' }).fill('archive')
  await expect(library.getByRole('button', { name: /Passive URL Discovery/i })).toBeVisible()
  await expect(library.getByRole('button', { name: /Quick Bug Bounty/i })).toHaveCount(0)
})

test('scan launcher guides workflow choice through authorization', async ({ page }) => {
  await page.goto('/scans')
  await page.getByRole('button', { name: 'Launch workflow' }).click()

  const launcher = page.getByRole('dialog', { name: 'Launch a packaged workflow' })
  await expect(launcher).toBeVisible()
  await expect(launcher.getByRole('button', { name: /Quick Bug Bounty/i })).toBeVisible()
  await expect(launcher.getByText('Tool chain')).toBeVisible()
  await expect(launcher.getByText('Subfinder', { exact: true })).toBeVisible()

  const launchButton = launcher.getByRole('button', { name: 'Authorize and launch' })
  await expect(launchButton).toBeDisabled()
  await launcher.getByRole('textbox', { name: 'Authorized target' }).fill('example.com')
  await launcher.getByRole('checkbox', { name: /Authorization confirmation/i }).check()
  await expect(launchButton).toBeEnabled()
  await launchButton.click()
  await expect(launcher).toHaveCount(0)
})

test('scan evidence, cancellation, rerun, and deletion controls complete their flows', async ({ page }) => {
  await page.goto('/scans')
  await page.getByRole('button', { name: 'Evidence' }).first().click()
  const details = page.getByRole('dialog', { name: /Scan Details: Acme perimeter review/i })
  await expect(details).toBeVisible()
  await expect(details.getByText(/STEP RUNNING/i)).toBeVisible()
  await details.getByRole('button', { name: 'Stop Scan' }).click()
  await expect(details.getByText('Cancelled').first()).toBeVisible()
  await details.getByRole('button', { name: 'Close scan details' }).click()

  await page.getByRole('button', { name: 'Rerun' }).first().click()
  await expect(page.getByRole('dialog', { name: 'Launch a packaged workflow' })).toBeVisible()
  await page.keyboard.press('Escape')

  await page.getByRole('button', { name: 'Delete API evidence sweep' }).click()
  const confirmation = page.getByRole('dialog', { name: 'Delete scan record?' })
  await confirmation.getByRole('button', { name: 'Delete record' }).click()
  await expect(page.getByText('API evidence sweep')).toHaveCount(0)
})

test('adapter catalog connects readiness, workflows, and structured argv', async ({ page }) => {
  await page.goto('/adapters')
  await expect(page.getByRole('heading', { name: 'Adaptive Tool Contracts' })).toBeVisible()
  await expect(page.getByText(/16\s*of 17 contracts/i)).toBeVisible()
  await expect(page.getByText(/2\s*local profiles/i)).toBeVisible()

  const catalog = page.getByRole('region', { name: 'Adapter catalog' })
  await catalog.getByRole('button', { name: /FFUF/i }).click()
  await expect(page.getByRole('heading', { name: 'FFUF' })).toBeVisible()
  await expect(page.getByText('https://example.com/FUZZ')).toBeVisible()
  await expect(page.getByText('<unihack-managed-web-wordlist>')).toBeVisible()
  await expect(page.getByText('argv · never a shell string')).toBeVisible()

  await catalog.getByRole('button', { name: /Rustscan/i }).click()
  await expect(page.getByText('85% inference confidence.')).toBeVisible()
  await expect(page.getByText('--addresses')).toBeVisible()

  await catalog.getByRole('button', { name: /Masscan/i }).click()
  await expect(page.getByText('55% inference confidence.')).toBeVisible()
  await expect(page.getByText(/requires review before command previews/i)).toBeVisible()
})

test('report generator explains local evidence formats and scan source', async ({ page }) => {
  await page.goto('/reports')
  await expect(page.getByRole('main').getByRole('heading', { name: 'Reports', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Generate report' }).first().click()

  const dialog = page.getByRole('dialog', { name: 'Generate a report' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText('Human-readable local review')).toBeVisible()
  await expect(dialog.getByText('Structured automation export')).toBeVisible()
  await expect(dialog.getByText('Compatible findings interchange')).toBeVisible()
  await expect(dialog.getByRole('button', { name: /Generate HTML/i })).toBeDisabled()
  await dialog.getByRole('button', { name: 'Close report generator' }).click()
  await expect(dialog).toHaveCount(0)
})

test('report generation, preview, and deletion operate on retained scans', async ({ page }) => {
  await page.goto('/reports')
  await page.getByRole('button', { name: 'Generate report' }).first().click()
  const generator = page.getByRole('dialog', { name: 'Generate a report' })
  await generator.getByRole('button', { name: 'Source scan' }).click()
  await generator.getByRole('option', { name: /Acme perimeter review/i }).click()
  await generator.getByLabel('Report title').fill('Acme evidence report')
  await generator.getByRole('button', { name: 'Generate HTML' }).click()

  const preview = page.getByRole('dialog', { name: 'Acme evidence report' })
  await expect(preview).toContainText('Target: example.com')
  await preview.getByRole('button', { name: 'Close report preview' }).click()
  await expect(page.getByRole('heading', { name: 'Acme evidence report' })).toBeVisible()
  await page.getByRole('button', { name: 'Delete Acme evidence report' }).click()
  await page.getByRole('dialog', { name: 'Delete this report?' }).getByRole('button', { name: 'Delete report' }).click()
  await expect(page.getByRole('heading', { name: 'Acme evidence report' })).toHaveCount(0)
})

test('manual tool registration works in browser preview without a native invoke failure', async ({ page }) => {
  await page.goto('/tools')
  await page.getByRole('button', { name: /Add Tool Manually/i }).click()
  await page.getByRole('button', { name: 'Add Tool', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: 'Add Manual Tool' })
  await dialog.getByLabel('Tool Name').fill('custom-scanner')
  await dialog.getByLabel('Tool Path').fill('/opt/tools/custom-scanner')
  await dialog.getByRole('button', { name: 'Add Tool', exact: true }).click()
  await expect(page.getByText('custom-scanner', { exact: true })).toBeVisible()
  page.once('dialog', (confirmation) => confirmation.accept())
  await page.getByRole('button', { name: 'Remove manual tool custom-scanner' }).click()
  await expect(page.getByText('custom-scanner', { exact: true })).toHaveCount(0)
})

test('tool refresh, updates, package managers, health check, and recheck are functional', async ({ page }) => {
  await page.goto('/tools')
  await page.getByRole('button', { name: 'Check Updates' }).click()
  await expect(page.getByText(/All 7 checked tool\(s\) are up to date/i)).toBeVisible()
  await page.getByRole('button', { name: 'Refresh Status' }).click()
  await expect(page.getByText(/Tools refreshed! Found 7 of 8 tools installed/i)).toBeVisible()

  await page.getByRole('button', { name: /Package Managers 3 of 4 package managers available/i }).click()
  await expect(page.locator('div.font-medium').filter({ hasText: /^Pipx$/ })).toBeVisible()

  await page.getByRole('button', { name: 'Open details for nmap' }).click()
  const details = page.getByRole('dialog', { name: 'nmap' })
  await details.getByRole('button', { name: 'Run Test Command' }).click()
  await expect(details.getByText(/nmap preview health check passed/i)).toBeVisible()
  await details.getByRole('button', { name: 'Recheck Status' }).click()
  await expect(page.getByText('nmap status checked')).toBeVisible()
  await details.getByRole('button', { name: 'Close tool details' }).click()

  await page.keyboard.press(process.platform === 'darwin' ? 'Meta+K' : 'Control+K')
  const palette = page.getByRole('dialog', { name: 'UniHack command palette' })
  await palette.getByPlaceholder(/navigate or run/i).fill('adapter')
  await palette.getByRole('button', { name: /open adapter contracts/i }).click()
  await expect(page.getByRole('heading', { name: 'Adaptive Tool Contracts' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Something went wrong' })).toHaveCount(0)
})

test('unknown routes recover through a functional fallback', async ({ page }) => {
  await page.goto('/module-that-does-not-exist')
  await expect(page.getByRole('heading', { name: 'Operation module not found' })).toBeVisible()
  await page.getByRole('button', { name: 'Return to Mission' }).click()
  await expect(page).toHaveURL(/\/$/)
  await expect(page.getByRole('heading', { name: /security toolchain/i })).toBeVisible()
})

test('visual settings persist accessible low-power controls', async ({ page }) => {
  await page.goto('/settings')
  await expect(page.getByRole('heading', { name: 'Runtime Settings' })).toBeVisible()
  await expect(page.getByLabel('3D quality')).toHaveValue('low')
  await expect(page.getByLabel('VM memory baseline')).toHaveValue('4096')
  await expect(page.getByText('Immersive topology')).toBeVisible()
  await expect(page.getByText('Reduced motion')).toBeVisible()
  await expect(page.getByText('High contrast')).toBeVisible()
})

test('runtime settings validate and save through the app bridge', async ({ page }) => {
  await page.goto('/settings')
  const parallelSteps = page.getByLabel('Maximum parallel steps')
  await parallelSteps.fill('5')
  await expect(page.getByText('Unsaved')).toBeVisible()
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByText('Unsaved')).toHaveCount(0)
  await page.getByRole('button', { name: /Notifications, 2 unread/i }).click()
  await expect(page.getByRole('dialog', { name: 'Notification center' }).getByText('Runtime settings saved')).toBeVisible()
})

test('readiness wizard keeps alternate runners explicit and disabled', async ({ page }) => {
  await page.goto('/readiness')
  await expect(page.getByRole('heading', { name: 'Native execution readiness' })).toBeVisible()
  await expect(page.getByText('100%')).toBeVisible()
  const runners = page.locator('section[aria-labelledby="runner-targets-title"]')
  await expect(runners.getByText('Native', { exact: true })).toBeVisible()
  await expect(runners.getByText('WSL', { exact: true })).toBeVisible()
  await expect(runners.getByText('Container', { exact: true })).toBeVisible()
  await expect(runners.getByText('No readiness result elevates privileges, installs a runner, or changes execution target automatically.')).toBeVisible()
})

test('tool catalog cards stay compact and keyboard accessible', async ({ page }) => {
  const consoleErrors: string[] = []
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text())
  })

  await page.goto('/tools')
  await expect(page.getByRole('heading', { name: 'Security Tools' })).toBeVisible()

  const cards = page.getByRole('button', { name: /open details for/i })
  await expect(cards).toHaveCount(8)
  await expect(cards.first()).toContainText('Installed')
  await expect(page.getByRole('button', { name: 'Open details for naabu' })).toContainText('Install options')

  const cardMetrics = await cards.evaluateAll((elements) => elements.map((element) => {
    const rect = element.getBoundingClientRect()
    return { height: rect.height, width: rect.width }
  }))
  expect(Math.max(...cardMetrics.map(({ height }) => height))).toBeLessThanOrEqual(260)
  expect(Math.max(...cardMetrics.map(({ height }) => height)) - Math.min(...cardMetrics.map(({ height }) => height))).toBeLessThanOrEqual(1)
  expect(cardMetrics.every(({ width }) => width >= 240)).toBeTruthy()

  await cards.first().focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('dialog', { name: 'nmap' })).toBeVisible()
  await expect.poll(() => consoleErrors).toEqual([])
})

test('tool catalog visual baseline @visual', async ({ page }, testInfo) => {
  test.skip(!['minimum-800x600', 'desktop-1440x900'].includes(testInfo.project.name), 'Representative visual baselines only')
  await page.goto('/tools')
  await expect(page.getByRole('heading', { name: 'Security Tools' })).toBeVisible()
  await page.evaluate(() => document.fonts.ready)
  await expect(page).toHaveScreenshot('tools.png', { fullPage: true })
})

test('desktop mission shell visual baseline @visual', async ({ page }, testInfo) => {
  test.skip(!['minimum-800x600', 'desktop-1440x900'].includes(testInfo.project.name), 'Representative visual baselines only')
  await expect(page.getByRole('heading', { name: /security toolchain/i })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Mission topology' })).toBeVisible()
  await expect(page.getByText('Selected module')).toBeVisible()
  await page.evaluate(() => document.fonts.ready)
  await expect(page).toHaveScreenshot('mission.png', { fullPage: true })
})
