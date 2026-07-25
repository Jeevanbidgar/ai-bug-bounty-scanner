import { defineConfig } from '@playwright/test'

const baseURL = 'http://127.0.0.1:43127'

export default defineConfig({
  testDir: './tests/e2e',
  outputDir: './test-results',
  snapshotPathTemplate: '{testDir}/{testFilePath}-snapshots/{arg}-{projectName}{ext}',
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  expect: {
    timeout: 8_000,
    toHaveScreenshot: {
      animations: 'disabled',
      caret: 'hide',
      maxDiffPixelRatio: 0.015,
    },
  },
  use: {
    baseURL,
    colorScheme: 'dark',
    locale: 'en-US',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'minimum-800x600', use: { viewport: { width: 800, height: 600 } } },
    { name: 'compact-1024x768', use: { viewport: { width: 1024, height: 768 } } },
    { name: 'desktop-1440x900', use: { viewport: { width: 1440, height: 900 } } },
    { name: 'wide-1920x1080', use: { viewport: { width: 1920, height: 1080 } } },
    { name: 'uhd-3840x2160', use: { viewport: { width: 3840, height: 2160 } } },
  ],
  webServer: {
    command: 'npm run dev -- --host 127.0.0.1 --port 43127',
    url: baseURL,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
