import { defineConfig, devices } from '@playwright/test';

// A production build must exist. Own the server so a stale dev checkout cannot
// accidentally satisfy these acceptance tests.
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  workers: 2,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: { baseURL: 'http://127.0.0.1:43135', trace: 'retain-on-failure' },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
  webServer: {
    command: 'npm run start -- --hostname 127.0.0.1 --port 43135',
    url: 'http://127.0.0.1:43135',
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
