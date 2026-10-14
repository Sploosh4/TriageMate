import { test, expect } from '@playwright/test';

test('dashboard uses coded screens and displays missing evidence honestly', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
  await expect(page.getByText('No retained OS review for this inventory device')).toBeVisible();
  await expect(page.getByRole('button', { name: 'New page', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Source mode', exact: true })).toHaveCount(0);
});

test('SQL explorer runs read-only queries and preserves the draft across navigation', async ({
  page,
}) => {
  await page.goto('/#database');
  const editor = page.getByRole('textbox', { name: 'Database SQL' });
  await expect(editor).toBeVisible();
  await editor.fill('SELECT current_user::text AS reader, 42::integer AS answer;');
  await page.getByRole('button', { name: 'Run query', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'tm_mock_reader', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: '42', exact: true })).toBeVisible();
  await editor.fill('DELETE FROM evidence.computers;');
  await page.getByRole('button', { name: 'Run query', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText(/SELECT|read-only/i);
  await page.getByRole('link', { name: 'Dashboard', exact: true }).click();
  await page.getByRole('link', { name: 'Database', exact: true }).click();
  await expect(editor).toContainText('DELETE FROM evidence.computers;');
});

test('notification and application controls use ordinary screens', async ({ page }) => {
  await page.goto('/#notifications');
  await expect(page.getByRole('heading', { name: 'Notifications', exact: true })).toBeVisible();
  await expect(page.getByText('No collection notifications.')).toBeVisible();
  await page.getByRole('button', { name: 'Application', exact: true }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByRole('dialog')).toContainText('Off');
});

test('populated operational notices retain details and resolved dates stay unknown', async ({
  page,
}) => {
  await page.route('**/api/notifications', (route) =>
    route.fulfill({
      json: {
        notifications: [
          {
            id: 'synthetic-resolved',
            source: 'Synthetic source',
            input: 'collection-overdue',
            scope: 'Synthetic scope',
            status: 'resolved',
            urgency: 'high',
            startedAt: null,
            resolvedAt: null,
            failureCount: null,
            failures: [],
            message: 'Synthetic overdue episode recovered',
            details: {
              at: '2026-10-14T00:00:00Z',
              skipped_count: 2,
              known_bytes: '9007199254740993',
            },
          },
        ],
      },
    }),
  );
  await page.goto('/#notifications');
  await expect(page.getByText('Synthetic overdue episode recovered')).toBeVisible();
  await expect(page.getByText('2026-10-14T00:00:00Z')).toBeVisible();
  await expect(page.getByText('9007199254740993', { exact: true })).toBeVisible();
  await expect(page.getByText('Unresolved', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Unknown', { exact: true })).toHaveCount(2);
});

test('catalogue controls work and classification is a separate screen', async ({ page }) => {
  await page.goto('/#database');
  await page.getByRole('button', { name: 'Collapse database sidebar' }).click();
  await page.getByRole('button', { name: 'Show catalogue' }).click();
  await expect(page.getByRole('button', { name: 'Refresh catalogue' })).toBeVisible();
  await page.getByRole('textbox', { name: 'Database SQL' }).fill('SELECT 7;');
  await page.getByRole('button', { name: 'New database query' }).click();
  await expect(page.getByRole('textbox', { name: 'Database SQL' })).toContainText('current_user');
  await page.getByRole('button', { name: 'Classifications', exact: true }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
});
