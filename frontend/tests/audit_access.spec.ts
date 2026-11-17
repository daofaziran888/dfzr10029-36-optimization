import { expect, test } from '@playwright/test'

test('审计：用户组授权、差异脱敏、清单追溯与导出', async ({ page }) => {
  test.setTimeout(120_000)
  const errors: string[] = []
  page.on('pageerror', e => errors.push(e.message))

  await page.goto('/audit')
  await expect(page.getByTestId('audit-group')).toBeVisible()

  // 审计员全量视图：至少能看到 3 条示例记录，且原始差异不被裁剪
  await expect(page.locator('tbody tr[data-testid="row-2"]')).toHaveCount(1)
  await expect(page.locator('tbody tr[data-testid="row-3"]')).toHaveCount(1)
  await expect(page.locator('tbody tr[data-testid="row-1"]')).toContainText('3 项原始差异')

  // 切到组1：只按当前用户组可见 2 条，差异被脱敏
  await page.getByTestId('audit-group').selectOption('分析用户组样例1')
  await expect(page.locator('tbody tr[data-testid^="row-"]')).toHaveCount(2)
  await expect(page.locator('tbody tr[data-testid="row-2"]')).toHaveCount(0)
  await expect(page.locator('tbody tr[data-testid="row-1"]')).toContainText('2 个变更字段因用户组授权已脱敏')

  // 差异弹窗只显示可读字段
  await page.getByTestId('diff-1').click()
  await expect(page.getByTestId('diff-modal')).toBeVisible()
  await expect(page.getByTestId('diff-item')).toHaveCount(1)
  await expect(page.getByTestId('diff-modal')).toContainText('口径版本')
  await expect(page.getByTestId('diff-modal')).not.toContainText('sum(amount)')
  await expect(page.getByTestId('diff-modal')).toContainText('已审计通过')
  await page.getByTestId('close-diff').click()

  // 导出 CSV 不含脱敏原值
  const downloadPromise = page.waitForEvent('download')
  await page.getByTestId('export').click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toBe('audit.csv')
  const path = await download.path()
  const text = await (await import('node:fs/promises')).readFile(path!, 'utf-8')
  expect(text).toContain('AUDI-0001')
  expect(text).not.toContain('sum(amount)')
  expect(text).not.toContain('旧指标名称')
  expect(text).not.toContain('AUDI-0002')
  expect(text).toContain('已审计通过')

  // 切到组3：AUDI-0002 不可见，AUDI-0001 越权差异无法打开
  await page.getByTestId('audit-group').selectOption('分析用户组样例3')
  await expect(page.locator('tbody tr[data-testid^="row-"]')).toHaveCount(1)
  await expect(page.locator('tbody tr[data-testid="row-1"]')).toHaveCount(0)

  // 按操作人归属：组1只看到 AUDI-0001
  await page.getByTestId('audit-mode').selectOption('operator')
  await page.getByTestId('audit-group').selectOption('分析用户组样例1')
  await expect(page.locator('tbody tr[data-testid^="row-"]')).toHaveCount(1)
  await expect(page.locator('tbody tr[data-testid="row-1"]')).toContainText('2 个变更字段因用户组授权已脱敏')

  // 只读用户：动作与登记被禁用
  await page.getByTestId('audit-role').selectOption('viewer')
  await expect(page.getByTestId('open-create')).toBeDisabled()
  await expect(page.getByTestId('action-1-提交审计')).toBeDisabled()

  // 审计员打开脱敏清单并追溯来源
  await page.getByTestId('audit-role').selectOption('auditor')
  await page.getByTestId('audit-mode').selectOption('group')
  await page.getByTestId('open-redactions').click()
  await expect(page.getByTestId('redaction-panel')).toBeVisible()
  await page.getByTestId('lineage-1').click()
  await expect(page.getByTestId('redaction-lineage')).toContainText('AUDI-0001')

  expect(errors).toEqual([])
})
