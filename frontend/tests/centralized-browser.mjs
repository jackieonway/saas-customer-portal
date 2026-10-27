// Production bundle with explicit HTTP fixtures. This is a UI check, not HTTPS
// federation acceptance. Reuse the workspace's installed browser test runtime.
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile, mkdir, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const require = createRequire(path.resolve(root, '../../saas-identity/tests/package.json'))
const { chromium } = require('playwright-core')
const executablePath = process.env.IDENTITY_TEST_BROWSER_EXECUTABLE
assert(executablePath && path.isAbsolute(executablePath), 'Explicit installed Chromium executable required')
const output = path.join(root, 'artifacts', 'centralized-selection')
await mkdir(output, { recursive: true })
const id = n => `019a1163-0000-7000-8000-${n.toString(16).padStart(12, '0')}`
const account = { id: id(1), username: 'lin.yue', realName: '林悦', avatar: '' }
const context = { contractVersion: 'customer-profile/1', purpose: 'CUSTOMER_PROFILE', userId: id(1), membershipId: id(2), memberType: 'CUSTOMER', identityVersion: '1', accountVersion: '0', tenant: { id: id(3), name: '青禾商贸' }, organization: { id: id(4), name: '华东服务中心' }, application: { id: id(5), code: 'customer-profile', name: '客户资料', entryPath: '/api/customer/profile' } }
const session = { contractVersion: 'portal-session/1', version: '2', csrfToken: 'c'.repeat(64), centralizedContextSelection: true, account,
  memberships: [{ membershipId: id(2), userId: id(1), memberType: 'CUSTOMER', identityVersion: '1', organizationId: id(4), organizationName: context.organization.name, tenantId: id(3), tenantName: context.tenant.name }], context }
const posts = []
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost')
    res.setHeader('Cache-Control', 'no-store')
    if (url.pathname.startsWith('/auth/') || url.pathname === '/api/profile') {
      res.setHeader('Content-Type', 'application/json')
      if (url.pathname === '/auth/config') { res.end(JSON.stringify({ mode: 'BFF' })); return }
      if (url.pathname === '/auth/session') { res.end(JSON.stringify(session)); return }
      if (url.pathname === '/api/profile') { res.end(JSON.stringify({ context, account })); return }
      if (url.pathname === '/auth/login' && req.method === 'POST') {
        let raw = ''; for await (const chunk of req) raw += chunk
        assert.equal(req.headers['x-csrf-token'], session.csrfToken)
        posts.push({ path: url.pathname, body: JSON.parse(raw) })
        res.end(JSON.stringify({ redirectTo: 'https://auth.example.test/oidc/authorize' })); return
      }
      throw new Error('Unexpected local selection or credential endpoint')
    }
    const relative = url.pathname.startsWith('/assets/') && !url.pathname.includes('..') ? url.pathname.slice(1) : 'index.html'
    res.setHeader('Content-Type', relative.endsWith('.js') ? 'text/javascript' : relative.endsWith('.css') ? 'text/css' : 'text/html')
    res.end(await readFile(path.join(root, 'dist', relative)))
  } catch { res.statusCode = 500; res.end('fixture failure') }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
let browser
const checks = []
try {
  browser = await chromium.launch({ headless: true, executablePath, args: ['--no-proxy-server'] })
  for (const [name, viewport] of [['desktop', { width: 1440, height: 1080 }], ['mobile', { width: 390, height: 844 }]]) {
    const page = await browser.newPage({ viewport, reducedMotion: 'reduce' })
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    await page.route('https://auth.example.test/**', route => route.fulfill({ body: '<p>Identity fixture</p>', contentType: 'text/html' }))
    await page.goto(`http://127.0.0.1:${server.address().port}/`)
    await page.getByTestId('portal-profile').waitFor({ state: 'visible' })
    assert.equal(await page.getByTestId('portal-membership').count(), 0)
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    await page.screenshot({ path: path.join(output, `${name}.png`), fullPage: true })
    await page.getByTestId('portal-central-switch').click()
    await page.waitForURL('https://auth.example.test/oidc/authorize')
    assert.deepEqual(posts.at(-1), { path: '/auth/login', body: { returnTo: '/', expectedVersion: '2' } })
    assert.deepEqual(errors, [])
    checks.push({ name, status: 'passed' })
    await page.close()
  }
  await writeFile(path.join(output, 'report.json'), JSON.stringify({ status: 'passed', scope: 'Production bundle + explicit HTTP fixtures; no backend federation session', checks }, null, 2))
  console.log(JSON.stringify({ status: 'passed', checks: checks.length, output }))
} finally {
  if (browser) await browser.close()
  await new Promise(resolve => server.close(resolve))
}
