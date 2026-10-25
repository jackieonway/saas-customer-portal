import test from 'node:test'
import assert from 'node:assert/strict'
import { createApi, HttpError } from '../src/api.ts'
import { PortalController } from '../src/controller.ts'
import { CHANGE_MESSAGE, isChangeMessage, parseProfile, parseRedirect, parseSession, ProtocolError } from '../src/protocol.ts'

const ids = {
  user: '019a1b60-0000-7000-8000-000000000001',
  otherUser: '019a1b60-0000-7000-8000-000000000002',
  member: '019a1b60-0000-7000-8000-000000000003',
  otherMember: '019a1b60-0000-7000-8000-000000000004',
  org: '019a1b60-0000-7000-8000-000000000005',
  otherOrg: '019a1b60-0000-7000-8000-000000000006',
  tenant: '019a1b60-0000-7000-8000-000000000007',
  app: '019a1b60-0000-7000-8000-000000000008',
}

function member(overrides = {}) {
  return {
    membershipId: ids.member, userId: ids.user, memberType: 'CUSTOMER', identityVersion: '1',
    organizationId: ids.org, organizationName: '本人所属组织', tenantId: ids.tenant, tenantName: '本人所属租户',
    ...overrides,
  }
}

function session(overrides = {}) {
  return {
    contractVersion: 'portal-session/1', version: '1', csrfToken: 'fixture-memory-only-csrf',
    account: { id: ids.user, username: 'owned-customer', realName: '本人', avatar: '' },
    memberships: [member()],
    context: {
      contractVersion: 'customer-profile/1', purpose: 'CUSTOMER_PROFILE', userId: ids.user,
      membershipId: ids.member, memberType: 'CUSTOMER', identityVersion: '1', accountVersion: '1',
      tenant: { id: ids.tenant, name: '本人所属租户' }, organization: { id: ids.org, name: '本人所属组织' },
      application: { id: ids.app, code: 'owned-portal', name: '客户本人资料', entryPath: '/api/customer/profile' },
    },
    ...overrides,
  }
}

function anonymous() {
  return session({ version: '0', account: null, memberships: [], context: null })
}

function profile(value = session()) {
  return { context: value.context, account: value.account }
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

function harness(overrides = {}, options = {}) {
  const calls = { login: 0, bootstrap: 0, profile: 0, selection: [], logout: [], broadcast: [], navigation: [] }
  const api = {
    configuration: async () => {},
    session: async () => session(),
    loginBootstrap: async () => { calls.bootstrap += 1; return anonymous() },
    profile: async (value) => { calls.profile += 1; return profile(value) },
    select: async (value, membershipId) => {
      calls.selection.push(membershipId)
      return { ...value, version: String(BigInt(value.version) + 1n) }
    },
    logout: async (_value, scope) => { calls.logout.push(scope); return '/signed-out' },
    login: async () => { calls.login += 1; return 'https://auth.owned.test/oauth/authorize' },
    ...overrides,
  }
  const controller = new PortalController(api, {
    navigate: (url) => calls.navigation.push(url), broadcast: (message) => calls.broadcast.push(message),
  }, options)
  return { controller, api, calls }
}

test('valid self profile is bound to the complete selected customer identity', () => {
  const value = parseSession(session())
  assert.deepEqual(parseProfile(profile(), value), profile())
})

test('initial account generation zero completes explicit selection and self-profile transport', async () => {
  const selected = session({ version: '2', context: { ...session().context, accountVersion: '0' } })
  const requests = []
  const api = createApi(async (path, init) => {
    requests.push({ path, init })
    if (path === '/auth/config') return json({ mode: 'BFF' })
    if (path === '/auth/session') return json(session({ context: null }))
    if (path === '/auth/context') return json(selected)
    if (path === '/api/profile') return json(profile(selected))
    throw new Error('Unexpected request')
  })
  const broadcasts = []
  const controller = new PortalController(api, { navigate: () => {}, broadcast: (message) => broadcasts.push(message) })
  await controller.reload()
  assert.equal(controller.getSnapshot().session.context, null)
  await controller.select(ids.member)
  assert.equal(controller.getSnapshot().status, 'ready')
  assert.equal(controller.getSnapshot().session.version, '2')
  assert.equal(controller.getSnapshot().profile.context.accountVersion, '0')
  assert.deepEqual(requests.map(({ path }) => path), ['/auth/config', '/auth/session', '/auth/context', '/api/profile'])
  assert.deepEqual(JSON.parse(requests[2].init.body), { expectedVersion: '1', membershipId: ids.member })
  assert.deepEqual(broadcasts, [CHANGE_MESSAGE])
})

test('account generations accept canonical nonnegative i64 while session and identity generations remain positive', () => {
  for (const accountVersion of ['0', '1', '9223372036854775807']) {
    const value = session({ context: { ...session().context, accountVersion } })
    assert.equal(parseProfile(profile(value), parseSession(value)).context.accountVersion, accountVersion)
  }
  for (const accountVersion of ['-1', '00', '01', '+0', ' 0', '0.0', 0, '9223372036854775808']) {
    assert.throws(() => parseSession(session({ context: { ...session().context, accountVersion } })), ProtocolError)
  }
  assert.throws(() => parseSession(session({ version: '0' })), ProtocolError)
  assert.throws(() => parseSession(session({ memberships: [member({ identityVersion: '0' })] })), ProtocolError)
})

test('self profile rejects a changed account generation after a zero-generation selection', () => {
  const value = session({ context: { ...session().context, accountVersion: '0' } })
  const current = parseSession(value)
  assert.throws(() => parseProfile({ ...profile(value), context: { ...value.context, accountVersion: '1' } }, current), ProtocolError)
})

test('anonymous CSRF bootstrap has version zero and cannot carry identity or profile', () => {
  assert.equal(parseSession(anonymous()).account, null)
  assert.throws(() => parseSession({ ...anonymous(), version: '1' }), ProtocolError)
  assert.throws(() => parseSession({ ...anonymous(), memberships: [member()] }), ProtocolError)
  assert.throws(() => parseSession({ ...anonymous(), context: session().context }), ProtocolError)
})

test('employee rows, foreign-account rows, duplicate membership IDs and non-v7 IDs are rejected', () => {
  for (const memberships of [
    [member({ memberType: 'EMPLOYEE' })], [member({ userId: ids.otherUser })],
    [member(), member()], [member({ membershipId: '019a1b60-0000-4000-8000-000000000003' })],
  ]) assert.throws(() => parseSession(session({ memberships })), ProtocolError)
})

test('session context cannot cross membership, organization, tenant or identity version', () => {
  const current = session()
  for (const change of [
    { membershipId: ids.otherMember }, { userId: ids.otherUser }, { memberType: 'EMPLOYEE' },
    { identityVersion: '2' }, { organization: { id: ids.otherOrg, name: 'other' } },
    { tenant: { id: ids.org, name: 'other' } },
  ]) assert.throws(() => parseSession(session({ context: { ...current.context, ...change } })), ProtocolError)
})

test('profile cannot cross subject, account version, client application or profile purpose', () => {
  const current = parseSession(session())
  const original = profile()
  const altered = [
    { ...original, account: { ...original.account, id: ids.otherUser } },
    { ...original, context: { ...original.context, accountVersion: '2' } },
    { ...original, context: { ...original.context, application: { ...original.context.application, code: 'admin' } } },
    { ...original, context: { ...original.context, purpose: 'EMPLOYEE_CONTEXT' } },
  ]
  for (const value of altered) assert.throws(() => parseProfile(value, current), ProtocolError)
})

test('only HTTPS login redirects without embedded credentials or fragments are allowed', () => {
  assert.equal(parseRedirect({ redirectTo: 'https://auth.owned.test/oauth/authorize?state=opaque' }), 'https://auth.owned.test/oauth/authorize?state=opaque')
  for (const redirectTo of ['javascript:alert(1)', 'http://auth.owned.test/', 'https://user:pass@auth.owned.test/', 'https://auth.owned.test/#fragment']) {
    assert.throws(() => parseRedirect({ redirectTo }))
  }
})

test('cross-tab payload accepts exactly two metadata fields and rejects credential-like additions', () => {
  assert.equal(isChangeMessage(CHANGE_MESSAGE), true)
  for (const value of [null, [], 'changed', { ...CHANGE_MESSAGE, account: ids.user }, { ...CHANGE_MESSAGE, token: 'forbidden' }, { type: 'other', contractVersion: 1 }]) {
    assert.equal(isChangeMessage(value), false)
  }
})

test('anonymous load does not request profile or trigger login automatically', async () => {
  const { controller, calls } = harness({ session: async () => anonymous() })
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'signed-out')
  assert.equal(calls.profile, 0)
  assert.equal(calls.login, 0)
  assert.equal(calls.bootstrap, 0)
})

test('employee-only account remains authenticated with no customer selection or profile', async () => {
  const { controller, calls } = harness({ session: async () => session({ memberships: [], context: null }) })
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'ready')
  assert.equal(controller.getSnapshot().session.memberships.length, 0)
  assert.equal(controller.getSnapshot().profile, null)
  assert.equal(calls.profile, 0)
})

test('a customer identity is never selected automatically, even when only one is available', async () => {
  const { controller, calls } = harness({ session: async () => session({ context: null }) })
  await controller.reload()
  assert.equal(controller.getSnapshot().session.context, null)
  assert.deepEqual(calls.selection, [])
  assert.equal(calls.profile, 0)
})

test('load publishes identity and self profile only after the complete proof succeeds', async () => {
  const pending = deferred()
  const { controller } = harness({ profile: async () => pending.promise })
  const operation = controller.reload()
  await Promise.resolve()
  await Promise.resolve()
  assert.equal(controller.getSnapshot().profile, null)
  assert.equal(controller.getSnapshot().session, null)
  pending.resolve(profile())
  await operation
  assert.equal(controller.getSnapshot().profile.account.id, ids.user)
})

test('401 during self-profile proof clears every identity and waits for explicit unified login', async () => {
  const { controller, calls } = harness({ profile: async () => { throw new HttpError(401) } })
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'signed-out')
  assert.equal(controller.getSnapshot().session, null)
  assert.equal(controller.getSnapshot().profile, null)
  assert.equal(calls.login, 0)
  assert.equal(calls.bootstrap, 0)
})

for (const status of [401, 409]) {
  test(`profile proof reconciliation reads the latest cross-tab identity once after ${status}`, async () => {
    const original = session()
    const switched = session({
      version: '2',
      memberships: [member(), member({ membershipId: ids.otherMember, organizationId: ids.otherOrg })],
      context: { ...original.context, membershipId: ids.otherMember, organization: { id: ids.otherOrg, name: '另一个客户组织' } },
    })
    const requests = [], published = []
    let sessionCalls = 0, profileCalls = 0
    const api = createApi(async (path, init) => {
      requests.push({ path, method: init.method })
      if (path === '/auth/config') return json({ mode: 'BFF' })
      if (path === '/auth/session') return json(++sessionCalls === 1 ? original : switched)
      if (path === '/api/profile') return ++profileCalls === 1 ? json({}, status) : json(profile(switched))
      throw new Error('Unexpected mutation during read reconciliation')
    })
    const controller = new PortalController(api, { navigate: () => assert.fail('No automatic navigation'), broadcast: () => assert.fail('No read broadcast') })
    controller.subscribe(() => published.push(controller.getSnapshot()))
    await controller.reload()
    assert.equal(controller.getSnapshot().status, 'ready')
    assert.equal(controller.getSnapshot().session.version, '2')
    assert.equal(controller.getSnapshot().profile.context.membershipId, ids.otherMember)
    assert.deepEqual(requests, ['/auth/config', '/auth/session', '/api/profile', '/auth/session', '/api/profile'].map((path) => ({ path, method: 'GET' })))
    assert.equal(published.some((state) => state.profile?.context.membershipId === ids.member), false)
  })
}

test('profile proof reconciliation also handles a rotated server capability with an unchanged public version', async () => {
  let sessionCalls = 0, profileCalls = 0
  const { controller, calls } = harness({
    session: async () => { sessionCalls += 1; return session() },
    profile: async (value) => { if (++profileCalls === 1) throw new HttpError(401); return profile(value) },
  })
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'ready')
  assert.equal(sessionCalls, 2)
  assert.equal(profileCalls, 2)
  assert.equal(controller.getSnapshot().session.version, '1')
  assert.deepEqual(calls.selection, [])
  assert.deepEqual(calls.logout, [])
  assert.equal(calls.login, 0)
})

test('profile proof reconciliation is bounded and persistent invalid credentials stay signed out', async () => {
  for (const failureAt of ['session', 'profile']) {
    let sessionCalls = 0, profileCalls = 0
    const { controller, calls } = harness({
      session: async () => { if (++sessionCalls === 2 && failureAt === 'session') throw new HttpError(401); return session() },
      profile: async () => { profileCalls += 1; throw new HttpError(401) },
    })
    await controller.reload()
    assert.equal(controller.getSnapshot().status, 'signed-out')
    assert.equal(controller.getSnapshot().profile, null)
    assert.equal(controller.getSnapshot().session, null)
    assert.equal(sessionCalls, 2)
    assert.equal(profileCalls, failureAt === 'session' ? 1 : 2)
    assert.equal(calls.login, 0)
    assert.equal(calls.bootstrap, 0)
    assert.deepEqual(calls.selection, [])
    assert.deepEqual(calls.logout, [])
  }
})

test('profile proof reconciliation never retries dependency failures, forbidden access, or malformed proof', async () => {
  for (const error of [new HttpError(403), new HttpError(503), new ProtocolError()]) {
    let sessionCalls = 0, profileCalls = 0
    const { controller } = harness({
      session: async () => { sessionCalls += 1; return session() },
      profile: async () => { profileCalls += 1; throw error },
    })
    await controller.reload()
    assert.equal(sessionCalls, 1)
    assert.equal(profileCalls, 1)
    assert.equal(controller.getSnapshot().profile, null)
    assert.equal(controller.getSnapshot().session, null)
    assert.equal(controller.getSnapshot().status, error instanceof HttpError ? error.status === 403 ? 'forbidden' : 'unavailable' : 'error')
  }
})

test('profile proof reconciliation cannot republish data after a newer logout or hidden-page fence', async () => {
  const entered = deferred(), pending = deferred()
  let sessionCalls = 0, reconciliationSignal
  const { controller } = harness({
    session: async (signal) => {
      if (++sessionCalls === 2) { reconciliationSignal = signal; entered.resolve(); return pending.promise }
      return sessionCalls === 1 ? session() : anonymous()
    },
    profile: async () => { throw new HttpError(401) },
  })
  const older = controller.reload()
  await entered.promise
  assert.equal(controller.getSnapshot().profile, null)
  controller.suspend()
  assert.equal(reconciliationSignal.aborted, true)
  await controller.reload()
  pending.resolve(session({ version: '2' }))
  await older
  assert.equal(controller.getSnapshot().status, 'signed-out')
  assert.equal(controller.getSnapshot().profile, null)
  assert.equal(controller.getSnapshot().session.account, null)
})

test('profile proof reconciliation after explicit selection does not replay the mutation', async () => {
  let sessionCalls = 0, profileCalls = 0
  const selected = session({ version: '2' })
  const { controller, api, calls } = harness({
    session: async () => ++sessionCalls === 1 ? session({ context: null }) : selected,
    profile: async (value) => { if (++profileCalls === 1) throw new HttpError(401); return profile(value) },
  })
  api.select = async (_value, membershipId) => { calls.selection.push(membershipId); return selected }
  await controller.reload()
  await controller.select(ids.member)
  assert.equal(controller.getSnapshot().status, 'ready')
  assert.equal(controller.getSnapshot().session.version, '2')
  assert.deepEqual(calls.selection, [ids.member])
  assert.deepEqual(calls.broadcast, [CHANGE_MESSAGE])
  assert.equal(calls.login, 0)
  assert.deepEqual(calls.logout, [])
})

for (const status of [401, 409]) {
  test(`bounded profile reconciliation waits through a session lease after profile ${status}`, async () => {
    const original = session()
    const membership = member({ membershipId: ids.otherMember, organizationId: ids.otherOrg })
    const switched = session({ version: '2', memberships: [membership], context: { ...original.context, membershipId: ids.otherMember, organization: { id: ids.otherOrg, name: membership.organizationName } } })
    const requests = [], published = []
    let sessionCalls = 0, profileCalls = 0
    const api = createApi(async (path, init) => {
      requests.push({ path, method: init.method })
      if (path === '/auth/config') return json({ mode: 'BFF' })
      if (path === '/auth/session') {
        sessionCalls += 1
        return sessionCalls === 1 ? json(original) : sessionCalls === 2 ? json({}, 503) : json(switched)
      }
      if (path === '/api/profile') return ++profileCalls === 1 ? json({}, status) : json(profile(switched))
      throw new Error('Unexpected mutation during read reconciliation')
    })
    const controller = new PortalController(api, { navigate: () => assert.fail('No automatic navigation'), broadcast: () => assert.fail('No read broadcast') })
    controller.subscribe(() => published.push(controller.getSnapshot()))
    await controller.reload()
    assert.equal(controller.getSnapshot().status, 'ready')
    assert.equal(controller.getSnapshot().session.version, '2')
    assert.equal(controller.getSnapshot().profile.context.membershipId, ids.otherMember)
    assert.deepEqual(requests, ['/auth/config', '/auth/session', '/api/profile', '/auth/session', '/auth/session', '/api/profile'].map((path) => ({ path, method: 'GET' })))
    assert.equal(published.some((state) => state.profile?.context.membershipId === ids.member), false)
  })
}

test('bounded profile reconciliation permits only three authority reads before a fresh bound profile', async () => {
  let sessionCalls = 0, profileCalls = 0
  const { controller, calls } = harness({
    session: async () => {
      sessionCalls += 1
      if (sessionCalls === 2 || sessionCalls === 3) throw new HttpError(503)
      return session({ version: sessionCalls === 1 ? '1' : '2' })
    },
    profile: async (value) => { if (++profileCalls === 1) throw new HttpError(409); return profile(value) },
  })
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'ready')
  assert.equal(controller.getSnapshot().session.version, '2')
  assert.equal(sessionCalls, 4)
  assert.equal(profileCalls, 2)
  assert.equal(calls.login, 0)
  assert.equal(calls.bootstrap, 0)
  assert.deepEqual(calls.selection, [])
  assert.deepEqual(calls.logout, [])
})

test('bounded profile reconciliation fails closed after persistent authority 503 and removes old data', async () => {
  let sessionCalls = 0, reconciling = false
  const published = []
  const { controller, calls } = harness({
    session: async () => { sessionCalls += 1; if (reconciling && sessionCalls > 2) throw new HttpError(503); return session() },
    profile: async (value) => { if (reconciling) throw new HttpError(401); return profile(value) },
  })
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'ready')
  controller.subscribe(() => published.push(controller.getSnapshot()))
  reconciling = true
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'unavailable')
  assert.equal(controller.getSnapshot().session, null)
  assert.equal(controller.getSnapshot().profile, null)
  assert.equal(sessionCalls, 5)
  assert.equal(published.every((state) => state.session === null && state.profile === null), true)
  assert.equal(calls.login, 0)
  assert.equal(calls.bootstrap, 0)
  assert.deepEqual(calls.selection, [])
  assert.deepEqual(calls.logout, [])
  assert.deepEqual(calls.broadcast, [])
  assert.deepEqual(calls.navigation, [])
})

test('bounded profile reconciliation does not retry ordinary initial session 503', async () => {
  let sessionCalls = 0
  const { controller, calls } = harness({ session: async () => { sessionCalls += 1; throw new HttpError(503) } })
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'unavailable')
  assert.equal(sessionCalls, 1)
  assert.equal(calls.profile, 0)
  assert.equal(calls.login, 0)
  assert.equal(calls.bootstrap, 0)
})

test('bounded profile reconciliation never retries other authority errors or a second profile failure', async () => {
  for (const failureAt of ['session', 'profile']) {
    for (const error of [new HttpError(401), new HttpError(403), new HttpError(409), new HttpError(503), new ProtocolError()]) {
      if (failureAt === 'session' && error instanceof HttpError && error.status === 503) continue
      let sessionCalls = 0, profileCalls = 0
      const { controller } = harness({
        session: async () => { if (++sessionCalls > 1 && failureAt === 'session') throw error; return session() },
        profile: async () => { if (++profileCalls === 1) throw new HttpError(401); throw error },
      })
      await controller.reload()
      assert.equal(sessionCalls, 2)
      assert.equal(profileCalls, failureAt === 'session' ? 1 : 2)
      assert.equal(controller.getSnapshot().profile, null)
      assert.equal(controller.getSnapshot().session, null)
      assert.equal(controller.getSnapshot().status, error instanceof HttpError ? error.status === 401 ? 'signed-out' : error.status === 403 ? 'forbidden' : error.status === 503 ? 'unavailable' : 'error' : 'error')
    }
  }
})

test('bounded profile reconciliation dispatches no retry after a slow authority failure exhausts its budget', async (t) => {
  let now = 0, sessionCalls = 0, profileCalls = 0
  t.mock.method(globalThis.performance, 'now', () => now)
  const { controller } = harness({
    session: async () => { if (++sessionCalls > 1) { now = 500; throw new HttpError(503) } return session() },
    profile: async () => { profileCalls += 1; throw new HttpError(401) },
  })
  await controller.reload()
  assert.equal(sessionCalls, 2)
  assert.equal(profileCalls, 1)
  assert.equal(controller.getSnapshot().status, 'unavailable')
  assert.equal(controller.getSnapshot().profile, null)
})

test('bounded profile reconciliation dispatches no request when its backoff reaches the deadline', async (t) => {
  let now = 0, sessionCalls = 0, profileCalls = 0
  const delays = []
  const realSetTimeout = globalThis.setTimeout
  t.mock.method(globalThis.performance, 'now', () => now)
  t.mock.method(globalThis, 'setTimeout', (callback, delay) => {
    delays.push(delay)
    return realSetTimeout(() => { now = 500; callback() }, 0)
  })
  const { controller } = harness({
    session: async () => { if (++sessionCalls > 1) { now = 450; throw new HttpError(503) } return session() },
    profile: async () => { profileCalls += 1; throw new HttpError(401) },
  })
  await controller.reload()
  assert.deepEqual(delays, [50])
  assert.equal(sessionCalls, 2)
  assert.equal(profileCalls, 1)
  assert.equal(controller.getSnapshot().status, 'unavailable')
})

test('bounded profile reconciliation never dispatches a profile for authority material arriving after its budget', async (t) => {
  let now = 0, sessionCalls = 0, profileCalls = 0
  t.mock.method(globalThis.performance, 'now', () => now)
  const { controller } = harness({
    session: async () => { if (++sessionCalls > 1) now = 500; return session() },
    profile: async (value) => { if (++profileCalls === 1) throw new HttpError(401); return profile(value) },
  })
  await controller.reload()
  assert.equal(sessionCalls, 2)
  assert.equal(profileCalls, 1)
  assert.equal(controller.getSnapshot().status, 'unavailable')
  assert.equal(controller.getSnapshot().session, null)
  assert.equal(controller.getSnapshot().profile, null)
})

test('bounded profile reconciliation aborts its wait without a later authority dispatch', async (t) => {
  const waiting = deferred()
  const realSetTimeout = globalThis.setTimeout
  const realClearTimeout = globalThis.clearTimeout
  let sessionCalls = 0, reconciliationSignal, cleared = 0
  t.mock.method(globalThis, 'setTimeout', (callback, delay) => { waiting.resolve(delay); return realSetTimeout(callback, delay) })
  t.mock.method(globalThis, 'clearTimeout', (timer) => { cleared += 1; return realClearTimeout(timer) })
  const { controller } = harness({
    session: async (signal) => { if (++sessionCalls > 1) { reconciliationSignal = signal; throw new HttpError(503) } return session() },
    profile: async () => { throw new HttpError(401) },
  })
  const operation = controller.reload()
  assert.equal(await waiting.promise, 100)
  controller.suspend()
  await operation
  assert.equal(reconciliationSignal.aborted, true)
  assert.equal(cleared, 1)
  assert.equal(sessionCalls, 2)
  assert.equal(controller.getSnapshot().status, 'loading')
  assert.equal(controller.getSnapshot().profile, null)
})

test('bounded profile reconciliation yields to a newer anonymous epoch during its wait', async (t) => {
  const waiting = deferred()
  const realSetTimeout = globalThis.setTimeout
  let sessionCalls = 0, profileCalls = 0
  t.mock.method(globalThis, 'setTimeout', (callback, delay) => { waiting.resolve(); return realSetTimeout(callback, delay) })
  const { controller } = harness({
    session: async () => { if (++sessionCalls === 2) throw new HttpError(503); return sessionCalls === 1 ? session() : anonymous() },
    profile: async () => { profileCalls += 1; throw new HttpError(401) },
  })
  const older = controller.reload()
  await waiting.promise
  await controller.reload()
  await older
  assert.equal(sessionCalls, 3)
  assert.equal(profileCalls, 1)
  assert.equal(controller.getSnapshot().status, 'signed-out')
  assert.equal(controller.getSnapshot().session.account, null)
  assert.equal(controller.getSnapshot().profile, null)
})

test('bounded profile reconciliation after explicit selection never replays the mutation', async () => {
  let sessionCalls = 0, profileCalls = 0
  const selected = session({ version: '2' })
  const { controller, api, calls } = harness({
    session: async () => { if (++sessionCalls === 2) throw new HttpError(503); return sessionCalls === 1 ? session({ context: null }) : selected },
    profile: async (value) => { if (++profileCalls === 1) throw new HttpError(401); return profile(value) },
  })
  api.select = async (_value, membershipId) => { calls.selection.push(membershipId); return selected }
  await controller.reload()
  await controller.select(ids.member)
  assert.equal(controller.getSnapshot().status, 'ready')
  assert.equal(controller.getSnapshot().session.version, '2')
  assert.equal(sessionCalls, 3)
  assert.deepEqual(calls.selection, [ids.member])
  assert.deepEqual(calls.broadcast, [CHANGE_MESSAGE])
  assert.deepEqual(calls.logout, [])
  assert.equal(calls.login, 0)
  assert.equal(calls.bootstrap, 0)
})

test('503 suspends personal data and supports an explicit successful retry', async () => {
  let unavailable = true
  const { controller } = harness({ profile: async () => {
    if (unavailable) throw new HttpError(503)
    return profile()
  } })
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'unavailable')
  assert.equal(controller.getSnapshot().profile, null)
  unavailable = false
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'ready')
})

test('403 and malformed protocol responses fail closed', async () => {
  for (const error of [new HttpError(403), new ProtocolError()]) {
    const { controller } = harness({ profile: async () => { throw error } })
    await controller.reload()
    assert.equal(controller.getSnapshot().profile, null)
    assert.equal(controller.getSnapshot().session, null)
    assert.equal(controller.getSnapshot().status, error instanceof HttpError ? 'forbidden' : 'error')
  }
})

test('forged membership IDs never reach the mutation transport', async () => {
  const { controller, calls } = harness()
  await controller.reload()
  await controller.select(ids.otherMember)
  assert.deepEqual(calls.selection, [])
  assert.equal(controller.getSnapshot().status, 'ready')
})

test('explicit selection clears old personal data immediately and broadcasts metadata only', async () => {
  const pending = deferred()
  const { controller, calls } = harness({ select: async () => pending.promise })
  await controller.reload()
  const selection = controller.select(ids.member)
  assert.equal(controller.getSnapshot().profile, null)
  assert.equal(controller.getSnapshot().session, null)
  pending.resolve(session({ version: '2' }))
  await selection
  assert.equal(controller.getSnapshot().session.version, '2')
  assert.deepEqual(calls.broadcast, [CHANGE_MESSAGE])
})

test('selection cannot swap account or return an unchanged or older session version', async () => {
  for (const value of [session(), session({ version: '0' }), session({ version: '2', account: { ...session().account, id: ids.otherUser } })]) {
    const { controller } = harness({ select: async () => value })
    await controller.reload()
    await controller.select(ids.member)
    assert.equal(controller.getSnapshot().status, 'error')
    assert.equal(controller.getSnapshot().profile, null)
  }
})

test('a delayed profile response cannot restore personal data after a newer reload', async () => {
  const oldProfile = deferred()
  let first = true
  const { controller } = harness({ profile: async () => {
    if (first) { first = false; return oldProfile.promise }
    throw new HttpError(401)
  } })
  const older = controller.reload()
  await Promise.resolve()
  await Promise.resolve()
  await controller.reload()
  oldProfile.resolve(profile())
  await older
  assert.equal(controller.getSnapshot().status, 'signed-out')
  assert.equal(controller.getSnapshot().profile, null)
})

test('cross-tab notification synchronously hides data and verifies server state', async () => {
  let current = session()
  const pending = deferred()
  const { controller, api } = harness({ session: async () => current })
  await controller.reload()
  api.session = async () => pending.promise
  const settled = new Promise((resolve) => {
    const unsubscribe = controller.subscribe(() => {
      if (controller.getSnapshot().status === 'signed-out') { unsubscribe(); resolve() }
    })
  })
  controller.onMessage(CHANGE_MESSAGE)
  assert.equal(controller.getSnapshot().profile, null)
  assert.equal(controller.getSnapshot().session, null)
  current = anonymous()
  pending.resolve(current)
  await settled
  assert.equal(controller.getSnapshot().status, 'signed-out')
})

test('a delayed selection cannot revive the old account after cross-tab logout', async () => {
  const pending = deferred()
  let current = session()
  const { controller } = harness({ session: async () => current, select: async () => pending.promise })
  await controller.reload()
  const selection = controller.select(ids.member)
  current = anonymous()
  await controller.reload()
  pending.resolve(session({ version: '2' }))
  await selection
  assert.equal(controller.getSnapshot().status, 'signed-out')
  assert.equal(controller.getSnapshot().session.account, null)
})

test('page suspension aborts pending work and immediately removes current personal data', async () => {
  const { controller } = harness()
  await controller.reload()
  controller.suspend()
  assert.equal(controller.getSnapshot().profile, null)
  assert.equal(controller.getSnapshot().session, null)
  assert.equal(controller.getSnapshot().status, 'loading')
})

test('both logout scopes clear locally before network completion and never automatically log in', async () => {
  for (const scope of ['PORTAL', 'GLOBAL']) {
    const pending = deferred()
    const { controller, calls } = harness({ logout: async () => pending.promise })
    await controller.reload()
    const operation = controller.logout(scope)
    assert.equal(controller.getSnapshot().profile, null)
    assert.equal(controller.getSnapshot().session, null)
    pending.resolve('/signed-out')
    await operation
    assert.equal(controller.getSnapshot().status, 'signed-out')
    assert.equal(calls.login, 0)
    assert.deepEqual(calls.navigation, ['/signed-out'])
    assert.deepEqual(calls.broadcast, [CHANGE_MESSAGE, CHANGE_MESSAGE])
  }
})

test('a delayed logout result cannot hide or navigate away from a newer login', async () => {
  const pending = deferred()
  const { controller, calls } = harness({ logout: async () => pending.promise })
  await controller.reload()
  const operation = controller.logout('PORTAL')
  await controller.reload()
  pending.resolve('/signed-out')
  await operation
  assert.equal(controller.getSnapshot().status, 'ready')
  assert.deepEqual(calls.navigation, [])
})

test('signed-out landing never loads a profile even when another tab has logged in', async () => {
  const { controller, calls } = harness({}, { signedOutLanding: true })
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'signed-out')
  assert.equal(controller.getSnapshot().profile, null)
  assert.equal(calls.profile, 0)
  assert.equal(calls.login, 0)
  assert.equal(calls.bootstrap, 0)
})

test('login is an explicit CSRF-bootstrap operation and only navigates after success', async () => {
  let sessionCalls = 0
  const { controller, calls } = harness({ session: async () => { sessionCalls += 1; return anonymous() } })
  await controller.reload()
  assert.equal(calls.login, 0)
  await controller.login()
  assert.equal(sessionCalls, 1)
  assert.equal(calls.bootstrap, 1)
  assert.equal(calls.login, 1)
  assert.deepEqual(calls.navigation, ['https://auth.owned.test/oauth/authorize'])
})

test('invalid authentication configuration never reaches session or login', async () => {
  let sessionCalls = 0
  const { controller, calls } = harness({ configuration: async () => { throw new ProtocolError() }, session: async () => { sessionCalls += 1; return session() } })
  await controller.reload()
  await controller.login()
  assert.equal(controller.getSnapshot().status, 'error')
  assert.equal(sessionCalls, 0)
  assert.equal(calls.login, 0)
  assert.equal(calls.bootstrap, 0)
})

test('invalid old session Cookie stays denied until explicit reconfirm uses the independent browser bootstrap', async () => {
  const { controller, calls } = harness({ session: async () => { throw new HttpError(401) } })
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'signed-out')
  assert.equal(calls.bootstrap, 0)
  assert.equal(calls.login, 0)
  await controller.login()
  assert.equal(calls.bootstrap, 1)
  assert.equal(calls.login, 1)
  assert.deepEqual(calls.navigation, ['https://auth.owned.test/oauth/authorize'])
  assert.equal(controller.getSnapshot().profile, null)
})

test('uncertain session outage never automatically bootstraps but supports explicit reconfirm', async () => {
  const { controller, calls } = harness({ session: async () => { throw new HttpError(503) } })
  await controller.reload()
  assert.equal(controller.getSnapshot().status, 'unavailable')
  assert.equal(calls.bootstrap, 0)
  assert.equal(calls.login, 0)
  await controller.login()
  assert.equal(calls.bootstrap, 1)
  assert.equal(calls.login, 1)
})

test('a delayed browser bootstrap cannot submit login or replace a newer authenticated state', async () => {
  const started = deferred()
  const pending = deferred()
  const { controller, calls } = harness({ loginBootstrap: async () => { started.resolve(); return pending.promise } })
  const login = controller.login()
  await started.promise
  await controller.reload()
  pending.resolve(anonymous())
  await login
  assert.equal(controller.getSnapshot().status, 'ready')
  assert.equal(controller.getSnapshot().profile.account.id, ids.user)
  assert.equal(calls.login, 0)
  assert.deepEqual(calls.navigation, [])
})

test('cross-tab invalidation aborts an explicit bootstrap and never receives credential fields', async () => {
  const started = deferred()
  const pending = deferred()
  let bootstrapSignal
  const { controller, calls } = harness({
    loginBootstrap: async (signal) => { bootstrapSignal = signal; started.resolve(); return pending.promise },
    session: async () => anonymous(),
  })
  const login = controller.login()
  await started.promise
  const settled = new Promise((resolve) => {
    const unsubscribe = controller.subscribe(() => {
      if (controller.getSnapshot().status === 'signed-out') { unsubscribe(); resolve() }
    })
  })
  controller.onMessage(CHANGE_MESSAGE)
  assert.equal(bootstrapSignal.aborted, true)
  await settled
  pending.resolve(anonymous())
  await login
  assert.equal(calls.login, 0)
  assert.deepEqual(calls.broadcast, [])
  assert.deepEqual(calls.navigation, [])
})

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

test('transport sends same-origin cookies and CSRF without Authorization or token-bearing payloads', async () => {
  const requests = []
  const api = createApi(async (path, init) => {
    requests.push({ path, init })
    if (path === '/auth/context') return json(session({ version: '2' }))
    if (path === '/auth/login-bootstrap') return json(anonymous())
    if (path === '/auth/login') return json({ redirectTo: 'https://auth.owned.test/oauth/authorize' })
    if (path === '/auth/logout') return json({ redirectTo: '/signed-out' })
    return json(session())
  })
  const signal = new AbortController().signal
  await api.session(signal)
  await api.select(session(), ids.member, signal)
  await api.login(await api.loginBootstrap(signal), signal)
  await api.logout(session(), 'GLOBAL', signal)
  for (const { init } of requests) {
    assert.equal(init.credentials, 'same-origin')
    assert.equal(init.cache, 'no-store')
    assert.equal(init.redirect, 'error')
    assert.equal('Authorization' in init.headers, false)
    if (init.method === 'POST') assert.equal(init.headers['X-CSRF-Token'], session().csrfToken)
  }
  assert.deepEqual(JSON.parse(requests[1].init.body), { expectedVersion: '1', membershipId: ids.member })
  assert.equal(requests[2].path, '/auth/login-bootstrap')
  assert.equal(requests[2].init.method, 'GET')
  assert.equal(requests[2].init.body, undefined)
  assert.deepEqual(JSON.parse(requests[3].init.body), { returnTo: '/' })
  assert.deepEqual(JSON.parse(requests[4].init.body), { expectedVersion: '1', scope: 'GLOBAL' })
})

test('bootstrap transport rejects authenticated session material and preserves old-session denial', async () => {
  const api = createApi(async (path) => {
    if (path === '/auth/session') return json({}, 401)
    return json(session())
  })
  await assert.rejects(() => api.session(new AbortController().signal), (error) => error instanceof HttpError && error.status === 401)
  await assert.rejects(() => api.loginBootstrap(new AbortController().signal), ProtocolError)
})

test('transport preserves 401 and 503 and rejects HTML/redirect-like JSON instead of treating it as a session', async () => {
  for (const status of [401, 503]) {
    const api = createApi(async () => json({}, status))
    await assert.rejects(() => api.session(new AbortController().signal), (error) => error instanceof HttpError && error.status === status)
  }
  const html = createApi(async () => new Response('<html>login</html>', { status: 200, headers: { 'Content-Type': 'text/html' } }))
  await assert.rejects(() => html.session(new AbortController().signal), ProtocolError)
  const wrongLogout = createApi(async () => json({ redirectTo: 'https://external.owned.test/' }))
  await assert.rejects(() => wrongLogout.logout(session(), 'PORTAL', new AbortController().signal), ProtocolError)
})
