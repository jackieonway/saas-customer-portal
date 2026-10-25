import { parseProfile, parseRedirect, parseSession, ProtocolError } from './protocol.ts'
import type { PortalSession, Profile } from './protocol.ts'

export class HttpError extends Error {
  readonly status: number

  constructor(status: number) {
    super('Portal request failed')
    this.name = 'HttpError'
    this.status = status
  }
}

export interface PortalApi {
  configuration(signal: AbortSignal): Promise<void>
  session(signal: AbortSignal): Promise<PortalSession>
  loginBootstrap(signal: AbortSignal): Promise<PortalSession>
  login(session: PortalSession, signal: AbortSignal): Promise<string>
  select(session: PortalSession, membershipId: string, signal: AbortSignal): Promise<PortalSession>
  profile(session: PortalSession, signal: AbortSignal): Promise<Profile>
  logout(session: PortalSession, scope: 'PORTAL' | 'GLOBAL', signal: AbortSignal): Promise<string>
}

type Fetch = (input: string, init: RequestInit) => Promise<Response>

export function createApi(fetcher: Fetch = (input, init) => fetch(input, init)): PortalApi {
  async function request(path: string, signal: AbortSignal, options?: { body: unknown; csrfToken: string }): Promise<unknown> {
    const response = await fetcher(path, {
      method: options ? 'POST' : 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      signal,
      headers: options
        ? { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': options.csrfToken }
        : { Accept: 'application/json' },
      ...(options ? { body: JSON.stringify(options.body) } : {}),
    })
    if (!response.ok) throw new HttpError(response.status)
    if (response.status === 204) return null
    if (!response.headers.get('content-type')?.includes('application/json')) throw new ProtocolError()
    return response.json()
  }

  return {
    async configuration(signal) {
      const value = await request('/auth/config', signal)
      if (typeof value !== 'object' || value === null || !('mode' in value) || value.mode !== 'BFF') {
        throw new ProtocolError()
      }
    },
    async session(signal) {
      return parseSession(await request('/auth/session', signal))
    },
    async loginBootstrap(signal) {
      const session = parseSession(await request('/auth/login-bootstrap', signal))
      if (session.version !== '0' || session.account !== null || session.memberships.length !== 0 || session.context !== null) {
        throw new ProtocolError()
      }
      return session
    },
    async login(session, signal) {
      return parseRedirect(await request('/auth/login', signal, {
        body: { returnTo: '/' }, csrfToken: session.csrfToken,
      }))
    },
    async select(session, membershipId, signal) {
      return parseSession(await request('/auth/context', signal, {
        body: { expectedVersion: session.version, membershipId }, csrfToken: session.csrfToken,
      }))
    },
    async profile(session, signal) {
      return parseProfile(await request('/api/profile', signal), session)
    },
    async logout(session, scope, signal) {
      const value = await request('/auth/logout', signal, {
        body: { expectedVersion: session.version, scope }, csrfToken: session.csrfToken,
      })
      if (typeof value !== 'object' || value === null || !('redirectTo' in value)
        || value.redirectTo !== '/signed-out') throw new ProtocolError()
      return '/signed-out'
    },
  }
}
