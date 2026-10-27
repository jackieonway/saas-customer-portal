import { HttpError } from './api.ts'
import type { PortalApi } from './api.ts'
import { CHANGE_MESSAGE, isChangeMessage, ProtocolError } from './protocol.ts'
import type { PortalSession, Profile } from './protocol.ts'

export type PortalStatus = 'loading' | 'signed-out' | 'ready' | 'unavailable' | 'forbidden' | 'error'

export interface PortalState {
  status: PortalStatus
  session: PortalSession | null
  profile: Profile | null
  busy: boolean
}

interface Effects {
  navigate: (url: string) => void
  broadcast: (message: typeof CHANGE_MESSAGE) => void
}

const initialState: PortalState = { status: 'loading', session: null, profile: null, busy: true }
const reconciliationBudgetMs = 500
const reconciliationDelaysMs = [100, 200]

/** Each new operation clears personal data before it begins; stale responses cannot republish it. */
export class PortalController {
  private state: PortalState = initialState
  private readonly listeners = new Set<() => void>()
  private epoch = 0
  private managedRevision: string | null = null
  private abort: AbortController | null = null
  private readonly api: PortalApi
  private readonly effects: Effects
  private readonly signedOutLanding: boolean

  constructor(api: PortalApi, effects: Effects, options: { signedOutLanding?: boolean } = {}) {
    this.api = api
    this.effects = effects
    this.signedOutLanding = options.signedOutLanding === true
  }

  readonly getSnapshot = (): PortalState => this.state

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  private publish(value: PortalState): void {
    this.state = value
    this.listeners.forEach((listener) => listener())
  }

  private begin(): { epoch: number; signal: AbortSignal } {
    this.abort?.abort()
    this.abort = new AbortController()
    const epoch = ++this.epoch
    this.publish({ status: 'loading', session: null, profile: null, busy: true })
    return { epoch, signal: this.abort.signal }
  }

  private current(epoch: number): boolean {
    return epoch === this.epoch && !this.abort?.signal.aborted
  }

  private fail(error: unknown, epoch: number): void {
    if (!this.current(epoch)) return
    const status: PortalStatus = error instanceof HttpError
      ? error.status === 401 ? 'signed-out'
        : error.status === 403 ? 'forbidden'
          : error.status === 503 ? 'unavailable' : 'error'
      : error instanceof ProtocolError ? 'error' : 'unavailable'
    this.publish({ status, session: null, profile: null, busy: false })
  }

  private waitForReconciliation(delay: number, signal: AbortSignal): Promise<void> {
    return new Promise((resolve) => {
      const finish = (): void => {
        clearTimeout(timer)
        signal.removeEventListener('abort', finish)
        resolve()
      }
      const timer = setTimeout(finish, delay)
      signal.addEventListener('abort', finish, { once: true })
      if (signal.aborted) finish()
    })
  }

  private async reconcile(epoch: number, signal: AbortSignal): Promise<void> {
    const deadline = performance.now() + reconciliationBudgetMs
    for (let attempt = 0; attempt <= reconciliationDelaysMs.length; attempt += 1) {
      if (!this.current(epoch) || signal.aborted) return
      if (performance.now() >= deadline) throw new HttpError(503)
      let session: PortalSession
      try {
        session = await this.api.session(signal)
      } catch (error) {
        if (!this.current(epoch) || signal.aborted) return
        if (!(error instanceof HttpError) || error.status !== 503 || attempt === reconciliationDelaysMs.length) throw error
        const remaining = deadline - performance.now()
        if (remaining <= 0) throw error
        // A context/refresh lease may still be settling. Only this read has a
        // short, cancellable retry budget; no mutation or refresh is replayed.
        await this.waitForReconciliation(Math.min(reconciliationDelaysMs[attempt], remaining), signal)
        continue
      }
      if (!this.current(epoch) || signal.aborted) return
      // The budget bounds dispatch, including the subsequent strict profile read.
      if (performance.now() >= deadline) throw new HttpError(503)
      await this.accept(session, epoch, signal, false)
      return
    }
  }

  private async accept(session: PortalSession, epoch: number, signal: AbortSignal, reconcileProfile = true): Promise<void> {
    if (!this.current(epoch)) return
    if (session.account === null || this.signedOutLanding) {
      this.managedRevision = null
      this.publish({ status: 'signed-out', session, profile: null, busy: false })
      return
    }
    let profile: Profile | null = null
    if (session.context !== null) {
      try {
        profile = await this.api.profile(session, signal)
      } catch (error) {
        if (!this.current(epoch)) return
        // Session and profile are separate reads. A tab switch or server-side
        // capability rotation may invalidate the first snapshot without logout.
        // Reconcile from authority with a bounded lease wait; never replay a write.
        if (!reconcileProfile || !(error instanceof HttpError) || (error.status !== 401 && error.status !== 409)) throw error
        await this.reconcile(epoch, signal)
        return
      }
    }
    if (!this.current(epoch)) return
    this.publish({ status: 'ready', session, profile, busy: false })
    if (session.centralizedContextSelection) {
      const revision = `${session.account.id}:${session.version}`
      if (revision !== this.managedRevision) { this.managedRevision = revision; this.effects.broadcast(CHANGE_MESSAGE) }
    }
  }

  readonly reload = async (): Promise<void> => {
    const { epoch, signal } = this.begin()
    try {
      await this.api.configuration(signal)
      if (!this.current(epoch)) return
      await this.accept(await this.api.session(signal), epoch, signal)
    } catch (error) {
      this.fail(error, epoch)
    }
  }

  readonly login = async (): Promise<void> => {
    const { epoch, signal } = this.begin()
    try {
      await this.api.configuration(signal)
      if (!this.current(epoch)) return
      const bootstrap = await this.api.loginBootstrap(signal)
      if (!this.current(epoch)) return
      const redirectTo = await this.api.login(bootstrap, signal)
      if (this.current(epoch)) this.effects.navigate(redirectTo)
    } catch (error) {
      this.fail(error, epoch)
    }
  }

  readonly switchContext = async (): Promise<void> => {
    const session = this.state.session
    if (!session?.account || !session.centralizedContextSelection || this.state.busy) return
    const { epoch, signal } = this.begin()
    try {
      const redirectTo = await this.api.login(session, signal, true)
      if (this.current(epoch)) this.effects.navigate(redirectTo)
    } catch (error) { this.fail(error, epoch) }
  }

  readonly select = async (membershipId: string): Promise<void> => {
    const session = this.state.session
    if (!session?.account || this.state.busy || !session.memberships.some((item) => item.membershipId === membershipId)) return
    const { epoch, signal } = this.begin()
    try {
      const selected = await this.api.select(session, membershipId, signal)
      if (!this.current(epoch)) return
      // A server mutation may only return the explicitly chosen identity for this account.
      if (!selected.context || selected.context.membershipId !== membershipId
        || selected.account?.id !== session.account.id || BigInt(selected.version) <= BigInt(session.version)) throw new ProtocolError()
      this.effects.broadcast(CHANGE_MESSAGE)
      await this.accept(selected, epoch, signal)
    } catch (error) {
      this.fail(error, epoch)
    }
  }

  readonly logout = async (scope: 'PORTAL' | 'GLOBAL'): Promise<void> => {
    const session = this.state.session
    if (!session?.account || this.state.busy) return
    const { epoch, signal } = this.begin()
    // Other tabs hide their existing profile even while this command is in flight.
    this.effects.broadcast(CHANGE_MESSAGE)
    try {
      const redirectTo = await this.api.logout(session, scope, signal)
      if (!this.current(epoch)) return
      this.publish({ status: 'signed-out', session: null, profile: null, busy: false })
      this.effects.broadcast(CHANGE_MESSAGE)
      this.effects.navigate(redirectTo)
    } catch (error) {
      this.fail(error, epoch)
    }
  }

  readonly onMessage = (message: unknown): void => {
    if (isChangeMessage(message)) void this.reload()
  }

  readonly suspend = (): void => {
    this.epoch += 1
    this.abort?.abort()
    this.publish({ status: 'loading', session: null, profile: null, busy: true })
  }

  readonly dispose = (): void => {
    this.suspend()
    this.listeners.clear()
  }
}
