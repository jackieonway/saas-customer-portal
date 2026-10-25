export interface Account {
  id: string
  username: string
  realName: string
  avatar: string
}

export interface CustomerMembership {
  membershipId: string
  userId: string
  memberType: 'CUSTOMER'
  identityVersion: string
  organizationId: string
  organizationName: string
  tenantId: string
  tenantName: string
}

export interface CustomerContext {
  contractVersion: 'customer-profile/1'
  purpose: 'CUSTOMER_PROFILE'
  userId: string
  membershipId: string
  memberType: 'CUSTOMER'
  identityVersion: string
  accountVersion: string
  tenant: { id: string; name: string }
  organization: { id: string; name: string }
  application: { id: string; code: string; name: string; entryPath: '/api/customer/profile' }
}

export interface PortalSession {
  contractVersion: 'portal-session/1'
  version: string
  csrfToken: string
  account: Account | null
  memberships: CustomerMembership[]
  context: CustomerContext | null
}

export interface Profile {
  context: CustomerContext
  account: Account
}

export class ProtocolError extends Error {
  constructor() {
    super('Invalid portal response')
    this.name = 'ProtocolError'
  }
}

type RecordValue = Record<string, unknown>

function record(value: unknown): RecordValue {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new ProtocolError()
  return value as RecordValue
}

function text(value: unknown, allowEmpty = false): string {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0) || value.length > 2048) {
    throw new ProtocolError()
  }
  return value
}

function id(value: unknown): string {
  const result = text(value)
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(result)) {
    throw new ProtocolError()
  }
  return result
}

function version(value: unknown, allowZero = false): string {
  const result = text(value)
  if (!/^(0|[1-9][0-9]{0,18})$/.test(result) || (!allowZero && result === '0')
    || BigInt(result) > 9223372036854775807n) throw new ProtocolError()
  return result
}

export function parseAccount(value: unknown): Account {
  const source = record(value)
  return {
    id: id(source.id),
    username: text(source.username),
    realName: text(source.realName, true),
    avatar: text(source.avatar, true),
  }
}

function membership(value: unknown, userId: string): CustomerMembership {
  const source = record(value)
  if (source.memberType !== 'CUSTOMER' || source.userId !== userId) throw new ProtocolError()
  return {
    membershipId: id(source.membershipId),
    userId,
    memberType: 'CUSTOMER',
    identityVersion: version(source.identityVersion),
    organizationId: id(source.organizationId),
    organizationName: text(source.organizationName),
    tenantId: id(source.tenantId),
    tenantName: text(source.tenantName),
  }
}

export function parseContext(value: unknown): CustomerContext {
  const source = record(value)
  const tenant = record(source.tenant)
  const organization = record(source.organization)
  const application = record(source.application)
  if (source.contractVersion !== 'customer-profile/1' || source.purpose !== 'CUSTOMER_PROFILE'
    || source.memberType !== 'CUSTOMER' || application.entryPath !== '/api/customer/profile') {
    throw new ProtocolError()
  }
  return {
    contractVersion: 'customer-profile/1',
    purpose: 'CUSTOMER_PROFILE',
    userId: id(source.userId),
    membershipId: id(source.membershipId),
    memberType: 'CUSTOMER',
    identityVersion: version(source.identityVersion),
    // Accounts begin at generation zero; member and portal session versions begin at one.
    accountVersion: version(source.accountVersion, true),
    tenant: { id: id(tenant.id), name: text(tenant.name) },
    organization: { id: id(organization.id), name: text(organization.name) },
    application: {
      id: id(application.id),
      code: text(application.code),
      name: text(application.name),
      entryPath: '/api/customer/profile',
    },
  }
}

export function parseSession(value: unknown): PortalSession {
  const source = record(value)
  if (source.contractVersion !== 'portal-session/1' || !Array.isArray(source.memberships)
    || source.memberships.length > 1000) throw new ProtocolError()
  if (source.account === null) {
    if (source.version !== '0' || source.memberships.length !== 0 || source.context !== null) throw new ProtocolError()
    return {
      contractVersion: 'portal-session/1', version: '0', csrfToken: text(source.csrfToken),
      account: null, memberships: [], context: null,
    }
  }
  const account = parseAccount(source.account)
  const memberships = source.memberships.map((item) => membership(item, account.id))
  if (new Set(memberships.map((item) => item.membershipId)).size !== memberships.length) throw new ProtocolError()
  const context = source.context === null ? null : parseContext(source.context)
  if (context !== null && !memberships.some((item) => matchesMembership(context, item))) throw new ProtocolError()
  return {
    contractVersion: 'portal-session/1',
    version: version(source.version),
    csrfToken: text(source.csrfToken),
    account,
    memberships,
    context,
  }
}

function matchesMembership(context: CustomerContext, member: CustomerMembership): boolean {
  return context.membershipId === member.membershipId && context.userId === member.userId
    && context.identityVersion === member.identityVersion && context.organization.id === member.organizationId
    && context.tenant.id === member.tenantId
}

export function sameContext(left: CustomerContext, right: CustomerContext): boolean {
  return left.userId === right.userId && left.membershipId === right.membershipId
    && left.identityVersion === right.identityVersion && left.accountVersion === right.accountVersion
    && left.organization.id === right.organization.id && left.tenant.id === right.tenant.id
    && left.application.id === right.application.id && left.application.code === right.application.code
}

export function parseProfile(value: unknown, session: PortalSession): Profile {
  const source = record(value)
  const context = parseContext(source.context)
  const account = parseAccount(source.account)
  if (!session.account || !session.context || !sameContext(context, session.context) || account.id !== session.account.id
    || context.userId !== account.id) throw new ProtocolError()
  return { context, account }
}

export function parseRedirect(value: unknown): string {
  const source = record(value)
  const target = new URL(text(source.redirectTo))
  if (target.protocol !== 'https:' || target.username || target.password || target.hash) throw new ProtocolError()
  return target.href
}

export const CHANGE_MESSAGE = Object.freeze({ type: 'portal-session-changed', contractVersion: 1 })

export function isChangeMessage(value: unknown): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const source = value as RecordValue
  return Object.keys(source).length === 2 && source.type === CHANGE_MESSAGE.type && source.contractVersion === 1
}
