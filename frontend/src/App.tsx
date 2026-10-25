import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { createApi } from './api.ts'
import { PortalController } from './controller.ts'
import type { PortalState } from './controller.ts'
import type { CustomerMembership } from './protocol.ts'

function Arrow({ back = false }: { back?: boolean }) {
  return <span aria-hidden="true" className={back ? 'arrow arrow-back' : 'arrow'}>↗</span>
}

function StatusPanel({ state, controller }: { state: PortalState; controller: PortalController }) {
  if (state.busy) {
    return <section className="notice" role="status" aria-live="polite" data-testid="portal-loading">
      <span className="loading-mark" aria-hidden="true" />
      <div><h2>正在确认您的身份</h2><p>确认完成后，才会展示当前客户身份下的本人资料。</p></div>
    </section>
  }

  if (state.status === 'signed-out') {
    const signedOut = window.location.pathname === '/signed-out'
    return <section className="entry-panel" data-testid="portal-signed-out">
      <span className="eyebrow">{signedOut ? 'SIGNED OUT · 已退出' : 'WELCOME · 欢迎回来'}</span>
      <h2>{signedOut ? '您已退出客户空间。' : '一个账号，安心抵达。'}</h2>
      <p>{signedOut ? '需要再次查看资料时，请主动继续统一登录。' : '使用统一账号登录后，选择已有的客户身份，查看属于您自己的基础资料。'}</p>
      <button className="button button-primary" onClick={() => void controller.login()} data-testid="portal-login">
        继续统一登录 <Arrow />
      </button>
      <p className="fine-print">当前未登录，或登录状态已失效。客户身份由所属组织登记。</p>
    </section>
  }

  if (state.status !== 'ready') {
    const unavailable = state.status === 'unavailable'
    const forbidden = state.status === 'forbidden'
    return <section className="notice notice-error" role="alert" data-testid={`portal-${state.status}`}>
      <span className="notice-symbol" aria-hidden="true">!</span>
      <div>
        <span className="eyebrow">{unavailable ? '暂时无法确认' : '资料展示已暂停'}</span>
        <h2>{unavailable ? '连接暂时中断，请稍后重试。' : forbidden ? '当前客户身份暂不可用。' : '暂时无法安全展示资料。'}</h2>
        <p>{unavailable ? '身份服务恢复并重新确认后，才能继续查看资料。' : forbidden ? '所属组织可能已调整您的客户身份或访问范围，请联系组织管理员。' : '当前资料已清除。请重新确认登录状态后再试。'}</p>
        <div className="recovery-actions">
          <button className="button button-secondary" onClick={() => void controller.reload()} data-testid="portal-retry">重新确认状态 <Arrow /></button>
          <button className="text-button" onClick={() => void controller.login()} data-testid="portal-reconfirm">重新确认账号 <Arrow /></button>
        </div>
        <p className="fine-print">重新确认账号会前往统一登录，由您主动确认后继续。</p>
      </div>
    </section>
  }

  return null
}

function MembershipOption({ member, current, controller }: {
  member: CustomerMembership
  current: boolean
  controller: PortalController
}) {
  return <button
    className={`identity-option${current ? ' identity-current' : ''}`}
    onClick={() => void controller.select(member.membershipId)}
    aria-pressed={current}
    data-testid="portal-membership"
    data-membership-id={member.membershipId}
  >
    <span className="identity-option-body"><span className="identity-tenant">{member.tenantName}</span>
      <strong>{member.organizationName}</strong><span className="identity-kind">客户身份</span></span>
    <span className="identity-option-action">{current ? '当前使用' : '选择此身份'}<span aria-hidden="true">{current ? '✓' : '→'}</span></span>
  </button>
}

function IdentityPanel({ state, controller }: { state: PortalState; controller: PortalController }) {
  const session = state.session
  if (state.status !== 'ready' || !session?.account) return null

  return <section className="identity-section" aria-labelledby="identity-title">
    <div className="section-heading"><span className="section-index">01</span><div><span className="eyebrow">您的归属</span><h2 id="identity-title">选择客户身份</h2></div></div>
    {session.memberships.length === 0
      ? <div className="empty-state" data-testid="portal-no-customer"><h3>账号已确认，暂时没有客户身份。</h3>
        <p>仅有员工身份的账号也需要由所属组织登记客户身份，才能进入客户空间。门户不会自动新增或绑定关系。</p>
        <p className="fine-print">如需协助，请联系您的组织管理员。</p></div>
      : <><p className="section-note">不同组织的身份分别确认。切换后，只展示该身份下的本人资料。</p>
        <div className="identity-options">{session.memberships.map((member) => <MembershipOption
          key={member.membershipId} member={member} current={session.context?.membershipId === member.membershipId} controller={controller}
        />)}</div></>}
  </section>
}

function ProfilePanel({ state }: { state: PortalState }) {
  if (state.status !== 'ready' || !state.session?.account || state.session.memberships.length === 0) return null
  const profile = state.profile
  return <section className="profile-section" aria-labelledby="profile-title" data-testid="portal-profile-section">
    <div className="section-heading"><span className="section-index">02</span><div><span className="eyebrow">仅本人可见</span><h2 id="profile-title">基础资料</h2></div></div>
    {profile === null ? <div className="profile-placeholder" data-testid="portal-select-prompt"><span className="placeholder-line" aria-hidden="true" />
      <h3>先选择一个客户身份。</h3><p>确认所属组织后，您的资料会在这里展开。</p></div>
      : <div className="profile-card" data-testid="portal-profile">
        <div className="profile-card-header"><span className="profile-monogram" aria-hidden="true">{(profile.account.realName || profile.account.username).slice(0, 1)}</span>
          <div><h3>{profile.account.realName || profile.account.username}</h3><p>{profile.context.organization.name} · 客户</p></div><span className="verified-label">已确认</span></div>
        <dl className="profile-details">
          <div><dt>姓名</dt><dd>{profile.account.realName || '尚未填写'}</dd></div>
          <div><dt>账号</dt><dd data-testid="portal-profile-username">{profile.account.username}</dd></div>
          <div><dt>所属租户</dt><dd>{profile.context.tenant.name}</dd></div>
          <div><dt>所属组织</dt><dd data-testid="portal-profile-organization">{profile.context.organization.name}</dd></div>
          <div className="profile-id"><dt>账号标识</dt><dd>{profile.account.id}</dd></div>
        </dl>
        <p className="profile-footnote">资料来自您的统一账号。需要修改时，请联系所属组织管理员。</p>
      </div>}
  </section>
}

export function App() {
  const channel = useRef<BroadcastChannel | null>(null)
  const [controller] = useState(() => new PortalController(createApi(), {
    navigate: (url) => window.location.assign(url),
    broadcast: (message) => channel.current?.postMessage(message),
  }, { signedOutLanding: window.location.pathname === '/signed-out' }))
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot)

  useEffect(() => {
    if (typeof BroadcastChannel !== 'undefined') {
      const current = new BroadcastChannel('saas-customer-portal-state-v1')
      channel.current = current
      current.onmessage = (event: MessageEvent<unknown>) => controller.onMessage(event.data)
    }
    const visibility = () => {
      if (document.visibilityState === 'hidden') controller.suspend()
      else void controller.reload()
    }
    const focus = () => { if (document.visibilityState === 'visible') void controller.reload() }
    const pageHide = () => controller.suspend()
    const pageShow = (event: PageTransitionEvent) => { if (event.persisted) void controller.reload() }
    document.addEventListener('visibilitychange', visibility)
    window.addEventListener('focus', focus)
    window.addEventListener('pagehide', pageHide)
    window.addEventListener('pageshow', pageShow)
    void controller.reload()
    return () => {
      controller.suspend()
      channel.current?.close()
      channel.current = null
      document.removeEventListener('visibilitychange', visibility)
      window.removeEventListener('focus', focus)
      window.removeEventListener('pagehide', pageHide)
      window.removeEventListener('pageshow', pageShow)
    }
  }, [controller])

  const account = state.status === 'ready' ? state.session?.account : null
  const active = state.profile !== null

  return <div className="portal-shell">
    <a className="skip-link" href="#main">跳至主要内容</a>
    <header className="site-header">
      <a className="brand" href="/" aria-label="客户空间首页"><span className="brand-mark" aria-hidden="true"><i /><i /></span><span>客户空间<small>CUSTOMER SPACE</small></span></a>
      <span className="header-label">在此，确认您的每一份归属。</span>
      {account && <span className="account-badge" data-testid="portal-account">{account.realName || account.username}<span>统一账号已登录</span></span>}
    </header>

    <main id="main" tabIndex={-1}>
      <div className="hero">
        <div><span className="eyebrow">YOUR OWN SPACE / 本人资料</span><h1>{account ? <>您好，<span>{account.realName || account.username}。</span></> : <>属于您的，<span>一页资料。</span></>}</h1>
          <p className="hero-intro">确认账号，选择客户身份。<br />在清晰的归属下，安心查看自己的资料。</p></div>
        <ol className="journey" aria-label="查看资料步骤">
          <li className={account ? 'journey-complete' : 'journey-current'}><span className="journey-number">01</span><div><strong>统一账号</strong><small>{account ? '已确认' : '登录并确认您的账号'}</small></div></li>
          <li className={active ? 'journey-complete' : account ? 'journey-current' : ''}><span className="journey-number">02</span><div><strong>客户身份</strong><small>{active ? '已确认所属组织' : '选择已有的组织身份'}</small></div></li>
          <li className={active ? 'journey-current' : ''}><span className="journey-number">03</span><div><strong>本人资料</strong><small>{active ? '已就绪，仅本人可见' : '查看您的基础资料'}</small></div></li>
        </ol>
      </div>

      <div className="workspace" aria-busy={state.busy}>
        <StatusPanel state={state} controller={controller} />
        <IdentityPanel state={state} controller={controller} />
        <ProfilePanel state={state} />
      </div>

      {account && <section className="session-actions" aria-label="登录管理"><p>已完成查看？<span>退出后，本页不再展示您的资料。</span></p><div>
        <button className="text-button" onClick={() => void controller.logout('PORTAL')} data-testid="portal-logout">退出客户门户 <Arrow /></button>
        <button className="text-button text-button-muted" onClick={() => void controller.logout('GLOBAL')} data-testid="portal-global-logout">退出所有登录 <Arrow /></button>
      </div><small>退出所有登录将同时结束此账号在平台等入口的登录状态。</small></section>}
    </main>

    <footer className="site-footer"><span className="footer-note">每一个身份，都有清晰的边界。</span><span>客户空间 · 本人资料</span></footer>
  </div>
}
