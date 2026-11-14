'use strict';
const zh = (navigator.language || '').toLowerCase().startsWith('zh');
const tr = (en, cn) => zh ? cn : en;
document.documentElement.lang = zh ? 'zh-CN' : 'en';
const app = document.getElementById('app');
const dialogs = document.getElementById('dialogs');
let csrf = '', state = null, tab = 'overview', subject = '', noticeTimer;
let setupCode = new URLSearchParams(location.hash.slice(1)).get('setup') || '';
let gmailResult = new URLSearchParams(location.search).get('gmail');
if (location.hash) history.replaceState(null, '', location.pathname);
const messages = {
  login_required: ['Your session expired. Sign in again.', '会话已过期，请重新登录。'],
  invalid_setup_link: ['This setup link is invalid, expired, or already used.', '设置链接无效、已过期或已被使用。'],
  verification_failed: ['Passkey verification failed. Try again.', '通行密钥验证失败，请重试。'],
  configuration_changed: ['Configuration changed in another window. Refresh and try again.', '其他窗口已修改配置，请刷新后重试。'],
  connector_unavailable: ['Could not start or reach this connector. Check its settings.', '无法启动或连接此连接器，请检查设置。'],
  connector_login_or_read_failed: ['Login or the read check failed. Check account credentials and permissions.', '登录或读取验证失败，请检查账号凭据和权限。'],
  invalid_configuration: ['Check the values and account-sharing permission.', '请检查输入值和跨账号授权选项。'],
  member_in_use: ['Remove this member’s clients, connectors, and permissions first.', '请先移除此成员的 Agent、连接器和权限。'],
  last_admin_passkey: ['Keep at least one administrator passkey.', '必须保留至少一个管理员通行密钥。'],
  tool_definitions_changed: ['Tool definitions changed. Edit and review this connector again.', '工具定义已变化，请编辑并重新审阅此连接器。'],
  draft_expired: ['This review expired. Preview the connector again.', '此次审阅已过期，请重新预览连接器。'],
  invalid_tool_configuration: ['A tool restriction does not match its schema.', '工具参数限制与工具定义不匹配。'],
  connector_identity_is_fixed: ['Owner and connector type cannot be changed. Add a new connector instead.', '连接器类型和所属成员固定，请新建连接器。'],
  wrong_origin: ['Open the configured HTTPS address.', '请打开配置的 HTTPS 地址。'],
  oauth_declined: ['Google authorization was cancelled. No connector was changed.', 'Google 授权已取消，连接器未发生变更。'],
  oauth_failed: ['Google authorization failed. Check the web OAuth client and callback URL.', 'Google 授权失败，请检查网页 OAuth 客户端和回调地址。'],
  gmail_readonly_required: ['Google must grant exactly Gmail read-only access.', 'Google 必须只授予 Gmail 只读权限。'],
  oauth_expired: ['Google authorization expired. Start again.', 'Google 授权已过期，请重新开始。'],
  active_calls_busy: ['Calls are still running. No configuration was changed; try again shortly.', '仍有调用正在执行，配置未变更，请稍后重试。'],
};
function el(parent, tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  parent.append(node); return node;
}
function notify(text) {
  const node = document.getElementById('notice'); node.textContent = text; node.style.display = 'block';
  clearTimeout(noticeTimer); noticeTimer = setTimeout(() => { node.style.display = 'none'; }, 5500);
}
function errorText(error) { return error.name === 'NotAllowedError' ? tr('Passkey operation cancelled or timed out.', '通行密钥操作已取消或超时。') : error.message; }
async function api(path, body) {
  const response = await fetch('/admin/api/' + path, body === undefined ? {} : {
    method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, body: JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401) { csrf = ''; state = null; dialogs.replaceChildren(); await welcome(true); }
    const known = messages[data.error];
    throw new Error(known ? tr(...known) : tr('Could not complete: ', '未能完成：') + data.error);
  }
  return data;
}
function button(parent, label, action, cls = '') {
  const node = el(parent, 'button', label, cls); node.type = 'button';
  node.addEventListener('click', async () => {
    node.disabled = true;
    try { await action(); } catch (error) { notify(errorText(error)); }
    finally { node.disabled = false; }
  }); return node;
}
function field(parent, label, name, value = '', type = 'text', help = '') {
  const group = el(parent, 'div', undefined, 'field');
  const id = 'field-' + name + '-' + Math.random().toString(36).slice(2, 8);
  el(group, 'label', label).htmlFor = id;
  const input = el(group, type === 'textarea' ? 'textarea' : 'input'); input.id = id; input.name = name;
  if (type !== 'textarea') input.type = type;
  input.value = value; input.autocomplete = 'off';
  if (help) el(group, 'small', help); return input;
}
function select(parent, label, name, options, value) {
  const group = el(parent, 'div', undefined, 'field'); const id = 'select-' + name + Math.random().toString(36).slice(2, 8);
  el(group, 'label', label).htmlFor = id;
  const input = el(group, 'select'); input.id = id; input.name = name;
  for (const [key, text] of options) { const option = el(input, 'option', text); option.value = key; }
  if (value) input.value = value; return input;
}
function checkbox(parent, text, checked = false) {
  const label = el(parent, 'label', undefined, 'check'); const input = el(label, 'input'); input.type = 'checkbox'; input.checked = checked;
  el(label, 'span', text); return input;
}
function modal(title) {
  const box = el(dialogs, 'dialog'); el(box, 'h2', title);
  const close = button(box, '×', () => box.close(), 'close'); close.setAttribute('aria-label', tr('Close', '关闭'));
  box.addEventListener('close', () => box.remove()); box.showModal(); return box;
}
function secretResult(title, value, isLink = false) {
  const box = modal(title);
  el(box, 'p', isLink ? tr('This private link expires in 15 minutes and works once.', '此私密链接 15 分钟后过期，只能使用一次。')
    : tr('Shown only now. Save it for this agent before closing.', '仅在此时显示。关闭前请保存到这个 Agent 的配置中。'), 'muted');
  const input = field(box, isLink ? tr('Registration link', '注册链接') : tr('Agent token', 'Agent Token'), 'secret', value, 'text'); input.readOnly = true; input.className = 'token';
  const actions = el(box, 'div', undefined, 'actions');
  button(actions, tr('Copy', '复制'), async () => { await navigator.clipboard.writeText(value); notify(tr('Copied', '已复制')); });
  if (isLink) { const link = el(actions, 'a', tr('Open registration', '打开注册页面'), 'button primary'); link.href = value; link.target = '_blank'; link.rel = 'noopener noreferrer'; }
  else { el(box, 'p', tr('Streamable HTTP endpoint', 'Streamable HTTP 地址'), 'muted'); el(box, 'code', state.mcp_url, 'url');
    el(box, 'p', tr('Use the token as the Authorization: Bearer header. Each agent gets its own token.', '通过 Authorization: Bearer 请求头发送 Token。每个 Agent 使用独立 Token。'), 'muted'); }
}
async function confirmAction(title, explanation, action) {
  const box = modal(title); el(box, 'p', explanation, 'muted'); const actions = el(box, 'div', undefined, 'actions');
  button(actions, tr('Cancel', '取消'), () => box.close());
  button(actions, tr('Confirm', '确认'), async () => { await action(); box.close(); }, 'danger');
}
const fromB64 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function authenticate(action, code = '') {
  if (!window.PublicKeyCredential) throw new Error(tr('This browser does not support passkeys.', '此浏览器不支持通行密钥。'));
  const start = await api('auth/begin', {action, code}); const options = start.options.publicKey;
  options.challenge = fromB64(options.challenge);
  for (const key of ['allowCredentials', 'excludeCredentials']) if (options[key]) options[key] = options[key].map(c => ({...c, id: fromB64(c.id)}));
  if (options.user) options.user.id = fromB64(options.user.id);
  const credential = await navigator.credentials[action === 'setup' ? 'create' : 'get']({publicKey: options});
  const response = {clientDataJSON: toB64(credential.response.clientDataJSON)};
  for (const key of ['attestationObject', 'authenticatorData', 'signature', 'userHandle']) if (credential.response[key]) response[key] = toB64(credential.response[key]);
  const result = await api('auth/finish', {ceremony_id: start.ceremony_id, response: {
    id: credential.id, rawId: toB64(credential.rawId), type: credential.type, response, clientExtensionResults: credential.getClientExtensionResults()}});
  csrf = result.csrf; setupCode = ''; await refresh(); await resumeGoogle();
}
async function welcome(initialized) {
  app.replaceChildren(); document.getElementById('identity').replaceChildren();
  const welcome = el(app, 'section', undefined, 'welcome');
  el(welcome, 'p', tr('Your accounts. Your permissions.', '你的账号，由你决定权限。'), 'eyebrow');
  el(welcome, 'h1', initialized ? tr('Welcome back.', '欢迎回来。') : tr('A private gateway for your agents.', '为你的 Agent 设置私人网关。'));
  el(welcome, 'p', tr('Connect accounts, decide what each agent can access, and approve sensitive actions with your passkey.', '连接账号，决定每个 Agent 能访问什么，并通过通行密钥批准敏感操作。'), 'muted');
  const card = el(welcome, 'div', undefined, 'card');
  el(card, 'h2', initialized ? tr('Administrator sign-in', '管理员登录') : tr('Create your administrator passkey', '创建管理员通行密钥'));
  let input;
  if (!initialized) {
    el(card, 'p', tr('Use the private setup link supplied with your deployment. Your passkey also approves requests for your personal account.', '使用部署时提供的私密设置链接。这个通行密钥也可以批准你个人账号的请求。'), 'muted');
    if (!setupCode) input = field(card, tr('Setup link or code', '设置链接或设置码'), 'setup_code');
  }
  const status = el(card, 'p', '', 'muted');
  button(card, initialized ? tr('Sign in with passkey', '用通行密钥登录') : tr('Create administrator passkey', '创建管理员通行密钥'), async () => {
    status.textContent = tr('Follow your device’s passkey prompt…', '请按设备提示完成通行密钥验证…');
    let code = setupCode || (input ? input.value.trim() : '');
    if (code.includes('#')) code = new URLSearchParams(code.split('#')[1]).get('setup') || '';
    try { await authenticate(initialized ? 'login' : 'setup', code); }
    catch (error) { status.textContent = errorText(error); status.className = 'error'; }
  }, 'primary');
  el(welcome, 'footer', tr('Agent tokens cannot sign in here. Administrator access requires your passkey.', 'Agent Token 无法登录此页面，管理权限需要你的通行密钥。'));
}
async function mutate(path, data) { const result = await api(path, {revision: state.revision, ...data}); await refresh(); return result; }
async function refresh() { state = await api('state'); render(); }
function render() {
  app.replaceChildren(); const identity = document.getElementById('identity'); identity.replaceChildren();
  el(identity, 'span', state.owner, 'muted');
  button(identity, tr('Sign out', '退出'), async () => { await api('auth/logout', {}); csrf = ''; state = null; dialogs.replaceChildren(); await welcome(true); });
  const nav = el(app, 'nav'); nav.setAttribute('aria-label', tr('Administration', '管理导航'));
  const tabs = [['overview', tr('Overview', '总览')], ['members', tr('Members', '家庭成员')], ['agents', tr('Agents', 'Agent 接入')], ['connections', tr('Connectors', '连接器')], ['permissions', tr('Permissions', '权限')]];
  for (const [key, label] of tabs) button(nav, label, () => { tab = key; render(); }, tab === key ? 'active' : '');
  ({overview, members, agents, connections, permissions})[tab]();
  const foot = el(app, 'footer'); el(foot, 'span', tr('Changes apply after active calls finish. Configuration changes invalidate outstanding approvals.', '配置在正在执行的调用结束后生效。修改配置会使未使用的审批失效。'));
}
function overview() {
  const hero = el(app, 'section', undefined, 'hero'); el(hero, 'p', tr('Ready when you are', '准备就绪'), 'eyebrow');
  el(hero, 'h1', tr('One gateway. Clear boundaries.', '一个网关，清晰的权限。'));
  el(hero, 'p', tr('Your administrator passkey is ready. Connect an account, then give your agent its own token.', '管理员通行密钥已就绪。连接账号，再为 Agent 创建独立 Token。'), 'muted');
  el(hero, 'code', state.mcp_url, 'url');
  const grid = el(app, 'div', undefined, 'grid');
  for (const [key, count, title, hint] of [
    ['members', state.members.length, tr('Household identities', '家庭身份'), tr('People and shared accounts stay separate.', '个人身份与共享身份分开管理。')],
    ['connections', state.connections.length, tr('Account connectors', '账号连接器'), tr('Start with demo notes, or connect your accounts.', '可先用模拟笔记，也可连接你的账号。')],
    ['agents', state.clients.length, tr('Agent credentials', 'Agent 凭据'), tr('Each token belongs to exactly one identity.', '每个 Token 只对应一个身份。')]]) {
    const card = el(grid, 'div', undefined, 'card'); el(card, 'p', String(count), 'count'); el(card, 'h3', title); el(card, 'p', hint, 'muted');
    button(card, tr('Manage', '管理'), () => { tab = key; render(); });
  }
  const card = el(app, 'section', undefined, 'card');
  el(card, 'h2', tr('Try the complete flow', '走一遍完整流程'));
  const steps = el(card, 'ol', undefined, 'steps');
  for (const text of [tr('Add or review a connector. Demo notes need no external account.', '添加或检查连接器。模拟笔记无需外部账号。'),
    tr('Run its read-only connection check.', '运行只读连接验证。'), tr('Inspect the permissions for each identity.', '检查各身份拥有的权限。'),
    tr('Create an agent token and connect it to the MCP endpoint above.', '创建 Agent Token，并连接上面的 MCP 地址。')]) el(steps, 'li', text);
}
function members() {
  const head = el(app, 'div', undefined, 'row between'); el(head, 'h1', tr('Household members', '家庭成员'));
  button(head, tr('Add member', '添加成员'), () => {
    const box = modal(tr('Add member', '添加成员')); const name = field(box, tr('Identity name', '身份名称'), 'member_id', '', 'text', tr('Lowercase letters, numbers, underscores, or hyphens.', '使用小写字母、数字、下划线或连字符。'));
    const shared = checkbox(box, tr('Shared household identity (no personal passkey)', '共享家庭身份（不注册个人通行密钥）'));
    button(box, tr('Add', '添加'), async () => { await mutate('members/add', {id: name.value, shared: shared.checked}); box.close(); }, 'primary');
  }, 'primary');
  const grid = el(app, 'div', undefined, 'grid');
  for (const member of state.members) {
    const card = el(grid, 'div', undefined, 'card'); el(card, 'h2', member.id);
    el(card, 'span', member.id === state.owner ? tr('Administrator', '管理员') : member.shared ? tr('Shared', '共享') : tr('Personal', '个人'), 'badge');
    el(card, 'p', member.shared ? tr('Give shared agents this identity.', '共享 Agent 使用此身份。') : tr(`${member.passkeys} passkey(s) registered`, `已注册 ${member.passkeys} 个通行密钥`), 'muted');
    const actions = el(card, 'div', undefined, 'actions');
    if (!member.shared) button(actions, tr('Register a passkey', '注册通行密钥'), async () => {
      const result = await api('members/enroll', {id: member.id}); secretResult(tr('Private registration link', '私密注册链接'), result.url, true);
    });
    if (member.id !== state.owner) button(actions, tr('Remove', '移除'), () => confirmAction(tr('Remove member?', '移除此成员？'), member.id, async () => mutate('members/remove', {id: member.id})), 'danger');
  }
  const card = el(app, 'section', undefined, 'card'); el(card, 'h2', tr('Registered passkeys', '已注册的通行密钥'));
  for (const key of state.passkeys) {
    const row = el(card, 'div', undefined, 'row between'); el(row, 'span', key.principal + ' · ' + key.id.slice(0, 12) + ' · ' + new Date(key.created * 1000).toLocaleDateString());
    button(row, tr('Revoke passkey', '撤销通行密钥'), () => confirmAction(tr('Revoke this passkey?', '撤销此通行密钥？'), tr('Sessions using it will also stop working.', '使用此通行密钥建立的管理会话也会失效。'), async () => { await api('passkeys/remove', {id: key.id}); await refresh(); }), 'danger');
  }
}
function agents() {
  const head = el(app, 'div', undefined, 'row between'); el(head, 'h1', tr('Agent access', 'Agent 接入'));
  button(head, tr('Create agent token', '创建 Agent Token'), () => {
    const box = modal(tr('Create agent token', '创建 Agent Token')); const name = field(box, tr('Agent name', 'Agent 名称'), 'client_id');
    const principal = select(box, tr('Identity', '身份'), 'principal', state.members.map(m => [m.id, m.id]), state.owner);
    el(box, 'p', tr('For an agent shared by several people, choose the shared household identity.', '多人共享的 Agent 应选择共享家庭身份。'), 'hint');
    button(box, tr('Create token', '创建 Token'), async () => { const result = await mutate('clients/create', {id: name.value, principal: principal.value}); box.close(); secretResult(tr('Save your agent token', '保存 Agent Token'), result.token); }, 'primary');
  }, 'primary');
  el(app, 'code', state.mcp_url, 'url');
  const table = el(el(app, 'div', undefined, 'table-wrap'), 'table'); const heading = el(el(table, 'thead'), 'tr');
  for (const name of [tr('Agent', 'Agent'), tr('Identity', '身份'), tr('Credentials', '凭据')]) el(heading, 'th', name);
  const body = el(table, 'tbody');
  for (const client of state.clients) {
    const row = el(body, 'tr'); el(row, 'td', client.id); el(row, 'td', client.principal); const actions = el(el(row, 'td'), 'div', undefined, 'actions');
    button(actions, tr('Rotate token', '轮换 Token'), () => confirmAction(tr('Replace this token?', '替换此 Token？'), tr('The old token will stop working immediately.', '旧 Token 将立即失效。'), async () => { const result = await mutate('clients/rotate', {id: client.id}); secretResult(tr('Save your new token', '保存新 Token'), result.token); }));
    button(actions, tr('Revoke', '撤销'), () => confirmAction(tr('Revoke agent access?', '撤销 Agent 接入？'), client.id, async () => mutate('clients/revoke', {id: client.id})), 'danger');
  }
}
function connections() {
  const head = el(app, 'div', undefined, 'row between'); el(head, 'h1', tr('Account connectors', '账号连接器'));
  button(head, tr('Add connector', '添加连接器'), () => connectorForm(), 'primary');
  el(app, 'p', tr('Credentials stay encrypted on the gateway. Read checks contact the actual upstream; demo checks use synthetic notes.', '凭据在网关加密保存。只读验证会连接对应服务；模拟笔记验证使用测试数据。'), 'muted');
  const grid = el(app, 'div', undefined, 'grid');
  for (const conn of state.connections) {
    const card = el(grid, 'div', undefined, 'card'); el(card, 'h2', conn.id, 'connector-title'); el(card, 'p', conn.owner + ' · ' + (state.catalog[conn.kind]?.label || tr('Custom YAML connector', 'YAML 自定义连接器')), 'muted');
    el(card, 'span', conn.test?.ok ? tr('Read check passed', '读取验证通过') : conn.connected ? tr('Tools connected · account not yet checked', '工具已连接 · 账号待验证') : tr('Connecting tools', '正在连接工具'), 'badge');
    if (conn.kind === 'demo') el(card, 'p', tr('Synthetic data. Notes reset when the connector restarts.', '模拟数据。连接器重启后笔记会重置。'), 'hint');
    if (conn.kind === 'reminders') el(card, 'p', tr('Experimental. Requires a helper in the account owner’s Mac login session.', '实验性功能。需要在账号所有者的 Mac 登录会话中运行辅助服务。'), 'hint');
    const actions = el(card, 'div', undefined, 'actions');
    if (conn.kind) {
      button(actions, tr('Test connection', '验证连接'), async () => { await api('connections/test', {id: conn.id}); await refresh(); notify(tr('Read-only connection check passed.', '只读连接验证通过。')); }, 'primary');
      button(actions, tr('Edit & review', '编辑并审阅'), () => connectorForm(conn));
    }
    button(actions, tr('Remove', '移除'), () => confirmAction(tr('Remove connector?', '移除连接器？'), tr('Its tools and permission rules will be removed.', '该连接器的工具和权限规则将一起移除。'), async () => mutate('connections/remove', {id: conn.id})), 'danger');
  }
}
function connectorForm(existing) {
  const box = modal(existing ? tr('Edit connector', '编辑连接器') : tr('Add connector', '添加连接器'));
  const form = el(box, 'form'); form.addEventListener('submit', e => e.preventDefault());
  const kind = select(form, tr('Service', '服务'), 'kind', Object.entries(state.catalog).map(([key, spec]) => [key, spec.label]), existing?.kind || 'demo'); kind.disabled = !!existing;
  const fixed = el(form, 'div', undefined, 'form-grid');
  const name = field(fixed, tr('Connector name', '连接器名称'), 'connection_id', existing?.id || '', 'text', tr('Up to 32 lowercase letters, numbers, underscores, or hyphens.', '最多 32 个小写字母、数字、下划线或连字符。')); name.disabled = !!existing;
  const owner = select(fixed, tr('Account owner', '账号所有者'), 'owner', state.members.map(m => [m.id, m.id]), existing?.owner || state.owner); owner.disabled = !!existing;
  const dynamic = el(form, 'div'); let settings = {}, credentials = {};
  const labels = {username: tr('Account email / username', '账号邮箱 / 用户名'), host: tr('IMAP server', 'IMAP 服务器'), port: tr('TLS port', 'TLS 端口'),
    url: tr('HTTPS service URL', '服务 HTTPS 地址'), timezone: tr('Time zone', '时区'), password: tr('App-specific password', 'App 专用密码'),
    client_id: tr('Google OAuth client ID', 'Google OAuth 客户端 ID'), client_secret: tr('Google OAuth client secret', 'Google OAuth 客户端密钥'),
    refresh_token: tr('Google refresh token', 'Google 刷新令牌'), token: tr('Helper bearer token', '辅助服务 Bearer Token')};
  function fields() {
    dynamic.replaceChildren(); settings = {}; credentials = {};
    const spec = state.catalog[kind.value];
    const defaults = {host: 'imap.mail.me.com', port: '993', url: kind.value === 'caldav' ? 'https://caldav.icloud.com' : '', timezone: 'UTC'};
    for (const key of spec.fields) settings[key] = field(dynamic, labels[key], key, existing?.settings[key] || defaults[key] || '');
    for (const key of spec.secrets) credentials[key] = field(dynamic, labels[key], key, '', 'password', existing ? tr('Leave blank to keep the saved value.', '留空保留已保存的值。') : '');
    if (kind.value === 'demo') el(dynamic, 'p', tr('No real account needed. Includes read tools and a demo write that requires passkey approval.', '无需真实账号。包含只读工具，以及一个需要通行密钥审批的模拟写入工具。'), 'hint');
    if (kind.value === 'gmail') {
      el(dynamic, 'p', tr('Create a Google OAuth client of type Web application. Register this exact callback URL:', '创建 Google「Web 应用」类型的 OAuth 客户端，并登记此完整回调地址：'), 'hint');
      el(dynamic, 'code', location.origin + '/admin/oauth/google/callback', 'url');
      el(dynamic, 'p', tr('Authorize read-only Gmail access below, or enter an existing refresh token above.', '点击下方按钮授予 Gmail 只读权限，也可在上方录入已有刷新令牌。'), 'muted');
      button(dynamic, tr('Authorize with Google', '通过 Google 授权'), async () => {
        const result = await api('oauth/start', values());
        location.assign(result.url);
      }, 'primary');
    }
    if (['imap', 'caldav'].includes(kind.value)) el(dynamic, 'p', tr('iCloud uses an app-specific password. The connector exposes read operations only.', 'iCloud 使用 App 专用密码。连接器只提供读取操作。'), 'hint');
  }
  kind.addEventListener('change', fields); fields();
  function values() {
    return {revision: state.revision, id: name.value, kind: kind.value, owner: owner.value,
      settings: Object.fromEntries(Object.entries(settings).map(([k, input]) => [k, input.value])),
      credentials: Object.fromEntries(Object.entries(credentials).map(([k, input]) => [k, input.value]))};
  }
  button(form, tr('Preview tools', '预览工具'), async () => {
    const result = await api('connections/preview', values());
    for (const input of Object.values(credentials)) input.value = '';
    showReview(result, box);
  }, 'primary');
}
function showReview(result, form) {
  const review = modal(tr('Review tool definitions', '审阅工具定义'));
  el(review, 'p', result.connection + ' · ' + result.owner, 'muted');
  if (result.google_account) el(review, 'p', tr('Authorized Google account: ', '已授权的 Google 账号：') + result.google_account, 'hint');
  el(review, 'p', tr('These descriptions and schemas are what agents will see. New connectors initially grant access only to their account owner.', 'Agent 将看到这些描述和参数定义。新连接器默认只授权给账号所有者。'), 'hint');
  for (const definition of result.definitions) { el(review, 'h3', definition.name); el(review, 'pre', JSON.stringify(definition, null, 2)); }
  const checked = checkbox(review, tr('I reviewed these definitions and permissions.', '我已审阅这些工具定义和权限。'));
  const apply = button(review, tr('Apply connector', '应用连接器'), async () => {
    await mutate('connections/apply', {draft: result.draft, reviewed: checked.checked}); review.close(); if (form) form.close(); notify(tr('Connector applied. Run its read check next.', '连接器已应用，请继续运行读取验证。'));
  }, 'primary'); apply.disabled = true; checked.addEventListener('change', () => { apply.disabled = !checked.checked; });
}
async function resumeGoogle() {
  if (!gmailResult) return;
  const id = gmailResult; gmailResult = null; history.replaceState(null, '', '/admin/');
  try { const result = await api('oauth/complete', {id}); tab = 'connections'; render(); showReview(result); }
  catch (error) { notify(errorText(error)); }
}
function permissions() {
  el(app, 'h1', tr('Inspect permissions', '检查权限'));
  el(app, 'p', tr('Unlisted access is denied. Approval-required tools still need a separate passkey decision for each exact call.', '未授权的访问默认拒绝。需要审批的工具，每次调用仍须对具体内容进行通行密钥审批。'), 'muted');
  if (!state.members.some(m => m.id === subject)) subject = state.owner;
  const person = select(app, tr('Inspect as', '以此身份检查'), 'inspect_principal', state.members.map(m => [m.id, m.id]), subject);
  person.addEventListener('change', () => { subject = person.value; render(); });
  const table = el(el(app, 'div', undefined, 'table-wrap'), 'table'); const heading = el(el(table, 'thead'), 'tr');
  for (const label of [tr('Tool / owner', '工具 / 所有者'), tr('Access', '访问权限'), tr('Changes', '修改')]) el(heading, 'th', label);
  const body = el(table, 'tbody');
  for (const conn of state.connections) for (const tool of conn.tools) {
    const row = el(body, 'tr'); const info = el(row, 'td'); el(info, 'strong', tool.name); el(info, 'div', conn.owner + ' · ' + conn.id, 'muted');
    if (tool.problem) el(info, 'span', tr('Disabled: ', '已停用：') + tool.problem, 'badge bad');
    if (Object.keys(tool.pin).length) el(info, 'pre', JSON.stringify(tool.pin));
    const settings = el(row, 'td'); const effect = select(settings, tr('Effect', '权限效果'), 'effect', [['deny', tr('Deny', '拒绝')], ['allow', tr('Allow', '允许')], ['approval_required', tr('Require approval', '需要审批')]], tool.permissions[subject]);
    const cross = conn.owner !== subject && !state.members.find(m => m.id === conn.owner)?.shared;
    const confirmed = cross ? checkbox(settings, tr('Explicitly share access to this other account', '明确允许访问另一人的账号'), tool.permissions[subject] !== 'deny') : null;
    const actions = el(el(row, 'td'), 'div', undefined, 'actions');
    button(actions, tr('Save access', '保存权限'), async () => { await mutate('permissions/save', {principal: subject, connection: conn.id, tool: tool.name, effect: effect.value, cross_account: confirmed?.checked || false}); notify(tr('Permissions updated.', '权限已更新。')); });
    button(actions, tr('Argument limits', '参数限制'), () => {
      const box = modal(tr('Argument limits', '参数限制')); el(box, 'p', tr('These restrictions apply to everyone using this exposed tool. Fixed arguments are hidden from agents. Changes invalidate pending approvals.', '这些限制适用于所有调用此工具的身份。固定参数对 Agent 隐藏。修改会使未使用的审批失效。'), 'muted');
      const pin = field(box, tr('Fixed arguments (JSON object)', '固定参数（JSON 对象）'), 'pin', JSON.stringify(tool.pin, null, 2), 'textarea');
      const allow = field(box, tr('Allowed values (JSON object of arrays)', '允许值（值为数组的 JSON 对象）'), 'allow_values', JSON.stringify(tool.allow_values, null, 2), 'textarea');
      button(box, tr('Save restrictions', '保存限制'), async () => { await mutate('tools/restrict', {connection: conn.id, tool: tool.name, pin: JSON.parse(pin.value), allow_values: JSON.parse(allow.value)}); box.close(); }, 'primary');
    });
  }
}
async function main() {
  try { const status = await api('status'); if (status.authenticated) { csrf = status.csrf; await refresh(); await resumeGoogle(); } else await welcome(status.initialized); }
  catch (error) { app.replaceChildren(); el(app, 'p', errorText(error), 'error'); }
}
main();
