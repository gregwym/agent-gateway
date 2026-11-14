// The approval page. Everything an agent chose (tool arguments, names) is put on the
// page with textContent only, and the CSP forbids inline script, so it stays text.
'use strict';

const ZH = (navigator.language || '').toLowerCase().startsWith('zh');
const TEXT = {
  title_pending: ['An agent is asking to do this', '有 Agent 请求执行以下操作'],
  title_approved: ['Approved', '已批准'],
  title_denied: ['Declined', '已拒绝'],
  title_cancelled: ['Withdrawn', '已撤回'],
  title_used: ['Approval used', '批准已使用'],
  title_expired: ['Expired', '已过期'],
  hint_pending: ['Read it carefully. Approving lets the agent run exactly this, once.', '请仔细核对。批准后，Agent 只能按下面的内容执行一次。'],
  hint_approved: ['The agent can now run exactly this, once, until the time below.', 'Agent 现在可以按下面的内容执行一次，截止时间如下。'],
  hint_used: ['This approval has been used and cannot be used again.', '这次批准已经用掉，不能再次使用。'],
  hint_gone: ['Nothing will be executed for this request.', '这个请求不会被执行。'],
  requested_by: ['Requested by', '请求方'],
  account: ['Account', '账号'],
  tool: ['Action', '操作'],
  decides: ['Who can decide', '谁可以决定'],
  until: ['Valid until', '有效期至'],
  decided_by: ['Decided by', '决定人'],
  outcome: ['Result', '执行结果'],
  arguments: ['Exact content', '具体内容'],
  no_arguments: ['(no longer stored)', '（已不再保存）'],
  approve: ['Approve with passkey', '用通行密钥批准'],
  deny: ['Decline', '拒绝'],
  cancel: ['Withdraw approval', '撤回批准'],
  enroll_title: ['Register a passkey', '注册通行密钥'],
  enroll_hint: ['This passkey will be able to approve actions on your accounts. The link works once.', '这个通行密钥将用于批准对你账号的操作。此链接只能使用一次。'],
  enroll: ['Register passkey', '注册通行密钥'],
  enrolled: ['Passkey registered. You can close this page.', '通行密钥已注册，可以关闭此页面。'],
  working: ['Waiting for your passkey…', '等待通行密钥验证…'],
  unsupported: ['This browser does not support passkeys.', '此浏览器不支持通行密钥。'],
  failed: ['Not done: ', '未完成：'],
};
const ERRORS = {
  not_found: ['No such request.', '没有这个请求。'],
  stale_request: ['The request has changed or is no longer open. Reload the page.', '请求已变化或已关闭，请刷新页面。'],
  expired_ceremony: ['That took too long. Try again.', '操作超时，请重试。'],
  verification_failed: ['The passkey could not be verified.', '通行密钥验证失败。'],
  not_enrolled: ['Nobody who can decide this has registered a passkey.', '可以决定此请求的人还没有注册通行密钥。'],
  invalid_enrollment_code: ['This link is invalid, expired or already used.', '此链接无效、已过期或已被使用。'],
  too_many_passkeys: ['Too many passkeys are registered already.', '已注册的通行密钥过多。'],
  rate_limited: ['Too many attempts. Try again in a few minutes.', '尝试次数过多，请几分钟后再试。'],
  wrong_origin: ['Open this page at the address your administrator configured.', '请通过管理员配置的地址打开此页面。'],
  invalid_argument: ['The request format is invalid. Reload this page.', '请求格式无效，请刷新页面。'],
  invalid_response: ['The browser returned an invalid passkey response. Retry with a supported browser.', '浏览器返回了无效的通行密钥响应，请使用支持的浏览器重试。'],
  no_such_passkey: ['That passkey is no longer registered.', '此通行密钥已不在注册列表中。'],
  ambiguous_passkey: ['The passkey ID matches more than one key. Use its complete ID.', '此通行密钥 ID 匹配多个密钥，请使用完整 ID。'],
  storage_full: ['The gateway disk is full. Ask its operator to free space.', '网关磁盘已满，请让管理员释放空间。'],
  storage_readonly: ['The gateway database is read-only. Ask its operator to fix the data mount.', '网关数据库为只读，请让管理员修复数据挂载。'],
  storage_permission_denied: ['The gateway cannot access its state files. Ask its operator to fix file permissions.', '网关无权访问数据文件，请让管理员修复文件权限。'],
  storage_missing: ['A required gateway file is missing. Ask its operator to restore it.', '网关所需文件缺失，请让管理员恢复。'],
  storage_busy: ['The gateway database is busy. Wait briefly and retry.', '网关数据库正忙，请稍后重试。'],
  storage_corrupt: ['The gateway database is damaged. Ask its operator to restore a verified backup.', '网关数据库损坏，请让管理员恢复经过验证的备份。'],
  storage_unavailable: ['The gateway could not read or save this decision. Ask its operator to check storage using the error ID.', '网关无法读取或保存此次决定，请让管理员根据错误编号检查存储。'],
  credential_store_unavailable: ['The gateway could not verify its encrypted credentials. Ask its operator to check the encryption key.', '网关无法验证加密凭据，请让管理员检查加密密钥。'],
  invalid_configuration: ['The gateway configuration is invalid. Ask its operator to correct it.', '网关配置无效，请让管理员修正。'],
  operation_failed: ['The gateway encountered an unexpected error. Ask its operator to inspect the error ID.', '网关发生未预期错误，请让管理员根据错误编号排查。'],
};
const t = (key) => TEXT[key][ZH ? 1 : 0];
const app = document.getElementById('app');

function el(parent, tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  parent.append(node);
  return node;
}

const fromB64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function api(path, body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  let response, data;
  try {
    response = await fetch('/approvals/api/' + path, {signal: controller.signal, ...(body === undefined ? {} : {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})});
    data = await response.json();
  } catch (error) {
    const message = error.name === 'AbortError' ? ['The request timed out. Reload to check its status before retrying.', '请求超时，请刷新确认状态后再重试。']
      : error.name === 'SyntaxError' ? [`The gateway returned an unreadable response (HTTP ${response?.status}).`, `网关返回了无法解析的响应（HTTP ${response?.status}）。`]
      : ['Could not reach the gateway. Check your network and Tailscale connection.', '无法连接网关，请检查网络和 Tailscale 连接。'];
    throw new Error(message[ZH ? 1 : 0]);
  } finally { clearTimeout(timer); }
  if (!response.ok) {
    const known = ERRORS[data?.error];
    let message = known ? known[ZH ? 1 : 0] : [`The gateway rejected this request (HTTP ${response.status}).`, `网关拒绝了此请求（HTTP ${response.status}）。`][ZH ? 1 : 0];
    if (/^[a-f0-9]{12}$/.test(data?.incident || '')) message += (ZH ? ' 错误编号：' : ' Error ID: ') + data.incident;
    throw new Error(message);
  }
  return data;
}

async function passkey(action, target) {
  if (!window.PublicKeyCredential) throw new Error(t('unsupported'));
  const start = await api('begin', {action, target});
  const options = start.options.publicKey;
  options.challenge = fromB64(options.challenge);
  for (const key of ['allowCredentials', 'excludeCredentials']) {
    if (options[key]) options[key] = options[key].map((c) => ({...c, id: fromB64(c.id)}));
  }
  if (options.user) options.user.id = fromB64(options.user.id);
  const credential = await navigator.credentials[action === 'enroll' ? 'create' : 'get']({publicKey: options});
  const response = {clientDataJSON: toB64(credential.response.clientDataJSON)};
  for (const key of ['attestationObject', 'authenticatorData', 'signature', 'userHandle']) {
    if (credential.response[key]) response[key] = toB64(credential.response[key]);
  }
  return api('finish', {ceremony_id: start.ceremony_id, response: {
    id: credential.id, rawId: toB64(credential.rawId), type: credential.type, response,
    clientExtensionResults: credential.getClientExtensionResults()}});
}

function act(parent, label, cls, run) {
  const button = el(parent, 'button', label, cls);
  button.addEventListener('click', async () => {
    const buttons = parent.querySelectorAll('button');
    buttons.forEach((b) => { b.disabled = true; });
    const status = document.getElementById('status');
    status.className = 'muted';
    status.textContent = t('working');
    try {
      await run();
    } catch (error) {
      status.className = 'notice bad';
      const browserErrors = {NotAllowedError: ['Passkey verification was cancelled or timed out.', '通行密钥验证已取消或超时。'],
        InvalidStateError: ['This passkey is already registered.', '此通行密钥已注册。'],
        SecurityError: ['Open this page at the gateway’s configured HTTPS address.', '请通过网关配置的 HTTPS 地址打开此页面。'],
        NotSupportedError: ['This browser or authenticator does not support the requested passkey operation.', '此浏览器或认证设备不支持此次通行密钥操作。']};
      status.textContent = t('failed') + (browserErrors[error.name]?.[ZH ? 1 : 0] || error.message || error.name);
      status.setAttribute('role', 'alert');
      buttons.forEach((b) => { b.disabled = false; });
    }
  });
}

function row(list, label, value) {
  if (value === null || value === undefined || value === '') return;
  el(list, 'dt', label);
  el(list, 'dd', String(value));
}

function showRequest(request) {
  const identity = (id) => {
    return request.names?.[id] || id;
  };
  app.replaceChildren();
  const open = request.status === 'pending' || request.status === 'approved';
  el(app, 'h1', t('title_' + request.status));
  el(app, 'p', t(request.status === 'pending' ? 'hint_pending' : request.status === 'approved' ? 'hint_approved'
    : request.status === 'used' ? 'hint_used' : 'hint_gone'), 'muted');

  const facts = el(el(app, 'div', undefined, 'card'), 'dl');
  row(facts, t('requested_by'), request.client);
  row(facts, t('account'), request.service + ' / ' + request.account);
  row(facts, t('tool'), request.tool + ' (' + request.upstream_tool + ')');
  if (request.status === 'pending') row(facts, t('decides'), request.approvers.map(identity).join(', '));
  if (open) row(facts, t('until'), new Date(request.expires * 1000).toLocaleString());
  row(facts, t('decided_by'), request.decided_by ? identity(request.decided_by) : null);
  row(facts, t('outcome'), request.outcome);

  const content = el(app, 'div', undefined, 'card');
  el(content, 'p', t('arguments'), 'muted');
  el(content, 'pre', request.arguments === null ? t('no_arguments') : JSON.stringify(request.arguments, null, 2));

  const actions = el(app, 'div', undefined, 'actions');
  const decide = (action) => async () => showRequest((await passkey(action, request.id)).request);
  if (request.status === 'pending') {
    act(actions, t('deny'), 'stop', decide('deny'));
    act(actions, t('approve'), 'go', decide('approve'));
  } else if (request.status === 'approved') {
    act(actions, t('cancel'), 'stop', decide('cancel'));
  }
  el(app, 'p', '', 'muted').id = 'status';
}

function showEnrollment(code) {
  el(app, 'h1', t('enroll_title'));
  el(app, 'p', t('enroll_hint'), 'muted');
  const actions = el(app, 'div', undefined, 'actions');
  act(actions, t('enroll'), 'go', async () => {
    await passkey('enroll', code);
    app.replaceChildren();
    el(app, 'h1', t('enroll_title'));
    el(app, 'p', t('enrolled'), 'notice ok');
  });
  el(app, 'p', '', 'muted').id = 'status';
}

async function main() {
  const parts = location.pathname.split('/').filter(Boolean);
  try {
    if (parts[1] === 'enroll') {
      const code = location.hash.slice(1);
      history.replaceState(null, '', location.pathname);  // keep the one-time code out of the address bar
      showEnrollment(code);
    } else {
      showRequest(await api('request/' + encodeURIComponent(parts[2] || '')));
    }
  } catch (error) {
    app.replaceChildren();
    el(app, 'p', error.message, 'notice bad');
  }
}
main();
