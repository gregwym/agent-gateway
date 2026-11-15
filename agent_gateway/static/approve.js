// The approval page. Everything an agent chose (tool arguments, names) is put on the
// page with textContent only, and the CSP forbids inline script, so it stays text.
'use strict';

let language, redraw, requestTimer;
try { language = localStorage.getItem('gateway.ui-language'); } catch {}
let ZH;
function setLanguage(preference) {
  ZH = preference === 'zh-CN' || (preference !== 'en' && (navigator.language || '').toLowerCase().startsWith('zh'));
  document.documentElement.lang = ZH ? 'zh-CN' : 'en';
}
setLanguage(language);
const TEXT = {
  title_pending: ['An agent is asking to do this', '有 Agent 请求执行以下操作'],
  title_approved: ['Approved', '已批准'],
  title_denied: ['Declined', '已拒绝'],
  title_cancelled: ['Withdrawn', '已撤回'],
  title_used: ['Approval used', '批准已使用'],
  title_running: ['Running', '正在执行'],
  title_succeeded: ['Completed', '已完成'],
  title_failed: ['Execution failed', '执行失败'],
  title_execution_unknown: ['Execution outcome unknown', '执行结果待核实'],
  title_member_review: ['Approve a member’s passkey', '批准成员的通行密钥'],
  hint_member_review: ['Confirm who registered this passkey before approving. Approving activates this key for the member below.', '请先核实登记人身份。批准后，这个通行密钥会为下方成员生效。'],
  hint_running: ['The gateway is executing the approved request.', '网关正在执行已批准的请求。'],
  hint_unknown: ['The operation may have run. Check the upstream before trying again.', '操作可能已执行，请先检查服务端结果。'],
  hint_previous_version: ['This request belongs to a previous gateway version. Ask the Agent to submit it again.', '此请求来自旧版网关，请让 Agent 重新发起。'],
  title_expired: ['Expired', '已过期'],
  hint_pending: ['Read it carefully. The gateway will run this exact request once after approval.', '请仔细核对。批准后，网关会自动按下面的内容执行一次。'],
  hint_approved: ['The approved request is queued and will run automatically.', '已批准，网关将自动执行。'],
  hint_used: ['This approval has been used and cannot be used again.', '这次批准已经用掉，不能再次使用。'],
  hint_gone: ['Nothing will be executed for this request.', '这个请求不会被执行。'],
  requested_by: ['Requested by', '请求方'],
  account: ['Account', '账号'],
  connection: ['Connector', '连接器'],
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
  enroll_hint: ['Create a passkey on this device. Agent-issued links require administrator approval after registration.', '请在这台设备创建通行密钥。通过 Agent 发起的登记需要管理员批准后才会生效。'],
  enroll: ['Register passkey', '注册通行密钥'],
  enrolled: ['Passkey registered. You can close this page.', '通行密钥已注册，可以关闭此页面。'],
  enrollment_pending: ['Passkey created. It will be active after administrator approval. Send this review link to the administrator.', '通行密钥已创建，管理员批准后才会生效。请将下面的审阅链接发给管理员。'],
  enrollment_review_link: ['Administrator review link', '管理员审阅链接'],
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
  administrator_passkey_required: ['The administrator must register their own passkey first.', '管理员需要先登记自己的通行密钥。'],
  enrollment_member_unavailable: ['The member or requesting Agent is no longer eligible.', '成员或发起登记的 Agent 已不符合条件。'],
  passkey_already_registered: ['This passkey was already submitted. Use the existing registration request.', '这个通行密钥已提交，请使用之前的登记请求。'],
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
    picker.disabled = true;
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
    } finally {
      picker.disabled = false;
    }
  });
}

function row(list, label, value) {
  if (value === null || value === undefined || value === '') return;
  el(list, 'dt', label);
  el(list, 'dd', String(value));
}

function showRequest(request) {
  clearTimeout(requestTimer);
  redraw = () => showRequest(request);
  const identity = (id) => {
    return request.names?.[id] || id;
  };
  app.replaceChildren();
  const open = request.status === 'pending' || request.status === 'approved';
  const status = request.automatic && request.status === 'used'
    ? (!request.outcome ? 'running' : request.outcome === 'ok' ? 'succeeded'
      : request.outcome === 'execution_unknown' ? 'execution_unknown' : request.outcome === 'configuration_changed' ? 'cancelled' : 'failed')
    : request.status;
  el(app, 'h1', t(request.enrollment && status === 'pending' ? 'title_member_review' : 'title_' + status));
  const hint = request.outcome === 'previous_version' ? 'hint_previous_version'
    : status === 'pending' ? (request.enrollment ? 'hint_member_review' : 'hint_pending')
    : status === 'approved' ? 'hint_approved'
    : status === 'running' ? 'hint_running' : status === 'execution_unknown' ? 'hint_unknown'
    : status === 'used' ? 'hint_used' : ['succeeded', 'failed'].includes(status) ? null : 'hint_gone';
  if (hint) el(app, 'p', t(hint), 'muted');
  if (request.automatic && ['approved', 'running'].includes(status)) {
    requestTimer = setTimeout(async () => {
      try { showRequest(await api('request/' + encodeURIComponent(request.id))); }
      catch { /* A temporary network failure can be checked by reloading. */ }
    }, 800);
  }

  const facts = el(el(app, 'div', undefined, 'card'), 'dl');
  row(facts, t('requested_by'), request.client);
  row(facts, t('account'), request.service + ' / ' + request.account);
  if (request.connection !== request.account) row(facts, t('connection'), request.connection);
  row(facts, t('tool'), request.tool + ' (' + request.upstream_tool + ')');
  if (request.status === 'pending') row(facts, t('decides'), request.approvers.map(identity).join(', '));
  if (open) row(facts, t('until'), new Date(request.expires * 1000).toLocaleString(ZH ? 'zh-CN' : 'en'));
  row(facts, t('decided_by'), request.decided_by ? identity(request.decided_by) : null);
  const outcomes = {
    ok: ['Completed', '已完成'],
    tool_error: ['The upstream tool reported an error.', '服务端工具返回错误。'],
    upstream_unavailable: ['The upstream service was unavailable.', '服务端暂不可用。'],
    upstream_rejected: ['The upstream service rejected the request.', '服务端拒绝了请求。'],
    execution_unknown: ['The upstream did not confirm an outcome.', '服务端未确认执行结果。'],
    previous_version: ['This request predates the current gateway version.', '此请求来自旧版本。'],
    configuration_changed: ['The connection, authorization or tool changed.', '连接、权限或工具已变化。'],
    approver_key_revoked: ['The approving passkey was revoked.', '批准此请求的通行密钥已被撤销。'],
    enrollment_member_unavailable: ['The member or requesting Agent is no longer eligible.', '成员或发起登记的 Agent 已不符合条件。'],
    too_many_passkeys: ['The member already has the maximum number of passkeys.', '成员的通行密钥数量已达上限。'],
    passkey_already_registered: ['This passkey was already registered.', '这个通行密钥已注册。'],
  };
  row(facts, t('outcome'), outcomes[request.outcome]?.[ZH ? 1 : 0] || request.outcome);

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
  redraw = () => showEnrollment(code);
  app.replaceChildren();
  el(app, 'h1', t('enroll_title'));
  el(app, 'p', t('enroll_hint'), 'muted');
  const actions = el(app, 'div', undefined, 'actions');
  act(actions, t('enroll'), 'go', async () => {
    const result = await passkey('enroll', code);
    redraw = () => {
      app.replaceChildren();
      el(app, 'h1', t('enroll_title'));
      el(app, 'p', t(result.pending ? 'enrollment_pending' : 'enrolled'), 'notice ok');
      if (result.pending) {
        const link = el(app, 'a', t('enrollment_review_link'));
        link.href = result.approval_url;
        el(app, 'p', result.approval_url);
      }
    };
    redraw();
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

const picker = document.getElementById('language');
picker.value = ['en', 'zh-CN'].includes(language) ? language : 'auto';
picker.addEventListener('change', () => {
  try { localStorage.setItem('gateway.ui-language', picker.value); } catch {}
  setLanguage(picker.value);
  redraw?.();
});
main();
