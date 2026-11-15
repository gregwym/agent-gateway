'use strict';
const zh = (navigator.language || '').toLowerCase().startsWith('zh');
const tr = (en, cn) => zh ? cn : en;
document.documentElement.lang = zh ? 'zh-CN' : 'en';
const app = document.getElementById('app');
const dialogs = document.getElementById('dialogs');
let csrf = '', state = null, tab = 'overview', subject = '', noticeTimer;
const advancedConnections = new Set();
let setupCode = new URLSearchParams(location.hash.slice(1)).get('setup') || '';
let gmailResult = new URLSearchParams(location.search).get('gmail');
const navigationError = document.querySelector('meta[name="gateway-error"]');
if (navigationError) history.replaceState(null, '', '/admin/');
if (location.hash) history.replaceState(null, '', location.pathname);
const messages = {
  login_required: ['Your session expired. Sign in again.', '会话已过期，请重新登录。'],
  invalid_setup_link: ['This setup link is invalid, expired, or already used.', '设置链接无效、已过期或已被使用。'],
  verification_failed: ['Passkey verification failed. Try again.', '通行密钥验证失败，请重试。'],
  configuration_changed: ['Configuration changed in another window. Refresh and try again.', '其他窗口已修改配置，请刷新后重试。'],
  connector_unavailable: ['Connector initialization or communication failed unexpectedly. Use the error ID to locate the gateway failure.', '连接器初始化或通信发生未预期故障，请使用错误编号定位网关故障。'],
  connector_internal_error: ['The connector encountered an internal error while reading the service. Use the error ID to locate it.', '连接器在读取服务时发生内部错误，请使用错误编号定位。'],
  connector_login_or_read_failed: ['Login or the read check failed. Check account credentials and permissions.', '登录或读取验证失败，请检查账号凭据和权限。'],
  imap_credentials_rejected: ['The mail server rejected the username or password. Edit this connector and check the mailbox username; iCloud requires an app-specific password.', '邮件服务器拒绝了用户名或密码。请编辑连接器，核对邮箱用户名；iCloud 需要使用 App 专用密码。'],
  imap_server_unreachable: ['The mail server could not be reached or its TLS connection failed. Check the server, port, and network.', '无法连接邮件服务器，或 TLS 连接失败。请检查服务器地址、端口和网络。'],
  connector_timeout: ['The connection check timed out. Check the upstream server and network, then try again.', '连接验证超时。请检查上游服务器和网络后重试。'],
  connector_tls_failed: ['TLS certificate verification failed. Check the server certificate and gateway clock.', 'TLS 证书验证失败，请检查服务器证书和网关时间。'],
  connector_dns_failed: ['The server hostname could not be resolved. Check its spelling and gateway DNS.', '无法解析服务器域名，请检查地址拼写和网关 DNS。'],
  connector_network_failed: ['The network connection failed or was closed. Check the service address, port, and network access.', '网络连接失败或被关闭，请检查服务地址、端口及网络访问。'],
  connector_executable_missing: ['The connector program is missing on the gateway. Repair its deployment.', '网关缺少连接器程序，请修复部署。'],
  connector_executable_denied: ['The gateway cannot execute the connector program. Check host file permissions.', '网关无权执行连接器程序，请检查主机文件权限。'],
  connector_process_exited: ['The connector process exited before completing the request. Check its required settings and host installation.', '连接器进程在请求完成前退出，请检查必要配置及主机安装。'],
  connector_protocol_error: ['The connector rejected the MCP request or returned an invalid protocol response.', '连接器拒绝了 MCP 请求，或返回了无效的协议响应。'],
  connector_auth_rejected: ['The upstream service rejected the saved token. Update this connector’s credentials.', '上游服务拒绝了已保存的 Token，请更新连接器凭据。'],
  connector_access_denied: ['The upstream account lacks permission for this read operation. Check its grants.', '上游账号没有执行此次读取的权限，请检查授权。'],
  connector_endpoint_missing: ['The service returned HTTP 404. Check the complete MCP endpoint URL.', '服务返回 HTTP 404，请检查完整的 MCP 接口地址。'],
  connector_rate_limited: ['The upstream service rate-limited this request. Wait before retrying.', '上游服务限制了请求频率，请稍后重试。'],
  connector_http_error: ['The upstream service returned an HTTP error. Check that the configured URL serves MCP and that the service is healthy.', '上游服务返回 HTTP 错误，请检查该地址是否提供 MCP 服务，以及服务是否正常。'],
  connector_request_rejected: ['The upstream service refused the read request. Check account access and service settings.', '上游服务拒绝了读取请求，请检查账号访问权限和服务配置。'],
  connector_resource_missing: ['The upstream calendar or resource no longer exists. Check the service URL.', '上游日历或资源不存在，请检查服务地址。'],
  caldav_credentials_rejected: ['The calendar server rejected the username or password. Check the Apple Account and app-specific password.', '日历服务器拒绝了用户名或密码，请核对 Apple 账号和 App 专用密码。'],
  caldav_server_unreachable: ['The calendar server connection failed. Check its HTTPS URL, certificate, and network.', '日历服务器连接失败，请检查 HTTPS 地址、证书和网络。'],
  gmail_authorization_rejected: ['Google rejected the stored authorization. Check the OAuth client and authorize this account again.', 'Google 拒绝了已保存的授权，请核对 OAuth 客户端并重新授权此账号。'],
  gmail_server_unreachable: ['The gateway could not connect to Google. Check DNS, TLS, and outbound HTTPS access.', '网关无法连接 Google，请检查 DNS、TLS 和出站 HTTPS 访问。'],
  gmail_request_rejected: ['Gmail refused the read request or is temporarily unavailable. Check account/API access and retry later.', 'Gmail 拒绝了读取请求或暂不可用，请检查账号及 API 访问并稍后重试。'],
  reminders_permission_required: ['macOS has not granted Reminders access to the helper. Enable it on the helper Mac.', 'macOS 尚未授予辅助程序提醒事项访问权限，请在运行辅助程序的 Mac 上授权。'],
  already_initialized: ['Setup is already complete. Sign in with the administrator passkey.', '首次设置已完成，请使用管理员通行密钥登录。'],
  not_initialized: ['The administrator has no passkey yet. Open the private setup link first.', '管理员尚未注册通行密钥，请先打开私密设置链接。'],
  expired_ceremony: ['Passkey verification expired. Start it again.', '通行密钥验证已过期，请重新开始。'],
  rate_limited: ['Too many passkey attempts are in progress. Wait a few minutes and retry.', '正在进行的通行密钥验证过多，请几分钟后重试。'],
  invalid_argument: ['The request format is invalid. Reload the page and check the form.', '请求格式无效，请刷新页面并检查表单。'],
  csrf_required: ['The page’s login verification no longer matches. Refresh or sign in again.', '页面的登录校验已失效，请刷新或重新登录。'],
  request_too_large: ['The submitted form is too large. Reduce the argument restrictions or pasted content.', '提交的表单过大，请减少参数限制或粘贴内容。'],
  not_found: ['This member, token, connector, or tool no longer exists. Refresh the page.', '此成员、Token、连接器或工具已不存在，请刷新页面。'],
  unknown_member: ['The selected member no longer exists. Refresh and select an existing member.', '选择的成员不存在，请刷新并选择现有成员。'],
  invalid_member_name: ['Enter a name of 1–80 characters without control characters.', '名字需为 1–80 个字符，不能包含控制字符。'],
  duplicate_member: ['This member name already exists. Choose a different name.', '已有成员使用这个名字，请使用不同名字。'],
  duplicate_household: ['This household name already exists.', '此家庭名称已存在。'],
  unknown_household: ['This household no longer exists. Refresh and select a household.', '此家庭已不存在，请刷新并选择所属家庭。'],
  unknown_agent: ['Select an existing Agent before assigning tool permissions.', '请先选择现有 Agent，再配置工具权限。'],
  outside_household: ['The Agent and connection belong to different households.', '此 Agent 与连接不属于同一个家庭。'],
  shared_identity_removed: ['A household is not a member. Add a person here; choose the household as owner for shared connections.', '家庭不是成员。请在这里添加个人，共享连接的所有者请选择家庭。'],
  member_limit: ['The gateway has reached its limit of 50 members. Remove an unused member first.', '网关已达到 50 个成员的上限，请先移除不再使用的成员。'],
  cannot_remove_member: ['The administrator identity cannot be removed; other members must still exist.', '不能移除管理员身份；其他待移除成员必须仍然存在。'],
  invalid_client_name: ['Agent names must start with a lowercase letter and contain up to 48 lowercase letters, numbers, underscores, or hyphens.', 'Agent 名称须以小写字母开头，最多 48 个小写字母、数字、下划线或连字符。'],
  duplicate_client: ['This Agent name already exists. Choose another name.', '此 Agent 名称已存在，请使用其他名称。'],
  client_limit: ['The gateway has reached its limit of 100 agents. Revoke an unused agent first.', '网关已达到 100 个 Agent 的上限，请先撤销不再使用的 Agent。'],
  connector_limit: ['The gateway has reached its limit of 50 connectors. Remove an unused connector first.', '网关已达到 50 个连接器的上限，请先移除不再使用的连接器。'],
  unsupported_connector: ['This custom connector has no built-in read check. Configure it on the gateway host.', '此自定义连接器没有内置的读取验证，请在网关主机上配置。'],
  missing_upstream_tool: ['The connector did not provide a tool required by its template. Check the connector version.', '连接器没有提供模板要求的工具，请检查连接器版本。'],
  too_many_drafts: ['There are already 16 pending previews or authorizations. Complete one or wait 10 minutes for expiry.', '已有 16 个待处理预览或授权，请先完成一个，或等待 10 分钟过期。'],
  review_required: ['Check the box confirming that you reviewed the tool definitions before applying.', '请先勾选已审阅工具定义，再应用连接器。'],
  https_url_required: ['Use an HTTPS service URL without embedded credentials, query parameters, or a fragment.', '请使用 HTTPS 服务地址，且不要在地址中包含凭据、查询参数或片段。'],
  invalid_timezone: ['The time zone is unknown. Use an IANA name such as America/Los_Angeles or UTC.', '无法识别此时区，请使用 America/Los_Angeles 或 UTC 等 IANA 时区名称。'],
  missing_host: ['Enter the IMAP server hostname.', '请填写 IMAP 服务器域名。'],
  missing_port: ['Enter the TLS port.', '请填写 TLS 端口。'],
  missing_timezone: ['Enter the calendar time zone.', '请填写日历时区。'],
  invalid_permission_effect: ['Choose Deny, Allow, or Require approval.', '请选择拒绝、允许或需要审批。'],
  invalid_connection_access: ['Choose a valid access scope and read/write approval settings.', '请选择有效的访问范围及读取、写入审批设置。'],
  connection_readonly: ['This connector has no write tools. Choose Read only.', '此连接器没有写入工具，请选择只读。'],
  invalid_connection_approver: ['Choose a member of this household, or any member of the household.', '请选择此家庭的一位成员，或家庭内任意成员。'],
  cross_account_required: ['This grants access to another person’s account. Select the explicit cross-account consent checkbox.', '此操作会开放其他个人账号，请勾选明确的跨账号授权选项。'],
  restrictions_object_required: ['Fixed arguments and allowed values must each be a JSON object.', '固定参数和允许值必须分别为 JSON 对象。'],
  restriction_conflict: ['The same argument cannot be both fixed and restricted to allowed values.', '同一个参数不能同时设为固定参数和允许值限制。'],
  allowed_values_required: ['Each allowed-values entry must be a non-empty JSON array.', '每个允许值条目必须是非空 JSON 数组。'],
  oauth_already_used: ['This Google callback was already used. Start authorization again.', '此次 Google 回调已使用，请重新发起授权。'],
  oauth_wrong_session: ['Google authorization belongs to another login session. Continue in the original session or start again.', '此次 Google 授权属于另一个登录会话，请回到原会话或重新授权。'],
  oauth_not_ready: ['Google authorization has not finished. Complete it before continuing.', 'Google 授权尚未完成，请先完成授权。'],
  oauth_refresh_token_missing: ['Google did not issue a refresh token. Reauthorize and allow offline access.', 'Google 没有返回刷新令牌，请重新授权并允许离线访问。'],
  oauth_client_rejected: ['Google rejected the OAuth client ID or secret. Check the Web application client settings.', 'Google 拒绝了 OAuth 客户端 ID 或密钥，请检查 Web 应用客户端配置。'],
  oauth_code_rejected: ['Google rejected the authorization code or callback URL. Check the exact redirect URI and authorize again.', 'Google 拒绝了授权码或回调地址，请核对完整重定向 URI 并重新授权。'],
  oauth_network_failed: ['The gateway could not reach Google’s authorization server. Check outbound HTTPS access.', '网关无法连接 Google 授权服务器，请检查出站 HTTPS 访问。'],
  oauth_profile_rejected: ['Google did not allow the Gmail account check. Confirm Gmail API access and the read-only grant.', 'Google 拒绝了 Gmail 账号验证，请确认 Gmail API 访问和只读授权。'],
  oauth_timeout: ['Google authorization timed out. Check network access and start authorization again.', 'Google 授权超时，请检查网络访问并重新授权。'],
  oauth_invalid_response: ['Google returned an invalid authorization or account response. Start authorization again.', 'Google 返回了无效的授权或账号响应，请重新授权。'],
  pin_unknown_argument: ['A fixed argument does not exist in this tool’s reviewed schema. Remove that argument.', '固定参数包含工具定义中不存在的参数，请移除此参数。'],
  allow_values_unknown_argument: ['An allowed-values restriction names an argument absent from this tool’s schema.', '允许值限制使用了工具定义中不存在的参数。'],
  missing_tool_lock: ['A tool has no reviewed definition. Edit and preview this connector again.', '工具缺少已审阅的定义，请编辑并重新预览连接器。'],
  invalid_tool_schema: ['The connector’s tool schema is invalid. Fix the connector before applying it.', '连接器的工具参数定义无效，请修复连接器后再应用。'],
  remote_tool_schema: ['The tool schema references a remote document. Only self-contained schemas are allowed.', '工具定义引用了远程文档；网关仅允许自包含的参数定义。'],
  storage_full: ['The gateway disk is full. Free space on the host, then retry.', '网关磁盘已满，请释放主机空间后重试。'],
  storage_readonly: ['The gateway data directory is read-only. Fix its host mount permissions.', '网关数据目录为只读，请修正主机挂载权限。'],
  storage_permission_denied: ['The gateway cannot access its saved state. Fix the data-directory ownership and permissions.', '网关无权访问保存的数据，请修正数据目录的所有者和权限。'],
  storage_missing: ['A required gateway state or key file is missing. Restore it on the host.', '网关所需的数据或密钥文件缺失，请在主机上恢复。'],
  storage_busy: ['The gateway database is locked by another operation. Wait briefly and retry.', '网关数据库被另一操作占用，请稍后重试。'],
  storage_corrupt: ['The gateway database is damaged. Restore a verified backup on the host.', '网关数据库损坏，请在主机上恢复经过验证的备份。'],
  storage_unavailable: ['The gateway could not read or save its state. Check host storage; use the error ID to locate the failure.', '网关无法读取或保存数据，请检查主机存储，并用错误编号定位故障。'],
  credential_store_unavailable: ['The encrypted credential store could not be read or verified. Check its file and encryption key on the host.', '无法读取或验证加密凭据存储，请检查主机上的加密文件和密钥。'],
  operation_failed: ['The server encountered an unexpected error. Use the error ID to locate it before retrying.', '服务器发生未预期错误，请用错误编号定位后重试。'],
  invalid_configuration: ['Check the values and account-sharing permission.', '请检查输入值和跨账号授权选项。'],
  invalid_connector_name: ['Connector names must start with a lowercase letter and use up to 32 lowercase letters, numbers, underscores, or hyphens.', '连接器名称须以小写字母开头，最多 32 个小写字母、数字、下划线或连字符。'],
  invalid_connector: ['Some connector fields are invalid. Check the form.', '连接器字段无效，请检查表单。'],
  invalid_imap_server: ['Check the IMAP server name and TLS port (1–65535).', '请检查 IMAP 服务器地址及 TLS 端口（1–65535）。'],
  invalid_smtp_server: ['Check the SMTP server name and port (1–65535).', '请检查 SMTP 服务器地址及端口（1–65535）。'],
  smtp_invalid_security: ['Choose STARTTLS or TLS for SMTP.', 'SMTP 加密方式请选择 STARTTLS 或 TLS。'],
  smtp_invalid_address: ['Enter a full sender email address, without a display name.', '请填写完整的发件邮箱地址，不要包含显示名称。'],
  smtp_credentials_rejected: ['SMTP rejected the username or app-specific password. Check the SMTP username in this connection; iCloud requires the full email address.', 'SMTP 拒绝了用户名或 App 专用密码。请核对本连接的 SMTP 用户名；iCloud 需要完整邮箱地址。'],
  smtp_not_configured: ['Set an SMTP server in this mail connection to enable sending.', '请在本邮箱连接中设置 SMTP 服务器以启用发信。'],
  smtp_tls_failed: ['SMTP TLS verification failed. Check the server, security mode and gateway clock.', 'SMTP TLS 验证失败，请检查服务器、加密方式和网关时间。'],
  smtp_dns_failed: ['The SMTP server hostname could not be resolved.', '无法解析 SMTP 服务器地址。'],
  smtp_not_supported: ['The SMTP server does not support the required TLS or authentication method. Check its port and security mode.', 'SMTP 服务器不支持所需的 TLS 或认证方式，请检查端口和加密方式。'],
  smtp_request_rejected: ['SMTP refused the connection or authentication request. Check server settings and account access.', 'SMTP 拒绝了连接或认证请求，请检查服务器设置及账号权限。'],
  smtp_unreachable: ['The SMTP server could not be reached or disconnected before submission. Check its server, port and network.', '无法连接 SMTP 服务器，或提交邮件前连接已断开，请检查服务器、端口和网络。'],
  missing_username: ['Enter the account email or username.', '请填写账号邮箱或用户名。'],
  missing_password: ['Enter the app-specific password.', '请填写 App 专用密码。'],
  missing_client_id: ['Enter the Google OAuth client ID.', '请填写 Google OAuth 客户端 ID。'],
  missing_client_secret: ['Enter the Google OAuth client secret.', '请填写 Google OAuth 客户端密钥。'],
  missing_refresh_token: ['Authorize with Google, or enter an existing refresh token.', '请先通过 Google 授权，或填写已有刷新令牌。'],
  missing_url: ['Enter the service HTTPS URL.', '请填写服务 HTTPS 地址。'],
  missing_token: ['Enter the helper bearer token.', '请填写辅助服务 Bearer Token。'],
  member_in_use: ['Remove this member’s clients, connectors, and permissions first.', '请先移除此成员的 Agent、连接器和权限。'],
  member_is_approver: ['This member is a connection approver. Select another approver for those connections before removing the member.', '此成员仍是连接的审批人，请先为这些连接选择其他审批人，再移除成员。'],
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
  const box = [...dialogs.querySelectorAll('dialog[open]')].at(-1);
  const node = box ? box.querySelector('.dialog-notice') || el(box, 'p', '', 'hint dialog-notice') : document.getElementById('notice');
  node.setAttribute('role', 'status'); node.textContent = text; node.style.display = 'block';
  clearTimeout(noticeTimer); noticeTimer = setTimeout(() => { if (box) node.remove(); else node.style.display = 'none'; }, 5500);
}
function errorText(error) {
  const known = {NotAllowedError: ['Passkey operation cancelled or timed out.', '通行密钥操作已取消或超时。'],
    InvalidStateError: ['This passkey is already registered. Use it to sign in.', '此通行密钥已注册，请用它登录。'],
    SecurityError: ['The browser rejected this passkey origin. Open the configured HTTPS address.', '浏览器拒绝了此通行密钥来源，请打开配置的 HTTPS 地址。'],
    NotSupportedError: ['This browser or authenticator does not support the requested passkey operation.', '此浏览器或认证设备不支持此次通行密钥操作。'],
    AbortError: ['The browser cancelled this operation. Try again.', '浏览器取消了此次操作，请重试。']};
  return known[error.name] ? tr(...known[error.name]) : error.message;
}
function showError(source, error) {
  const dialog = source.closest('dialog');
  const box = dialog?.open && dialog.isConnected ? dialog : app;
  let message = box.querySelector('.operation-error');
  if (!message) {
    message = el(box, 'p', '', 'error operation-error'); message.setAttribute('role', 'alert'); message.tabIndex = -1;
    box.insertBefore(message, box === app ? box.firstChild : box.children[2] || null);
  }
  message.textContent = errorText(error); message.scrollIntoView({block: 'nearest'}); message.focus();
}
async function api(path, body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45000);
  let response, data;
  try {
    response = await fetch('/admin/api/' + path, {signal: controller.signal, ...(body === undefined ? {} : {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, body: JSON.stringify(body)})});
    data = await response.json();
  } catch (error) {
    throw new Error(error.name === 'SyntaxError' ? tr(`The gateway returned an unreadable response (HTTP ${response?.status}). Refresh and check the service.`, `网关返回了无法解析的响应（HTTP ${response?.status}），请刷新并检查服务。`)
      : error.name === 'AbortError' ? tr('The request timed out. Refresh to check its status before retrying.', '请求超时，请刷新确认状态后再重试。')
      : tr('Could not reach the gateway. Check your connection and try again.', '无法连接网关，请检查连接后重试。'));
  } finally { clearTimeout(timer); }
  if (!response.ok) {
    if (response.status === 401) { csrf = ''; state = null; dialogs.replaceChildren(); await welcome(true); }
    throw serverError(data, response.status);
  }
  return data;
}
function serverError(data, status) {
    const known = messages[data?.error];
    let message = known ? tr(...known) : tr(`The server rejected this request (HTTP ${status}).`, `服务器拒绝了此请求（HTTP ${status}）。`);
    const reasons = {missing: ['required field', '必填字段缺失'], string_pattern_mismatch: ['invalid name format: lowercase letters, numbers, underscores, or hyphens', '名称格式无效：仅支持小写字母、数字、下划线或连字符'],
      string_type: ['must be text', '必须是文本'], dict_type: ['must be a JSON object', '必须是 JSON 对象'], list_type: ['must be an array', '必须是数组'],
      literal_error: ['unsupported choice', '选项无效'], extra_forbidden: ['unknown field', '不支持此字段']};
    for (const field of Array.isArray(data?.fields) ? data.fields : []) {
      if (typeof field.path === 'string' && /^[a-zA-Z0-9_.]{1,160}$/.test(field.path)) message += ` ${field.path}: ${tr(...(reasons[field.reason] || ['invalid field value or configuration combination', '字段值或配置组合不合法']))}.`;
    }
    if (/^[a-f0-9]{12}$/.test(data?.incident || '')) message += tr(' Error ID: ', ' 错误编号：') + data.incident;
    return new Error(message);
}
function button(parent, label, action, cls = '', busyLabel = '') {
  const node = el(parent, 'button', label, cls); node.type = 'button';
  node.addEventListener('click', async () => {
    node.disabled = true;
    node.setAttribute('aria-busy', 'true');
    app.querySelector('.operation-error')?.remove();
    node.closest('dialog')?.querySelector('.operation-error')?.remove();
    if (busyLabel) node.textContent = busyLabel;
    try { await action(); } catch (error) { showError(node, error); }
    finally { node.disabled = false; node.removeAttribute('aria-busy'); node.textContent = label; }
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
function secretResult(title, value, isLink = false, fingerprint = '') {
  const box = modal(title);
  el(box, 'p', isLink ? tr('This private link expires in 15 minutes and works once.', '此私密链接 15 分钟后过期，只能使用一次。')
    : tr('Shown only now. Save it for this agent before closing.', '仅在此时显示。关闭前请保存到这个 Agent 的配置中。'), 'muted');
  const input = field(box, isLink ? tr('Registration link', '注册链接') : tr('Agent token', 'Agent Token'), 'secret', value, 'text'); input.readOnly = true; input.className = 'token';
  input.addEventListener('click', () => input.select());
  if (fingerprint) el(box, 'p', tr('Token check code (SHA-256, first 12): ', 'Token 核对码（SHA-256 前 12 位）：') + fingerprint, 'token-fingerprint');
  const actions = el(box, 'div', undefined, 'actions');
  button(actions, tr('Copy', '复制'), async () => {
    box.querySelector('.dialog-notice')?.remove();
    try { await navigator.clipboard.writeText(value); }
    catch {
      showError(input, new Error(tr('Copy failed: the browser did not allow clipboard access. The value is selected; copy it manually with your device’s Copy action.', '复制失败：浏览器未允许访问剪贴板。内容已全选，请使用设备的「复制」操作手动复制。')));
      input.focus(); input.select();
      return;
    }
    notify(tr('Copied', '已复制') + (fingerprint ? ' · ' + fingerprint : ''));
  });
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
function nameOf(id) { return [...state.members, ...state.households].find(member => member.id === id)?.name || id; }
function identityLabel(id) { return nameOf(id); }
function householdOptions() { return state.households.map(h => [h.id, h.name]); }
function renameMember(member, kind = 'members') {
  const box = modal(tr('Edit name', '修改名称'));
  const name = field(box, tr('Name', '名字'), 'name', member.name,
    'text', tr('Your permissions and existing passkeys stay the same.', '修改名称不会改变权限和现有通行密钥。'));
  name.maxLength = 80; name.required = true;
  button(box, tr('Save name', '保存名称'), async () => {
    if (!name.reportValidity()) return;
    await mutate(kind + '/rename', {id: member.id, name: name.value}); box.close();
    notify(tr('Name updated.', '名字已更新。'));
  }, 'primary');
}
function render() {
  app.replaceChildren(); const identity = document.getElementById('identity'); identity.replaceChildren();
  button(identity, nameOf(state.owner), () => renameMember(state.members.find(m => m.id === state.owner)), 'profile-name');
  button(identity, tr('Sign out', '退出'), async () => { await api('auth/logout', {}); csrf = ''; state = null; dialogs.replaceChildren(); await welcome(true); });
  const nav = el(app, 'nav'); nav.setAttribute('aria-label', tr('Administration', '管理导航'));
  const tabs = [['overview', tr('Overview', '总览')], ['members', tr('Members', '家庭成员')], ['agents', tr('Agents', 'Agent 接入')], ['connections', tr('Connectors', '连接器')], ['permissions', tr('Permissions', '权限')]];
  for (const [key, label] of tabs) button(nav, label, () => { tab = key; render(); }, tab === key ? 'active' : '');
  ({overview, members, agents, connections, permissions})[tab]();
  const foot = el(app, 'footer'); el(foot, 'span', tr('Access and connector changes apply after active calls finish and invalidate outstanding approvals.', '接入和权限配置在正在执行的调用结束后生效，并使未使用的审批失效。'));
}
function overview() {
  const hero = el(app, 'section', undefined, 'hero'); el(hero, 'p', tr('Ready when you are', '准备就绪'), 'eyebrow');
  el(hero, 'h1', tr('One gateway. Clear boundaries.', '一个网关，清晰的权限。'));
  el(hero, 'p', tr('Your administrator passkey is ready. Connect an account, then give your agent its own token.', '管理员通行密钥已就绪。连接账号，再为 Agent 创建独立 Token。'), 'muted');
  el(hero, 'code', state.mcp_url, 'url');
  const grid = el(app, 'div', undefined, 'grid');
  for (const [key, count, title, hint] of [
    ['members', state.members.length, tr('Household members', '家庭成员'), tr('Members and agents belong to a household.', '成员和 Agent 都有明确的家庭归属。')],
    ['connections', state.connections.length, tr('Account connectors', '账号连接器'), tr('Start with demo notes, or connect your accounts.', '可先用模拟笔记，也可连接你的账号。')],
    ['agents', state.clients.length, tr('Agent credentials', 'Agent 凭据'), tr('Each agent has its own tool permissions.', '每个 Agent 单独配置工具权限。')]]) {
    const card = el(grid, 'div', undefined, 'card'); el(card, 'p', String(count), 'count'); el(card, 'h3', title); el(card, 'p', hint, 'muted');
    button(card, tr('Manage', '管理'), () => { tab = key; render(); });
  }
  const card = el(app, 'section', undefined, 'card');
  el(card, 'h2', tr('Try the complete flow', '走一遍完整流程'));
  const steps = el(card, 'ol', undefined, 'steps');
  for (const text of [tr('Add or review a connector. Demo notes need no external account.', '添加或检查连接器。模拟笔记无需外部账号。'),
    tr('Run its read-only connection check.', '运行只读连接验证。'), tr('Grant specific tools to your agent.', '为 Agent 授予所需工具的权限。'),
    tr('Create an agent token and connect it to the MCP endpoint above.', '创建 Agent Token，并连接上面的 MCP 地址。')]) el(steps, 'li', text);
}
function members() {
  const head = el(app, 'div', undefined, 'row between'); el(head, 'h1', tr('Household members', '家庭成员'));
  for (const household of state.households) {
    const card = el(app, 'section', undefined, 'card'); el(card, 'h2', household.name);
    el(card, 'p', tr('This household contains its members, agents, and shared accounts. Tool access is granted to individual agents.', '家庭包含成员、Agent 和共享账号。工具权限逐个授予 Agent。'), 'muted');
    button(card, tr('Rename household', '修改家庭名称'), () => renameMember(household, 'households'));
  }
  button(head, tr('Add member', '添加成员'), () => {
    const box = modal(tr('Add member', '添加成员')); const name = field(box, tr('Name', '名字'), 'member_name');
    name.required = true; name.maxLength = 80;
    const household = select(box, tr('Household', '所属家庭'), 'household', householdOptions());
    button(box, tr('Add', '添加'), async () => { if (!name.reportValidity()) return; await mutate('members/add', {name: name.value, household: household.value}); box.close(); }, 'primary');
  }, 'primary');
  const grid = el(app, 'div', undefined, 'grid');
  for (const member of state.members) {
    const card = el(grid, 'div', undefined, 'card'); el(card, 'h2', nameOf(member.id));
    el(card, 'span', member.id === state.owner ? tr('Administrator', '管理员') : tr('Member', '成员'), 'badge');
    el(card, 'p', nameOf(member.household), 'muted');
    el(card, 'p', tr(`${member.passkeys} passkey(s) registered`, `已注册 ${member.passkeys} 个通行密钥`), 'muted');
    const actions = el(card, 'div', undefined, 'actions');
    button(actions, tr('Edit name', '修改名称'), () => renameMember(member));
    button(actions, tr('Register a passkey', '注册通行密钥'), async () => {
      const result = await api('members/enroll', {id: member.id}); secretResult(tr('Private registration link', '私密注册链接'), result.url, true);
    });
    if (member.id !== state.owner) button(actions, tr('Remove', '移除'), () => confirmAction(tr('Remove member?', '移除此成员？'), identityLabel(member.id), async () => mutate('members/remove', {id: member.id})), 'danger');
  }
  const card = el(app, 'section', undefined, 'card'); el(card, 'h2', tr('Registered passkeys', '已注册的通行密钥'));
  for (const key of state.passkeys) {
    const row = el(card, 'div', undefined, 'row between'); el(row, 'span', identityLabel(key.principal) + ' · ' + key.id.slice(0, 12) + ' · ' + new Date(key.created * 1000).toLocaleDateString());
    button(row, tr('Revoke passkey', '撤销通行密钥'), () => confirmAction(tr('Revoke this passkey?', '撤销此通行密钥？'), tr('Sessions using it will also stop working.', '使用此通行密钥建立的管理会话也会失效。'), async () => { await api('passkeys/remove', {id: key.id}); await refresh(); }), 'danger');
  }
}
function renameAgent(client) {
  const box = modal(tr('Rename Agent', '修改 Agent 名称'));
  const name = field(box, tr('Agent name', 'Agent 名称'), 'agent_name', client.id, 'text', tr('Start with a lowercase letter; use lowercase letters, numbers, underscores, or hyphens.', '以小写字母开头，可使用小写字母、数字、下划线或连字符。'));
  name.maxLength = 48; name.required = true;
  el(box, 'p', tr('Your token, MCP address, household, and tool permissions stay the same. Outstanding approvals must be requested again.', 'Token、MCP 地址、所属家庭和工具权限不变。尚未完成的审批需要重新发起。'), 'hint');
  button(box, tr('Save name', '保存名称'), async () => {
    name.value = name.value.trim();
    if (!name.reportValidity()) return;
    const result = await mutate('clients/rename', {id: client.id, name: name.value});
    if (subject === client.id) subject = result.id;
    box.close(); notify(tr('Agent renamed. Keep using the same token.', 'Agent 已改名，继续使用原来的 Token 即可。'));
  }, 'primary');
}
function agents() {
  const head = el(app, 'div', undefined, 'row between'); el(head, 'h1', tr('Agent access', 'Agent 接入'));
  button(head, tr('Create agent token', '创建 Agent Token'), () => {
    const box = modal(tr('Create agent token', '创建 Agent Token')); const name = field(box, tr('Agent name', 'Agent 名称'), 'client_id');
    const household = select(box, tr('Household', '所属家庭'), 'household', householdOptions());
    el(box, 'p', tr('A new agent starts with no tool access. Assign its permissions after creating the token.', '新 Agent 默认没有工具权限。创建 Token 后，请为它配置权限。'), 'hint');
    button(box, tr('Create token', '创建 Token'), async () => { const result = await mutate('clients/create', {id: name.value, household: household.value}); box.close(); secretResult(tr('Save your agent token', '保存 Agent Token'), result.token, false, result.fingerprint); }, 'primary');
  }, 'primary');
  el(app, 'code', state.mcp_url, 'url');
  const table = el(el(app, 'div', undefined, 'table-wrap'), 'table'); const heading = el(el(table, 'thead'), 'tr');
  for (const name of [tr('Agent', 'Agent'), tr('Household / access', '家庭 / 权限'), tr('Credentials', '凭据')]) el(heading, 'th', name);
  const body = el(table, 'tbody');
  for (const client of state.clients) {
    const row = el(body, 'tr'); const agent = el(row, 'td'); el(agent, 'div', client.id);
    button(agent, tr('Rename', '改名'), () => renameAgent(client));
    const access = el(row, 'td'); el(access, 'div', nameOf(client.household));
    el(access, 'p', client.tool_count ? tr(`${client.tool_count} tool(s) granted`, `已授权 ${client.tool_count} 个工具`) : tr('No tools granted. MCP will return an empty tool list.', '尚未授权工具，MCP 将返回空工具列表。'), 'muted');
    button(access, tr('Configure permissions', '配置权限'), () => { subject = client.id; tab = 'permissions'; render(); });
    const actions = el(el(row, 'td'), 'div', undefined, 'actions');
    el(actions, 'code', tr('Check code: ', '核对码：') + client.fingerprint, 'token-fingerprint');
    button(actions, tr('Check token', '核对 Token'), () => checkToken(client));
    button(actions, tr('Rotate token', '轮换 Token'), () => confirmAction(tr('Replace this token?', '替换此 Token？'), tr('The old token will stop working immediately.', '旧 Token 将立即失效。'), async () => { const result = await mutate('clients/rotate', {id: client.id}); secretResult(tr('Save your new token', '保存新 Token'), result.token, false, result.fingerprint); }));
    button(actions, tr('Revoke', '撤销'), () => confirmAction(tr('Revoke agent access?', '撤销 Agent 接入？'), client.id, async () => mutate('clients/revoke', {id: client.id})), 'danger');
  }
}
function checkToken(client) {
  const box = modal(tr('Check an existing token', '核对现有 Token'));
  el(box, 'p', tr('The pasted value is hashed only in this browser. It is not sent to the gateway or saved. This does not rotate your token.', '粘贴内容仅在此浏览器计算摘要，不会发送到网关或保存，也不会轮换 Token。'), 'hint');
  const input = field(box, tr('Token to check', '待核对的 Token'), 'check_token', '', 'password');
  const result = el(box, 'p', '', 'token-check-result'); result.setAttribute('role', 'status');
  button(box, tr('Compare check code', '比较核对码'), async () => {
    if (!input.value) throw new Error(tr('Paste the token to check.', '请粘贴待核对的 Token。'));
    const current = (await api('state')).clients.find(c => c.id === client.id);
    if (!current) throw new Error(tr(...messages.not_found));
    if (!crypto.subtle) throw new Error(tr('Use a browser with HTTPS and SHA-256 support.', '请使用支持 HTTPS 和 SHA-256 的浏览器。'));
    const digest = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))].map(n => n.toString(16).padStart(2, '0')).join('').slice(0, 12);
    const raw = await digest(input.value), cleaned = input.value.trim().replace(/^Bearer\s+/i, '').trim();
    const matched = raw === current.fingerprint;
    const formatting = !matched && cleaned !== input.value && await digest(cleaned) === current.fingerprint;
    result.className = 'token-check-result ' + (matched ? 'hint' : 'error');
    result.textContent = (matched ? tr('Check codes match.', '核对码一致。') : formatting ? tr('The value has extra whitespace or a Bearer prefix. Save only the plain token.', '输入包含多余空白或 Bearer 前缀，请只保存纯 Token。') : tr('Check codes differ. This is not the currently configured token.', '核对码不同，此值与当前配置的 Token 不一致。'))
      + tr(` Pasted: ${raw}; current: ${current.fingerprint}.`, ` 粘贴值：${raw}；当前：${current.fingerprint}。`);
    input.value = '';
  }, 'primary');
}
function connections() {
  const head = el(app, 'div', undefined, 'row between'); el(head, 'h1', tr('Account connectors', '账号连接器'));
  button(head, tr('Add connector', '添加连接器'), () => connectorForm(), 'primary');
  el(app, 'p', tr('Credentials stay encrypted on the gateway. Read checks contact the actual upstream; demo checks use synthetic notes.', '凭据在网关加密保存。只读验证会连接对应服务；模拟笔记验证使用测试数据。'), 'muted');
  const grid = el(app, 'div', undefined, 'grid');
  for (const conn of state.connections) {
    const card = el(grid, 'div', undefined, 'card'); el(card, 'h2', conn.id, 'connector-title'); el(card, 'p', identityLabel(conn.owner) + ' · ' + (state.catalog[conn.kind]?.label || tr('Custom YAML connector', 'YAML 自定义连接器')), 'muted');
    const failed = conn.test?.ok === false;
    el(card, 'span', failed ? tr('Read check failed', '读取验证失败') : conn.test?.ok ? tr('Read check passed', '读取验证通过') : conn.connected ? tr('Tools connected · account not yet checked', '工具已连接 · 账号待验证') : tr('Connecting tools', '正在连接工具'), failed ? 'badge bad' : 'badge');
    if (failed) el(card, 'p', serverError({error: conn.test.reason, incident: conn.test.incident}, 422).message, 'error').setAttribute('role', 'alert');
    if (conn.kind === 'demo') el(card, 'p', tr('Synthetic data. Notes reset when the connector restarts.', '模拟数据。连接器重启后笔记会重置。'), 'hint');
    if (conn.kind === 'reminders') el(card, 'p', tr('Experimental. Requires a helper in the account owner’s Mac login session.', '实验性功能。需要在账号所有者的 Mac 登录会话中运行辅助服务。'), 'hint');
    const actions = el(card, 'div', undefined, 'actions');
    if (conn.kind) {
      button(actions, tr('Test connection', '验证连接'), async () => {
        try { await api('connections/test', {id: conn.id}); }
        catch (error) { if (state) await refresh(); throw error; }
        await refresh(); notify(tr('Read-only connection check passed.', '只读连接验证通过。'));
      }, 'primary', tr('Testing connection…', '正在验证连接…'));
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
  name.required = true; name.maxLength = 32; name.pattern = '[a-z][a-z0-9_\\-]{0,31}';
  name.title = tr('Start with a lowercase letter; use lowercase letters, numbers, underscores, or hyphens.', '以小写字母开头，只用小写字母、数字、下划线或连字符。');
  const owner = select(fixed, tr('Account owner', '账号所有者'), 'owner', [...state.members.map(m => [m.id, m.name]), ...state.households.map(h => [h.id, tr('Household: ', '家庭共享：') + h.name])], existing?.owner || state.owner); owner.disabled = !!existing;
  const dynamic = el(form, 'div'); let settings = {}, credentials = {};
  const labels = {username: tr('Account email / username', '账号邮箱 / 用户名'), host: tr('IMAP server', 'IMAP 服务器'), port: tr('TLS port', 'TLS 端口'),
    smtp_host: tr('SMTP server (blank disables sending)', 'SMTP 服务器（留空关闭发信）'), smtp_port: tr('SMTP port', 'SMTP 端口'),
    smtp_security: tr('SMTP encryption', 'SMTP 加密方式'), smtp_username: tr('SMTP username (optional override)', 'SMTP 用户名（可选覆盖）'),
    smtp_sender: tr('Sender email (defaults to account email)', '发件邮箱（默认账号邮箱）'),
    url: tr('HTTPS service URL', '服务 HTTPS 地址'), timezone: tr('Time zone', '时区'), password: tr('App-specific password', 'App 专用密码'),
    client_id: tr('Google OAuth client ID', 'Google OAuth 客户端 ID'), client_secret: tr('Google OAuth client secret', 'Google OAuth 客户端密钥'),
    refresh_token: tr('Google refresh token', 'Google 刷新令牌'), token: tr('Helper bearer token', '辅助服务 Bearer Token')};
  function fields() {
    dynamic.replaceChildren(); settings = {}; credentials = {};
    const spec = state.catalog[kind.value];
    const defaults = {host: 'imap.mail.me.com', port: '993', smtp_host: !existing || (existing.settings.host || 'imap.mail.me.com') === 'imap.mail.me.com' ? 'smtp.mail.me.com' : '', smtp_port: '587', smtp_security: 'starttls', url: kind.value === 'caldav' ? 'https://caldav.icloud.com' : '', timezone: 'UTC'};
    for (const key of spec.fields) settings[key] = key === 'smtp_security' ? select(dynamic, labels[key], key, [['starttls', 'STARTTLS (587)'], ['tls', 'TLS (465)']], existing?.settings[key] ?? defaults[key]) : field(dynamic, labels[key], key, existing?.settings[key] ?? defaults[key] ?? '');
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
    if (kind.value === 'caldav') el(dynamic, 'p', tr('iCloud uses an app-specific password. The calendar connector exposes read operations only.', 'iCloud 使用 App 专用密码。日历连接器只提供读取操作。'), 'hint');
    if (kind.value === 'imap') {
      el(dynamic, 'p', tr('One mail account: IMAP reads and organizes mail; SMTP sends it. Both use the same saved password. Enable write access and choose approval settings in Permissions. Test connection checks IMAP and configured SMTP authentication without sending mail.', '一个邮箱账号：IMAP 读取和整理邮件，SMTP 发信，两者共用已保存的密码。请在「权限」中启用写入并选择审批方式。「测试连接」会检查 IMAP 及已配置的 SMTP 登录，不会发出邮件。'), 'hint');
      el(dynamic, 'p', tr('iCloud requires an app-specific password. SMTP uses the full email address; when the IMAP username has no domain, @icloud.com is added for SMTP. Other providers: enter their SMTP server or leave it blank.', 'iCloud 需要 App 专用密码。SMTP 使用完整邮箱地址；IMAP 用户名不带域名时，SMTP 自动补上 @icloud.com。其他服务商请填写对应的 SMTP 服务器，或留空关闭发信。'), 'muted');
    }
  }
  kind.addEventListener('change', fields); fields();
  function values() {
    return {revision: state.revision, id: name.value, kind: kind.value, owner: owner.value,
      settings: Object.fromEntries(Object.entries(settings).map(([k, input]) => [k, input.value])),
      credentials: Object.fromEntries(Object.entries(credentials).map(([k, input]) => [k, input.value]))};
  }
  button(form, tr('Preview tools', '预览工具'), async () => {
    name.value = name.value.trim();
    if (!name.checkValidity()) throw new Error(tr(...messages.invalid_connector_name));
    if (!form.reportValidity()) return;
    const result = await api('connections/preview', values());
    for (const input of Object.values(credentials)) input.value = '';
    showReview(result, box);
  }, 'primary', tr('Reading tool definitions…', '正在读取工具定义…'));
}
function showReview(result, form) {
  const review = modal(tr('Review tool definitions', '审阅工具定义'));
  el(review, 'p', result.connection + ' · ' + identityLabel(result.owner), 'muted');
  if (result.google_account) el(review, 'p', tr('Authorized Google account: ', '已授权的 Google 账号：') + result.google_account, 'hint');
  el(review, 'p', tr('These descriptions and schemas are what authorized agents will see. New connectors and newly added tools grant no access. After applying, choose the connection access and approval settings for each Agent in Permissions. Existing tool permissions are preserved.', '已获授权的 Agent 将看到这些描述和参数定义。新连接器和新增工具默认不开放访问。应用后，请在「权限」中为每个 Agent 选择连接权限及审批设置。原有工具权限会保留。'), 'hint');
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
  catch (error) { showError(app, error); }
}
function permissions() {
  el(app, 'h1', tr('Inspect permissions', '检查权限'));
  el(app, 'p', tr('Unlisted access is denied. Approval-required tools still need a separate passkey decision for each exact call.', '未授权的访问默认拒绝。需要审批的工具，每次调用仍须对具体内容进行通行密钥审批。'), 'muted');
  if (!state.clients.length) {
    el(app, 'p', tr('Create an Agent token first, then assign its tools here.', '请先创建 Agent Token，再在这里为它配置工具权限。'));
    button(app, tr('Create agent token', '创建 Agent Token'), () => { tab = 'agents'; render(); }); return;
  }
  if (!state.clients.some(c => c.id === subject)) subject = state.clients[0].id;
  const agent = state.clients.find(c => c.id === subject);
  const selected = select(app, tr('Agent', 'Agent'), 'inspect_agent', state.clients.map(c => [c.id, c.id]), subject);
  selected.addEventListener('change', () => { subject = selected.value; render(); });
  el(app, 'p', tr('Household: ', '所属家庭：') + nameOf(agent.household), 'muted');
  el(app, 'p', tr('These permissions apply to every person using this Agent. An Agent token does not identify the person chatting with it.', '这些权限适用于所有通过此 Agent 发起的调用。Agent Token 不识别当前和它聊天的人。'), 'hint');
  if (!state.connections.some(c => c.household === agent.household)) el(app, 'p', tr('This household has no connections yet. Add a connector first.', '此家庭尚无连接，请先添加连接器。'), 'muted');
  for (const conn of state.connections.filter(c => c.household === agent.household)) {
    const card = el(app, 'section', undefined, 'card permission-card'); card.dataset.connection = conn.id;
    el(card, 'h2', conn.id);
    el(card, 'p', tr('Account owner: ', '账号归属：') + nameOf(conn.owner), 'muted');
    const reads = conn.tools.filter(t => t.access === 'read').length, writes = conn.tools.length - reads;
    const current = conn.access[subject];
    const scope = current.startsWith('read_write') || current === 'read_approval_write_direct' ? 'read_write' : current === 'read_approval' ? 'read' : current;
    const options = [['none', tr('No access', '禁止访问')], ['read', tr('Read only', '只读')]];
    if (writes) options.push(['read_write', tr('Read and write', '读写')]);
    if (current === 'custom') options.push(['custom', tr('Custom — keep existing tool settings', '自定义（保留现有逐工具配置）')]);
    const mode = select(card, tr('Connection access', '连接权限'), 'connection_access', options, scope);
    if (!writes) el(card, 'p', tr('This connector only provides read operations.', '此连接器只提供读取操作，不支持写入。'), 'muted');
    el(card, 'p', tr(`${reads} read tool(s) · ${writes} write or unclassified tool(s)`, `${reads} 个读取工具 · ${writes} 个写入或未分类工具`), 'muted');
    const approvalFields = el(card, 'div', undefined, 'form-grid');
    const readSettings = el(approvalFields, 'div'), writeSettings = el(approvalFields, 'div');
    const choices = [['allow', tr('No approval', '无需审批')], ['approval_required', tr('Approve every operation', '每次操作都审批')]];
    const readApproval = select(readSettings, tr('Read approval', '读取审批'), 'read_approval', choices,
      ['read_approval', 'read_write_approval', 'read_approval_write_direct'].includes(current) ? 'approval_required' : 'allow');
    const writeApproval = select(writeSettings, tr('Write approval', '写入审批'), 'write_approval', choices,
      ['read_write_direct', 'read_approval_write_direct'].includes(current) ? 'allow' : 'approval_required');
    const approval = el(card, 'div');
    const members = state.members.filter(m => m.household === conn.household);
    const approver = select(approval, tr('Who can approve?', '由谁审批？'), 'connection_approver',
      [...members.map(m => [m.id, m.name]), [conn.household, tr('Any household member', '家庭内任意成员')]], conn.approver);
    el(approval, 'p', tr('Operations requiring approval show their exact contents for a one-use passkey decision. This approver setting applies to this connection for all Agents.', '需要审批的操作会展示具体内容，并通过通行密钥单独批准一次。此审批人设置适用于该连接的所有 Agent。'), 'hint');
    const enrollment = el(approval, 'p', '', 'muted');
    function feedback() {
      readSettings.hidden = !['read', 'read_write'].includes(mode.value);
      writeSettings.hidden = mode.value !== 'read_write';
      const required = (!readSettings.hidden && readApproval.value === 'approval_required') || (!writeSettings.hidden && writeApproval.value === 'approval_required');
      approval.hidden = !required && !(mode.value === 'custom' && conn.tools.some(t => t.permissions[subject] === 'approval_required'));
      const eligible = approver.value === conn.household ? members : members.filter(m => m.id === approver.value);
      enrollment.textContent = eligible.some(m => m.passkeys) ? '' : tr('No selected approver has a passkey yet. Register one under Members before approving requests.', '所选审批人尚未注册通行密钥，请先在家庭成员中注册，再处理审批。');
    }
    for (const input of [mode, readApproval, writeApproval, approver]) input.addEventListener('change', feedback);
    feedback();
    button(card, tr('Save connection access', '保存连接权限'), async () => {
      let access = mode.value;
      if (access === 'read' && readApproval.value === 'approval_required') access = 'read_approval';
      if (access === 'read_write') access = readApproval.value === 'approval_required'
        ? (writeApproval.value === 'approval_required' ? 'read_write_approval' : 'read_approval_write_direct')
        : (writeApproval.value === 'approval_required' ? 'read_write' : 'read_write_direct');
      await mutate('permissions/connection', {client: subject, connection: conn.id, access,
        ...(!approval.hidden ? {approver: approver.value} : {})});
      notify(tr('Connection permissions updated.', '连接权限已更新。'));
    }, 'primary');
    const details = el(card, 'details'); details.open = advancedConnections.has(conn.id);
    el(details, 'summary', tr('Advanced: individual tools and argument limits', '高级设置：逐工具权限与参数限制'));
    details.addEventListener('toggle', () => { if (details.open) advancedConnections.add(conn.id); else advancedConnections.delete(conn.id); });
    advancedPermissions(details, conn);
  }
}
function advancedPermissions(parent, conn) {
  el(parent, 'p', tr('Changing individual tools may produce a custom connection setting. Unclassified tools are treated as writes.', '逐工具修改后，连接权限可能显示为自定义。未分类工具按写入处理。'), 'muted');
  const table = el(el(parent, 'div', undefined, 'table-wrap'), 'table'); const heading = el(el(table, 'thead'), 'tr');
  for (const label of [tr('Tool / owner', '工具 / 所有者'), tr('Access', '访问权限'), tr('Changes', '修改')]) el(heading, 'th', label);
  const body = el(table, 'tbody');
  for (const tool of conn.tools) {
    const row = el(body, 'tr'); const info = el(row, 'td'); el(info, 'strong', tool.name); el(info, 'div', identityLabel(conn.owner) + ' · ' + conn.id, 'muted');
    if (tool.problem) el(info, 'span', tr('Disabled: ', '已停用：') + tool.problem, 'badge bad');
    if (Object.keys(tool.pin).length) el(info, 'pre', JSON.stringify(tool.pin));
    const settings = el(row, 'td');
    const choices = [['deny', tr('Deny', '拒绝')], ['allow', tr('Allow without approval', '允许，无需审批')], ['approval_required', tr('Require approval', '需要审批')]];
    const effect = select(settings, tr('Effect', '权限效果'), 'effect', choices, tool.permissions[subject]);
    el(info, 'span', tool.access === 'read' ? tr('Read', '读取') : tr('Write / unclassified', '写入 / 未分类'), 'badge');
    el(settings, 'p', tr('If approval is required: ', '需要审批时由以下成员批准：') + conn.approvers.map(nameOf).join(tr(' or ', ' 或 ')), 'hint');
    if (!conn.approvers.some(id => state.members.find(m => m.id === id)?.passkeys)) el(settings, 'p', tr('No approver has a passkey yet. Register one before using approval-required tools.', '审批人尚未注册通行密钥，需要审批的工具暂时无法执行。'), 'hint');
    const actions = el(el(row, 'td'), 'div', undefined, 'actions');
    button(actions, tr('Save access', '保存权限'), async () => { await mutate('permissions/save', {client: subject, connection: conn.id, tool: tool.name, effect: effect.value}); notify(tr('Permissions updated.', '权限已更新。')); });
    button(actions, tr('Argument limits', '参数限制'), () => {
      const box = modal(tr('Argument limits', '参数限制')); el(box, 'p', tr('These restrictions apply to everyone using this exposed tool. Fixed arguments are hidden from agents. Changes invalidate pending approvals.', '这些限制适用于所有调用此工具的身份。固定参数对 Agent 隐藏。修改会使未使用的审批失效。'), 'muted');
      const pin = field(box, tr('Fixed arguments (JSON object)', '固定参数（JSON 对象）'), 'pin', JSON.stringify(tool.pin, null, 2), 'textarea');
      const allow = field(box, tr('Allowed values (JSON object of arrays)', '允许值（值为数组的 JSON 对象）'), 'allow_values', JSON.stringify(tool.allow_values, null, 2), 'textarea');
      button(box, tr('Save restrictions', '保存限制'), async () => {
        let fixed, allowed;
        try { fixed = JSON.parse(pin.value); } catch { throw new Error(tr('Fixed arguments: invalid JSON. Check quotes and commas.', '固定参数：JSON 格式错误，请检查引号和逗号。')); }
        try { allowed = JSON.parse(allow.value); } catch { throw new Error(tr('Allowed values: invalid JSON. Check quotes and commas.', '允许值：JSON 格式错误，请检查引号和逗号。')); }
        await mutate('tools/restrict', {connection: conn.id, tool: tool.name, pin: fixed, allow_values: allowed}); box.close();
      }, 'primary');
    });
  }
}
async function main() {
  try {
    const status = await api('status'); if (status.authenticated) { csrf = status.csrf; await refresh(); await resumeGoogle(); } else await welcome(status.initialized);
    if (navigationError) { const error = JSON.parse(navigationError.content); showError(app, serverError(error, error.status)); }
  }
  catch (error) { app.replaceChildren(); el(app, 'p', errorText(error), 'error'); }
}
main();
