'use strict';
const zh = (navigator.language || '').toLowerCase().startsWith('zh');
const tr = (en, cn) => zh ? cn : en;
document.documentElement.lang = zh ? 'zh-CN' : 'en';
const app = document.getElementById('app');
const dialogs = document.getElementById('dialogs');
const version = document.getElementById('gateway-version');
const tabUrls = {overview: '/admin/', members: '/admin/members', agents: '/admin/agents',
  connections: '/admin/connections', permissions: '/admin/permissions'};
let csrf = '', state = null, subject = '', dismissNotice;
const filters = {connections: "", permissions: ""};
let setupCode = new URLSearchParams(location.hash.slice(1)).get('setup') || '';
let gmailResult = new URLSearchParams(location.search).get('gmail');
let mcpOAuthResult = new URLSearchParams(location.search).get('mcp_oauth');
const navigationError = document.querySelector('meta[name="gateway-error"]');
if (navigationError) history.replaceState(null, '', '/admin/');
if (setupCode) history.replaceState(null, '', location.pathname + location.search);
window.addEventListener('popstate', () => { dialogs.replaceChildren(); if (state) render(); });
function navigate(key, replace = false) {
  const url = tabUrls[key];
  if (url === location.pathname + location.search + location.hash) return;
  if (replace) history.replaceState(null, '', url);
  else history.pushState(null, '', url);
  render();
}
const messages = {
  registry_query_invalid: ['Enter a service name between 3 and 100 characters.', '请输入 3 到 100 字符的服务名称。'],
  registry_cursor_invalid: ['This results page is no longer available. Search again.', '此结果页已无法读取，请重新搜索。'],
  registry_rate_limited: ['The MCP Registry is limiting requests. Try again shortly or enter the endpoint manually.', 'MCP Registry 正在限制请求，请稍后重试或手动填写接口地址。'],
  registry_timeout: ['The MCP Registry did not respond in time. Try again or enter the endpoint manually.', 'MCP Registry 响应超时，请重试或手动填写接口地址。'],
  registry_response_invalid: ['The MCP Registry returned data the gateway could not read. Try again or enter the endpoint manually.', '网关无法读取 MCP Registry 返回的数据，请重试或手动填写接口地址。'],
  registry_unavailable: ['The gateway could not reach the MCP Registry or the registry returned an error. Try again or enter the endpoint manually.', '网关无法访问 MCP Registry，或目录返回了错误。请重试或手动填写接口地址。'],
  oauth_refresh_busy: ['An OAuth request is still running. Wait for it to finish and revoke again.', 'OAuth 请求仍在执行，请等待结束后再次撤销授权。'],
  oauth_registration_rejected: ['The provider rejected automatic client registration. Use a registered client or check its supported client settings.', '服务商拒绝自动注册客户端，请使用已注册客户端，或检查其支持的客户端配置。'],
  oauth_discovery_failed: ['OAuth metadata is invalid or does not match this MCP resource or issuer. Check the server configuration.', 'OAuth 元数据无效，或与 MCP 资源、issuer 不匹配，请检查服务器配置。'],
  oauth_callback_invalid: ['The authorization response failed state or issuer validation. Start authorization again.', '授权回调的 state 或 issuer 校验失败，请重新授权。'],
  oauth_reauthorization_required: ["OAuth authorization is missing, expired, or revoked. Authorize this connection again.", "OAuth 授权缺失、过期或已撤销，请重新授权此连接。"],
  oauth_issuer_required: ["Enter the authorization server issuer for this registered OAuth client.", "使用已注册的 OAuth 客户端时，请填写授权服务器的 issuer 地址。"],
  oauth_issuer_changed: ["The discovered authorization server differs from the configured issuer. Check the MCP address and issuer.", "发现的授权服务器与配置的 issuer 不一致，请核对 MCP 地址和 issuer。"],
  oauth_client_settings_invalid: ["Check the OAuth client ID, secret and token authentication method. Use either a registered client or a client metadata URL.", "请核对 OAuth 客户端 ID、密钥和 Token 认证方式；已注册客户端与客户端元数据 URL 只能选一种。"],
  oauth_metadata_missing: ["The server did not publish usable OAuth metadata. Check its MCP and authorization-server configuration.", "服务器没有提供有效的 OAuth 元数据，请检查 MCP 及授权服务器配置。"],
  oauth_pkce_required: ["The authorization server must support PKCE S256.", "授权服务器必须支持 PKCE S256。"],
  oauth_client_registration_required: ["This server does not support automatic client registration. Enter a registered client ID and issuer.", "此服务器不支持自动注册客户端，请填写已注册的客户端 ID 和 issuer。"],
  oauth_scope_rejected: ["The authorization does not permit this operation. Reauthorize with the required scopes.", "当前授权范围不允许此操作，请使用所需 scope 重新授权。"],
  oauth_token_rejected: ["The authorization server rejected the token request. Check client settings and authorize again.", "授权服务器拒绝了 Token 请求，请检查客户端设置并重新授权。"],
  oauth_refresh_failed: ["The authorization server could not refresh the token. Check its availability and retry.", "授权服务器未能刷新 Token，请检查服务可用性后重试。"],
  oauth_not_required: ["This MCP endpoint did not request OAuth. Select no authentication or check the endpoint URL.", "此 MCP 接口没有请求 OAuth，请选择无需认证或核对接口地址。"],
  invalid_remote_settings: ["Choose a valid authentication mode and a service ID using lowercase letters, digits, underscores or hyphens.", "请选择有效认证方式；服务标识只能使用小写字母、数字、下划线或连字符。"],
  invalid_remote_token: ["The credential contains a newline or control character. Paste only the credential value.", "凭据包含换行或控制字符，请只粘贴凭据本身。"],
  invalid_credential_header: ["Enter an API-key header such as X-API-Key. Routing and protocol headers cannot hold credentials.", "请填写 X-API-Key 等 API 密钥 Header，路由和协议 Header 不能用于凭据。"],
  invalid_remote_tool_list: ["The server returned duplicate tool names, more than 1,000 tools, or a list that did not finish within 50 pages.", "服务器返回了重复工具名、超过 1,000 个工具，或工具列表超过 50 页仍未结束。"],
  remote_tool_selection_required: ["Select at least one tool and classify it as read or write.", "请至少选择一个工具，并标明读取或写入。"],
  invalid_remote_tool_selection: ["The tool selection is invalid. Preview the current tools again.", "工具选择无效，请重新预览当前工具。"],
  remote_no_tools: ["This MCP server returned no tools for the current authorization.", "此 MCP 服务器没有为当前授权返回工具。"],

  login_required: ['Your session expired. Sign in again.', '会话已过期，请重新登录。'],
  invalid_setup_link: ['This setup link is invalid, expired, or already used.', '设置链接无效、已过期或已被使用。'],
  verification_failed: ['Passkey verification failed. Try again.', '通行密钥验证失败，请重试。'],
  configuration_changed: ['Configuration changed in another window. Refresh and try again.', '其他窗口已修改配置，请刷新后重试。'],
  admin_busy: ['Another configuration change or connection check is still running. Wait for it to finish; this request was not applied.', '另一项配置变更或连接检查仍在运行，请等待其完成；本次请求未应用。'],
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
  connector_auth_rejected: ['The upstream service rejected or requires authentication. Check the authentication method and credentials.', '上游服务拒绝认证或要求提供认证，请检查连接的认证方式和凭据。'],
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
  connection_tools_update_required: ['New write tools are available for this connection. Review and enable them before choosing Read and write.', '此连接有新增写入工具，请先审阅并启用，再选择读写。'],
  invalid_connection_approver: ['Choose a member of this household, or any member of the household.', '请选择此家庭的一位成员，或家庭内任意成员。'],
  cross_account_required: ['This grants access to another person’s account. Select the explicit cross-account consent checkbox.', '此操作会开放其他个人账号，请勾选明确的跨账号授权选项。'],
  restrictions_object_required: ['Fixed arguments and allowed values must each be a JSON object.', '固定参数和允许值必须分别为 JSON 对象。'],
  restriction_conflict: ['The same argument cannot be both fixed and restricted to allowed values.', '同一个参数不能同时设为固定参数和允许值限制。'],
  allowed_values_required: ['Each allowed-values entry must be a non-empty JSON array.', '每个允许值条目必须是非空 JSON 数组。'],
  oauth_already_used: ['This OAuth callback was already used. Start authorization again.', '此次 OAuth 回调已使用，请重新发起授权。'],
  oauth_wrong_session: ['OAuth authorization belongs to another login session. Continue in the original session or start again.', '此次 OAuth 授权属于另一个登录会话，请回到原会话或重新授权。'],
  oauth_not_ready: ['OAuth authorization has not finished. Complete it before continuing.', 'OAuth 授权尚未完成，请先完成授权。'],
  oauth_refresh_token_missing: ['OAuth did not issue a refresh token. Reauthorize and allow offline access.', 'OAuth 没有返回刷新令牌，请重新授权并允许离线访问。'],
  oauth_client_rejected: ['OAuth rejected the OAuth client ID or secret. Check the Web application client settings.', 'OAuth 拒绝了 OAuth 客户端 ID 或密钥，请检查 Web 应用客户端配置。'],
  oauth_code_rejected: ['OAuth rejected the authorization code or callback URL. Check the exact redirect URI and authorize again.', 'OAuth 拒绝了授权码或回调地址，请核对完整重定向 URI 并重新授权。'],
  oauth_network_failed: ['The gateway could not reach the authorization server. Check outbound HTTPS access.', '网关无法连接 OAuth 授权服务器，请检查出站 HTTPS 访问。'],
  oauth_profile_rejected: ['Google did not allow the Gmail account check. Confirm Gmail API access and the read-only grant.', 'Google 拒绝了 Gmail 账号验证，请确认 Gmail API 访问和只读授权。'],
  oauth_timeout: ['OAuth authorization timed out. Check network access and start authorization again.', 'OAuth 授权超时，请检查网络访问并重新授权。'],
  oauth_invalid_response: ['OAuth returned an invalid authorization or account response. Start authorization again.', 'OAuth 返回了无效的授权或账号响应，请重新授权。'],
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
  duplicate_connector: ['This connector name already exists. Choose another name.', '此连接器名称已存在，请使用其他名称。'],
  invalid_mailbox_email: ['Enter a full mailbox email address.', '请填写完整的邮箱地址。'],
  invalid_mailbox_aliases: ['Enter up to 50 full email addresses, one per line.', '请填写完整的邮箱别名，每行一个，最多 50 个。'],
  invalid_connector: ['Some connector fields are invalid. Check the form.', '连接器字段无效，请检查表单。'],
  connector_review_required: ['Preview tools to review this new MCP endpoint before saving.', '请先预览并审阅这个新 MCP 地址的工具，再保存。'],
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
  oauth_declined: ['OAuth authorization was cancelled. No connector was changed.', 'OAuth 授权已取消，连接器未发生变更。'],
  oauth_failed: ['OAuth authorization failed. Check the web OAuth client and callback URL.', 'OAuth 授权失败，请检查网页 OAuth 客户端和回调地址。'],
  gmail_access_invalid: ['Choose a Gmail permissions preset.', '请选择 Gmail 权限。'],
  gmail_scope_mismatch: ['Google did not grant the selected Gmail permissions. Authorize again and approve the requested access.', 'Google 授予的权限与所选范围不一致。请重新授权并批准所请求的权限。'],
  gmail_reauthorize_required: ['Authorize with Google again to change this client or its Gmail permissions.', '要更换客户端或 Gmail 权限，请重新通过 Google 授权。'],
  gmail_readonly_required: ['Google must grant exactly Gmail read-only access.', 'Google 必须只授予 Gmail 只读权限。'],
  oauth_expired: ['OAuth authorization expired. Start again.', 'OAuth 授权已过期，请重新开始。'],
  active_calls_busy: ['Calls are still running. No configuration was changed; try again shortly.', '仍有调用正在执行，配置未变更，请稍后重试。'],
};
function el(parent, tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  parent.append(node); return node;
}
function notify(text) {
  dismissNotice?.();
  const box = [...dialogs.querySelectorAll('dialog[open]')].at(-1);
  const node = box ? box.querySelector('.dialog-notice') || el(box, 'p', '', 'hint dialog-notice') : document.getElementById('notice');
  node.setAttribute('role', 'status'); node.textContent = text; node.style.display = 'block';
  dismissNotice = () => {
    clearTimeout(timer);
    if (box) node.remove(); else node.style.display = 'none';
    dismissNotice = null;
  };
  const timer = setTimeout(dismissNotice, 5500);
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
async function api(path, body, timeoutMs = 45000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response, data;
  try {
    response = await fetch('/admin/api/' + path, {signal: controller.signal, ...(body === undefined ? {} : {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, body: JSON.stringify(body)})});
    data = await response.json();
  } catch (error) {
    const failure = new Error(error.name === 'SyntaxError' ? tr(`The gateway returned an unreadable response (HTTP ${response?.status}). Refresh and check the service.`, `网关返回了无法解析的响应（HTTP ${response?.status}），请刷新并检查服务。`)
      : error.name === 'AbortError' ? tr('The request timed out. Refresh to check its status before retrying.', '请求超时，请刷新确认状态后再重试。')
      : tr('Could not reach the gateway. Check your connection and try again.', '无法连接网关，请检查连接后重试。'));
    failure.code = error.name === 'AbortError' ? 'request_timeout' : 'network_error';
    throw failure;
  } finally { clearTimeout(timer); }
  if (!response.ok) {
    if (response.status === 401 && data?.error === 'login_required') { csrf = ''; state = null; dialogs.replaceChildren(); await welcome(true); }
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
    const error = new Error(message); error.code = data?.error; return error;
}
function button(parent, label, action, cls = '', busyLabel = '') {
  const text = typeof label === 'function' ? label : () => label;
  const node = el(parent, 'button', text(), cls); node.type = 'button';
  node.addEventListener('click', async () => {
    node.disabled = true;
    node.setAttribute('aria-busy', 'true');
    app.querySelector('.operation-error')?.remove();
    node.closest('dialog')?.querySelector('.operation-error')?.remove();
    if (busyLabel) node.textContent = busyLabel;
    try { await action(); } catch (error) { showError(node, error); }
    finally { node.disabled = false; node.removeAttribute('aria-busy'); node.textContent = text(); }
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
  const box = el(dialogs, 'dialog'); box.setAttribute('aria-label', title); el(box, 'h2', title);
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
  version.hidden = true;
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
function permissionMatches(path, data, current) {
  const conn = current.connections.find(c => c.id === data.connection);
  if (!conn) return false;
  if (path === 'permissions/save') return conn.tools.find(t => t.name === data.tool)?.permissions[data.client] === data.effect;
  return path === 'permissions/connection' && conn.access[data.client] === data.access &&
    (data.approver === undefined || conn.approver === data.approver);
}
async function mutate(path, data) {
  const revision = state.revision, permission = path.startsWith('permissions/');
  let result;
  try { result = await api(path, {revision, ...data}); }
  catch (error) {
    if (!permission || !['request_timeout', 'network_error'].includes(error.code)) throw error;
    let current;
    try { current = await api('state', undefined, 10000); } catch (_) { throw error; }
    state = current; render();
    if (current.revision > revision && permissionMatches(path, data, current)) return {revision: current.revision, recovered: true};
    throw new Error(tr('Could not confirm that the requested permissions were saved. The latest settings are shown; check them before retrying.', '尚未确认所选权限已保存。已显示最新设置，请核对后再重试。'));
  }
  try { await refresh(); }
  catch (error) {
    if (permission) throw new Error(tr('Permissions were saved, but the page could not reload them. Refresh to display the saved settings; do not submit again.', '权限已保存，但页面未能重新读取。请刷新以显示已保存设置，无需重复提交。'));
    throw error;
  }
  return result;
}
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
  const tab = Object.keys(tabUrls).find(key => tabUrls[key] === location.pathname) || 'overview';
  version.textContent = 'v' + state.version; version.hidden = false;
  app.replaceChildren(); const identity = document.getElementById('identity'); identity.replaceChildren();
  button(identity, nameOf(state.owner), () => renameMember(state.members.find(m => m.id === state.owner)), 'profile-name');
  button(identity, tr('Sign out', '退出'), async () => { await api('auth/logout', {}); csrf = ''; state = null; dialogs.replaceChildren(); await welcome(true); });
  const nav = el(app, 'nav'); nav.setAttribute('aria-label', tr('Administration', '管理导航'));
  const tabs = [['overview', tr('Overview', '总览')], ['members', tr('Members', '家庭成员')], ['agents', tr('Agents', 'Agent 接入')], ['connections', tr('Connectors', '连接器')], ['permissions', tr('Permissions', '权限')]];
  for (const [key, label] of tabs) {
    const link = el(nav, 'a', label, tab === key ? 'button active' : 'button');
    link.href = tabUrls[key];
    if (tab === key) link.setAttribute('aria-current', 'page');
    link.addEventListener('click', event => {
      if (event.button || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault(); navigate(key);
    });
  }
  ({overview, members, agents, connections, permissions})[tab]();
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
    button(card, tr('Manage', '管理'), () => navigate(key));
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
    el(access, 'p', client.tool_count ? tr(`${client.tool_count} tool(s) granted`, `已授权 ${client.tool_count} 个工具`) : tr('No tools granted. Tool search will return no available tools.', '尚未授权工具，工具搜索将不会返回可用工具。'), 'muted');
    button(access, tr('Configure permissions', '配置权限'), () => { subject = client.id; navigate('permissions'); });
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
function connectorNameField(parent, value = '') {
  const name = field(parent, tr('Connector name', '连接器名称'), 'connection_id', value, 'text',
    tr('Start with a lowercase letter. Use up to 32 lowercase letters, numbers, underscores, or hyphens.', '以小写字母开头，最多 32 个小写字母、数字、下划线或连字符。'));
  name.required = true; name.maxLength = 32; name.pattern = '[a-z][a-z0-9_\\-]{0,31}';
  name.title = tr(...messages.invalid_connector_name);
  return name;
}
function renameConnector(conn, details) {
  const revision = state.revision;
  const box = modal(tr('Rename connector', '修改连接器名称'));
  const name = connectorNameField(box, conn.id);
  el(box, 'p', tr('Update workflows that use this name. Pending approvals will expire.',
    '请更新使用旧名称的工作流。待审批请求将失效。'), 'hint');
  button(box, tr('Save name', '保存名称'), async () => {
    name.value = name.value.trim();
    if (!name.checkValidity()) throw new Error(tr(...messages.invalid_connector_name));
    await mutate('connections/rename', {revision, id: conn.id, name: name.value});
    box.close();
    details.close(); notify(tr('Connector renamed.', '连接器已改名。'));
  }, 'primary');
  name.focus(); name.select();
}
function infoHeading(parent, tag, title, explanation) {
  const head = el(parent, 'div', undefined, 'info-heading');
  el(head, tag, title);
  const hint = el(head, 'details', undefined, 'info-tip');
  const icon = el(hint, 'summary', 'ⓘ');
  icon.setAttribute('aria-label', tr('About ', '关于') + title);
  el(hint, 'p', explanation);
  return head;
}
function settingsTable(parent, key, label, headings, entries, searchText, addRow) {
  const search = field(el(parent, 'div', undefined, 'table-search'), tr('Filter connectors', '筛选连接器'), 'filter_' + key, filters[key], 'search');
  const table = el(el(parent, 'div', undefined, 'compact-table'), 'table');
  table.setAttribute('aria-label', label);
  const head = el(el(table, 'thead'), 'tr');
  for (const title of headings) el(head, 'th', title).scope = 'col';
  const body = el(table, 'tbody');
  const rows = entries.map(entry => {
    const row = el(body, 'tr'); row.dataset.connection = entry.id; addRow(row, entry);
    return {row, terms: searchText(entry).toLowerCase()};
  });
  const empty = el(body, 'tr');
  el(empty, 'td', tr('No matching connectors.', '没有匹配的连接器。'), 'empty').colSpan = headings.length;
  function filter() {
    const query = search.value.trim().toLowerCase();
    filters[key] = search.value;
    let found = false;
    for (const {row, terms} of rows) {
      row.hidden = !terms.includes(query);
      if (!row.hidden) found = true;
    }
    empty.hidden = found;
  }
  search.addEventListener('input', filter); filter();
}
function serviceLabel(conn) { return state.catalog[conn.kind]?.label || tr('Custom connector', '自定义连接器'); }
function connectionRowTitle(row, conn, showMailbox = false) {
  const name = el(row, 'th'); name.scope = 'row';
  el(name, 'strong', conn.id);
  el(name, 'small', [serviceLabel(conn), nameOf(conn.owner)].join(' · '));
  if (showMailbox && conn.mailbox?.email) el(name, 'small', conn.mailbox.email);
}
function connectionSearchText(conn) {
  return [conn.id, serviceLabel(conn), nameOf(conn.owner), conn.mailbox?.email, ...(conn.mailbox?.aliases || [])].join(' ');
}
function connectionStatus(parent, conn) {
  const remote = conn.kind === 'remote', failed = conn.test?.ok === false;
  const [label, style] = failed ? [remote ? tr('MCP check failed', 'MCP 验证失败') : tr('Read check failed', '读取验证失败'), 'bad'] :
    conn.oauth?.error ? [tr('Authorization error', '授权异常'), 'bad'] :
    conn.test?.ok ? [remote ? tr('MCP check passed', 'MCP 验证通过') : tr('Read check passed', '读取验证通过'), ''] :
    conn.connected ? [tr('Not yet tested', '待验证'), 'warn'] : [tr('Connecting', '连接中'), 'warn'];
  el(parent, 'span', label, ('badge ' + style).trim());
  if (conn.available_tools?.length && parent.matches('td')) el(parent, 'small', tr('Tools to review', '有工具待审阅'));
  const reason = (failed ? conn.test.reason : null) || conn.oauth?.error;
  if (reason) el(parent, 'small', serverError({error: reason, incident: failed && conn.test.incident}, 422).message, 'status-error').setAttribute('role', 'alert');
}
function connections() {
  const title = tr('Account connectors', '账号连接器');
  const head = el(app, 'div', undefined, 'row between page-heading');
  infoHeading(head, 'h1', title, tr('Credentials are encrypted. Testing contacts the connected service without writing data.', '凭据加密保存。验证会连接对应服务，不会写入数据。'));
  button(head, tr('Add connector', '添加连接器'), () => connectorForm(), 'primary');
  if (!state.connections.length) { el(app, 'p', tr('No connectors yet.', '还没有连接器。'), 'muted'); return; }
  settingsTable(app, 'connections', title, [tr('Connector', '连接器'), tr('Status', '状态'), tr('Actions', '操作')], state.connections, connectionSearchText, (row, conn) => {
    connectionRowTitle(row, conn, true);
    connectionStatus(el(row, 'td'), conn);
    const actions = el(el(row, 'td'), 'div', undefined, 'actions');
    if (conn.kind && conn.kind !== 'demo') button(actions, tr('Edit settings', '编辑设置'), () => connectorForm(conn));
    button(actions, tr('Details', '详情'), () => connectorDetails(conn.id));
  });
}
function connectorDetails(id) {
  const box = modal(id), content = el(box, 'div');
  function populate() {
    const conn = state?.connections.find(c => c.id === id);
    if (!conn) { box.close(); return; }
    const remote = conn.kind === 'remote';
    content.replaceChildren();
    el(content, 'p', [serviceLabel(conn), nameOf(conn.owner), conn.mailbox?.email].filter(Boolean).join(' · '), 'muted');
    if (conn.kind === 'gmail') el(content, 'p', tr('Gmail access: ', 'Gmail 权限：') + gmailAccessLabels()[conn.settings.gmail_access || 'read'], 'muted');
    if (conn.mailbox?.aliases?.length) el(content, 'p', tr('Aliases: ', '邮箱别名：') + conn.mailbox.aliases.join(', '), 'muted');
    connectionStatus(content, conn);
    if (conn.kind === 'demo') el(content, 'p', tr('Demo notes reset on restart.', '模拟笔记在重启后清空。'), 'muted');
    if (conn.kind === 'reminders') el(content, 'p', tr('Requires the Reminders helper on the owner’s Mac.', '需要账号所有者的 Mac 运行提醒事项助手。'), 'muted');
    if (conn.oauth) {
      const auth = el(content, 'details');
      el(auth, 'summary', tr('OAuth details', 'OAuth 详情'));
      if (conn.oauth.issuer) el(auth, 'p', tr('Issuer: ', '授权服务器：') + conn.oauth.issuer);
      if (conn.oauth.scope) el(auth, 'p', tr('Scopes: ', '授权范围：') + conn.oauth.scope);
      if (!conn.oauth.refreshable && !conn.oauth.error) el(auth, 'p', tr('Reauthorize when access expires.', '授权过期后需重新授权。'));
    }
    toolUpdateNotice(content, conn);
    const actions = el(content, 'div', undefined, 'actions');
    if (conn.kind) button(actions, tr('Test connection', '验证连接'), async () => {
      try { await api('connections/test', {id}); }
      catch (error) {
        if (state) {
          await refresh(); populate();
          if (error.code !== state.connections.find(c => c.id === id)?.test?.reason || !error.code) showError(content, error);
        }
        return;
      }
      await refresh(); populate();
      notify(remote ? tr('MCP check passed.', 'MCP 验证通过。') : tr('Read check passed.', '读取验证通过。'));
    }, 'primary', tr('Testing connection…', '正在验证连接…'));
    button(actions, tr('Rename', '改名'), () => renameConnector(conn, box));
    if (remote) button(actions, tr('Review current tools', '审阅当前工具'), async () => {
      showReview(await api('connections/review-tools', {id, revision: state.revision}), box);
    });
    if (conn.oauth) {
      button(actions, tr('Reauthorize', '重新授权'), () => { connectorForm(conn, true); box.close(); });
      button(actions, tr('Revoke authorization', '撤销授权'), () => confirmAction(tr('Revoke authorization?', '撤销授权？'), tr('Reconnect to use this account again.', '需重新授权后才能继续使用此账号。'), async () => {
        const result = await api('oauth/revoke', {id, revision: state.revision}); await refresh(); box.close();
        notify(result.provider === 'revoked' ? tr('Authorization revoked locally and at the provider.', '已在网关和服务商撤销授权。') : result.provider === 'unsupported' ? tr('Gateway tokens cleared. The provider has no revocation endpoint; remove the grant in its account settings if needed.', '网关 Token 已清除。服务商未提供撤销接口，需要时请在其账号设置中移除授权。') : tr('Gateway tokens cleared. The provider revocation request failed; remove the grant in its account settings.', '网关 Token 已清除。服务商撤销请求失败，请在其账号设置中移除授权。'));
      }), 'danger');
    }
    button(actions, tr('Remove', '移除'), () => confirmAction(tr('Remove connector?', '移除连接器？'), tr('Its tools and permissions will also be removed.', '工具和权限也会一并移除。'), async () => { await mutate('connections/remove', {id}); box.close(); }), 'danger');
  }
  populate();
}
function registryPicker(onSelect) {
  const box = modal(tr('Search MCP Registry', '搜索 MCP Registry'));
  const form = el(box, 'form');
  const query = field(form, tr('Service name', '服务名称'), 'registry_query', '', 'search', tr('Search terms are sent to the public MCP Registry.', '搜索词会发送到公开的 MCP Registry。'));
  query.required = true;
  query.minLength = 3;
  query.maxLength = 100;
  const suggested = el(box, 'div', undefined, 'actions');
  const status = el(box, 'p', '', 'muted registry-status');
  status.setAttribute('role', 'status');
  const results = el(box, 'ul', undefined, 'registry-results');
  const paging = el(box, 'div');

  async function search(term, cursor) {
    if (query.disabled) return;
    query.disabled = true;
    submit.disabled = true;
    try {
      const data = await api('registry/search', {query: term, cursor});
      if (!box.open) return;
      if (!cursor) results.replaceChildren();
      for (const result of data.results) {
        const row = el(results, 'li');
        el(row, 'strong', result.title);
        if (result.title !== result.name) el(row, 'p', result.name, 'muted');
        if (result.description) el(row, 'p', result.description);
        el(row, 'code', result.url, 'url');
        const actions = el(row, 'div', undefined, 'row');
        button(actions, tr('Use endpoint', '使用此地址'), () => {
          onSelect(result);
          box.close();
        });
        if (result.docs) {
          const docs = el(actions, 'a', tr('Provider setup', '服务商配置说明'));
          docs.href = result.docs;
          docs.target = '_blank';
          docs.rel = 'noopener noreferrer';
        }
      }
      status.textContent = results.children.length ? '' : data.next_cursor
        ? tr('No compatible endpoints on this page.', '本页没有兼容的接口。')
        : tr('No HTTPS Streamable HTTP endpoints found. Try another name or enter a URL manually.', '未找到 HTTPS Streamable HTTP 接口。请更换名称或手动填写地址。');
      paging.replaceChildren();
      if (data.next_cursor) button(paging, tr('More results', '更多结果'), () => search(term, data.next_cursor), '', tr('Searching…', '搜索中…'));
    } finally {
      query.disabled = false;
      submit.disabled = false;
    }
  }

  const submit = button(form, tr('Search', '搜索'), () => {
    query.value = query.value.trim();
    if (form.reportValidity()) return search(query.value);
  }, 'primary', tr('Searching…', '搜索中…'));
  form.addEventListener('submit', event => { event.preventDefault(); submit.click(); });
  for (const [label, term] of [['Todoist', 'net.todoist/mcp'], ['Notion', 'com.notion/mcp'], ['Linear', 'app.linear/linear'], ['GitHub', 'io.github.github/github-mcp-server']]) {
    button(suggested, label, () => {
      if (query.disabled) return;
      query.value = term;
      return search(term);
    }, '', tr('Searching…', '搜索中…'));
  }
  query.focus();
}

function gmailAccessLabels() {
  return {
    read: tr('Read only', '只读'),
    read_send: tr('Read and send', '读取和发送'),
    read_organize: tr('Read and organize', '读取和整理'),
    read_organize_send: tr('Read, organize, and send', '读取、整理和发送'),
  };
}
function gmailSettings(parent, existing) {
  const settings = {}, credentials = {};
  settings.gmail_access = select(parent, tr('Google permissions', 'Google 权限'), 'gmail_access',
    Object.entries(gmailAccessLabels()), existing?.settings.gmail_access || 'read');
  const permissions = el(parent, 'small', '', 'gmail-scope-note');
  function scopeNote() {
    const value = settings.gmail_access.value;
    permissions.textContent = value === 'read_organize' || value === 'read_organize_send'
      ? tr('gmail.modify · Google also permits sending with this scope. The gateway exposes Send only when selected above.',
           'gmail.modify · Google 的此权限也允许发信；只有在上方选了「发送」，网关才开放发送工具。')
      : value === 'read_send'
        ? tr('gmail.readonly + gmail.send · Agent access is managed separately.', 'gmail.readonly + gmail.send · Agent 的权限仍在「权限」里配置。')
        : 'gmail.readonly';
  }
  settings.gmail_access.addEventListener('change', scopeNote); scopeNote();

  const guide = el(parent, 'details');
  el(guide, 'summary', tr('Google Cloud setup', 'Google Cloud 设置'));
  const link = el(guide, 'a', tr('Open Google Cloud OAuth clients', '打开 Google Cloud OAuth 客户端'));
  link.href = 'https://console.cloud.google.com/auth/clients';
  link.target = '_blank'; link.rel = 'noopener noreferrer';
  el(guide, 'p', tr('Enable Gmail API. Create a Web application OAuth client and register this redirect URI:', '启用 Gmail API，创建「Web 应用」OAuth 客户端，并登记以下重定向 URI：'));
  const callback = location.origin + '/admin/oauth/google/callback';
  el(guide, 'code', callback, 'url');
  button(guide, tr('Copy redirect URI', '复制重定向 URI'), async () => {
    await navigator.clipboard.writeText(callback);
    notify(tr('Redirect URI copied.', '已复制重定向 URI。'));
  });
  el(guide, 'p', tr('Download the client JSON, then import it here.', '下载该客户端的 JSON 文件，然后在这里导入。'));

  const imported = field(parent, existing ? tr('Replace OAuth client (optional)', '更换 OAuth 客户端（可选）') :
    tr('Google OAuth client JSON', 'Google OAuth 客户端 JSON'), 'google_client_file', '', 'file');
  imported.accept = '.json,application/json';
  const status = el(parent, 'p', '', 'muted');
  status.setAttribute('role', 'status');
  const manual = el(parent, 'details');
  el(manual, 'summary', tr('Enter credentials manually', '手动填写凭据'));
  settings.client_id = field(manual, tr('Google OAuth client ID', 'Google OAuth 客户端 ID'), 'client_id', existing?.settings.client_id || '');
  credentials.client_secret = field(manual, tr('Google OAuth client secret', 'Google OAuth 客户端密钥'), 'client_secret', '', 'password',
    existing ? tr('Leave blank to keep this client’s saved secret.', '留空保留此客户端已保存的密钥。') : '');
  credentials.refresh_token = field(manual, tr('Existing refresh token (optional)', '已有刷新令牌（可选）'), 'refresh_token', '', 'password',
    tr('Leave blank to authorize in your browser.', '留空即可通过浏览器授权。'));

  imported.addEventListener('change', async () => {
    if (!imported.files.length) return;
    status.textContent = '';
    imported.closest('dialog').querySelector('.operation-error')?.remove();
    try {
      const file = imported.files[0];
      let data;
      try { if (file.size <= 64 * 1024) data = JSON.parse(await file.text()); } catch {}
      if (data?.installed && !data?.web) throw new Error(tr('This is a Desktop app client. Download a Web application client instead.', '这是「桌面应用」客户端，请下载「Web 应用」客户端。'));
      const {client_id: id, client_secret: secret} = data?.web || {};
      if ([id, secret].some(value => typeof value !== 'string' || !value.trim() || value.length > 16000)) {
        throw new Error(tr('This file does not contain a Web application client ID and secret.', '此文件里没有「Web 应用」客户端的 ID 和密钥。'));
      }
      settings.client_id.value = id.trim();
      credentials.client_secret.value = secret.trim();
      credentials.refresh_token.value = '';
      manual.open = false;
      status.textContent = tr('OAuth client loaded.', '已导入 OAuth 客户端。');
    } catch (error) { showError(imported, error); }
    finally { imported.value = ''; imported.dispatchEvent(new Event('input', {bubbles: true})); }
  });
  return {settings, credentials};
}
function connectorForm(existing, reauthorize = false) {
  const revision = state.revision;
  const box = modal(existing ? tr('Edit connector', '编辑连接器') : tr('Add connector', '添加连接器'));
  const form = el(box, 'form'); form.addEventListener('submit', e => e.preventDefault());
  const kind = select(form, tr('Service', '服务'), 'kind', Object.entries(state.catalog).map(([key, spec]) => [key, spec.label]), existing?.kind || 'demo'); kind.disabled = !!existing;
  const fixed = el(form, 'div', undefined, 'form-grid');
  const name = connectorNameField(fixed, existing?.id || ''); name.disabled = !!existing;
  const owner = select(fixed, tr('Account owner', '账号所有者'), 'owner', [...state.members.map(m => [m.id, m.name]), ...state.households.map(h => [h.id, tr('Household: ', '家庭共享：') + h.name])], existing?.owner || state.owner); owner.disabled = !!existing;
  const dynamic = el(form, 'div'); let settings = {}, credentials = {}, mailProvider;
  const labels = {username: tr('Account email / username', '账号邮箱 / 用户名'), host: tr('IMAP server', 'IMAP 服务器'), port: tr('TLS port', 'TLS 端口'),
    smtp_host: tr('SMTP server (blank disables sending)', 'SMTP 服务器（留空关闭发信）'), smtp_port: tr('SMTP port', 'SMTP 端口'),
    smtp_security: tr('SMTP encryption', 'SMTP 加密方式'), smtp_username: tr('SMTP username (optional override)', 'SMTP 用户名（可选覆盖）'),
    smtp_sender: tr('Sender email (defaults to account email)', '发件邮箱（默认账号邮箱）'),
    url: tr('HTTPS service URL', '服务 HTTPS 地址'), timezone: tr('Time zone', '时区'), password: tr('App-specific password', 'App 专用密码'),
    token: tr('Helper bearer token', '辅助服务 Bearer Token')};
  function fields() {
    dynamic.replaceChildren(); settings = {}; credentials = {}; mailProvider = null;
    if (kind.value === 'gmail') {
      ({settings, credentials} = gmailSettings(dynamic, existing));
      return;
    }
    const spec = state.catalog[kind.value];
    const defaults = {host: 'imap.mail.me.com', port: '993', smtp_host: !existing || (existing.settings.host || 'imap.mail.me.com') === 'imap.mail.me.com' ? 'smtp.mail.me.com' : '', smtp_port: '587', smtp_security: 'starttls', url: kind.value === 'caldav' ? 'https://caldav.icloud.com' : '', timezone: 'UTC'};
    if (kind.value === 'remote') {
      if (!existing) button(dynamic, tr('Search MCP Registry', '搜索 MCP Registry'), () => registryPicker(result => {
        settings.url.value = result.url;
        settings.service.value = result.service;
        settings.auth.value = result.auth || '';
        settings.auth.dispatchEvent(new Event('change'));
        name.focus();
      }));
      settings.url = field(dynamic, tr('MCP endpoint URL', 'MCP 接口地址'), 'url', existing?.settings.url || '', 'url'); settings.url.required = true;
      settings.service = field(dynamic, tr('Service ID', '服务标识'), 'service', existing?.settings.service || 'remote-mcp', 'text', tr('Use the same ID for accounts that expose the same service tools.', '同一服务的不同账号使用相同标识。')); settings.service.disabled = !!existing;
      settings.auth = select(dynamic, tr('Authentication', '认证方式'), 'auth', [['', tr('Choose authentication', '选择认证方式')], ['none', tr('None', '无需认证')], ['bearer', 'Bearer token'], ['header', tr('API key header', 'API 密钥 Header')], ['oauth', 'OAuth']], existing?.settings.auth || 'oauth');
      settings.auth.required = true;
      const tokenBox = el(dynamic, 'div'), headerBox = el(dynamic, 'div'), oauthBox = el(dynamic, 'div');
      credentials.token = field(tokenBox, tr('Token / API key', 'Token / API 密钥'), 'token', '', 'password', existing ? tr('Blank keeps the saved value only when the endpoint is unchanged.', '接口地址未变时，留空保留原值。') : '');
      settings.header = field(headerBox, tr('Credential header', '凭据 Header'), 'header', existing?.settings.header || 'X-API-Key');
      const advancedOAuth = el(oauthBox, 'details');
      el(advancedOAuth, 'summary', tr('Advanced OAuth settings', 'OAuth 高级设置'));
      el(advancedOAuth, 'p', tr('Register this callback URL with the provider if you use a pre-registered client.', '使用预先注册的客户端时，请在服务商处登记此回调地址。'), 'muted');
      el(advancedOAuth, 'code', location.origin + '/admin/oauth/mcp/callback', 'url');
      settings.issuer = field(advancedOAuth, 'Issuer', 'issuer', existing?.settings.issuer || '');
      settings.client_id = field(advancedOAuth, tr('OAuth client ID (optional)', 'OAuth 客户端 ID（可选）'), 'client_id', existing?.settings.client_id || '');
      credentials.client_secret = field(advancedOAuth, tr('OAuth client secret', 'OAuth 客户端密钥'), 'client_secret', '', 'password', existing ? tr('Leave blank to keep the saved value for this client.', '同一客户端留空保留原值。') : '');
      settings.auth_method = select(advancedOAuth, tr('Client authentication', '客户端认证'), 'auth_method', [['none', tr('Public client (no secret)', '公共客户端（无密钥）')], ['client_secret_post', 'Client secret in POST'], ['client_secret_basic', 'Client secret in Basic header']], existing?.settings.auth_method || 'none');
      settings.scope = field(advancedOAuth, tr('Scopes (optional, space separated)', 'Scope（可选，用空格分隔）'), 'scope', existing?.settings.scope || '', 'text', tr('Blank uses the scopes requested by the MCP server. Review them on the authorization page.', '留空使用 MCP 服务器要求的范围，请在授权页面核对。'));
      settings.client_metadata_url = field(advancedOAuth, tr('Client metadata URL (optional)', '客户端元数据 URL（可选）'), 'client_metadata_url', existing?.settings.client_metadata_url || '', 'text', tr('For providers supporting URL-based client registration. Use instead of a client ID.', '用于支持 URL 客户端注册的服务商，与客户端 ID 二选一。'));
      function authFields() { tokenBox.hidden = !['bearer', 'header'].includes(settings.auth.value); headerBox.hidden = settings.auth.value !== 'header'; oauthBox.hidden = settings.auth.value !== 'oauth'; }
      settings.auth.addEventListener('change', authFields); authFields();
      return;
    }
    if (kind.value === 'imap' && !existing) mailProvider = select(dynamic, tr('Mail provider', '邮箱服务商'), 'mail_provider', [
      ['icloud', 'iCloud'], ['gmail', 'Gmail'], ['custom', tr('Other', '其他')],
    ], 'icloud');
    if (kind.value === 'imap') infoHeading(dynamic, 'h3', tr('Mail settings', '邮件设置'),
      tr('iCloud requires an app-specific password. IMAP and SMTP share the password. Leave the SMTP server blank to disable sending.', 'iCloud 需要 App 专用密码。IMAP 和 SMTP 共用密码。SMTP 服务器留空会关闭发信。'));
    for (const key of spec.fields) {
      if (key === 'mailbox_email' || key === 'mailbox_aliases') continue;
      settings[key] = key === 'smtp_security' ? select(dynamic, labels[key], key, [['starttls', 'STARTTLS (587)'], ['tls', 'TLS (465)']], existing?.settings[key] ?? defaults[key]) : field(dynamic, labels[key], key, existing?.settings[key] ?? defaults[key] ?? '');
    }
    for (const key of spec.secrets) credentials[key] = field(dynamic, labels[key], key, '', 'password', existing ? tr('Leave blank to keep the saved value.', '留空保留已保存的值。') : '');
    if (kind.value === 'caldav') el(dynamic, 'p', tr('iCloud requires an app-specific password. Read only.', 'iCloud 使用 App 专用密码。日历连接器只提供读取操作。'), 'hint');
    if (kind.value === 'imap') {
      if (mailProvider) {
        const presets = {icloud: ['imap.mail.me.com', 'smtp.mail.me.com'], gmail: ['imap.gmail.com', 'smtp.gmail.com'], custom: ['', '']};
        const link = el(dynamic, 'a', tr('Create a Google app password', '创建 Google App 专用密码'));
        link.href = 'https://myaccount.google.com/apppasswords';
        link.target = '_blank'; link.rel = 'noopener noreferrer'; link.hidden = true;
        mailProvider.addEventListener('change', () => {
          [settings.host.value, settings.smtp_host.value] = presets[mailProvider.value];
          settings.port.value = '993'; settings.smtp_port.value = '587'; settings.smtp_security.value = 'starttls';
          link.hidden = mailProvider.value !== 'gmail';
        });
      }
      const addresses = el(dynamic, 'details');
      el(addresses, 'summary', tr('Mailbox addresses', '邮箱地址与别名'));
      settings.mailbox_email = field(addresses, tr('Primary email address', '主邮箱地址'), 'mailbox_email', existing?.settings.mailbox_email || '', 'email',
        tr('Optional. Overrides the address inferred from the login name.', '可选。填写后会覆盖根据登录名推断的地址。'));
      settings.mailbox_aliases = field(addresses, tr('Email aliases', '邮箱别名'), 'mailbox_aliases', existing?.settings.mailbox_aliases || '', 'textarea',
        tr('One address per line. Authorized Agents can use these addresses to find this mailbox.', '每行一个地址。获授权的 Agent 可以用这些地址找到此邮箱。'));
    }
  }
  fields();
  function values() {
    const values = Object.fromEntries(Object.entries(credentials).map(([k, input]) => [k, input.value]));
    if (mailProvider?.value === 'gmail') values.password = values.password.replace(/\s+/g, '');
    return {revision, id: name.value, kind: kind.value, owner: owner.value,
      settings: Object.fromEntries(Object.entries(settings).map(([k, input]) => [k, input.value])),
      credentials: values};
  }
  function needsReview() {
    return ['remote', 'reminders'].includes(kind.value) && (!existing || settings.url.value.trim() !== existing.settings.url);
  }
  function needsOAuth() {
    return kind.value === 'remote' && settings.auth.value === 'oauth' && (
      reauthorize || needsReview() || existing?.settings.auth !== 'oauth' || credentials.client_secret.value ||
      ['issuer', 'client_id', 'auth_method', 'scope', 'client_metadata_url'].some(key => settings[key].value !== (existing?.settings[key] || ''))
    );
  }
  function saveLabel() {
    if (kind.value === 'gmail' && !credentials.refresh_token?.value.trim()) return tr('Authorize with Google', '通过 Google 授权');
    if (needsReview()) return tr('Preview tools', '预览工具');
    if (needsOAuth()) return tr('Authorize and save', '授权并保存');
    return tr('Save connector', '保存连接器');
  }
  const save = button(form, saveLabel, async () => {
    name.value = name.value.trim();
    if (!name.checkValidity()) throw new Error(tr(...messages.invalid_connector_name));
    if (!form.reportValidity()) return;
    if (kind.value === 'gmail') {
      settings.client_id.value = settings.client_id.value.trim();
      credentials.refresh_token.value = credentials.refresh_token.value.trim();
      if (!settings.client_id.value || ((!existing || settings.client_id.value !== existing.settings.client_id) && !credentials.client_secret.value)) {
        throw new Error(tr('Import a Google OAuth client JSON or enter the client ID and secret manually.', '请导入 Google OAuth 客户端 JSON，或手动填写客户端 ID 和密钥。'));
      }
      if (!credentials.refresh_token.value) {
        const result = await api('oauth/start', values()); location.assign(result.url); return;
      }
    }
    if (needsOAuth()) {
      const result = await api('oauth/mcp/start', values()); location.assign(result.url); return;
    }
    if (needsReview()) {
      const result = await api('connections/preview', values());
      for (const input of Object.values(credentials)) input.value = '';
      showReview(result, box);
      return;
    }
    await mutate('connections/save', values());
    box.close(); notify(tr('Connector saved.', '连接器已保存。'));
  }, 'primary', tr('Saving…', '正在保存…'));
  kind.addEventListener('change', fields);
  form.addEventListener('input', () => { if (!save.disabled) save.textContent = saveLabel(); });
  form.addEventListener('change', () => { if (!save.disabled) save.textContent = saveLabel(); });
}
function showReview(result, form) {
  const review = modal(tr('Review tool definitions', '审阅工具定义'));
  el(review, 'p', result.connection + ' · ' + identityLabel(result.owner), 'muted');
  if (result.google_account) el(review, 'p', tr('Authorized Google account: ', '已授权的 Google 账号：') + result.google_account, 'hint');
  el(review, 'p', tr('Grant Agent access to new tools under Permissions.', '新增工具默认不授权，请在「权限」中配置。'), 'hint');
  if (result.oauth?.issuer) el(review, 'p', tr('Authorization server: ', '授权服务器：') + result.oauth.issuer, 'hint');
  if (result.oauth?.scope) el(review, 'p', tr('Granted scopes: ', '已授权范围：') + result.oauth.scope, 'hint');
  if (result.remote) el(review, 'p', tr('Confirm each tool’s access. Deselecting a tool or changing it from Read to Write removes its existing grants.', '请核对工具类型。取消选择工具或将其从读取改为写入，会撤销已有授权。'), 'hint');
  const selections = [];
  for (const definition of result.definitions) {
    const row = el(review, 'div', undefined, 'row');
    if (result.remote) {
      const included = checkbox(row, definition.name); included.checked = true;
      const access = select(row, tr('Operation type: ', '操作类型：') + definition.name, 'access_' + selections.length, [['write', tr('Write', '写入')], ['read', tr('Read', '读取')]], result.tools.find(t => t.upstream === definition.name)?.access || 'write');
      selections.push({upstream: definition.name, included, access});
    } else el(row, 'strong', definition.name);
    const detail = el(review, 'details'); el(detail, 'summary', tr('Definition', '工具定义')); el(detail, 'pre', JSON.stringify(definition, null, 2));
  }
  const checked = checkbox(review, tr('I reviewed these definitions and permissions.', '我已审阅这些工具定义和权限。'));
  const apply = button(review, tr('Apply connector', '应用连接器'), async () => {
    await mutate('connections/apply', {draft: result.draft, reviewed: checked.checked, ...(result.remote ? {tools: selections.filter(s => s.included.checked).map(s => ({upstream: s.upstream, access: s.access.value}))} : {})}); review.close(); if (form) form.close(); notify(tr('Connector applied. Run its read check next.', '连接器已应用，请继续运行读取验证。'));
  }, 'primary'); apply.disabled = true; checked.addEventListener('change', () => { apply.disabled = !checked.checked; });
}
function toolUpdateNotice(parent, conn) {
  const sync = conn.catalog_sync;
  if (sync?.automatic) {
    if (sync.added.length) el(parent, 'p', tr(`${sync.added.length} new tools were registered automatically. Review their access under Permissions.`, `已自动登记 ${sync.added.length} 个新工具，请到权限页为它们授权。`), 'hint');
    if (sync.revoked.length) el(parent, 'p', tr('Some tools changed from reading to writing. Their old grants were removed; choose write permissions before using them.', '部分工具从读取变为写入，已撤销这些工具的旧授权，请重新选择写入权限。'), 'hint');
  }
  for (const issue of sync?.issues || []) {
    const reasons = {
      bundle_unavailable: tr('Bundled connector definitions could not be loaded. Check that this connector’s dependencies are installed.', '无法加载内置连接器定义，请检查其依赖是否已安装。'),
      tool_removed: tr('This tool is no longer provided by the installed connector.', '当前连接器版本已不再提供此工具。'),
      pin_unknown_argument: tr('A fixed argument was removed by the connector update. Adjust this tool’s argument limits under Advanced.', '连接器更新移除了固定参数中的字段，请在高级设置中调整该工具的参数限制。'),
      allow_values_unknown_argument: tr('A restricted argument was removed by the connector update. Adjust this tool’s argument limits under Advanced.', '连接器更新移除了受限参数字段，请在高级设置中调整该工具的参数限制。'),
    };
    el(parent, 'p', (issue.tool ? issue.tool + ': ' : '') + (reasons[issue.reason] || serverError({error: issue.reason}, 400).message), 'error');
  }
  const additions = conn.available_tools || [];
  if (!additions.length) return;
  const writes = additions.filter(t => t.access === 'write').length;
  el(parent, 'p', tr(`${additions.length} new tools to review, including ${writes} write tools.`, `${additions.length} 个新工具待审阅，其中 ${writes} 个可写入。`), 'hint');
  button(parent, tr('Review new tools', '审阅新工具'), async () => {
    const result = await api('connections/review-tools', {id: conn.id, revision: state.revision});
    showReview(result, parent.closest('dialog'));
  }, 'primary', tr('Reading tool definitions…', '正在读取工具定义…'));
}
async function resumeGoogle() {
  if (!gmailResult && !mcpOAuthResult) return;
  const operation = mcpOAuthResult ? 'oauth/mcp/complete' : 'oauth/complete';
  const id = mcpOAuthResult || gmailResult; gmailResult = null; mcpOAuthResult = null; navigate('connections', true);
  try {
    const result = await api(operation, {id});
    if (result.saved) { await refresh(); notify(tr('Connector saved.', '连接器已保存。')); }
    else showReview(result);
  }
  catch (error) {
    showError(app, error);
    if (['oauth_not_ready', 'active_calls_busy', 'admin_busy'].includes(error.code)) {
      if (operation === 'oauth/mcp/complete') mcpOAuthResult = id; else gmailResult = id;
      button(app, tr('Continue authorization', '继续授权'), resumeGoogle);
    }
  }
}
function accessProfile(conn, client) {
  const current = conn.access[client];
  const scope = current.startsWith('read_write') || current === 'read_approval_write_direct' ? 'read_write' :
    current === 'read_approval' ? 'read' : current;
  return {current, scope,
    readApprovalRequired: ['read_approval', 'read_write_approval', 'read_approval_write_direct'].includes(current),
    writeApprovalRequired: ['read_write', 'read_write_approval'].includes(current)};
}
function accessSummary(parent, conn, client) {
  const {scope, readApprovalRequired, writeApprovalRequired} = accessProfile(conn, client);
  const labels = {none: tr('No access', '禁止访问'), read: tr('Read only', '只读'), read_write: tr('Read and write', '读写'), custom: tr('Custom', '自定义')};
  el(parent, 'span', labels[scope], 'badge');
  if (scope === 'read' || scope === 'read_write') {
    const approval = (required) => required ? tr('approval', '需审批') : tr('direct', '无需审批');
    const read = tr('Read: ', '读取：') + approval(readApprovalRequired);
    const write = tr('Write: ', '写入：') + approval(writeApprovalRequired);
    const modes = el(parent, 'small', undefined, 'approval-summary');
    el(modes, 'span', read);
    if (scope === 'read_write') el(modes, 'span', write);
  }
  if (readApprovalRequired || writeApprovalRequired || (scope === 'custom' && conn.tools.some(tool => tool.permissions[client] === 'approval_required'))) {
    const approver = conn.approver === conn.household ? tr('Any household member', '家庭内任意成员') : nameOf(conn.approver);
    el(parent, 'small', tr('Approver: ', '审批人：') + approver);
  }
}
function permissions() {
  const title = tr('Inspect permissions', '检查权限');
  infoHeading(app, 'h1', title, tr('These permissions apply to everyone using the selected Agent. Each approval covers one operation. Changes expire pending approvals.', '权限适用于此 Agent 的所有使用者。每次审批只批准一次操作。权限变更会使待审批请求失效。')).classList.add('page-heading');
  if (!state.clients.length) {
    el(app, 'p', tr('Create an Agent token to set its permissions.', '创建 Agent Token 后即可配置权限。'));
    button(app, tr('Create agent token', '创建 Agent Token'), () => navigate('agents')); return;
  }
  if (!state.clients.some(c => c.id === subject)) subject = state.clients[0].id;
  const agent = state.clients.find(c => c.id === subject);
  const agentBar = el(app, 'div', undefined, 'agent-select');
  const selected = select(agentBar, tr('Agent', 'Agent'), 'inspect_agent', state.clients.map(c => [c.id, c.id]), subject);
  selected.addEventListener('change', () => { subject = selected.value; render(); });
  el(agentBar, 'p', tr('Household: ', '所属家庭：') + nameOf(agent.household), 'muted');
  const entries = state.connections.filter(c => c.household === agent.household);
  if (!entries.length) { el(app, 'p', tr('No connectors in this household.', '此家庭还没有连接器。'), 'muted'); return; }
  settingsTable(app, 'permissions', title, [tr('Connector', '连接器'), tr('Access', '访问权限'), tr('Actions', '操作')], entries, connectionSearchText, (row, conn) => {
    connectionRowTitle(row, conn, true);
    accessSummary(el(row, 'td'), conn, agent.id);
    button(el(row, 'td'), tr('Edit access', '编辑权限'), () => permissionEditor(conn.id, agent.id));
  });
}
function permissionEditor(id, client) {
  const box = modal(tr('Permissions: ', '权限：') + id), content = el(box, 'div');
  box.classList.add('permission-dialog');
  function populate() {
    const conn = state?.connections.find(c => c.id === id);
    if (!conn) { box.close(); return; }
    const advancedOpen = content.querySelector('.advanced-permissions')?.open || false;
    content.replaceChildren();
    const card = el(content, 'div'); card.dataset.connection = id;
    el(card, 'p', [client, tr('Account owner: ', '账号归属：') + nameOf(conn.owner)].join(' · '), 'muted');
    toolUpdateNotice(card, conn);
    const reads = conn.tools.filter(t => t.access === 'read').length, writes = conn.tools.length - reads;
    const {current, scope, readApprovalRequired, writeApprovalRequired} = accessProfile(conn, client);
    const options = [['none', tr('No access', '禁止访问')], ['read', tr('Read only', '只读')]];
    if (writes) options.push(['read_write', tr('Read and write', '读写')]);
    if (current === 'custom') options.push(['custom', tr('Custom — keep existing tool settings', '自定义（保留现有逐工具配置）')]);
    const mode = select(card, tr('Connection access', '连接权限'), 'connection_access', options, scope);
    if (!writes && !(conn.available_tools || []).some(t => t.access === 'write')) el(card, 'p', tr('This connector only provides read operations.', '此连接器只提供读取操作，不支持写入。'), 'muted');
    const approvalFields = el(card, 'div', undefined, 'form-grid');
    const readSettings = el(approvalFields, 'div'), writeSettings = el(approvalFields, 'div');
    const choices = [['allow', tr('No approval', '无需审批')], ['approval_required', tr('Approve every operation', '每次操作都审批')]];
    const readApproval = select(readSettings, tr('Read approval', '读取审批'), 'read_approval', choices,
      readApprovalRequired ? 'approval_required' : 'allow');
    const writeApproval = select(writeSettings, tr('Write approval', '写入审批'), 'write_approval', choices,
      scope === 'read_write' && !writeApprovalRequired ? 'allow' : 'approval_required');
    const approval = el(card, 'div');
    const members = state.members.filter(m => m.household === conn.household);
    const approver = select(approval, tr('Who can approve?', '由谁审批？'), 'connection_approver',
      [...members.map(m => [m.id, m.name]), [conn.household, tr('Any household member', '家庭内任意成员')]], conn.approver);
    el(approval, 'small', tr('Applies to all Agents using this connector.', '适用于使用此连接器的所有 Agent。'), 'muted');
    const enrollment = el(approval, 'p', '', 'muted');
    function feedback() {
      readSettings.hidden = !['read', 'read_write'].includes(mode.value);
      writeSettings.hidden = mode.value !== 'read_write';
      const required = (!readSettings.hidden && readApproval.value === 'approval_required') || (!writeSettings.hidden && writeApproval.value === 'approval_required');
      approval.hidden = !required && !(mode.value === 'custom' && conn.tools.some(t => t.permissions[client] === 'approval_required'));
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
      const controls = [...card.querySelectorAll('input, select, button')];
      const disabled = controls.map(control => control.disabled);
      controls.forEach(control => { control.disabled = true; });
      try {
        await mutate('permissions/connection', {client, connection: conn.id, access,
          ...(!approval.hidden ? {approver: approver.value} : {})});
        populate(); notify(tr('Connection permissions updated.', '连接权限已更新。'));
      } finally { controls.forEach((control, index) => { control.disabled = disabled[index]; }); }
    }, 'primary');
    const details = el(card, 'details', undefined, 'advanced-permissions'); details.open = advancedOpen;
    el(details, 'summary', tr('Advanced: individual tools and argument limits', '高级设置：逐工具权限与参数限制'));
    const tools = el(details, 'div');
    function loadTools() {
      if (details.open && !tools.hasChildNodes()) advancedPermissions(tools, conn, client, populate);
    }
    details.addEventListener('toggle', loadTools); loadTools();
  }
  populate();
}
function advancedPermissions(parent, conn, client, populate) {
  infoHeading(parent, 'h3', tr('Tool permissions', '工具权限'), tr('Unclassified tools count as writes. Argument limits apply to every Agent.', '未分类工具按写入处理。参数限制适用于所有 Agent。'));
  const table = el(el(parent, 'div', undefined, 'table-wrap'), 'table'); const heading = el(el(table, 'thead'), 'tr');
  for (const label of [tr('Tool / owner', '工具 / 所有者'), tr('Access', '访问权限'), tr('Changes', '修改')]) el(heading, 'th', label);
  const body = el(table, 'tbody');
  for (const tool of conn.tools) {
    const row = el(body, 'tr'); const info = el(row, 'td'); el(info, 'strong', tool.name);
    if (tool.problem) el(info, 'span', tr('Disabled: ', '已停用：') + tool.problem, 'badge bad');
    if (Object.keys(tool.pin).length) el(info, 'pre', JSON.stringify(tool.pin));
    const settings = el(row, 'td');
    const choices = [['deny', tr('Deny', '拒绝')], ['allow', tr('Allow without approval', '允许，无需审批')], ['approval_required', tr('Require approval', '需要审批')]];
    const effect = select(settings, tr('Effect', '权限效果'), 'effect', choices, tool.permissions[client]);
    el(info, 'span', tool.access === 'read' ? tr('Read', '读取') : tr('Write / unclassified', '写入 / 未分类'), 'badge');
    if (!conn.approvers.some(id => state.members.find(m => m.id === id)?.passkeys)) {
      const warning = el(settings, 'small', tr('No approver has a passkey.', '审批人尚未注册通行密钥。'), 'status-error');
      const showWarning = () => { warning.hidden = effect.value !== 'approval_required'; };
      showWarning(); effect.addEventListener('change', showWarning);
    }
    const actions = el(el(row, 'td'), 'div', undefined, 'actions');
    button(actions, tr('Save access', '保存权限'), async () => { await mutate('permissions/save', {client, connection: conn.id, tool: tool.name, effect: effect.value}); populate(); notify(tr('Permissions updated.', '权限已更新。')); });
    button(actions, tr('Argument limits', '参数限制'), () => {
      const box = modal(tr('Argument limits', '参数限制')); el(box, 'p', tr('These restrictions apply to everyone using this exposed tool. Fixed arguments are hidden from agents. Changes invalidate pending approvals.', '这些限制适用于所有调用此工具的身份。固定参数对 Agent 隐藏。修改会使未使用的审批失效。'), 'muted');
      const pin = field(box, tr('Fixed arguments (JSON object)', '固定参数（JSON 对象）'), 'pin', JSON.stringify(tool.pin, null, 2), 'textarea');
      const allow = field(box, tr('Allowed values (JSON object of arrays)', '允许值（值为数组的 JSON 对象）'), 'allow_values', JSON.stringify(tool.allow_values, null, 2), 'textarea');
      button(box, tr('Save restrictions', '保存限制'), async () => {
        let fixed, allowed;
        try { fixed = JSON.parse(pin.value); } catch { throw new Error(tr('Fixed arguments: invalid JSON. Check quotes and commas.', '固定参数：JSON 格式错误，请检查引号和逗号。')); }
        try { allowed = JSON.parse(allow.value); } catch { throw new Error(tr('Allowed values: invalid JSON. Check quotes and commas.', '允许值：JSON 格式错误，请检查引号和逗号。')); }
        await mutate('tools/restrict', {connection: conn.id, tool: tool.name, pin: fixed, allow_values: allowed}); box.close(); populate();
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
