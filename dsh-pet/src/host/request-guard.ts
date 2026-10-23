/**
 * 浏览器来源校验（CSRF 防线）—— `/dsh-pet-7340` 前缀路由的**第一道门**。
 *
 * 为什么必须有这一层：
 *   DSH WebServer 的通用路由表**不做鉴权**（鉴权只发生在 index 静态页与 `/api` 连接层，见
 *   `@deepseek-ai/dsh-client-connection` 的 authorizeIndex / isAuthenticated）。插件注册的
 *   `kind: 'prefix'` 路由因此对**任何能连到本机端口的请求**开放，其中也包括用户在浏览器里
 *   访问的**任意网页**：浏览器允许跨站发"简单请求"（`Content-Type: text/plain` 不触发预检，
 *   服务端只读正文、不看 Content-Type），于是
 *
 *     POST /chat、/whisper  → 花掉用户的模型额度（正文是合法 JSON 就能走完整业务）
 *     POST /broadcast       → 让桌宠说任意话；配合 /anim 的 `url` 还能让它去拉第三方素材
 *     POST /config          → 整份重置用户配置（「同步内置默认」）
 *     POST /reload          → 重启桌面 Helper
 *
 *   全都可能变成"用户只是打开了一个网页"就发生的事。独立模式
 *   （`src/standalone/request-security.ts`）已经用启动令牌 + Origin 校验挡住了同一类请求；
 *   DSH 内运行没有令牌可用（第三方脚本、桌面管道都要调用），所以这里只做**来源判定**：
 *   浏览器带着 `Origin` / `Sec-Fetch-Site` 来的，必须是同源；不带这些头的（curl、脚本、
 *   桌面 helper 的管道、独立模式自己的本地页面）一律放行——能力边界一个字都没变。
 *
 * 判定规则（宁可窄，不可漏）：
 *   ① `Sec-Fetch-Site: cross-site` → 拒绝。现代浏览器对**所有**跨站请求都带这个头（含 GET），
 *      而它无法被网页脚本伪造（脚本改不了被禁用的请求头）；
 *   ② 有 `Origin` → 必须能解析、不能是 `null`（沙箱 iframe / `file://` 的取值），且 **host 必须
 *      等于 `Host` 头**。只比 host 不比 scheme：反向代理终止 TLS 后 Origin 是 `https://host`，
 *      而 Node 收到的 `Host` 只有 `host:port`；
 *   ③ **Host 白名单**（只在「回环绑定」的单机默认部署下生效，见下）：`Host` 必须是回环名字
 *      （`localhost` / `127.x` / `[::1]`）、IP 字面量，或 `DSH_PET_TRUSTED_HOSTS` 里显式信任的
 *      authority。其余一律 403；
 *   ④ 没有 `Host`（非浏览器调用方：curl / 脚本 / 桌面管道）→ 放行。
 *
 * 为什么要有 ③（DNS rebinding）：
 *   ①②只比对"Origin 与 Host 是否一致"，而这两个头在 rebinding 攻击里**是一致的**——攻击者页面
 *   从 `evil.example` 加载，DNS TTL 过期后该域名解析到 `127.0.0.1`，浏览器仍认为是同源，于是
 *   攻击者既能发请求**也能读响应**（`/state`、`/chat` 的对话记忆）。浏览器能提供的其它信号
 *   （`Sec-Fetch-Site: same-origin`）在这个场景下也是"同源"，帮不上忙。唯一可靠的判据是
 *   **本机部署的 Host 不可能是任意外部域名**：DSH 默认只绑回环，访问它只该用回环名/IP 字面量。
 *   回环名与 IP 字面量都无法被 rebinding 伪造（浏览器按 URL 里的字面量直连，不经过攻击者的 DNS）。
 *
 * 为什么默认只在「回环绑定」时启用 ③：
 *   `ctx.webServer.host` 非回环 = 用户主动把服务开到局域网/公网（`dsh web --host 0.0.0.0`），
 *   Host 可以是任意内网主机名，枚举不出来；此时再钉白名单会把**正常访问**也拦掉（浏览器端桌宠
 *   直接 403）。既然用户已经选择对外暴露，rebinding 就不再是主要威胁，退回 ①② 的同源判定。
 *   回环绑定 + 反向代理（Host 是外部域名）属于少数派，用 `DSH_PET_TRUSTED_HOSTS` 显式放行。
 *
 * 刻意**不做**的两件事：
 *   - 不加 CORS 响应头：同源页面不需要，跨源页面本来也读不到响应（浏览器强制）。这里只负责
 *     "不让它产生副作用 / 不让它读状态"，不负责"让它能读"；
 *   - 不校验 `Origin` 的端口之外的路径：来源只看 authority，路径由路由自己负责。
 *
 * 纯函数、零 I/O：判定与测试都只依赖请求头与一份由调用方传入的策略，故与 `./lock`、`./playback`
 * 一样可离线单测。
 */
import type { IncomingHttpHeaders } from 'node:http';

/** 判定失败的原因（写进 403 响应，便于调用方自查；文案面向第三方开发者，不面向终端用户） */
export type RequestOriginReason = 'cross-site' | 'bad-origin' | 'origin-mismatch' | 'untrusted-host';

/** 判定结果：ok 为 true 时 reason/message 缺席 */
export type RequestOriginVerdict = { ok: true } | { ok: false; reason: RequestOriginReason; message: string };

/** 调用方（`apply`）提供的部署事实；全部可选，缺省按「回环绑定、端口未知」处理（从严） */
export interface RequestOriginPolicy {
  /** DSH WebServer 实际绑定的地址（`ctx.webServer.host`）。非回环 = 主动对外暴露，跳过 Host 白名单 */
  boundHost?: string;
  /** DSH WebServer 实际端口（`ctx.webServer.port`）。回环 Host 带端口时要求与之一致 */
  port?: number;
  /** 额外信任的 authority（`host` 或 `host:port`），来自 `DSH_PET_TRUSTED_HOSTS`（反向代理 / mDNS） */
  trustedHosts?: readonly string[];
}

/** 统一的 403 文案：几处拒绝共用同一副措辞，避免调用方要靠猜区分 */
const HINT =
  '跨站浏览器请求被拒绝：该接口只接受同源页面或非浏览器调用方（curl / 脚本）。' +
  '第三方插件请在服务端调用，不要从别的网页直接 fetch。';

/** 去掉 IPv6 字面量的方括号并小写（URL.hostname 会把 `[::1]` 连括号一起给你） */
function bareHost(hostname: string): string {
  return hostname.replace(/^\[|\]$/g, '').toLowerCase();
}

/** 回环名字：localhost / 127.0.0.0/8 / ::1 —— 浏览器访问本机的全部合法写法 */
function isLoopbackName(hostname: string): boolean {
  const bare = bareHost(hostname);
  return bare === 'localhost' || bare === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bare);
}

/** IP 字面量（v4 点分十进制 / 含冒号的 v6）：浏览器按字面量直连，rebinding 伪造不出来 */
function isIpLiteral(hostname: string): boolean {
  const bare = bareHost(hostname);
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(bare) || bare.includes(':');
}

/**
 * 服务是不是绑在回环上（= 单机默认部署）。
 * 拿不到绑定地址时按"是"处理：宁可对少数代理部署要求显式配置，也不默认放开白名单。
 */
function isLoopbackBind(boundHost: string | undefined): boolean {
  if (boundHost === undefined || boundHost === '') return true;
  return isLoopbackName(boundHost);
}

/** 拆 `host:port`；非法 authority（含 userinfo、空格等）→ undefined */
function splitAuthority(host: string): { hostname: string; port: string } | undefined {
  try {
    const url = new URL('http://' + host);
    // userinfo / 路径 / 查询串都不该出现在 Host 头里：出现即视为伪造
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) return undefined;
    return { hostname: url.hostname, port: url.port };
  } catch {
    return undefined;
  }
}

/** Host 白名单判定：回环名 / IP 字面量 / 显式信任的 authority 三者之一 */
function judgeHost(host: string, policy: RequestOriginPolicy): RequestOriginVerdict {
  const parts = splitAuthority(host);
  if (parts === undefined) {
    return { ok: false, reason: 'untrusted-host', message: 'Host 不是合法的 authority：' + host + '。' + HINT };
  }
  const { hostname, port } = parts;

  if (isLoopbackName(hostname)) {
    // 回环 + 显式端口：必须等于服务器实际端口（代理转发到别的端口的 loopback Host 不成立）。
    // policy.port 为 0/未知时跳过：独立模式的 `port: 0` 由内核分配，取不到真端口时不该误杀。
    if (port !== '' && policy.port !== undefined && policy.port > 0 && Number(port) !== policy.port) {
      return {
        ok: false,
        reason: 'untrusted-host',
        message: 'Host 的端口（' + port + '）与服务器实际端口（' + policy.port + '）不一致。' + HINT,
      };
    }
    return { ok: true };
  }

  if (isIpLiteral(hostname)) return { ok: true };

  const trusted = policy.trustedHosts ?? [];
  const full = host.toLowerCase();
  if (
    trusted.some((entry) => {
      const value = entry.trim().toLowerCase();
      return value !== '' && (value === full || value === hostname.toLowerCase());
    })
  ) {
    return { ok: true };
  }

  return {
    ok: false,
    reason: 'untrusted-host',
    message:
      'Host 不在信任列表内：' +
      host +
      '。本机部署只接受回环地址与 IP 字面量（防 DNS rebinding）；' +
      '反向代理 / 自定义域名请设置 DSH_PET_TRUSTED_HOSTS（逗号分隔的 host 或 host:port）。',
  };
}

/**
 * 判定一次请求的来源是否可信。
 *
 * @param headers Node 收到的请求头；测试桩可能没有（undefined），按"非浏览器调用方"处理
 *   —— 真实 Node 服务器上该字段恒存在，缺省只出现在单测里。
 * @param policy 部署事实（绑定地址 / 端口 / 额外信任的 authority），由 `apply` 从
 *   `ctx.webServer` 与环境变量读出后传入；缺省值见 `RequestOriginPolicy`。
 * @returns `{ ok: true }` 或带 reason 的拒绝结果；调用方负责回 403（本函数不产生副作用）。
 */
export function judgeRequestOrigin(
  headers?: IncomingHttpHeaders,
  policy: RequestOriginPolicy = {},
): RequestOriginVerdict {
  // 单测桩 / 极老的 Node：没有请求头对象 = 不是浏览器，放行（等价于 curl）
  if (!headers) return { ok: true };

  // ① 跨站请求：浏览器必带，且网页脚本无法篡改/删除——最可靠的一条判据，先于 Origin
  const site = headers['sec-fetch-site'];
  if (typeof site === 'string' && site.trim().toLowerCase() === 'cross-site') {
    return { ok: false, reason: 'cross-site', message: HINT };
  }

  const host = typeof headers.host === 'string' ? headers.host.trim() : '';
  const origin = headers.origin;

  // ② Origin：有就必须与 Host 同 authority（同源页面 / 脚本自带的来源声明）
  if (origin !== undefined && origin !== '') {
    // `null` 是沙箱 iframe / file:// 页面的 Origin——正是最该拒绝的一种，不能当成"没有"
    if (typeof origin !== 'string' || origin === 'null') {
      return {
        ok: false,
        reason: 'bad-origin',
        message: 'Origin 无法识别（null）；跨站沙箱页面不允许调用该接口。' + HINT,
      };
    }

    let parsed: URL;
    try {
      parsed = new URL(origin);
    } catch {
      return { ok: false, reason: 'bad-origin', message: 'Origin 不是合法地址：' + origin + '。' + HINT };
    }
    // 只认 http/https：`file:` / `app:` 之类的 Origin 不可能是 DSH 页面
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { ok: false, reason: 'bad-origin', message: 'Origin 的协议不受支持：' + parsed.protocol + '。' + HINT };
    }

    // Host 缺失时无法比对：有 Origin 却无 Host 只可能是伪造的请求，按拒绝处理
    if (host === '') {
      return { ok: false, reason: 'bad-origin', message: '请求缺少 Host 头，无法确认来源。' + HINT };
    }
    // scheme 不参与比较（见文件头：反向代理会改写 scheme，但 authority 必须一致）
    if (parsed.host.toLowerCase() !== host.toLowerCase()) {
      return {
        ok: false,
        reason: 'origin-mismatch',
        message: 'Origin（' + parsed.host + '）与请求的 Host（' + host + '）不一致。' + HINT,
      };
    }
  }

  // ③ Host 白名单：只在本机（回环绑定）部署下生效。**无 Origin 的请求也要查**——
  //    同源 GET（rebinding 读 /state 就是这一形态）根本不带 Origin，只看 ② 会漏。
  if (host !== '' && isLoopbackBind(policy.boundHost)) {
    const verdict = judgeHost(host, policy);
    if (!verdict.ok) return verdict;
  }

  return { ok: true };
}
