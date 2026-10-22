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
 *   ③ 两者都没有 → 放行（非浏览器调用方：curl / 脚本 / 桌面管道）。
 *
 * 刻意**不做**的两件事：
 *   - 不校验 `Host`：DSH 支持远端访问（publicUrl / 局域网），把 Host 钉死在 `127.0.0.1` 会误伤
 *     正常部署；跨站请求的 Origin 与 Host 必然不同，②已经覆盖了 DNS rebinding 之外的场景；
 *   - 不加 CORS 响应头：同源页面不需要，跨源页面本来也读不到响应（浏览器强制）。这里只负责
 *     "不让它产生副作用"，不负责"让它能读"。
 *
 * 纯函数、零 I/O：判定与测试都只依赖请求头，故与 `./lock`、`./playback` 一样可离线单测。
 */
import type { IncomingHttpHeaders } from 'node:http';

/** 判定失败的原因（写进 403 响应，便于调用方自查；文案面向第三方开发者，不面向终端用户） */
export type RequestOriginReason = 'cross-site' | 'bad-origin' | 'origin-mismatch';

/** 判定结果：ok 为 true 时 reason/message 缺席 */
export type RequestOriginVerdict = { ok: true } | { ok: false; reason: RequestOriginReason; message: string };

/** 统一的 403 文案：三处拒绝共用同一副措辞，避免调用方要靠猜区分 */
const HINT =
  '跨站浏览器请求被拒绝：该接口只接受同源页面或非浏览器调用方（curl / 脚本）。' +
  '第三方插件请在服务端调用，不要从别的网页直接 fetch。';

/**
 * 判定一次请求的来源是否可信。
 *
 * @param headers Node 收到的请求头；测试桩可能没有（undefined），按"非浏览器调用方"处理
 *   —— 真实 Node 服务器上该字段恒存在，缺省只出现在单测里。
 * @returns `{ ok: true }` 或带 reason 的拒绝结果；调用方负责回 403 与日志（本函数不产生副作用）。
 */
export function judgeRequestOrigin(headers?: IncomingHttpHeaders): RequestOriginVerdict {
  // 单测桩 / 极老的 Node：没有请求头对象 = 不是浏览器，放行（等价于 curl）
  if (!headers) return { ok: true };

  // ① 跨站请求：浏览器必带，且网页脚本无法篡改/删除——最可靠的一条判据，先于 Origin
  const site = headers['sec-fetch-site'];
  if (typeof site === 'string' && site.trim().toLowerCase() === 'cross-site') {
    return { ok: false, reason: 'cross-site', message: HINT };
  }

  // ② Origin：没有就是非浏览器调用方（同源 GET / <img> 之类也不带 Origin，但那两类本来就只读）
  const origin = headers.origin;
  if (origin === undefined || origin === '') return { ok: true };

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
  const host = headers.host;
  if (typeof host !== 'string' || host === '') {
    return { ok: false, reason: 'bad-origin', message: '请求缺少 Host 头，无法确认来源。' + HINT };
  }
  // scheme 不参与比较（见文件头：反向代理会改写 scheme，但 authority 必须一致）
  if (parsed.host.toLowerCase() !== host.trim().toLowerCase()) {
    return {
      ok: false,
      reason: 'origin-mismatch',
      message: 'Origin（' + parsed.host + '）与请求的 Host（' + host + '）不一致。' + HINT,
    };
  }

  return { ok: true };
}
