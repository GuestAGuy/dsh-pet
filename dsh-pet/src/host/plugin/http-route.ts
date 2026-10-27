/**
 * 路由装配：把装配期对象收成 PetRouteDeps，接上领域路由，并把处理函数挂到 webServer。
 *
 * 路由层只认这个 deps 表，不认识 apply 的闭包；素材路径与协议细节归 ../http.ts。
 * 必须始终成立：HTTP 前缀路由与桌面 Helper 管道消费同一个 handlePetRoute（两端行为严格一致）。
 * @module dsh-pet/src/host/plugin/http-route
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { ROUTE_PATH } from '../../shared/constants.ts';
import { readBody, sendFile, sendJson, sendText, type RouteResult } from '../http.ts';
import { failureBody } from '../routes/result.ts';
import { judgeRequestOrigin } from '../request-guard.ts';
import { createPetRouter } from '../routes/index.ts';
import type { PetRouteDeps } from '../routes/types.ts';
import type { HostContext } from './context.ts';

/**
 * 反向代理 / 自定义域名部署的显式信任列表（`DSH_PET_TRUSTED_HOSTS`，逗号分隔 `host` 或 `host:port`）。
 *
 * 只影响 **回环绑定** 部署的 Host 白名单（见 ../request-guard.ts 的 ③）：DSH 默认只绑 127.0.0.1，
 * 本机访问只该用回环名/IP 字面量；若把 DSH 放在反向代理后面、用域名访问，就把那个 authority
 * 填进来。非回环绑定（`--host 0.0.0.0` 等）本来就不查白名单，不需要设置。
 *
 * @param env - 进程环境（测试可注入）。
 * @returns 去空白后的信任 authority 列表。
 */
function trustedHostsFromEnv(env: NodeJS.ProcessEnv = process.env): string[] {
  return (env.DSH_PET_TRUSTED_HOSTS ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '');
}

/** 单次业务请求的处理函数：URL 已解析、方法已归一。 */
export type HttpRouteHandler = (
  url: string,
  method: string,
  body?: string,
  signal?: AbortSignal,
) => Promise<RouteResult>;

/**
 * 由依赖表构造 HTTP 处理函数。
 * @param deps - 路由层依赖（store、路径、动作函数）。
 * @returns 按前缀分发到领域路由的处理函数。
 */
export function createHttpRoute(deps: PetRouteDeps): { handlePetRoute: HttpRouteHandler } {
  // 配置请求覆盖完整读改写：下一次更新必须读取前一次完成后的配置。
  // GET /config 同样排队，避免写入尚未完成时读到空文件而回退内置默认。
  let configQueue: Promise<void> = Promise.resolve();

  /** 单次业务路由（HTTP 落盘与桌面 Helper 管道共用同一份实现）：输入 rawUrl + method + body 文本，
   *  返回 RouteResult，消费方各自落盘——业务逻辑只有一份，两端天然一致。
   *  signal 可选：调用方断开时中止挂起等待（只有 /playback 的 wait 分支会用到；管道侧不传）。 */
  const handlePetRoute = async (
    rawUrl: string,
    method: string,
    body?: string,
    signal?: AbortSignal,
  ): Promise<RouteResult> => {
    const url = new URL(rawUrl, 'http://localhost');
    const rest = decodeURIComponent(url.pathname.slice(ROUTE_PATH.length + 1));
    const run = (): Promise<RouteResult> => dispatchPetRoute(url, rest, method, body, signal);
    // 写配置的三条路径（PUT/POST /config、POST /pet-display、POST /pet-config）都是「读当前配置
    // → 白名单重建整段 pets → 写盘」，并发交错会互相覆盖，必须共用一条串行队列；
    // GET /config 同样排队，避免写入尚未完成时读到空文件而回退内置默认。
    const isConfigQueue = rest === 'config' || ((rest === 'pet-display' || rest === 'pet-config') && method === 'POST');
    if (isConfigQueue) {
      const pending = configQueue.then(run, run);
      configQueue = pending.then(
        () => undefined,
        () => undefined,
      );
      return pending;
    }
    return run();
  };

  // 路由层依赖表：显式传参取代闭包捕获，各领域模块因此可独立演进（见 ./routes/index.ts）
  const dispatchPetRoute = createPetRouter(deps);

  return { handlePetRoute };
}

/**
 * 把前缀路由挂到宿主 webServer，随插件卸载自动摘除。
 * @param ctx - 宿主上下文。
 * @param handlePetRoute - 业务处理函数（桌面 Helper 管道复用同一个）。
 */
export function registerHttpRoute(ctx: HostContext, handlePetRoute: HttpRouteHandler): void {
  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: 'prefix',
        path: ROUTE_PATH,
        handler: async (req: IncomingMessage, res: ServerResponse) => {
          // CSRF 防线（见 ../request-guard.ts）：浏览器跨站请求在**读 body 之前**拒绝。
          // 恶意页面能用「简单请求」（text/plain + JSON 正文）绕过 CORS 预检，却绕不过来源判定；
          // 不带 Origin / Sec-Fetch-Site 的非浏览器调用方（curl、脚本、桌面管道）行为完全不变。
          // 策略来自部署事实：回环绑定 = 单机默认，Host 必须回环/字面量（防 DNS rebinding）；
          // 非回环绑定 = 用户主动对外暴露，退回 Origin 同源判定（Host 枚举不出来）。
          const verdict = judgeRequestOrigin(req.headers, {
            boundHost: ctx.webServer?.host,
            // 端口取本次连接的实际监听口：独立模式允许把同一份路由挂到另一个端口上，
            // ctx.webServer.port 会指向最初那个监听，直接拿来比 Host 会误杀。
            port: req.socket?.localPort ?? ctx.webServer?.port,
            trustedHosts: trustedHostsFromEnv(),
          });
          if (!verdict.ok) {
            sendJson(res, 403, { error: verdict.message, reason: verdict.reason });
            return;
          }
          // 挂起等待（/playback?wait=）期间调用方可能提前断开：据此中止等待，
          // 否则那个等待者要一直留到超时才回收。'close' 在正常应答后也会触发，但那时监听已摘掉。
          const abort = new AbortController();
          const onClose = (): void => abort.abort();
          res.on('close', onClose);
          try {
            const body = req.method === 'PUT' || req.method === 'POST' ? await readBody(req) : undefined;
            const result = await handlePetRoute(req.url ?? '/', req.method ?? 'GET', body, abort.signal);
            res.off('close', onClose);
            if (result.kind === 'json') sendJson(res, result.status, result.obj, result.headers);
            else if (result.kind === 'text') sendText(res, result.status, result.body);
            else if (result.kind === 'none') {
              /* 调用方已断开：不再写（写了会抛） */
            } else sendFile(res, result.file, result.contentType); // 非 async：流在 open 后自己 pipe，错误内部收口
          } catch (e) {
            res.off('close', onClose);
            // 连接已断（挂起等待被中止后也可能撞上）→ 不再写，避免二次抛错
            if (!res.destroyed && !res.writableEnded) {
              // 请求体超限与客户端中断是用户侧问题，不能报成 500；断连时连响应都写不出去。
              const code = (e as { code?: string }).code;
              if (code === 'body-too-large')
                sendJson(res, 413, failureBody('payload-too-large', 'request body too large'));
              else if (code !== 'client-aborted') {
                // 未预期异常：真实原因只进日志，响应里只回分类文案（可能含绝对路径，不外泄）
                ctx.logger?.warn?.(`[dsh-pet] route failed: ${e instanceof Error ? e.message : String(e)}`);
                sendJson(res, 500, failureBody('internal-error', 'dsh-pet: internal error'));
              }
            }
          }
        },
      }),
    'dsh-pet: /dsh-pet-7340 asset route',
  );
}
