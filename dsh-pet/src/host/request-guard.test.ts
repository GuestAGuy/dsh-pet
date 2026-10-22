/**
 * 请求来源判定的单元测试 —— 钉住 `/dsh-pet-7340` 的 CSRF 门禁真值表。
 *
 * 为什么单独钉这些：这一层是**唯一会拒绝第三方调用**的地方（其余端点只校验参数），判错一次就是
 * 两种事故之一——「浏览器跨站请求被放行」（花用户的模型额度、重置配置）或「正常调用方被误杀」
 * （第三方脚本、桌面管道、反向代理后面的 DSH 页面）。所以这里把三条判据（Sec-Fetch-Site /
 * Origin / Host）和三个放行场景（无头、同源、反代 https）逐条写死。
 *
 * 跑法：node --experimental-strip-types --test src/host/request-guard.test.ts
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { judgeRequestOrigin } from './request-guard.ts';

const HOST = '127.0.0.1:3080';

describe('放行：不带浏览器来源头的调用方（curl / 脚本 / 桌面管道）', () => {
  test('完全没有 headers（单测桩的形态）→ 放行', () => {
    assert.deepEqual(judgeRequestOrigin(undefined), { ok: true });
  });

  test('空对象 → 放行', () => {
    assert.deepEqual(judgeRequestOrigin({}), { ok: true });
  });

  test('只有 Host、没有 Origin / Sec-Fetch-Site → 放行', () => {
    assert.deepEqual(judgeRequestOrigin({ host: HOST }), { ok: true });
  });

  test('Origin 是空串（某些代理会这么写）→ 当作没有 → 放行', () => {
    assert.deepEqual(judgeRequestOrigin({ host: HOST, origin: '' }), { ok: true });
  });

  test('Sec-Fetch-Site: same-origin + 同源 Origin → 放行', () => {
    assert.deepEqual(judgeRequestOrigin({ host: HOST, origin: 'http://' + HOST, 'sec-fetch-site': 'same-origin' }), {
      ok: true,
    });
  });

  test('反向代理终止 TLS：Origin=https://host、Host 只有 host:port → 放行（只比 authority，不比 scheme）', () => {
    assert.deepEqual(judgeRequestOrigin({ host: 'dsh.example.com', origin: 'https://dsh.example.com' }), {
      ok: true,
    });
  });

  test('authority 大小写不敏感（Host 在 HTTP/1.1 里不区分大小写）→ 放行', () => {
    assert.deepEqual(judgeRequestOrigin({ host: 'DSH.example.com', origin: 'http://dsh.example.com' }), {
      ok: true,
    });
  });
});

describe('拒绝：跨站浏览器请求', () => {
  test('Sec-Fetch-Site: cross-site（无 Origin）→ cross-site', () => {
    const v = judgeRequestOrigin({ host: HOST, 'sec-fetch-site': 'cross-site' });
    assert.equal(v.ok, false);
    if (v.ok) return;
    assert.equal(v.reason, 'cross-site');
  });

  test('Sec-Fetch-Site 大小写/空白容忍（cross-site 与 CROSS-SITE 同判）→ cross-site', () => {
    const v = judgeRequestOrigin({ host: HOST, 'sec-fetch-site': 'Cross-Site' });
    assert.equal(v.ok, false);
    if (v.ok) return;
    assert.equal(v.reason, 'cross-site');
  });

  test('别的站点 Origin → origin-mismatch，且 error 文案带上两边的 authority', () => {
    const v = judgeRequestOrigin({ host: HOST, origin: 'http://evil.example' });
    assert.equal(v.ok, false);
    if (v.ok) return;
    assert.equal(v.reason, 'origin-mismatch');
    assert.match(v.message, /evil\.example/);
    assert.match(v.message, new RegExp(HOST.replace('.', '\\.')));
  });

  test('同主机不同端口也算跨源（本地另一个服务起的页面）→ origin-mismatch', () => {
    const v = judgeRequestOrigin({ host: HOST, origin: 'http://127.0.0.1:3199' });
    assert.equal(v.ok, false);
    if (v.ok) return;
    assert.equal(v.reason, 'origin-mismatch');
  });

  test('Origin: null（沙箱 iframe / file://）→ bad-origin', () => {
    const v = judgeRequestOrigin({ host: HOST, origin: 'null' });
    assert.equal(v.ok, false);
    if (v.ok) return;
    assert.equal(v.reason, 'bad-origin');
  });

  test('Origin 不是合法 URL → bad-origin', () => {
    const v = judgeRequestOrigin({ host: HOST, origin: 'not a url' });
    assert.equal(v.ok, false);
    if (v.ok) return;
    assert.equal(v.reason, 'bad-origin');
  });

  test('Origin 协议不是 http/https（file: / app:）→ bad-origin', () => {
    for (const origin of ['file:///tmp/x.html', 'app://dsh-pet']) {
      const v = judgeRequestOrigin({ host: HOST, origin });
      assert.equal(v.ok, false, origin);
      if (v.ok) continue;
      assert.equal(v.reason, 'bad-origin');
    }
  });

  test('有 Origin 却没有 Host → bad-origin（无法确认来源，按拒绝处理）', () => {
    const v = judgeRequestOrigin({ origin: 'http://' + HOST });
    assert.equal(v.ok, false);
    if (v.ok) return;
    assert.equal(v.reason, 'bad-origin');
  });
});
