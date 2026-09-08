import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { makeFixture } from './fixtures.mjs';

const fixture = makeFixture();
const prefix = '/app/flclash/';
const allowed = new Set(['index.html', 'app.js', 'model.js', 'style.css']);
const shell = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>FlClash 0.2.1 本地交互验收 · 模拟数据</title><style>body{margin:0;background:#dfe4ee;font:14px "Microsoft YaHei",sans-serif;color:#344056}header{padding:12px 20px;background:#fff;display:flex;gap:12px;align-items:center;flex-wrap:wrap}header strong{margin-right:auto}button{border:1px solid #d3d7e1;border-radius:6px;padding:7px 12px;background:white;cursor:pointer}main{padding:20px;display:flex;justify-content:center}iframe{border:1px solid #cbd1df;border-radius:10px;background:white;box-shadow:0 10px 35px #59678522;max-width:100%;height:720px;width:1200px}small{color:#a16d28}</style><header><strong>FlClash 0.2.1 · 本地交互验收</strong><small>全部为模拟数据，不连接 NAS，不修改系统网络</small><button data-w="1200" data-h="720">常规窗口</button><button data-w="840" data-h="560">缩小窗口</button><button data-w="390" data-h="640">窄屏</button><button data-w="1600" data-h="850">大窗口</button></header><main><iframe title="FlClash 模拟内嵌窗口" src="/app/flclash/"></iframe></main><script>document.querySelectorAll('button').forEach(b=>b.onclick=()=>{const f=document.querySelector('iframe');f.style.width=b.dataset.w+'px';f.style.height=b.dataset.h+'px'})</script></html>`;

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1:19877');
  const send = (data, status = 200, type = 'application/json; charset=utf-8') => {
    res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' }); res.end(type.startsWith('application/json') ? JSON.stringify(data) : data);
  };
  try {
    if (url.pathname === '/' && req.method === 'GET') { send(shell, 200, 'text/html; charset=utf-8'); return; }
    if (url.pathname.startsWith(`${prefix}api/`)) {
      const path = url.pathname.slice(`${prefix}api/`.length);
      let raw = ''; for await (const chunk of req) { raw += chunk; if (raw.length > 1048576) { send({ error: '预览请求过大' }, 413); return; } }
      const body = raw ? JSON.parse(raw) : {};
      const s = fixture.status;
      const p = s.settings.profiles.find(p => p.id === body.id);
      s.updatedAt = new Date().toISOString(); s.trafficAt = s.updatedAt;
      if (path === 'session') { send({ csrfToken: 'local-preview-csrf' }); return; }
      if (path === 'status') { send(s); return; }
      if (path === 'proxies') { send(fixture.proxies); return; }
      if (path === 'logs') { send(fixture.logs); return; }
      if (req.method !== 'POST') { send({ error: '未知预览接口' }, 404); return; }
      switch (path) {
        case 'settings': Object.assign(s.settings, body); s.network.mode = s.settings.networkMode; s.network.ready = s.settings.networkMode === 'ipv4'; s.network.checks[1].required = s.settings.networkMode !== 'ipv4'; break;
        case 'network/detect': s.network.at = new Date().toISOString(); break;
        case 'control': s.settings.enabled = s.proxyActive = !!body.enabled; break;
        case 'restart': s.revision++; fixture.proxies.revision = s.revision; break;
        case 'proxies/select': fixture.proxies.proxies[body.group].now = body.proxy; break;
        case 'proxies/delay': await new Promise(resolve => setTimeout(resolve, 450)); send({ value: body.proxy.includes('003') ? -1 : 28 + body.proxy.length, revision: s.revision, session: s.session, at: new Date().toISOString() }); return;
        case 'profiles': {
          const id = `mock-${Date.now()}`;
          s.settings.profiles.push({ id, name: body.name, url: body.url ? '已保存订阅地址' : '', intervalHours: body.intervalHours, updated: new Date().toISOString() }); send({ id }); return;
        }
        case 'profiles/select': s.settings.active = body.id; s.revision++; fixture.proxies.revision = s.revision; break;
        case 'profiles/edit': p.name = body.name; p.intervalHours = body.intervalHours; break;
        case 'profiles/update': p.updated = new Date().toISOString(); p.error = ''; break;
        default: send({ error: '本地预览不提供此操作', code: 'preview_only' }, 400); return;
      }
      send({ ok: true }); return;
    }
    if (!url.pathname.startsWith(prefix) || req.method !== 'GET') { send({ error: '不存在' }, 404); return; }
    const file = url.pathname.slice(prefix.length) || 'index.html';
    if (file === 'logo.png') { send(await readFile(new URL('../../macos/Runner/Assets.xcassets/AppIcon.appiconset/app_icon_64.png', import.meta.url)), 200, 'image/png'); return; }
    if (!allowed.has(file)) { send({ error: '不存在' }, 404); return; }
    const type = file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html';
    send(await readFile(new URL(`../internal/service/web/${file}`, import.meta.url)), 200, `${type}; charset=utf-8`);
  } catch { if (!res.headersSent) send({ error: '模拟操作失败' }, 400); else res.end(); }
});

server.listen(19877, '127.0.0.1', () => console.log('本地模拟预览：http://127.0.0.1:19877/，仅监听本机回环，30 分钟后关闭。'));
setTimeout(() => { server.close(); server.closeAllConnections(); }, 30 * 60 * 1000).unref();
