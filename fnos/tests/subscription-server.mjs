import { readFileSync } from 'node:fs';
import http from 'node:http';
import { isIP } from 'node:net';

const [bind, client, portText] = process.argv.slice(2);
const port = Number(portText);
if (isIP(bind) !== 4 || isIP(client) !== 4 || bind === '0.0.0.0' || !Number.isInteger(port) || port < 1024 || port > 65535) {
  throw new Error('用法：node subscription-server.mjs 本机指定IPv4 测试NAS的IPv4 临时端口');
}
const sample = readFileSync(new URL('../testdata/smoke.yaml', import.meta.url));
const requests = new Map();
const server = http.createServer((req, res) => {
  if (req.socket.remoteAddress !== client || req.method !== 'GET') {
    res.writeHead(403).end();
    return;
  }
  const path = req.url;
  if (!['/stable.yaml', '/retry.yaml', '/bad-update.yaml'].includes(path)) {
    res.writeHead(404).end();
    return;
  }
  const count = (requests.get(path) || 0) + 1;
  requests.set(path, count);
  console.log(`${path}：第 ${count} 次请求`);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/yaml; charset=utf-8');
  if (path === '/retry.yaml' && count > 1) {
    res.writeHead(503).end('测试订阅暂时不可用');
  } else if (path === '/bad-update.yaml' && count > 1) {
    res.end('proxies: []\nrules: [MATCH,不存在的策略组]\n');
  } else {
    res.end(sample);
  }
});
server.requestTimeout = 5000;
server.headersTimeout = 5000;
server.listen(port, bind, () => console.log('临时订阅测试服务已启动，仅允许指定 NAS；20 分钟后自动关闭。'));
function stop() { server.close(); server.closeAllConnections(); }
setTimeout(stop, 20 * 60 * 1000).unref();
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
