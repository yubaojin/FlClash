export function makeFixture(count = 500) {
  const names = Array.from({ length: count }, (_, i) => `测试节点 ${String(i + 1).padStart(3, '0')}${i % 20 === 0 ? ' · 长名称与不同区域的连接示例 · 仅用于界面验证' : ''}`);
  const proxies = Object.fromEntries(names.map(name => [name, { type: 'Http' }]));
  const all = ['主要代理', '自动选择', '故障转移', 'GLOBAL'];
  for (const [name, type] of [['主要代理', 'Selector'], ['自动选择', 'URLTest'], ['故障转移', 'Fallback'], ['GLOBAL', 'Selector']]) {
    proxies[name] = { type, now: names[0], all: [...names] };
  }
  const now = new Date().toISOString();
  return {
    status: {
      version: '0.3.0', session: '无凭据模拟会话', coreSession: '模拟核心', revision: 1, coreRunning: true, coreReady: true,
      proxyActive: false, degraded: '', blocked: '', operation: '', updatedAt: now, trafficAt: now,
      traffic: { up: 384, down: 8192 }, gatewayForwarding: false, networkRecoveryPending: false,
      settings: { active: 'sample', enabled: false, mode: 'rule', networkMode: 'ipv4', networkModeConfirmed: true,
        healthGroup: '主要代理', healthURL: 'https://example.com/', selected: {}, gatewayCIDRs: [],
        profiles: [{ id: 'sample', name: '界面验收 · 模拟订阅', url: '已保存订阅地址', intervalHours: 24, updated: now }, { id: 'local', name: '本地备用配置', intervalHours: 0, updated: now }],
      },
      network: { mode: 'ipv4', at: now, ready: true, exit4: 'eth0', exit6: '', checks: [
        { name: 'IPv4 默认路由', family: 'ipv4', required: true, ok: true, detail: '模拟出口条件通过（不代表流量已验证）' },
        { name: 'IPv6 默认路由', family: 'ipv6', required: false, ok: false, detail: '模拟环境无 IPv6 默认出口' },
        { name: 'TUN 设备', family: 'common', required: true, ok: true, detail: '模拟条件，不修改开发机网络' },
      ], coverage: ['宿主机', 'Docker host / bridge', '飞牛虚拟机 / OVS'].map(name => ({ name, state: '待接入', detail: '本页使用模拟数据，未验证实际流量。' })) },
    },
    proxies: { all, proxies, revision: 1, session: '无凭据模拟会话' },
    targets: { at: now, items: [
      { id: 'nas', name: 'NAS／共享宿主网络', kind: 'nas', mode: 'host', running: true, canProbe: true, code: 'ready', detail: '模拟网络环境；不是实机检测', sourceID: 'nas', sourceName: 'NAS／共享宿主网络', addresses: ['192.0.2.2'], networks: [], dns: ['192.0.2.1'] },
      { id: 'a'.repeat(64), name: '中文容器 · 默认 bridge', kind: 'container', mode: 'bridge', running: true, canProbe: true, code: 'ready', detail: '模拟默认 bridge', sourceID: 'a'.repeat(64), sourceName: '中文容器 · 默认 bridge', addresses: ['172.17.0.2'], networks: ['bridge'], dns: ['192.0.2.1'] },
      { id: 'b'.repeat(64), name: 'host 容器', kind: 'container', mode: 'host', running: true, canProbe: true, code: 'ready', detail: '不能单独归属 host 容器', sourceID: 'nas', sourceName: 'NAS／共享宿主网络', addresses: [], networks: ['host'], dns: [] },
      { id: 'c'.repeat(64), name: '停止的容器', kind: 'container', mode: 'bridge', running: false, canProbe: false, code: 'stopped', detail: '容器未运行，启动后可检测', sourceID: 'c'.repeat(64), addresses: [], networks: [], dns: [] },
      { id: 'd'.repeat(64), name: '隔离容器', kind: 'container', mode: 'none', running: true, canProbe: false, code: 'isolated', detail: '无外部网络', sourceID: 'd'.repeat(64), addresses: [], networks: [], dns: [] },
    ] },
    diagnostics: [],
    connections: Array.from({ length: 1000 }, (_, i) => ({ id: `connection-${i}`, metadata: { sourceIP: i % 2 ? '172.17.0.2' : '192.0.2.2', sourcePort: 32000 + i, destinationIP: '198.51.100.1', destinationPort: 443, host: `访问目标-${i}.example.com`, network: i % 3 ? 'tcp' : 'udp' }, sourceID: i % 2 ? 'a'.repeat(64) : 'nas', sourceName: i % 2 ? '中文容器 · 默认 bridge' : 'NAS／共享宿主网络', upload: 4096, download: 8192, start: now, observedAt: now, active: true, path: i % 2 ? 'proxy' : 'direct', exit: i % 2 ? names[0] : 'DIRECT', rule: 'DomainSuffix', rulePayload: 'example.com', chains: i % 2 ? [names[0], '主要代理'] : ['DIRECT'] })),
    events: [{ id: 'event-1', at: now, code: 'proxy_enabled', level: 'success', title: '透明代理已开启', detail: '模拟运行事件，不代表 NAS 已接管', next: '检测 NAS 或容器网络' }],
    logs: Array.from({ length: 500 }, (_, i) => `${now} 模拟日志 ${i + 1}：管理服务界面验证，不代表真实 NAS 网络状态。`),
  };
}

export function connectionFixture(fixture, query) {
  const q = new URLSearchParams(query);
  const items = fixture.connections.filter(c => (!q.get('source') || c.sourceID === q.get('source')) && (!q.get('path') || c.path === q.get('path')) && `${c.metadata.host} ${c.sourceName} ${c.rule}`.includes(q.get('q') || ''));
  const offset = Number(q.get('offset') || 0);
  return { items: items.slice(offset, offset + 50), total: items.length, offset, coreSession: fixture.status.coreSession, updatedAt: new Date().toISOString(), stale: false };
}
