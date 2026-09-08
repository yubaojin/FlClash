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
      version: '0.2.1', session: '无凭据模拟会话', revision: 1, coreRunning: true, coreReady: true,
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
    logs: Array.from({ length: 500 }, (_, i) => `${now} 模拟日志 ${i + 1}：管理服务界面验证，不代表真实 NAS 网络状态。`),
  };
}
