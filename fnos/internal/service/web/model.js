'use strict';

globalThis.FlclashUI = (() => {
  function proxyStatus(s) {
    if (!s) return { title: '正在读取状态', detail: '等待管理服务连接。', tone: '', action: '请稍候' };
    if (s.networkRecoveryPending) return { title: '网络恢复未完成', detail: s.degraded || s.blocked || '请查看网络恢复工具，暂不重新开启接管。', tone: 'warning', action: '关闭并重试恢复' };
    if (s.proxyActive) return { title: '代理已开启', detail: s.settings.networkMode === 'ipv4' ? '正在接管 IPv4，IPv6 不在代理范围内。' : '正在接管 IPv4 与 IPv6，覆盖对象仍需分别验证。', tone: 'good', action: '关闭代理' };
    if (s.settings.enabled && s.degraded) return { title: '直连降级中', detail: s.degraded, tone: 'warning', action: '停止自动恢复' };
    if (s.blocked) return { title: '代理未开启', detail: s.blocked, tone: 'warning', action: '重新开启' };
    return { title: '代理已关闭', detail: s.coreReady ? '配置已就绪，开启后才会接管 NAS 流量。' : '先使用有效配置，再完成网络设置。', tone: '', action: '开启代理' };
  }
  function filteredNodes(group, query, order, delays) {
    const needle = query.trim().toLocaleLowerCase();
    const names = (group?.all || []).filter(name => name.toLocaleLowerCase().includes(needle));
    if (order === 'delay') names.sort((a, b) => {
      const value = name => { const d = delays.get(name); return d?.state === 'done' && d.value >= 0 ? d.value : Infinity; };
      return value(a) - value(b);
    });
    return names;
  }
  class Latest {
    value = 0;
    next() { return ++this.value; }
    valid(ticket) { return ticket === this.value; }
  }
  class WorkQueue {
    pending = [];
    running = 0;
    completed = 0;
    total = 0;
    constructor(work, changed = () => {}) { this.work = work; this.changed = changed; }
    start(items) {
      if (this.running || this.pending.length) return false;
      this.pending = [...new Set(items)]; this.completed = 0; this.total = this.pending.length;
      this.pump(); return true;
    }
    cancel() { this.pending = []; this.total = this.completed + this.running; this.changed(); }
    pump() {
      while (this.running < 2 && this.pending.length) {
        const item = this.pending.shift(); this.running++;
        Promise.resolve().then(() => this.work(item)).catch(() => {}).finally(() => {
          this.running--; this.completed++; this.pump();
        });
      }
      this.changed();
    }
  }
  async function importProfile(api, body, use) {
    const result = await api('profiles', body);
    if (!use) return { id: result.id, used: false };
    try { await api('profiles/select', { id: result.id }); return { id: result.id, used: true }; }
    catch (error) { return { id: result.id, used: false, error }; }
  }
  const operationNames = { startup: '正在启动服务', shutdown: '正在停用应用', control: '正在调整代理', restart: '正在重启核心', settings: '正在保存设置', profiles: '正在导入配置', 'profiles/edit': '正在保存配置', 'profiles/update': '正在更新订阅', 'profiles/select': '正在使用配置', 'profiles/delete': '正在删除配置', 'network/detect': '正在检测网络', 'network/recover': '正在恢复网络', health: '正在检查运行情况' };
  return { proxyStatus, filteredNodes, Latest, WorkQueue, importProfile, operationNames };
})();
