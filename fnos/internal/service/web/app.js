'use strict';

const $ = id => document.getElementById(id);
const UI = FlclashUI;
const stateGate = new UI.Latest();
const proxyGate = new UI.Latest();
const logGate = new UI.Latest();
let state;
let connected = false;
let busy = false;
let polling = false;
let currentTab = 'overview';
let proxyData;
let proxyGroup = '';
let nodeLimit = 80;
let nodeSignature = '';
let networkSignature = '';
let lastProxyRead = 0;
let toastTimer;
let logLines = [];
let source = 'url';
let editing = '';
let dialogDirty = false;
let fileYAML = '';
let dialogEpoch = 0;
let confirmResult;
let lastFocus;
const dirty = new Set();
const scrollPositions = new Map();
const delays = new Map();
const profileCards = new Map();
const nodeRows = new Map();
const batch = new UI.WorkQueue(testNode, renderBatch);

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function setText(id, value) { if ($(id).textContent !== value) $(id).textContent = value; }
function message(scope, text = '', tone = 'error', owner = 'operation') {
  const node = $(`${scope}-message`);
  node.textContent = text;
  node.className = `notice ${tone}`;
  node.hidden = !text;
  node.dataset.owner = owner;
}
function operationError(scope, error) {
  const next = scope === 'profiles' || scope === 'dialog' ? '检查地址或配置内容后重试，原有效配置保留。' : scope === 'proxies' ? '刷新策略组并测试所选节点后重试。' : '查看网络条件或最近检测结果，修正后再操作。';
  message(scope, `本次操作未完成。${next}`);
  const detail = element('details'); detail.append(element('summary', '查看技术原因'), element('p', `${error.code || 'request_failed'}：${error.message}`, 'technical'));
  $(`${scope}-message`).append(detail);
}
function toast(text) {
  clearTimeout(toastTimer);
  setText('toast', text); $('toast').hidden = false;
  toastTimer = setTimeout(() => { $('toast').hidden = true; }, 4500);
}
function date(value) {
  if (!value || value.startsWith('0001')) return '尚无记录';
  return new Date(value).toLocaleString('zh-CN', { hour12: false });
}
function rate(value) {
  if (!Number.isFinite(value)) return '—';
  return value < 1024 ? `${value} B/s` : value < 1048576 ? `${(value / 1024).toFixed(1)} KiB/s` : `${(value / 1048576).toFixed(1)} MiB/s`;
}
function currentProfile() { return state?.settings.profiles.find(p => p.id === state.settings.active); }
function currentGroup() { return proxyData?.proxies?.[proxyGroup]; }
function coreKey(value = state) { return `${value?.session || ''}:${value?.revision}`; }
function coreRequest() { return { revision: proxyData?.revision, session: proxyData?.session }; }
function mainGroup() { return state?.settings.mode === 'global' ? 'GLOBAL' : state?.settings.healthGroup || ''; }
function serverBusy() { return !!state?.operation && !['health', 'proxies', 'network'].includes(state.operation); }
function canWrite() { return connected && !busy && !serverBusy(); }

async function api(path, body) {
  const token = body === undefined ? '' : (await api('session')).csrfToken;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), body === undefined || path === 'proxies/delay' ? 15000 : 115000);
  try {
    const response = await fetch(`/app/flclash/api/${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'Content-Type': 'application/json', 'X-FlClash-Request': '1', ...(body === undefined ? {} : { 'X-FlClash-CSRF': token }) },
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    let result;
    try { result = await response.json(); }
    catch { const error = new Error('管理服务未返回有效数据，请检查飞牛登录状态后重试。'); error.code = 'invalid_response'; throw error; }
    if (!response.ok) { const error = new Error(result.error || '操作未完成，请稍后重试。'); error.code = result.code || 'request_failed'; throw error; }
    return result;
  } catch (error) {
    if (error.name === 'AbortError') { const timeout = new Error('请求超时；操作可能仍在执行，请先检查运行状态，不要重复提交。'); timeout.code = 'timeout'; throw timeout; }
    if (error instanceof TypeError) { const offline = new Error('无法连接管理服务，请检查网络或应用中心运行状态。'); offline.code = 'connection_failed'; throw offline; }
    throw error;
  } finally { clearTimeout(timer); }
}

async function mutate(scope, task) {
  if (!canWrite()) { message(scope, '后台正在处理操作或连接尚未恢复，请稍后重试。'); return; }
  busy = true; stateGate.next(); batch.cancel(); message(scope); updateLocks();
  try { await task(); }
  catch (error) { operationError(scope, error); }
  finally {
    busy = false; stateGate.next();
    await refresh(false);
    if (connected && state?.coreReady && !serverBusy()) await loadProxies(false);
    updateLocks();
  }
}
function actionButton(label, scope, task, style = 'secondary') {
  const b = element('button', label, style);
  b.dataset.write = '';
  b.addEventListener('click', () => { void mutate(scope, task); });
  return b;
}
function fillOptions(id, names, selected, placeholder) {
  const node = $(id);
  const signature = JSON.stringify([names, placeholder]);
  if (node.dataset.options !== signature) {
    const options = names.map(name => { const option = element('option', name); option.value = name; return option; });
    if (placeholder !== undefined) { const empty = element('option', placeholder); empty.value = ''; options.unshift(empty); }
    node.replaceChildren(...options); node.dataset.options = signature;
  }
  if (document.activeElement !== node) node.value = selected || '';
}
function updateLocks() {
  if (state) setText('toggle', busy || serverBusy() ? UI.operationNames[state.operation] || '正在处理…' : UI.proxyStatus(state).action);
  document.querySelectorAll('[data-write]').forEach(node => { node.disabled = !canWrite() || node.dataset.locked === 'true'; });
  $('main-group').disabled = !canWrite() || !proxyData || state?.settings.mode === 'global';
  const group = proxyData?.proxies?.[mainGroup()];
  $('quick-node').disabled = !canWrite() || group?.type !== 'Selector' || state?.settings.mode === 'direct';
  $('restart').disabled = !canWrite() || !currentProfile();
  for (const card of profileCards.values()) {
    const p = state?.settings.profiles.find(item => item.id === card.id);
    if (p) {
      card.use.disabled = !canWrite() || (p.id === state.settings.active && state.coreReady);
      card.remove.disabled = !canWrite() || p.id === state.settings.active;
    }
  }
  $('profile-dialog').querySelectorAll('input,select,textarea,button').forEach(node => { node.disabled = busy; });
  $('profile-interval').disabled = busy || source !== 'url';
  for (const name of nodeRows.keys()) updateNode(name);
  renderBatch();
}

function renderNetworkConfirmation() {
  setText('network-confirm-text', $('network-mode').value === 'ipv4'
    ? '我确认所选范围：仅 IPv4，不接管 IPv6，也不提供 IPv6 防泄漏保证。'
    : '我确认所选范围：同时接管 IPv4 和 IPv6，两个地址族都必须有可用出口。');
}

function renderState() {
  const s = state.settings;
  const display = UI.proxyStatus(state);
  setText('proxy-state', display.title);
  setText('proxy-detail', display.detail);
  $('proxy-failure').hidden = !state.blocked && !state.degraded;
  setText('proxy-failure-detail', state.blocked || state.degraded || '');
  if (state.blocked && !state.proxyActive) setText('proxy-detail', '开启未完成；当前没有透明接管。请查看原因并重新检测，不会自动反复启动。');
  $('power-icon').className = `power ${display.tone}`;
  setText('toggle', display.action);
  setText('core-state', state.coreReady ? '配置已就绪' : state.coreRunning ? '尚未加载配置' : '核心未运行');
  setText('core-description', state.coreReady ? '核心就绪不代表已接管流量' : '使用配置后加载核心');
  setText('network-state', s.networkMode === 'ipv4' ? '仅 IPv4' : 'IPv4 + IPv6');
  setText('gateway-state', state.gatewayForwarding ? '已保留客户端普通转发' : '未启用客户端转发');
  const freshTraffic = state.trafficAt && Date.now() - Date.parse(state.trafficAt) < 15000;
  setText('traffic', freshTraffic ? `${rate(state.traffic?.up)} / ${rate(state.traffic?.down)}` : '— / —');
  setText('traffic-description', freshTraffic ? '核心流量 · 不是 NAS 总流量' : '暂无最新采样 · 不是 NAS 总流量');
  $('ipv4-notice').hidden = s.networkMode !== 'ipv4';
  $('operation').hidden = !state.operation;
  setText('operation', UI.operationNames[state.operation] || '正在读取数据');
  const p = currentProfile();
  setText('active-profile', p?.name || '尚未使用配置');
  setText('active-profile-detail', p ? `${p.url ? '订阅配置' : '本地配置'} · ${state.coreReady ? '已加载' : '已保存选择，待加载'} · ${date(p.updated)}` : '添加订阅或本地 YAML，即可开始。');
  document.querySelectorAll('[data-mode]').forEach(node => {
    node.classList.toggle('selected', node.dataset.mode === s.mode);
    node.setAttribute('aria-pressed', String(node.dataset.mode === s.mode));
  });
  setText('mode-help', { rule: '按订阅规则分流；不同规则仍可指向不同策略组。', global: '所有纳入接管的流量使用 GLOBAL 策略组。', direct: '核心按直连模式处理流量，透明接管仍开启；“关闭代理”才会停止接管。' }[s.mode]);
  if (!dirty.has('network')) { $('network-mode').value = s.networkMode || 'dual'; $('network-confirm').checked = !!s.networkModeConfirmed; }
  renderNetworkConfirmation();
  if (!dirty.has('gateway')) $('gateway-cidrs').value = (s.gatewayCIDRs || []).join('\n');
  if (!dirty.has('health')) $('health-url').value = s.healthURL;
  renderQuick();
  renderProfiles();
  renderNetwork(state.network || {});
  const steps = [
    ['使用有效配置', state.coreReady, 'profiles'],
    ['选择主要策略组', s.mode !== 'rule' || !!s.healthGroup, 'overview'],
    ['确认并检测网络', s.networkModeConfirmed && state.network?.ready, 'network'],
    ['开启透明代理', state.proxyActive, 'overview'],
  ];
  const signature = JSON.stringify(steps);
  if ($('setup-steps').dataset.signature !== signature) {
    $('setup-steps').replaceChildren(...steps.map(([label, done, tab], index) => {
      if (done) return null;
      const b = element('button', undefined, `setup-step${done ? ' done' : ''}`);
      b.append(element('span', done ? '✓' : String(index + 1), 'step-number'), element('span', label));
      b.addEventListener('click', () => { navigate(tab); if (index === 1) $('main-group').focus(); });
      return b;
    }).filter(Boolean));
    $('setup-steps').dataset.signature = signature;
  }
  $('setup-guide').hidden = steps.every(item => item[1]);
  updateLocks();
  globalThis.FlclashConsole?.stateChanged();
}

async function refresh(loadNodes = true) {
  const ticket = stateGate.next();
  try {
    const next = await api('status');
    if (!stateGate.valid(ticket)) return;
    if (!next.settings || !Array.isArray(next.settings.profiles)) throw new Error('后台状态格式不匹配，请确认安装包版本。');
    const changed = !state || coreKey(next) !== coreKey(state) || !next.coreReady;
    state = next; connected = true;
    setText('connection', '管理服务已连接');
    $('connection-dot').className = 'dot good';
    $('retry').hidden = true; $('service-alert').hidden = true;
    if (changed) {
      proxyGate.next(); proxyData = undefined; nodeSignature = ''; delays.clear(); batch.cancel();
      renderNodes();
    }
    renderState();
    if (loadNodes && state.coreReady && !busy && !serverBusy() && (!proxyData || (currentTab === 'proxies' && Date.now() - lastProxyRead > 10000))) await loadProxies(false);
  } catch (error) {
    if (!stateGate.valid(ticket)) return;
    connected = false; setText('connection', '管理服务连接中断');
    $('connection-dot').className = 'dot error'; $('retry').hidden = false;
    $('service-alert').textContent = `${error.message}${state ? ' 下方为上一次已知状态，不代表当前运行情况。' : ''}`;
    $('service-alert').hidden = false; updateLocks();
  }
}
function renderProfiles() {
  const profiles = state?.settings.profiles || [];
  const root = $('profile-list');
  const ids = new Set(profiles.map(p => p.id));
  for (const [id, card] of profileCards) if (!ids.has(id)) { card.root.remove(); profileCards.delete(id); }
  root.querySelector('.empty-state')?.remove();
  const query = $('profile-search').value.trim().toLocaleLowerCase();
  let visible = 0;
  for (const p of profiles) {
    let card = profileCards.get(p.id);
    if (!card) {
      const row = element('article', undefined, 'profile-row');
      const info = element('div', undefined, 'profile-info');
      const line = element('div', undefined, 'profile-name-line');
      const name = element('h2'); const badge = element('span', '', 'badge');
      const detail = element('p'); const error = element('p', '', 'profile-error');
      line.append(name, badge); info.append(line, detail, error);
      const actions = element('div', undefined, 'profile-actions');
      const use = actionButton('使用', 'profiles', async () => { await api('profiles/select', { id: p.id }); toast('配置已使用，代理开关保持原状态。'); });
      const update = actionButton('更新', 'profiles', async () => { await api('profiles/update', { id: p.id }); toast('订阅已更新。'); });
      const menu = element('details', undefined, 'menu'); const summary = element('summary', '更多');
      const items = element('div');
      const edit = element('button', '编辑', 'secondary'); edit.dataset.write = '';
      edit.addEventListener('click', () => { menu.open = false; openProfile(p.id); });
      const remove = element('button', '删除', 'danger'); remove.dataset.write = '';
      remove.addEventListener('click', async () => {
        menu.open = false;
        const current = state.settings.profiles.find(item => item.id === p.id);
        if (await confirmAction('删除配置', `删除“${current?.name || '此配置'}”？这不会删除其他配置。`)) {
          await mutate('profiles', async () => { await api('profiles/delete', { id: p.id }); toast('配置已删除。'); });
        }
      });
      items.append(edit, remove); menu.append(summary, items); actions.append(use, update, menu);
      row.append(info, actions); root.append(row);
      card = { id: p.id, root: row, name, badge, detail, error, use, update, remove }; profileCards.set(p.id, card);
    }
    const active = p.id === state.settings.active;
    card.name.textContent = p.name;
    card.badge.textContent = active ? state.coreReady ? '正在使用' : '已保存 · 待加载' : '已保存';
    card.badge.className = `badge${active && state.coreReady ? ' good' : ''}`;
    card.detail.textContent = `${p.url ? '订阅配置' : '本地配置'} · 上次成功 ${date(p.updated)} · ${p.url && p.intervalHours ? `下次 ${date(new Date(Math.max(Date.parse(p.updated) || 0, Date.parse(p.lastAttempt) || 0) + p.intervalHours * 3600000).toISOString())}（每 ${p.intervalHours} 小时）` : '手动更新'}`;
    card.error.textContent = p.error ? `更新失败，旧配置仍保留。可稍后重试更新。详情：${p.error}` : '';
    card.error.hidden = !p.error;
    card.use.textContent = active && state.coreReady ? '使用中' : active ? '加载配置' : '使用';
    card.update.hidden = !p.url;
    card.root.hidden = !p.name.toLocaleLowerCase().includes(query);
    if (!card.root.hidden) visible++;
  }
  setText('profile-count', `${profiles.length} 份配置${query ? ` · 匹配 ${visible} 份` : ''}`);
  if (!visible) {
    const empty = element('div', undefined, 'empty-state');
    empty.append(element('h2', profiles.length ? '没有匹配的配置' : '从一份配置开始'), element('p', profiles.length ? '尝试其他关键词。' : '点击右上角“添加配置”，导入订阅或本地 YAML。'));
    root.append(empty);
  }
}

async function loadProxies(showError = true) {
  if (!connected || !state?.coreReady || serverBusy()) { renderQuick(); renderNodes(); return; }
  const ticket = proxyGate.next(); const key = coreKey();
  try {
    const data = await api('proxies');
    if (!proxyGate.valid(ticket) || coreKey() !== key || coreKey(data) !== key) return;
    proxyData = data; lastProxyRead = Date.now();
    if (!(data.all || []).includes(proxyGroup)) proxyGroup = data.all?.includes(mainGroup()) ? mainGroup() : (data.all?.find(name => name !== 'GLOBAL') || data.all?.[0] || '');
    if ($('proxies-message').dataset.owner === 'read') message('proxies');
    renderQuick(); renderNodes(); updateLocks();
  } catch (error) { if (proxyGate.valid(ticket) && showError) message('proxies', error.message, 'error', 'read'); }
}
function renderQuick() {
  const names = proxyData?.all || [];
  fillOptions('main-group', names, mainGroup(), names.length ? '选择主要策略组' : '先使用有效配置');
  const group = proxyData?.proxies?.[mainGroup()];
  fillOptions('quick-node', group?.all || [], group?.now || '', group?.type === 'Selector' ? undefined : group ? '由核心自动管理' : '先选择策略组');
  setText('group-help', state?.settings.mode === 'global' ? '全局模式使用 GLOBAL；切回规则模式后恢复原主要策略组。' : state?.settings.mode === 'direct' ? '直连模式不使用代理节点；保留原主要策略组选择。' : group && group.type !== 'Selector' ? '该组由核心自动选择，不能手动覆盖。' : '用于首页快捷切换及规则模式故障检测，不改写订阅规则。');
}
function namesInView() { return UI.filteredNodes(currentGroup(), $('node-search').value, $('node-sort').value, delays); }
function renderNodes() {
  const group = currentGroup();
  $('proxy-empty').hidden = !!group; $('proxy-browser').hidden = !group;
  const query = $('group-search').value.trim().toLocaleLowerCase();
  const groups = (proxyData?.all || []).filter(name => name.toLocaleLowerCase().includes(query));
  fillOptions('proxy-group', groups, groups.includes(proxyGroup) ? proxyGroup : '', query ? (groups.length ? '选择匹配的策略组' : '没有匹配的策略组') : undefined);
  if (!group) { $('node-list').replaceChildren(); nodeRows.clear(); nodeSignature = ''; return; }
  const names = namesInView();
  const type = { Selector: '手动选择', URLTest: '自动选择', Fallback: '故障转移', LoadBalance: '负载均衡', Relay: '链式代理' }[group.type] || group.type;
  setText('selected-node', group.now || '由核心管理');
  setText('selected-node-help', `${proxyGroup} · ${type}。切换后，既有连接可能继续使用旧出口。`);
  setText('group-description', `${type} · ${names.length} 个匹配项`);
  const visible = names.slice(0, nodeLimit);
  const signature = JSON.stringify([coreKey(proxyData), proxyGroup, visible, group.type]);
  if (signature !== nodeSignature) {
    nodeSignature = signature; nodeRows.clear(); $('node-list').replaceChildren();
    for (const name of visible) {
      const row = element('div', undefined, 'node-row'); const info = element('div', undefined, 'node-info');
      const labels = element('div'); labels.append(element('div', name, 'node-name'));
      const subtype = proxyData.proxies?.[name]?.type;
      if (subtype) labels.append(element('small', subtype));
      info.append(element('span', '', 'node-mark'), labels);
      const actions = element('div', undefined, 'node-actions'); const delay = element('span', '未检测', 'delay');
      const groupName = proxyGroup;
      const request = coreRequest();
      const select = actionButton('选择', 'proxies', async () => {
        await api('proxies/select', { group: groupName, proxy: name, ...request }); toast('节点已切换；既有连接可能继续使用旧出口。');
      });
      select.hidden = group.type !== 'Selector';
      const test = element('button', '测延迟', 'secondary'); test.addEventListener('click', () => { void testNode(name); });
      actions.append(delay, select, test); row.append(info, actions); $('node-list').append(row);
      nodeRows.set(name, { root: row, delay, select, test });
    }
    if (!names.length) $('node-list').append(element('div', '没有匹配的节点，试试其他关键词。', 'empty-state'));
  }
  $('more-nodes').hidden = names.length <= nodeLimit;
  setText('more-nodes', `显示更多（已显示 ${Math.min(nodeLimit, names.length)} / ${names.length}）`);
  for (const name of nodeRows.keys()) updateNode(name);
  renderBatch();
}
function updateNode(name) {
  const row = nodeRows.get(name); if (!row) return;
  const selected = currentGroup()?.now === name;
  row.root.classList.toggle('current', selected);
  row.select.textContent = selected ? '已选择' : '选择';
  row.select.disabled = !canWrite() || selected;
  const d = delays.get(name);
  row.test.disabled = !canWrite() || d?.state === 'pending' || batch.running > 0 || batch.pending.length > 0;
  row.delay.className = `delay${d?.state === 'done' ? d.value >= 0 ? ' good' : ' error' : d?.state === 'error' ? ' error' : ''}`;
  row.delay.replaceChildren(element('span', !d ? '未检测' : d.state === 'pending' ? '检测中…' : d.state === 'error' ? '检测失败' : d.value < 0 ? '不可用' : `${d.value} ms`));
  if (d?.at) row.delay.append(element('small', new Date(d.at).toLocaleTimeString('zh-CN', { hour12: false })));
  row.delay.title = d?.error || '连接延迟，不是下载速率';
}
async function testNode(name) {
  if (!canWrite() || !state?.coreReady || !proxyData || coreKey(proxyData) !== coreKey() || delays.get(name)?.state === 'pending') return;
  const key = coreKey(); const request = coreRequest();
  delays.set(name, { state: 'pending' }); updateNode(name);
  try {
    const result = await api('proxies/delay', { proxy: name, ...request });
    if (coreKey() !== key) return;
    if (coreKey(result) !== key) throw new Error('核心会话已变化，请刷新节点后重试。');
    delays.set(name, { state: 'done', value: result.value, at: result.at });
  } catch (error) {
    if (coreKey() !== key) return;
    delays.set(name, { state: 'error', error: error.message, at: new Date().toISOString() });
  } finally { if (coreKey() === key) { updateNode(name); if ($('node-sort').value === 'delay') renderNodes(); } }
}
function renderBatch() {
  const active = batch.running > 0 || batch.pending.length > 0;
  $('cancel-test').hidden = !active;
  $('batch-test').disabled = active || !canWrite() || !currentGroup();
  setText('batch-progress', batch.total ? `${active ? '检测中' : '已完成'} ${batch.completed} / ${batch.total}` : '');
  for (const name of nodeRows.keys()) updateNode(name);
}

function renderNetwork(report) {
  const signature = JSON.stringify(report);
  if (signature === networkSignature) return;
  networkSignature = signature;
  for (const id of ['network-summary', 'family-status', 'network-checks', 'network-coverage']) $(id).replaceChildren();
  if (!report.at || report.at.startsWith('0001')) {
    setText('network-report-time', '尚未检测');
    $('network-summary').append(element('div', '保存网络模式后运行检测。未检测不等于网络不可用。', 'notice'));
    return;
  }
  setText('network-report-time', date(report.at));
  const blockers = (report.checks || []).filter(c => c.required && !c.ok);
  const notice = element('div', undefined, `notice ${report.ready ? 'success' : 'warning'}`);
  notice.append(element('strong', report.ready ? '所选模式的前置条件已满足' : '还有前置条件需要处理'));
  if (blockers.length) {
    const list = element('ul'); blockers.forEach(c => list.append(element('li', `${c.name}：${c.detail}`))); notice.append(list);
  }
  notice.append(element('p', '条件检测不等于实际流量已验证。'));
  $('network-summary').append(notice);
  for (const family of ['ipv4', 'ipv6']) {
    const check = report.checks?.find(c => c.family === family);
    const excluded = family === 'ipv6' && report.mode === 'ipv4';
    const card = element('article'); card.append(element('h2', family === 'ipv4' ? 'IPv4 出口' : 'IPv6 出口'));
    card.append(element('span', excluded ? '不参与接管' : check?.ok ? '出口条件通过' : '需要处理', `badge ${excluded ? '' : check?.ok ? 'good' : 'warning'}`));
    card.append(element('p', excluded ? '系统 IPv6 保持原样，可能直接连接。' : check?.detail || '等待检测', 'footnote'));
    $('family-status').append(card);
  }
  for (const check of report.checks || []) {
    const row = element('div', undefined, 'check-row'); const detail = element('div');
    detail.append(element('strong', check.name), element('p', check.detail));
    row.append(detail, element('span', check.ok ? '通过' : check.required ? '需处理' : '不阻塞', `badge ${check.ok ? 'good' : check.required ? 'warning' : ''}`));
    $('network-checks').append(row);
  }
  for (const c of report.coverage || []) {
    const row = element('div', undefined, 'coverage-row');
    row.append(element('h3', c.name), element('span', c.state, 'badge'), element('p', c.detail));
    $('network-coverage').append(row);
  }
}
async function loadLogs(showError = true) {
  const ticket = logGate.next();
  try { const lines = await api('logs'); if (!logGate.valid(ticket)) return; logLines = lines; message('logs'); renderLogs(); }
  catch (error) { if (logGate.valid(ticket) && showError) message('logs', error.message); }
}
function renderLogs() {
  const log = $('log-content');
  const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
  const query = $('log-search').value.toLocaleLowerCase();
  const filtered = logLines.filter(line => line.toLocaleLowerCase().includes(query));
  const text = filtered.join('\n') || '暂无匹配的日志。';
  if (log.textContent !== text) log.textContent = text;
  if ($('log-bottom').checked && atBottom) log.scrollTop = log.scrollHeight;
  setText('log-count', `显示 ${filtered.length} / ${logLines.length} 条 · ${$('log-auto').checked ? '每 5 秒自动刷新' : '已暂停自动刷新'}`);
}

function navigate(tab, updateHash = true) {
  if (!['overview', 'profiles', 'proxies', 'connections', 'network', 'logs'].includes(tab)) tab = 'overview';
  scrollPositions.set(currentTab, $('workspace').scrollTop);
  if (currentTab !== tab) { batch.cancel(); logGate.next(); }
  currentTab = tab;
  document.querySelectorAll('.panel').forEach(node => { node.hidden = node.id !== tab; });
  document.querySelectorAll('[data-tab]').forEach(node => {
    node.classList.toggle('selected', node.dataset.tab === tab);
    if (node.dataset.tab === tab) node.setAttribute('aria-current', 'page'); else node.removeAttribute('aria-current');
  });
  $('mobile-page').value = tab;
  $('workspace').scrollTop = scrollPositions.get(tab) || 0;
  if (updateHash && location.hash !== `#${tab}`) history.replaceState(null, '', `#${tab}`);
  if (tab === 'proxies') void loadProxies();
  if (tab === 'logs') void loadLogs();
  globalThis.FlclashConsole?.navigated();
}
function confirmAction(title, text) {
  if (confirmResult) return Promise.resolve(false);
  setText('confirm-title', title); setText('confirm-text', text);
  $('confirm-dialog').showModal(); $('confirm-no').focus();
  return new Promise(resolve => { confirmResult = resolve; });
}
function finishConfirm(yes) {
  $('confirm-dialog').close();
  const resolve = confirmResult; confirmResult = undefined; resolve?.(yes);
}
function setSource(next) {
  source = next;
  for (const type of ['url', 'file', 'yaml']) $(`source-${type}`).hidden = type !== next;
  document.querySelectorAll('[data-source]').forEach(node => { node.classList.toggle('selected', node.dataset.source === next); node.setAttribute('aria-pressed', String(node.dataset.source === next)); });
  $('profile-interval').disabled = next !== 'url';
}
function openProfile(id = '') {
  if (!canWrite()) return;
  lastFocus = document.activeElement; editing = id; dialogEpoch++; fileYAML = ''; dialogDirty = false;
  $('profile-form').reset(); message('dialog');
  const p = state?.settings.profiles.find(item => item.id === id);
  setSource(p && !p.url ? 'yaml' : 'url');
  $('source-tabs').hidden = !!p; $('import-only').hidden = !!p;
  setText('dialog-title', p ? '编辑配置' : '添加配置');
  setText('dialog-description', p ? '保存基本信息；替换地址失败不会覆盖原有效订阅。' : '导入后可立即使用配置，但不会自动开启代理。');
  setText('save-profile', p ? '保存修改' : '导入并使用');
  setText('url-label', p ? '替换订阅地址（留空保留）' : '订阅地址');
  setText('url-help', p ? '已保存的订阅地址不会反显。如需更换，请填写新地址。' : '地址包含访问凭据，默认隐藏。只向 NAS 后台提交。');
  setText('file-description', '支持 .yaml / .yml，最大 8 MiB。');
  if (p) { $('profile-name').value = p.name; $('profile-interval').value = p.intervalHours; $('source-yaml').hidden = true; }
  const interval = $('profile-interval').value;
  $('profile-interval-preset').value = ['0', '6', '12', '24'].includes(interval) ? interval : 'custom';
  $('custom-interval').hidden = $('profile-interval-preset').value !== 'custom';
  $('profile-dialog').showModal(); $('profile-name').focus(); updateLocks();
}
function closeProfileNow() {
  $('profile-dialog').close(); $('profile-form').reset(); fileYAML = ''; editing = ''; dialogEpoch++; dialogDirty = false; lastFocus?.focus();
}
async function closeProfile() {
  if (busy) return;
  if (dialogDirty && !await confirmAction('放弃未保存的内容？', '关闭后会清除本次填写的内容，已保存的配置不会改变。')) return;
  closeProfileNow();
}

document.querySelectorAll('[data-tab]').forEach(node => node.addEventListener('click', () => navigate(node.dataset.tab)));
document.querySelectorAll('[data-go]').forEach(node => node.addEventListener('click', () => navigate(node.dataset.go)));
$('mobile-page').addEventListener('change', () => navigate($('mobile-page').value));
window.addEventListener('hashchange', () => navigate(location.hash.slice(1), false));
$('retry').addEventListener('click', () => { void refresh(); });
document.querySelectorAll('[data-mode]').forEach(node => node.addEventListener('click', () => { void mutate('overview', async () => { await api('settings', { mode: node.dataset.mode }); toast('分流模式已保存。'); }); }));
$('main-group').addEventListener('change', () => { const value = $('main-group').value; void mutate('overview', async () => { await api('settings', { healthGroup: value }); toast('主要策略组已保存。'); }); });
$('quick-node').addEventListener('change', () => { const name = $('quick-node').value; const request = coreRequest(); void mutate('overview', async () => { await api('proxies/select', { group: mainGroup(), proxy: name, ...request }); toast('节点已切换；既有连接可能继续使用旧出口。'); }); });
for (const id of ['main-group', 'quick-node']) $(id).addEventListener('blur', renderQuick);
$('toggle').addEventListener('click', () => {
  if (!state) return;
  const off = state.settings.enabled || state.proxyActive || state.networkRecoveryPending;
  if (!off && !state.coreReady) { navigate('profiles'); message('profiles', '请先使用一份有效配置。', 'warning'); return; }
  if (!off && state.settings.mode === 'rule' && !state.settings.healthGroup) { $('main-group').focus(); message('overview', '请选择主要策略组，用于故障检测。', 'warning'); return; }
  if (!off && !state.settings.networkModeConfirmed) { navigate('network'); $('network-confirm').focus(); return; }
  if (!off && !state.network?.ready) { navigate('network'); message('network', '请先检查并处理当前模式的前置条件，然后重新检测。', 'warning'); return; }
  void mutate('overview', async () => { await api('control', { enabled: !off }); toast(off ? '透明代理已关闭；已登记客户端的普通转发继续保留。' : '透明代理已开启，请继续验证实际流量。'); });
});
$('restart').addEventListener('click', () => { void mutate('overview', async () => { await api('restart', {}); toast('核心已重启。'); }); });
$('add-profile').addEventListener('click', () => openProfile());
$('profile-search').addEventListener('input', () => { renderProfiles(); updateLocks(); });
$('refresh-proxies').addEventListener('click', () => { void loadProxies(); });
$('group-search').addEventListener('input', renderNodes);
$('profile-interval-preset').addEventListener('change', () => { const value = $('profile-interval-preset').value; $('custom-interval').hidden = value !== 'custom'; if (value !== 'custom') $('profile-interval').value = value; dialogDirty = true; });
$('proxy-group').addEventListener('change', () => { if (!$('proxy-group').value) return; batch.cancel(); proxyGroup = $('proxy-group').value; nodeLimit = 80; renderNodes(); });
for (const id of ['node-search', 'node-sort']) $(id).addEventListener(id === 'node-search' ? 'input' : 'change', () => { nodeLimit = 80; renderNodes(); });
$('more-nodes').addEventListener('click', () => { nodeLimit += 80; renderNodes(); });
$('batch-test').addEventListener('click', () => { batch.start(namesInView()); });
$('cancel-test').addEventListener('click', () => batch.cancel());
$('network-mode').addEventListener('change', () => { dirty.add('network'); $('network-confirm').checked = false; renderNetworkConfirmation(); });
$('network-confirm').addEventListener('change', () => dirty.add('network'));
$('gateway-cidrs').addEventListener('input', () => dirty.add('gateway'));
$('health-url').addEventListener('input', () => dirty.add('health'));
$('network-form').addEventListener('submit', event => {
  event.preventDefault(); const mode = $('network-mode').value; const confirmed = $('network-confirm').checked;
  void mutate('network', async () => {
    await api('settings', { networkMode: mode, networkModeConfirmed: confirmed }); dirty.delete('network');
    await api('network/detect', {}); toast('网络模式已保存，检测结果已更新。');
  });
});
$('detect').addEventListener('click', () => { void mutate('network', async () => { await api('network/detect', {}); toast('网络检测已完成。'); }); });
$('gateway-form').addEventListener('submit', event => { event.preventDefault(); const cidrs = $('gateway-cidrs').value.split(/\s+/).filter(Boolean); void mutate('network', async () => { await api('settings', { gatewayCIDRs: cidrs }); dirty.delete('gateway'); toast('网关网段已保存。'); }); });
$('health-form').addEventListener('submit', event => { event.preventDefault(); const url = $('health-url').value; void mutate('network', async () => { await api('settings', { healthURL: url }); dirty.delete('health'); toast('检测地址已保存。'); }); });
$('recover').addEventListener('click', async () => {
  if (!await confirmAction('恢复本应用网络变更', '确认所有相关客户端已恢复原网关（或没有网关客户端）？此操作将关闭代理并撤销本应用的普通转发。')) return;
  await mutate('network', async () => { await api('network/recover', { gatewayRestored: true }); toast('本应用网络变更已恢复。'); });
});
$('refresh-logs').addEventListener('click', () => { void loadLogs(); });
$('log-search').addEventListener('input', renderLogs);
$('log-auto').addEventListener('change', () => { renderLogs(); if ($('log-auto').checked) void loadLogs(); });
$('log-bottom').addEventListener('change', () => { if ($('log-bottom').checked) $('log-content').scrollTop = $('log-content').scrollHeight; });
$('close-profile').addEventListener('click', () => { void closeProfile(); });
$('cancel-profile').addEventListener('click', () => { void closeProfile(); });
$('profile-dialog').addEventListener('cancel', event => { event.preventDefault(); void closeProfile(); });
$('profile-form').addEventListener('input', () => { dialogDirty = true; });
document.querySelectorAll('[data-source]').forEach(node => node.addEventListener('click', () => setSource(node.dataset.source)));
$('confirm-no').addEventListener('click', () => finishConfirm(false));
$('confirm-yes').addEventListener('click', () => finishConfirm(true));
$('confirm-dialog').addEventListener('cancel', event => { event.preventDefault(); finishConfirm(false); });
$('profile-file').addEventListener('change', async () => {
  const file = $('profile-file').files[0]; const epoch = dialogEpoch; fileYAML = '';
  if (!file) return;
  dialogDirty = true;
  try {
    if (file.size > 8 * 1048576) throw new Error('文件不能超过 8 MiB。');
    const text = await file.text(); if (epoch !== dialogEpoch) return;
    fileYAML = text; setText('file-description', `${file.name} · ${(file.size / 1024).toFixed(1)} KiB · 已读取`);
    if (!$('profile-name').value) $('profile-name').value = file.name.replace(/\.ya?ml$/i, '');
    message('dialog');
  } catch (error) { if (epoch === dialogEpoch) message('dialog', error.message); }
});
$('profile-form').addEventListener('submit', event => {
  event.preventDefault(); const use = event.submitter?.value !== 'import';
  const body = { name: $('profile-name').value.trim(), intervalHours: source === 'url' ? Number($('profile-interval').value) : 0 };
  if (source === 'url') body.url = $('profile-url').value.trim();
  else if (!editing) body.yaml = source === 'file' ? fileYAML : $('profile-yaml').value;
  if (!editing && !(body.url || body.yaml)) { message('dialog', '请填写订阅地址或提供 YAML 内容。'); return; }
  void mutate('dialog', async () => {
    if (editing) { await api('profiles/edit', { ...body, id: editing }); closeProfileNow(); toast('配置修改已保存。'); return; }
    const result = await UI.importProfile(api, body, use);
    closeProfileNow(); navigate('profiles'); $('import-next').hidden = false;
    if (result.error) message('profiles', `配置已导入，但使用失败：${result.error.message} 原运行配置保留；请修正后再使用。`, 'warning');
    else toast(result.used ? '配置已导入并使用，未自动开启透明代理。' : '配置已导入，可在列表中选择使用。');
  });
});

async function poll() {
  if (polling || document.hidden) return;
  polling = true;
  try { await refresh(); if (currentTab === 'logs' && $('log-auto').checked && connected) await loadLogs(false); }
  finally { polling = false; }
}
navigate(location.hash.slice(1) || 'overview', false);
void poll();
setInterval(poll, 5000);
