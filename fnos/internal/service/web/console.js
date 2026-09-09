'use strict';

globalThis.FlclashConsole = (() => {
  const targetGate = new UI.Latest();
  const historyGate = new UI.Latest();
  const connectionGate = new UI.Latest();
  const eventGate = new UI.Latest();
  const targetRows = new Map();
  const targetGroups = new Map();
  const connectionRows = new Map();
  const eventRows = new Map();
  let targets = [];
  let history = [];
  let events = [];
  let context = '';
  let activeID = '';
  let targetID = 'nas';
  let dialogID = '';
  let dialogFocus;
  let dialogBusy = false;
  let dialogEpoch = 0;
  let offset = 0;
  let total = 0;
  let lastTargets = 0;
  let reading = false;
  let searchTimer;
  const labels = { running: '检测中', done: '已完成', failed: '未完成', cancelled: '已取消', passed: '通过', warning: '需留意', skipped: '未参与', direct: 'DIRECT 直连', proxy: '经过代理', reject: '已拒绝', unknown: '路径未确认', excluded: '不参与接管' };
  const tone = value => ['passed', 'direct', 'proxy'].includes(value) ? 'good' : ['failed', 'reject'].includes(value) ? 'error' : ['warning', 'cancelled'].includes(value) ? 'warning' : '';
  const badge = (text, value) => element('span', text, `badge ${tone(value)}`);
  const put = (node, text) => { if (node.textContent !== text) node.textContent = text; };
  const bytes = n => !Number.isFinite(n) ? '—' : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1048576).toFixed(1)} MiB`;
  const button = (title, task, className = 'secondary') => { const b = element('button', title, className); b.addEventListener('click', task); return b; };
  const stale = task => task.stale || !connected;
  function resetReadError(scope) { if ($(`${scope}-message`).dataset.owner === 'read') message(scope); }
  function latest(id) { return history.find(item => item.targetID === id); }
  function connectivity(task) {
    if (stale(task)) return '结果已过期，需要重新检测';
    if (task.state === 'running') return `正在${task.stage || '检测'}`;
    if (task.state !== 'done') return task.summary || labels[task.state];
    const checks = (task.steps || []).filter(step => step.state !== 'skipped');
    if (checks.some(step => step.state === 'failed')) return '部分检测未通过';
    if (checks.some(step => step.state === 'warning')) return '目标已响应，部分项目需留意';
    return checks.length ? '本次网络检测通过' : '没有完成的检测项目';
  }
  function paths(task) { return (task.paths || []).filter(p => p.path !== 'excluded').map(p => `${p.family === 'ipv4' ? 'IPv4' : 'IPv6'}：${labels[p.path] || '路径未确认'}${p.path === 'proxy' ? ` · ${p.exit}` : ''}`).join('；') || '路径未确认'; }
  function linkConnections(sourceID = '') {
    const select = $('connection-source');
    if (sourceID && ![...select.options].some(item => item.value === sourceID)) { const option = element('option', '所选网络来源'); option.value = sourceID; select.append(option); }
    select.value = sourceID; offset = 0; navigate('connections');
  }
  function renderTargets() {
    const root = $('network-targets');
    if (targets.length) root.querySelector(':scope > p')?.remove();
    const ids = new Set(targets.map(t => t.id));
    for (const [id, row] of targetRows) if (!ids.has(id)) { row.root.remove(); targetRows.delete(id); }
    const groups = new Set(targets.filter(t => t.sourceID?.startsWith('shared-')).map(t => t.sourceID));
    for (const [id, group] of targetGroups) if (!groups.has(id)) { group.root.remove(); targetGroups.delete(id); }
    for (const t of targets) {
      let row = targetRows.get(t.id);
      if (!row) {
        const box = element('div', undefined, 'target-row'); const info = element('div', undefined, 'target-info');
        const name = element('h3'); const status = element('span', '', 'badge'); const detail = element('p', '', 'muted'); const result = element('p', '', 'target-result');
        const technical = element('details'); technical.append(element('summary', '网络信息')); const data = element('p', '', 'technical'); technical.append(data);
        const actions = element('div', undefined, 'target-actions');
        const detect = button('检测网络', () => openDiagnostic(t.id));
        const connections = button('查看连接', () => { const current = targets.find(item => item.id === t.id); linkConnections(current?.ambiguous ? 'unknown' : current?.sourceID || 'unknown'); }, 'text-button');
        info.append(name, status, detail, result, technical); actions.append(detect, connections); box.append(info, actions); root.append(box);
        row = { root: box, name, status, detail, result, data, detect, connections }; targetRows.set(t.id, row);
      }
      const recent = latest(t.id);
      let parent = root;
      if (groups.has(t.sourceID)) {
        let group = targetGroups.get(t.sourceID);
        if (!group) { const box = element('div', undefined, 'network-group'); const title = element('h3'); box.append(title, element('p', '共享同一网络命名空间；连接无法区分组内应用。', 'muted')); root.append(box); group = { root: box, title }; targetGroups.set(t.sourceID, group); }
        put(group.title, t.sourceName); parent = group.root;
      }
      if (row.root.parentElement !== parent) parent.append(row.root);
      put(row.name, t.name);
      put(row.status, !t.running ? '未运行' : t.code === 'isolated' ? '无外部网络' : !t.canProbe ? '无法自动检测' : t.mode === 'host' ? '共享宿主网络' : groups.has(t.sourceID) ? '共享容器网络' : '可检测');
      put(row.detail, t.detail || '');
      put(row.result, recent ? `${connectivity(recent)} · ${date(recent.started)}` : '尚未检测 · 不代表无法联网');
      put(row.data, `网络：${(t.networks || []).join('、') || t.mode}；地址：${(t.addresses || []).join('、') || '无可识别地址'}；DNS：${(t.dns || []).join('、') || '未读取'}${t.ambiguous ? '。多网卡或来源冲突，连接归属未确定。' : ''}`);
      row.detect.disabled = !connected || !t.canProbe || !!activeID;
      row.connections.disabled = !t.running;
    }
    const select = $('connection-source'); const selection = select.value;
    const names = new Map([['', '全部来源'], ['nas', 'NAS／共享宿主网络'], ['unknown', '来源未确定']]);
    for (const t of targets) if (t.running && !t.ambiguous && t.sourceID) names.set(t.sourceID, t.sourceName || t.name);
    if (selection && !names.has(selection)) names.set(selection, '先前选择的来源（已变化）');
    const signature = JSON.stringify([...names]);
    if (select.dataset.signature !== signature) {
      select.replaceChildren(...[...names].map(([value, name]) => { const option = element('option', name); option.value = value; return option; }));
      select.value = selection; select.dataset.signature = signature;
    }
  }
  async function loadTargets(force = false) {
    if (!connected || (!force && Date.now() - lastTargets < 15000)) return;
    const ticket = targetGate.next();
    try {
      const report = await api(`network/targets${force ? '?refresh=1' : ''}`);
      if (!targetGate.valid(ticket)) return;
      if (!Array.isArray(report.items)) throw new Error('对象列表暂不可用，请确认后台版本。');
      const rank = t => t.kind === 'nas' ? 0 : !t.running ? 3 : t.canProbe ? 1 : 2;
      targets = [...report.items].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name, 'zh-CN')); lastTargets = Date.now(); resetReadError('targets'); renderTargets();
      if (report.detail || report.truncated) message('targets', `${report.detail || ''}${report.truncated ? ' 仅显示本次发现的部分对象，请稍后刷新。' : ''}`, 'warning', 'read');
    } catch (error) { if (targetGate.valid(ticket)) message('targets', `${error.message} 请刷新对象后重试；不会改用 NAS 冒充容器检测。`, 'error', 'read'); }
  }
  function renderHistory() {
    const running = history.find(task => task.state === 'running'); activeID = running?.id || '';
    const nas = latest('nas');
    setText('nas-result', nas ? connectivity(nas) : '尚未检测实际网络');
    setText('nas-result-detail', nas ? `${paths(nas)} · ${date(nas.started)}` : '联网结果和代理路径分别确认，不改变当前规则与节点。');
    $('nas-result-open').hidden = !nas;
    $('nas-detect').disabled = !connected || !!activeID;
    const root = $('diagnostic-history'); const signature = JSON.stringify(history.map(t => [t.id, t.state, t.stale, t.stage, t.summary]));
    if (root.dataset.signature !== signature) {
      root.replaceChildren(...history.map(task => {
        const row = element('div', undefined, 'history-row'); const info = element('div'); info.append(element('strong', task.targetName), element('p', `${connectivity(task)} · ${date(task.started)}`, 'muted'));
        row.append(info, button('查看结果', () => showResult(task.id), 'text-button')); return row;
      }));
      if (!history.length) root.append(element('p', '尚无检测记录。选择 NAS 或容器开始检测。', 'muted'));
      root.dataset.signature = signature;
    }
    renderTargets();
    if (dialogID && $('diagnostic-dialog').open) { const task = history.find(item => item.id === dialogID); if (task) renderDiagnostic(task); }
  }
  async function loadHistory() {
    if (!connected) return;
    const ticket = historyGate.next(); const key = context;
    try {
      const result = await api('diagnostics/result');
      if (!historyGate.valid(ticket) || context !== key) return;
      if (!Array.isArray(result.items)) throw new Error('检测记录暂不可用');
      history = result.items; renderHistory();
      if ($('diagnostic-message').dataset.owner === 'read') message('diagnostic');
    } catch (error) { if (historyGate.valid(ticket) && dialogID) message('diagnostic', `无法读取最新进度：${error.message} 已显示的结果可能过期。`, 'warning', 'read'); }
  }
  function destination() {
    let host = '尚未保存有效检测地址';
    try { host = new URL($('diagnostic-preset').value === 'docker' ? 'https://registry-1.docker.io/v2/' : state?.settings.healthURL).hostname; } catch {}
    setText('diagnostic-destination', `目标域名：${host} · ${state?.settings.networkMode === 'ipv4' ? '仅 IPv4；IPv6 不参与接管' : 'IPv4 + IPv6 双栈'}`);
  }
  function openDiagnostic(id) {
    targetID = id; dialogID = ''; dialogEpoch++; dialogFocus = document.activeElement;
    setText('diagnostic-object', targets.find(t => t.id === id)?.name || (id === 'nas' ? 'NAS／共享宿主网络' : '正在识别对象'));
    $('diagnostic-options').hidden = false; $('diagnostic-limits').hidden = true;
    for (const name of ['diagnostic-progress', 'diagnostic-steps', 'diagnostic-paths']) $(name).replaceChildren();
    $('diagnostic-start').hidden = false; $('diagnostic-start').disabled = !connected || !!activeID;
    setText('diagnostic-start', activeID ? '已有检测正在进行' : '开始检测');
    $('diagnostic-export').hidden = true; $('diagnostic-cancel').hidden = !activeID;
    message('diagnostic'); destination(); $('diagnostic-dialog').showModal(); $('diagnostic-preset').focus();
  }
  function showResult(id) {
    const task = history.find(item => item.id === id); if (!task) return;
    dialogFocus = document.activeElement; dialogID = id; targetID = task.targetID; dialogEpoch++;
    message('diagnostic'); renderDiagnostic(task); $('diagnostic-dialog').showModal(); $('close-diagnostic').focus();
  }
  function closeDiagnostic() { $('diagnostic-dialog').close(); dialogEpoch++; dialogID = ''; dialogFocus?.focus(); }
  function renderDiagnostic(task) {
    setText('diagnostic-object', `${task.targetName} · ${task.destination} · ${date(task.started)}`);
    $('diagnostic-options').hidden = true; $('diagnostic-limits').hidden = false;
    const isRunning = task.state === 'running';
    setText('diagnostic-progress', `${isRunning ? '◌ ' : ''}${connectivity(task)}`);
    $('diagnostic-progress').className = `notice ${stale(task) ? 'warning' : task.state === 'failed' ? 'error' : ''}`;
    const root = $('diagnostic-steps'); const signature = JSON.stringify(task.steps);
    if (root.dataset.signature !== signature) {
      root.replaceChildren(...(task.steps || []).map(step => {
        const row = element('div', undefined, 'probe-step'); const title = element('div', undefined, 'split-line');
        title.append(element('strong', `${step.family === 'ipv4' ? 'IPv4' : 'IPv6'} · ${step.title}`), badge(labels[step.state] || step.state, step.state));
        row.append(title, element('p', step.detail, 'muted'));
        if (step.next) row.append(element('p', `下一步：${step.next}`, 'next-action'));
        const details = element('details'); details.append(element('summary', '技术信息'), element('p', `${step.code}${step.httpStatus ? ` · HTTP ${step.httpStatus}` : ''} · ${date(step.at)}${step.error ? `\n${step.error}` : ''}`, 'technical'));
        row.append(details); return row;
      }));
      root.dataset.signature = signature;
    }
    const pathRoot = $('diagnostic-paths'); const pathSignature = JSON.stringify([task.paths, task.state, task.stale]);
    if (pathRoot.dataset.signature !== pathSignature) {
      pathRoot.replaceChildren();
      if (!isRunning) {
        pathRoot.append(element('h3', '本次 HTTPS 请求的代理路径'));
        for (const path of task.paths || []) {
          const box = element('div', undefined, 'path-evidence'); box.append(badge(`${path.family === 'ipv4' ? 'IPv4' : 'IPv6'} · ${labels[path.path] || '路径未确认'}`, stale(task) ? 'unknown' : path.path));
          box.append(element('p', path.path === 'proxy' ? `实际出口：${path.exit}` : path.path === 'direct' ? '本次请求命中 DIRECT，属于有效直连结论。' : path.path === 'excluded' ? '不接管 IPv6，也不提供 IPv6 防泄漏保证。' : '未捕获到关联连接，不能确认是否经过代理。', 'muted'));
          if (path.connectionID) { box.append(element('p', `命中规则：${path.rule || '未提供'} · 链路：${[...(path.chains || [])].reverse().join(' → ')}`, 'technical')); }
          pathRoot.append(box);
        }
        const details = element('details'); details.append(element('summary', '任务结果详情'), element('p', `${task.code} · ${task.summary}`, 'technical')); pathRoot.append(details);
        pathRoot.append(button('查看相关来源连接', () => { closeDiagnostic(); linkConnections(targets.find(t => t.id === task.targetID)?.sourceID || 'unknown'); }, 'text-button'));
      }
      pathRoot.dataset.signature = pathSignature;
    }
    $('diagnostic-start').hidden = isRunning;
    $('diagnostic-start').disabled = dialogBusy || !connected || !!activeID;
    setText('diagnostic-start', '重新检测');
    $('diagnostic-cancel').hidden = !isRunning;
    $('diagnostic-cancel').disabled = dialogBusy;
    $('diagnostic-export').hidden = isRunning;
    $('diagnostic-export').disabled = !connected;
  }
  async function start() {
    if (dialogBusy || activeID || !connected) return;
    if (dialogID) { openDiagnostic(targetID); return; }
    dialogBusy = true; const epoch = dialogEpoch;
    $('diagnostic-start').disabled = true; setText('diagnostic-start', '正在开始…'); message('diagnostic');
    try {
      const result = await api('diagnostics/start', { targetID, preset: $('diagnostic-preset').value });
      history = [result, ...history.filter(t => t.id !== result.id)].slice(0, 20); activeID = result.id;
      if (epoch === dialogEpoch) { dialogID = result.id; renderDiagnostic(result); }
      renderHistory();
    } catch (error) { if (epoch === dialogEpoch) message('diagnostic', `${error.message} 本次未开始检测；请刷新对象或等待当前操作结束。`); }
    finally { dialogBusy = false; if (epoch === dialogEpoch) { $('diagnostic-start').disabled = !connected || !!activeID; $('diagnostic-cancel').disabled = false; setText('diagnostic-start', '开始检测'); } }
  }
  async function cancel() {
    if (dialogBusy || !activeID) return;
    dialogBusy = true; $('diagnostic-cancel').disabled = true; setText('diagnostic-cancel', '正在取消…');
    try { await api('diagnostics/cancel', { id: activeID }); await loadHistory(); }
    catch (error) { message('diagnostic', error.message); }
    finally { dialogBusy = false; $('diagnostic-cancel').disabled = false; setText('diagnostic-cancel', '取消检测'); }
  }
  async function exportResult() {
    if (!dialogID) return;
    try {
      const response = await fetch(`/app/flclash/api/diagnostics/export?id=${encodeURIComponent(dialogID)}`, { credentials: 'same-origin', headers: { 'X-FlClash-Request': '1' } });
      if (!response.ok) throw new Error('无法导出，请确认登录状态或重新检测。');
      const blob = await response.blob(); const url = URL.createObjectURL(blob); const a = element('a');
      a.href = url; a.download = 'FlClash-诊断摘要.txt'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast('已导出脱敏摘要，不包含订阅和访问历史。');
    } catch (error) { message('diagnostic', error.message); }
  }
  async function loadConnections() {
    if (currentTab !== 'connections' || !connected) return;
    const ticket = connectionGate.next(); const key = context;
    const query = new URLSearchParams({ source: $('connection-source').value, q: $('connection-search').value.trim(), path: $('connection-path').value, offset: String(offset), limit: '50' });
    try {
      const result = await api(`connections?${query}`);
      if (!connectionGate.valid(ticket) || currentTab !== 'connections' || context !== key) return;
      if (!Array.isArray(result.items)) throw new Error('连接列表暂不可用，请检查后台版本。');
      if (state?.coreSession && result.coreSession !== state.coreSession) return;
      resetReadError('connections'); total = result.total;
      if (offset >= total && offset > 0) { offset = Math.max(0, Math.floor((total - 1) / 50) * 50); void loadConnections(); return; }
      const root = $('connection-list'); const ids = new Set(result.items.map(c => c.id));
      root.querySelector('.empty-state')?.remove();
      for (const [id, row] of connectionRows) if (!ids.has(id)) { row.root.remove(); connectionRows.delete(id); }
      result.items.forEach((c, index) => {
        let row = connectionRows.get(c.id);
        if (!row) {
          const box = element('details', undefined, 'connection-row'); const summary = element('summary');
          const target = element('div', undefined, 'connection-target'); const host = element('strong'); const source = element('small'); target.append(host, source);
          const exit = element('span', '', 'connection-exit'); const traffic = element('small'); const detail = element('div', undefined, 'connection-detail');
          summary.append(target, exit, traffic); box.append(summary, detail); row = { root: box, host, source, exit, traffic, detail }; connectionRows.set(c.id, row);
        }
        const m = c.metadata || {};
        put(row.host, `${m.host || m.destinationIP || '未知目标'}${m.destinationPort ? `:${m.destinationPort}` : ''}`);
        put(row.source, `${c.sourceName || '来源未确定'} · ${(m.network || '').toUpperCase()} · ${date(c.start)}`);
        put(row.exit, `${labels[c.path] || '路径未确认'}${c.path === 'proxy' ? ` · ${c.exit}` : ''}`);
        put(row.traffic, `↑ ${bytes(c.upload)} / ↓ ${bytes(c.download)} · ${c.active ? '最近观察为活动' : '最近快照中已结束'}`);
        const text = `来源：${m.sourceIP || '未知'}:${m.sourcePort || '—'}\n目标：${m.destinationIP || '未知'}:${m.destinationPort || '—'}\n命中规则：${c.rule || '未提供'}${c.rulePayload ? `（${c.rulePayload}）` : ''}\n策略链路：${[...(c.chains || [])].reverse().join(' → ') || '未捕获'}\n最近观察：${date(c.observedAt)}`;
        put(row.detail, text);
        if (root.children[index] !== row.root) root.insertBefore(row.root, root.children[index] || null);
      });
      if (!result.items.length) root.append(element('div', total ? '本页暂无连接。' : '尚未观察到匹配的连接。请从对应对象发起访问，或调整筛选条件；这不代表对象无法联网。', 'empty-state'));
      setText('connection-count', `${total} 条匹配 · ${result.stale ? '快照已过期，不能代表当前连接' : `更新于 ${date(result.updatedAt)}`}`);
      setText('connection-page', `第 ${Math.floor(offset / 50) + 1} / ${Math.max(1, Math.ceil(total / 50))} 页`);
      $('connection-prev').disabled = offset === 0; $('connection-next').disabled = offset + 50 >= total;
    } catch (error) { if (connectionGate.valid(ticket)) message('connections', `${error.message} 下方仅为上次观察结果。`, 'error', 'read'); }
  }
  function renderEvents() {
    const root = $('event-list'); const query = $('log-search').value.trim().toLocaleLowerCase();
    const filtered = events.filter(e => `${e.title} ${e.detail} ${e.code} ${e.next}`.toLocaleLowerCase().includes(query));
    const ids = new Set(filtered.map(e => e.id)); root.querySelector('.empty-state')?.remove();
    for (const [id, row] of eventRows) if (!ids.has(id)) { row.remove(); eventRows.delete(id); }
    filtered.forEach((e, index) => {
      let row = eventRows.get(e.id);
      if (!row) {
        row = element('details', undefined, `event-row ${e.level === 'error' ? 'event-error' : ''}`); const summary = element('summary');
        summary.append(element('span', e.level === 'error' ? '!' : e.level === 'warning' ? '△' : '•', 'event-symbol'), element('strong', e.title), element('time', date(e.at)));
        const detail = element('div'); detail.append(element('p', e.detail || '操作已完成。'));
        if (e.next) detail.append(element('p', `下一步：${e.next}`, 'next-action'));
        detail.append(element('code', e.code)); row.append(summary, detail); eventRows.set(e.id, row);
      }
      if (root.children[index] !== row) root.insertBefore(row, root.children[index] || null);
    });
    if (!filtered.length) root.append(element('div', events.length ? '没有匹配的运行事件。' : '暂无运行事件。服务重启后从新的操作开始记录。', 'empty-state'));
  }
  async function loadEvents() {
    if (!connected || currentTab !== 'logs') return;
    const ticket = eventGate.next();
    try { const next = await api('events'); if (!eventGate.valid(ticket) || currentTab !== 'logs') return; if (!Array.isArray(next)) throw new Error('事件列表暂不可用'); events = next; renderEvents(); }
    catch (error) { if (eventGate.valid(ticket)) message('logs', `运行事件读取失败：${error.message}`, 'warning', 'events'); }
  }
  function stateChanged() {
    const key = `${coreKey()}:${state?.coreSession || ''}:${state?.settings.mode}:${state?.settings.networkMode}:${JSON.stringify(state?.settings.selected || {})}:${state?.proxyActive}`;
    if (key !== context) {
      const old = !!context; context = key; connectionGate.next(); historyGate.next();
      if (old) history.forEach(task => { task.stale = true; });
      renderHistory(); void loadHistory();
    }
    if (currentTab === 'network' || currentTab === 'connections') void loadTargets();
    if (currentTab === 'logs' && $('log-auto').checked) void loadEvents();
  }
  function navigated() {
    connectionGate.next(); eventGate.next();
    if (currentTab === 'network' || currentTab === 'connections') { void loadTargets(); void loadHistory(); }
    if (currentTab === 'connections') void loadConnections();
    if (currentTab === 'logs') void loadEvents();
  }
  async function poll() {
    if (reading || document.hidden || !connected) return;
    reading = true;
    try { await Promise.all([activeID ? loadHistory() : undefined, currentTab === 'connections' && $('connection-auto').checked ? loadConnections() : undefined]); }
    finally { reading = false; }
  }
  $('nas-detect').addEventListener('click', () => openDiagnostic('nas'));
  $('nas-result-open').addEventListener('click', () => { const task = latest('nas'); if (task) showResult(task.id); });
  $('refresh-targets').addEventListener('click', () => { void loadTargets(true); });
  $('diagnostic-preset').addEventListener('change', destination);
  $('diagnostic-start').addEventListener('click', () => { void start(); });
  $('diagnostic-cancel').addEventListener('click', () => { void cancel(); });
  $('diagnostic-export').addEventListener('click', () => { void exportResult(); });
  $('close-diagnostic').addEventListener('click', closeDiagnostic);
  $('diagnostic-dialog').addEventListener('cancel', event => { event.preventDefault(); closeDiagnostic(); });
  $('refresh-connections').addEventListener('click', () => { void loadConnections(); });
  for (const id of ['connection-source', 'connection-path']) $(id).addEventListener('change', () => { offset = 0; void loadConnections(); });
  $('connection-search').addEventListener('input', () => { connectionGate.next(); clearTimeout(searchTimer); offset = 0; searchTimer = setTimeout(loadConnections, 250); });
  $('connection-prev').addEventListener('click', () => { offset = Math.max(0, offset - 50); void loadConnections(); });
  $('connection-next').addEventListener('click', () => { if (offset + 50 < total) offset += 50; void loadConnections(); });
  $('log-search').addEventListener('input', renderEvents);
  $('refresh-logs').addEventListener('click', () => { void loadEvents(); });
  $('log-auto').addEventListener('change', () => { if ($('log-auto').checked) void loadEvents(); });
  document.addEventListener('visibilitychange', () => { if (document.hidden) { connectionGate.next(); eventGate.next(); } else { navigated(); void loadHistory(); } });
  setInterval(poll, 2000);
  stateChanged(); navigated();
  return { stateChanged, navigated, loadTargets, loadHistory, loadConnections, loadEvents, poll, openDiagnostic };
})();
