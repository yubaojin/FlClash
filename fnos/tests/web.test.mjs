import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
import { JSDOM } from 'jsdom';
import { makeFixture } from './fixtures.mjs';

const source = name => readFileSync(new URL(`../internal/service/web/${name}`, import.meta.url), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
async function settle() { for (let i = 0; i < 8; i++) await tick(); }

test('只有右侧正文可滚动，顶栏和导航保持固定', () => {
  const css = source('style.css');
  assert.match(css, /html,body\{[^}]*overflow:hidden/);
  assert.match(css, /\.app-shell\{[^}]*overflow:hidden/);
  assert.match(css, /\.app-bar\{[^}]*position:sticky;top:0/);
  assert.match(css, /\.sidebar\{[^}]*position:sticky;top:56px;[^}]*overflow:hidden/);
  assert.match(css, /#workspace\{[^}]*overflow-y:auto/);
});

function page(t, handler) {
  const fixture = makeFixture();
  const dom = new JSDOM(source('index.html'), { url: 'http://localhost/app/flclash/', runScripts: 'outside-only' });
  t.after(() => dom.window.close());
  const w = dom.window;
  Object.defineProperty(w.document, 'hidden', { value: true });
  w.HTMLDialogElement.prototype.showModal = function() { this.open = true; };
  w.HTMLDialogElement.prototype.close = function() { this.open = false; };
  const requests = [];
  w.fetch = async (url, options) => {
    new Headers(options.headers);
    const path = url.split('/api/')[1];
    const body = options.body && JSON.parse(options.body);
    requests.push({ path, body });
    const response = await handler?.(path, body, fixture);
    if (response) return { ok: response.ok !== false, json: async () => structuredClone(response.data) };
    const data = path === 'session' ? { csrfToken: 'test-csrf' } : path === 'status' ? fixture.status : path === 'proxies' ? fixture.proxies : path === 'logs' ? fixture.logs : { ok: true };
    return { ok: true, json: async () => structuredClone(data) };
  };
  const run = code => vm.runInContext(code, dom.getInternalVMContext());
  run(source('model.js')); run(source('app.js'));
  return { w, run, requests, fixture, get: id => w.document.getElementById(id), ready: () => run('refresh()') };
}

test('轮询保留输入草稿、焦点、配置按钮和未变化的节点行', async t => {
  const p = page(t); await p.ready();
  const row = p.get('profile-list').firstElementChild;
  const node = p.get('node-list').firstElementChild;
  p.get('gateway-cidrs').value = '192.168.99.0/24'; p.get('gateway-cidrs').dispatchEvent(new p.w.Event('input'));
  p.get('node-search').value = '测试'; p.get('node-search').focus();
  p.run('openProfile()'); p.get('profile-name').value = '未提交的草稿'; p.get('profile-name').focus();
  for (let i = 0; i < 5; i++) await p.ready();
  assert.equal(p.get('profile-list').firstElementChild, row);
  assert.equal(p.get('node-list').firstElementChild, node);
  assert.equal(p.get('gateway-cidrs').value, '192.168.99.0/24');
  assert.equal(p.get('profile-name').value, '未提交的草稿');
  assert.equal(p.w.document.activeElement, p.get('profile-name'));
  assert.equal(p.get('node-search').value, '测试');
});

test('500 个长名称节点只呈现当前组，搜索与延迟排序不删改成员', async t => {
  const p = page(t); await p.ready();
  assert.equal(p.get('node-list').children.length, 80);
  p.get('more-nodes').click(); assert.equal(p.get('node-list').children.length, 160);
  p.get('node-search').value = '500'; p.get('node-search').dispatchEvent(new p.w.Event('input'));
  assert.equal(p.get('node-list').children.length, 1);
  assert.match(p.get('node-list').textContent, /500/);
  p.get('node-search').value = ''; p.get('node-sort').value = 'delay';
  p.run("delays.set(proxyData.proxies['主要代理'].all[499], {state: 'done', value: 1}); renderNodes();");
  assert.match(p.get('node-list').firstElementChild.textContent, /500/);
  assert.equal(p.fixture.proxies.proxies['主要代理'].all.length, 500);
  p.get('proxy-group').value = '自动选择'; p.get('proxy-group').dispatchEvent(new p.w.Event('change'));
  assert.match(p.get('group-description').textContent, /自动选择/);
  assert.equal(p.run('[...nodeRows.values()].every(row => row.select.hidden)'), true);
});

test('旧状态与旧核心会话的节点响应不会覆盖最新状态', async t => {
  const pending = [];
  let delayed = false;
  const p = page(t, (path, body, fixture) => path === 'status' && delayed ? new Promise(resolve => pending.push(resolve)) : undefined);
  await p.ready(); delayed = true;
  const first = p.run('refresh(false)'); const second = p.run('refresh(false)');
  const newer = structuredClone(p.fixture.status); newer.session = '新会话'; newer.settings.active = 'local';
  pending[1]({ data: newer }); await second;
  pending[0]({ data: p.fixture.status }); await first;
  assert.equal(p.run('state.session'), '新会话');
  assert.equal(p.get('active-profile').textContent, '本地备用配置');
  assert.equal(p.get('node-list').children.length, 0);
  assert.equal(p.get('proxy-empty').hidden, false);
});

test('节点列表读取恢复只清除读取错误，不吞掉节点切换错误', async t => {
  let failure = true;
  const p = page(t, path => path === 'proxies' && failure ? { ok: false, data: { error: '节点读取失败' } } : undefined);
  await p.ready(); await p.run('loadProxies()');
  assert.match(p.get('proxies-message').textContent, /读取失败/);
  failure = false; await p.run('loadProxies()'); assert.equal(p.get('proxies-message').hidden, true);
  p.run("message('proxies', '节点选择失败');"); await p.run('loadProxies()');
  assert.equal(p.get('proxies-message').textContent, '节点选择失败');
  p.run("navigate('network')"); assert.equal(p.get('proxies').hidden, true); assert.equal(p.get('network-message').hidden, true);
});

test('管理连接中断显示过期状态，恢复后清除故障，不伪造零流量', async t => {
  let offline = false;
  const p = page(t, path => { if (path === 'status' && offline) throw new Error('模拟断开'); });
  await p.ready(); const prior = p.get('traffic').textContent;
  offline = true; await p.ready();
  assert.match(p.get('service-alert').textContent, /上一次已知状态/);
  assert.equal(p.get('traffic').textContent, prior);
  assert.equal(p.get('toggle').disabled, true);
  offline = false; await p.ready();
  assert.equal(p.get('service-alert').hidden, true); assert.equal(p.get('toggle').disabled, false);
});

test('导入与使用部分成功明确区分，不自动开启透明代理', async t => {
  const p = page(t, path => path === 'profiles' ? { data: { id: 'new' } } : path === 'profiles/select' ? { ok: false, data: { error: '核心拒绝配置' } } : undefined);
  await p.ready(); p.run('openProfile(); setSource("yaml")');
  p.get('profile-name').value = '语义错误配置'; p.get('profile-yaml').value = 'proxies: []';
  p.get('profile-form').dispatchEvent(new p.w.SubmitEvent('submit', { bubbles: true, cancelable: true, submitter: p.get('save-profile') }));
  await settle();
  assert.equal(p.get('profile-dialog').open, false);
  assert.match(p.get('profiles-message').textContent, /已导入，但使用失败/);
  assert.equal(p.requests.some(r => r.path === 'control'), false);
  assert.equal(p.get('active-profile').textContent, '界面验收 · 模拟订阅');
});

test('导入弹窗默认提交为导入并使用，编辑地址不反显且空值保留', async t => {
  const p = page(t); await p.ready();
  p.get('add-profile').focus(); p.get('add-profile').click();
  assert.equal(p.get('profile-form').querySelector('button[type="submit"]').id, 'save-profile');
  p.run('closeProfileNow()'); assert.equal(p.w.document.activeElement, p.get('add-profile'));
  p.run('openProfile("sample")');
  assert.equal(p.get('profile-url').value, ''); assert.equal(p.get('source-tabs').hidden, true);
  p.get('profile-name').value = '改名';
  p.get('profile-form').dispatchEvent(new p.w.SubmitEvent('submit', { cancelable: true, submitter: p.get('save-profile') }));
  await settle();
  const request = p.requests.find(r => r.path === 'profiles/edit');
  assert.deepEqual(request.body, { name: '改名', intervalHours: 24, url: '', id: 'sample' });
});

test('忙碌时禁止重复提交，完成后恢复按钮', async t => {
  let finish;
  const p = page(t, path => path === 'profiles/edit' ? new Promise(resolve => { finish = resolve; }) : undefined);
  await p.ready(); p.run('openProfile("sample")');
  const submit = () => p.get('profile-form').dispatchEvent(new p.w.SubmitEvent('submit', { cancelable: true, submitter: p.get('save-profile') }));
  submit(); await settle(); assert.equal(p.get('save-profile').disabled, true);
  submit(); await settle(); assert.equal(p.requests.filter(r => r.path === 'profiles/edit').length, 1);
  finish({ data: { ok: true } }); await settle(); assert.equal(p.get('add-profile').disabled, false);
});

test('模式、网段、检测地址分别保存，不携带其他表单草稿', async t => {
  const p = page(t); await p.ready();
  p.get('gateway-cidrs').value = '192.168.50.0/24'; p.get('gateway-cidrs').dispatchEvent(new p.w.Event('input'));
  p.w.document.querySelector('[data-mode="global"]').click(); await settle();
  assert.deepEqual(p.requests.filter(r => r.path === 'settings').at(-1).body, { mode: 'global' });
  p.get('gateway-form').dispatchEvent(new p.w.Event('submit', { cancelable: true })); await settle();
  assert.deepEqual(p.requests.filter(r => r.path === 'settings').at(-1).body, { gatewayCIDRs: ['192.168.50.0/24'] });
  p.get('health-url').value = 'https://example.org/'; p.get('health-form').dispatchEvent(new p.w.Event('submit', { cancelable: true })); await settle();
  assert.deepEqual(p.requests.filter(r => r.path === 'settings').at(-1).body, { healthURL: 'https://example.org/' });
});

test('网络范围确认文案跟随地址族模式变化', async t => {
  const p = page(t); await p.ready();
  assert.match(p.get('network-confirm-text').textContent, /仅 IPv4/);
  p.get('network-mode').value = 'dual';
  p.get('network-mode').dispatchEvent(new p.w.Event('change'));
  assert.match(p.get('network-confirm-text').textContent, /同时接管 IPv4 和 IPv6/);
  assert.equal(p.get('network-confirm').checked, false);
});

test('批量延迟检测最多两项并行，停止后不发送排队请求', async t => {
  const releases = [];
  const p = page(t, path => path === 'proxies/delay' ? new Promise(resolve => releases.push(resolve)) : undefined);
  await p.ready(); p.get('batch-test').click(); await settle();
  assert.equal(releases.length, 2); assert.equal(p.get('batch-test').disabled, true);
  p.get('cancel-test').click();
  for (const release of releases) release({ data: { value: 42, revision: 1, session: '无凭据模拟会话', at: new Date().toISOString() } });
  await settle();
  assert.equal(releases.length, 2); assert.equal(p.get('cancel-test').hidden, true);
  assert.match(p.get('node-list').textContent, /42 ms/);
  assert.equal(p.requests.some(r => r.path === 'proxies/select'), false);
});

test('核心会话变化丢弃进行中的延迟结果', async t => {
  let finish;
  const p = page(t, path => path === 'proxies/delay' ? new Promise(resolve => { finish = resolve; }) : undefined);
  await p.ready(); const work = p.run('testNode(currentGroup().all[0])'); await settle();
  p.fixture.status.session = '重启后的会话'; p.fixture.proxies.session = '重启后的会话'; await p.ready();
  finish({ data: { value: 99, revision: 1, session: '无凭据模拟会话', at: new Date().toISOString() } }); await work;
  assert.doesNotMatch(p.get('node-list').textContent, /99 ms/);
  assert.equal(p.run('delays.size'), 0);
});

test('历史日志阅读位置和各页面滚动位置保留', async t => {
  const p = page(t); await p.ready();
  p.run('navigate("logs")'); await settle();
  const log = p.get('log-content');
  Object.defineProperties(log, { scrollHeight: { value: 9000 }, clientHeight: { value: 300 } }); log.scrollTop = 1500;
  p.fixture.logs.push('新日志'); await p.run('loadLogs()'); assert.equal(log.scrollTop, 1500);
  p.get('workspace').scrollTop = 210; p.run('navigate("proxies")');
  p.get('workspace').scrollTop = 450; p.run('navigate("logs")'); assert.equal(p.get('workspace').scrollTop, 210);
  p.run('navigate("proxies")'); assert.equal(p.get('workspace').scrollTop, 450);
  await settle();
});

test('配置名称按文本渲染，服务连接与代理接管状态独立', async t => {
  const p = page(t); p.fixture.status.settings.profiles[0].name = '<img src=x onerror=alert(1)>'; await p.ready();
  assert.equal(p.get('profile-list').querySelector('img'), null);
  assert.equal(p.get('core-state').textContent, '配置已就绪'); assert.equal(p.get('proxy-state').textContent, '代理已关闭');
  p.fixture.status.coreRunning = true; p.fixture.status.coreReady = false; await p.ready();
  assert.equal(p.get('core-state').textContent, '尚未加载配置'); assert.equal(p.get('proxy-state').textContent, '代理已关闭');
});
