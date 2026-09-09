import argparse
import http.client
import json
import socket
import time


class LocalAPI(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/run/flclash/api.sock')


def api(path, body=None):
    for attempt in range(20):
        client = LocalAPI('localhost', timeout=100)
        try:
            client.request('GET' if body is None else 'POST', '/app/flclash/api/' + path,
                           None if body is None else json.dumps(body), {'Content-Type': 'application/json'})
            response = client.getresponse()
            result = json.loads(response.read())
            if response.status < 400:
                return result
            if result.get('code') == 'operation_busy' and attempt < 19:
                time.sleep(.5)
                continue
            raise RuntimeError(result.get('code', 'request_failed'))
        finally:
            client.close()


def record(kind, **values):
    print(json.dumps({'test': kind, **values}, ensure_ascii=False), flush=True)


def wait_result(task):
    until = time.monotonic() + 65
    while time.monotonic() < until:
        result = api('diagnostics/result?id=' + task['id'])
        if result['state'] != 'running':
            return result
        time.sleep(.3)
    api('diagnostics/cancel', {'id': task['id']})
    raise RuntimeError('检测超时')


def diagnostic(target, name, preset='health', cycle=0):
    started = api('diagnostics/start', {'targetID': target, 'preset': preset})
    task = wait_result(started)
    record('diagnostic', object=name, cycle=cycle, preset=preset, state=task['state'], stale=task['stale'], code=task['code'],
           checks=[{k: step.get(k) for k in ('id', 'family', 'state', 'code', 'httpStatus')} for step in task['steps']],
           paths=[{'family': path['family'], 'path': path['path'], 'evidence': bool(path.get('connectionID')), 'rule': path.get('rule')} for path in task['paths']])
    return task


def main():
    parser = argparse.ArgumentParser(description='仅在已授权的测试 NAS 上执行；会短暂关闭代理并恢复原设置，不改容器网络。')
    parser.add_argument('--run-authorized-test', action='store_true', required=True)
    parser.parse_args()
    before = api('status')
    inventory = api('network/targets?refresh=1')['items']
    expected = ['fct030-bridge', 'fct030-custom', 'fct030-host', 'fct030-shared']
    targets = [(t['id'], t['name']) for name in expected for t in inventory if t['name'] == name and t['running']]
    if len(targets) != len(expected) or before['settings'].get('gatewayCIDRs'):
        raise RuntimeError('缺少专用测试容器，或存在网关客户端；拒绝接管测试')
    record('baseline', version=before['version'], mode=before['settings']['mode'], networkMode=before['settings']['networkMode'], enabled=before['proxyActive'], profiles=len(before['settings']['profiles']))
    try:
        for target, name in [('nas', 'NAS')] + targets:
            diagnostic(target, name)
        diagnostic('nas', 'NAS', 'docker')
        api('settings', {'mode': 'direct'})
        diagnostic(targets[0][0], targets[0][1] + ' / 全部直连')
        api('settings', {'mode': before['settings']['mode']})
        for cycle in range(1, 4):
            api('control', {'enabled': False})
            stopped = api('status')
            record('关闭代理', cycle=cycle, off=not stopped['proxyActive'], mode=stopped['settings']['mode'])
            api('control', {'enabled': True})
            record('开启代理', cycle=cycle, active=api('status')['proxyActive'])
            diagnostic('nas', 'NAS', cycle=cycle)
            diagnostic(targets[0][0], targets[0][1], cycle=cycle)
        task = api('diagnostics/start', {'targetID': 'nas', 'preset': 'docker'})
        try:
            api('diagnostics/cancel', {'id': task['id']})
        except RuntimeError as error:
            if str(error) != 'diagnostic_missing':
                raise
        result = wait_result(task)
        record('取消检测', state=result['state'], code=result['code'])
        task = api('diagnostics/start', {'targetID': 'nas', 'preset': 'docker'})
        api('settings', {'mode': 'direct'})
        result = wait_result(task)
        record('配置变化后失效', stale=result['stale'], code=result['code'])
    finally:
        running = next((t for t in api('diagnostics/result')['items'] if t['state'] == 'running'), None)
        if running:
            api('diagnostics/cancel', {'id': running['id']})
            wait_result(running)
        api('settings', {'mode': before['settings']['mode']})
        api('control', {'enabled': before['settings']['enabled']})
        after = api('status')
        keys = ('active', 'selected', 'mode', 'networkMode', 'enabled', 'profiles')
        record('恢复原设置', preserved=all(before['settings'].get(k) == after['settings'].get(k) for k in keys), active=after['proxyActive'])


if __name__ == '__main__':
    main()
