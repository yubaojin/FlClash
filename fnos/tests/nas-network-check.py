import argparse
import importlib.util
import json
import pathlib
import socket
import subprocess
import time


spec = importlib.util.spec_from_file_location('acceptance', pathlib.Path(__file__).with_name('nas-acceptance.py'))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)
api, record = acceptance.api, acceptance.record


def docker(*args):
    return subprocess.check_output(['docker', *args], timeout=15, text=True).strip()


def inventory():
    return {item['name']: item for item in api('network/targets?refresh=1')['items']}


def request_status(host, port):
    with socket.create_connection((host, port), timeout=5) as client:
        client.sendall(b'GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n')
        return client.recv(1024).split(b'\r\n')[0].decode()


def main():
    parser = argparse.ArgumentParser(description='只操作带本轮标签的隔离容器，短暂接入额外测试网卡后恢复；不操作业务容器。')
    parser.add_argument('--run-authorized-test', action='store_true', required=True)
    parser.parse_args()
    targets = inventory()
    names = ['fct030-bridge', 'fct030-custom', 'fct030-host', 'fct030-shared', 'fct030-none', 'fct030-stopped']
    for name in names:
        if name not in targets or docker('inspect', '--format', '{{index .Config.Labels "flclash.acceptance"}}', name) != '0.3.0':
            raise RuntimeError('缺少隔离测试对象或标签不匹配')
    record('来源分组', host=targets['fct030-host']['sourceID'] == 'nas', shared=targets['fct030-shared']['sourceID'] == targets['fct030-custom']['sourceID'], sharedGroup=targets['fct030-custom']['sourceID'].startswith('shared-'))
    for name in ['fct030-none', 'fct030-stopped']:
        result = acceptance.wait_result(api('diagnostics/start', {'targetID': targets[name]['id'], 'preset': 'health'}))
        record('不能检测的对象', object=name, state=result['state'], code=result['code'], steps=len(result['steps']))
    docker('network', 'connect', 'fct030-net', 'fct030-bridge')
    try:
        refreshed = inventory()
        record('多网络归属', ambiguous=refreshed['fct030-bridge']['ambiguous'])
        custom_ip = next(a for a in refreshed['fct030-custom']['addresses'] if ':' not in a)
        docker('exec', '-d', 'fct030-custom', 'httpd', '-f', '-p', '8081', '-h', '/tmp')
        response = subprocess.run(['docker', 'exec', '-i', 'fct030-bridge', 'nc', '-w', '3', custom_ip, '8081'], input='GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n', text=True, capture_output=True, timeout=8)
        record('容器互访', status=response.stdout.splitlines()[0] if response.stdout else '无响应', source='默认 bridge 测试容器的附加测试网络', destination='自定义 bridge 测试容器')
    finally:
        docker('network', 'disconnect', 'fct030-net', 'fct030-bridge')
    refreshed = inventory()
    record('多网络恢复', restored=not refreshed['fct030-bridge']['ambiguous'])
    bindings = json.loads(docker('inspect', '--format', '{{json .NetworkSettings.Ports}}', 'fct030-bridge'))
    binding = bindings['8080/tcp'][0]
    record('发布端口', status=request_status(binding['HostIp'], int(binding['HostPort'])))
    with socket.create_connection(('127.0.0.1', 445), timeout=3):
        record('SMB 端口', reachable=True, boundary='仅 TCP 连接，不代表 SMB 文件读写验收')
    started = api('diagnostics/start', {'targetID': targets['fct030-bridge']['id'], 'preset': 'docker'})
    time.sleep(.5)
    docker('restart', '-t', '1', 'fct030-bridge')
    result = acceptance.wait_result(started)
    record('容器重启', state=result['state'], code=result['code'], stale=result['stale'])
    acceptance.diagnostic(targets['fct030-bridge']['id'], '重启后的默认 bridge')
    acceptance.diagnostic(targets['fct030-custom']['id'], '自定义 bridge 复测')
    acceptance.diagnostic(targets['fct030-host']['id'], 'host 复测')
    processes = subprocess.check_output(['ps', '-eo', 'args'], text=True)
    record('检测进程回收', remaining=sum('FlClashFnos' in line and line.endswith(' probe') for line in processes.splitlines()))


if __name__ == '__main__':
    main()
