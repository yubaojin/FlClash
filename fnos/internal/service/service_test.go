package service

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const sampleConfig = "proxies:\n  - name: 示例节点\n    type: http\n    server: 127.0.0.1\n    port: 9\nproxy-groups:\n  - name: 代理组\n    type: select\n    proxies: [示例节点, DIRECT]\nrules: ['MATCH,代理组']\n"

func testSettings() Settings {
	return Settings{Mode: "rule", Selected: map[string]string{}, HealthURL: "https://example.com/", HealthGroup: "代理组", Profiles: []Profile{}}
}

func TestReservedConfigurationCannotEscape(t *testing.T) {
	raw := sampleConfig + "external-controller: 0.0.0.0:9090\nexternal-ui: /etc\nlisteners: [{name: 开放, type: socks, port: 7891}]\ntun: {enable: true, device: eth0}\ndns: {listen: '0.0.0.0:53', enhanced-mode: fake-ip}\n"
	b, err := prepareConfig(raw, testSettings(), t.TempDir(), false, []string{"2001:db8:1::/64"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = yaml.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["external-controller"] != "" || m["listeners"] != nil || m["external-ui"] != nil {
		t.Fatal("导入配置覆盖管理入口")
	}
	tun := m["tun"].(map[string]any)
	if tun["enable"] != false || tun["device"] != tunDevice || tun["iproute2-table-index"] != routeTable {
		t.Fatal("接管参数没有隔离")
	}
	dns := m["dns"].(map[string]any)
	if dns["enhanced-mode"] != "redir-host" || dns["listen"] != "" {
		t.Fatal("DNS 未采用保留的真实地址模式")
	}
	if !strings.Contains(string(b), "2001:db8:1::/64") {
		t.Fatal("未保留直连 IPv6 网段")
	}
}

func TestProviderPathsAndValidation(t *testing.T) {
	home := t.TempDir()
	raw := "proxy-providers:\n  '../越界':\n    type: http\n    url: https://example.com/list\n    path: /etc/passwd\n"
	b, err := prepareConfig(raw, testSettings(), home, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "/etc/passwd") || !strings.Contains(string(b), "providers/") {
		t.Fatal("集合路径未被重写")
	}
	for _, bad := range []string{"", "[1,2]", "proxies: [", "proxy-providers: {a: {type: file, path: /etc/passwd}}", "proxies: [{private-key-path: /etc/shadow}]"} {
		if _, err := prepareConfig(bad, testSettings(), home, false, nil); err == nil {
			t.Fatalf("不应接受配置: %q", bad)
		}
	}
	for _, u := range []string{"file:///etc/passwd", "ftp://example.com", "https://u:p@example.com", "//example.com"} {
		if validURL(u) == nil {
			t.Fatal("接受了非法订阅地址")
		}
	}
}

func TestGatewayCIDRValidation(t *testing.T) {
	for _, value := range []string{"0.0.0.0/0", "::/0", "8.8.8.0/24", "fd00::/8", "192.168.0.0/15", "192.168.0.0/24;flush ruleset"} {
		if validateCIDRs([]string{value}) == nil {
			t.Fatalf("接受了危险网段 %s", value)
		}
	}
	if err := validateCIDRs([]string{"192.168.10.0/24", "fd12:3456:789a::/64"}); err != nil {
		t.Fatal(err)
	}
}

func TestStoreAtomicAndLogsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	for _, value := range []string{"旧配置", "新配置"} {
		if err := atomicWrite(path, []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(path)
	if string(b) != "新配置" {
		t.Fatal("原子替换失败")
	}
	l := &Logs{}
	for i := 0; i < 700; i++ {
		l.Add("订阅 https://example.com/path?token=abcdef password=xyz")
	}
	lines := l.List()
	if len(lines) != 500 || strings.Contains(strings.Join(lines, ""), "abcdef") || strings.Contains(lines[0], "xyz") {
		t.Fatal("日志容量或脱敏失败")
	}
}

func TestGatewayAdminAndCSRF(t *testing.T) {
	h := GatewayHandler(filepath.Join(t.TempDir(), "missing.sock"))
	cases := []struct {
		admin, uid, user, method, path, origin, marker string
		want                                           int
	}{
		{"", "", "", "GET", prefix + "/", "", "", 403},
		{"false", "1001", "普通用户", "GET", prefix + "/", "", "", 403},
		{"true", "not-id", "管理员", "GET", prefix + "/", "", "", 403},
		{"true", "1000", "管理员", "GET", prefix + "/", "", "", 200},
		{"true", "1000", "管理员", "POST", prefix + "/api/control", "https://evil.example", "1", 403},
		{"true", "1000", "管理员", "POST", prefix + "/api/control", "", "", 403},
		{"true", "1000", "管理员", "POST", prefix + "/api/shutdown", "", "1", 403},
		{"true", "1000", "管理员", "GET", prefix + "/api/status", "", "", 503},
		{"false", "1001", "普通用户", "GET", prefix + "/api/connections", "", "", 403},
		{"false", "1001", "普通用户", "GET", prefix + "/api/diagnostics/export?id=test", "", "", 403},
		{"true", "1000", "管理员", "POST", prefix + "/api/diagnostics/start", "", "", 403},
		{"true", "1000", "管理员", "POST", prefix + "/api/diagnostics/cancel", "https://evil.example", "1", 403},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "http://nas"+c.path, strings.NewReader("{}"))
		r.Header.Set("X-Trim-Isadmin", c.admin)
		r.Header.Set("X-Trim-Userid", c.uid)
		r.Header.Set("X-Trim-Username", c.user)
		r.Header.Set("Origin", c.origin)
		r.Header.Set("X-FlClash-Request", c.marker)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Fatalf("%s %s: 期望 %d，得到 %d", c.method, c.path, c.want, w.Code)
		}
	}
}

func TestGatewayCSRFThroughRewrittenHost(t *testing.T) {
	h := GatewayHandler(filepath.Join(t.TempDir(), "missing.sock"))
	request := func(handler http.Handler, method, path, uid, token, site, contentType string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://internal-gateway"+prefix+"/api/"+path, strings.NewReader("{}"))
		r.Header.Set("X-Trim-Isadmin", "true")
		r.Header.Set("X-Trim-Userid", uid)
		r.Header.Set("X-Trim-Username", "管理员")
		r.Header.Set("Origin", "http://nas.example:5666")
		r.Header.Set("Sec-Fetch-Site", site)
		r.Header.Set("Content-Type", contentType)
		r.Header.Set("X-FlClash-Request", "1")
		r.Header.Set("X-FlClash-CSRF", token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	session := request(h, "GET", "session", "1000", "", "same-origin", "application/json")
	var body map[string]string
	if err := json.Unmarshal(session.Body.Bytes(), &body); err != nil || session.Code != 200 || len(body["csrfToken"]) != 64 {
		t.Fatal("无法取得管理员防跨站令牌")
	}
	if session.Header().Get("Cache-Control") != "no-store" || session.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("防跨站令牌不能被缓存或跨源读取")
	}
	for _, c := range []struct {
		name, uid, token, site, contentType, path string
		want                                      int
	}{
		{"网关改写 Host", "1000", body["csrfToken"], "same-origin", "application/json", "control", 503},
		{"HTTP 无来源元数据", "1000", body["csrfToken"], "", "application/json; charset=utf-8", "control", 503},
		{"缺少令牌", "1000", "", "same-origin", "application/json", "control", 403},
		{"伪造令牌", "1000", strings.Repeat("0", 64), "same-origin", "application/json", "control", 403},
		{"其他管理员令牌", "1001", body["csrfToken"], "same-origin", "application/json", "control", 403},
		{"跨站请求", "1000", body["csrfToken"], "cross-site", "application/json", "control", 403},
		{"同站异源请求", "1000", body["csrfToken"], "same-site", "application/json", "control", 403},
		{"错误内容类型", "1000", body["csrfToken"], "same-origin", "application/jsonp", "control", 403},
		{"隐藏生命周期接口", "1000", body["csrfToken"], "same-origin", "application/json", "shutdown", 404},
	} {
		t.Run(c.name, func(t *testing.T) {
			if w := request(h, "POST", c.path, c.uid, c.token, c.site, c.contentType); w.Code != c.want {
				t.Fatalf("期望 %d，得到 %d", c.want, w.Code)
			}
		})
	}
	other := GatewayHandler(filepath.Join(t.TempDir(), "missing.sock"))
	if w := request(other, "POST", "control", "1000", body["csrfToken"], "same-origin", "application/json"); w.Code != 403 {
		t.Fatal("服务重启后旧令牌仍然有效")
	}
}

func wireRead(conn net.Conn) (map[string]any, error) {
	var size uint32
	if err := binary.Read(conn, binary.LittleEndian, &size); err != nil {
		return nil, err
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(conn, b); err != nil {
		return nil, err
	}
	var result map[string]any
	err := json.Unmarshal(b, &result)
	return result, err
}

func wireWrite(conn net.Conn, msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if err = binary.Write(conn, binary.LittleEndian, uint32(len(b))); err != nil {
		return err
	}
	_, err = conn.Write(b)
	return err
}

func TestRPCOutOfOrderAndEvents(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	events := make(chan json.RawMessage, 1)
	r := newRPC(a, func(raw json.RawMessage) { events <- raw })
	go func() {
		first, _ := wireRead(b)
		second, _ := wireRead(b)
		_ = wireWrite(b, map[string]any{"method": "message", "arguments": []any{map[string]any{"type": "log", "data": "事件"}}})
		_ = wireWrite(b, map[string]any{"id": second["id"], "result": second["arguments"]})
		_ = wireWrite(b, map[string]any{"id": first["id"], "result": first["arguments"]})
	}()
	var wg sync.WaitGroup
	for _, name := range []string{"请求一", "请求二"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var result string
			if err := r.Call(ctx, "echo", name, &result); err != nil || result != name {
				t.Errorf("请求关联失败: %s %v", result, err)
			}
		}()
	}
	wg.Wait()
	select {
	case <-events:
	case <-time.After(time.Second):
		t.Fatal("未收到批量事件")
	}
}

func TestRPCDisconnectTimeoutAndFrameLimit(t *testing.T) {
	t.Run("断开", func(t *testing.T) {
		a, b := net.Pipe()
		r := newRPC(a, nil)
		go func() { _, _ = wireRead(b); b.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := r.Call(ctx, "pending", nil, nil); err == nil || !strings.Contains(err.Error(), "断开") {
			t.Fatalf("未报告断开: %v", err)
		}
	})
	t.Run("超时", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		r := newRPC(a, nil)
		go func() { _, _ = wireRead(b) }()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if err := r.Call(ctx, "pending", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("未报告超时: %v", err)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.pending) != 0 {
			t.Fatal("泄漏等待请求")
		}
	})
	t.Run("超大帧", func(t *testing.T) {
		a, b := net.Pipe()
		defer b.Close()
		r := newRPC(a, nil)
		_ = binary.Write(b, binary.LittleEndian, uint32(maxFrame+1))
		select {
		case <-r.done:
		case <-time.After(time.Second):
			t.Fatal("未拒绝超大帧")
		}
	})
}

func TestRestoreOnlyOwnedNetworkAndIdempotent(t *testing.T) {
	n, err := newNetwork(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	n.run = func(name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		if call == "nft list tables" {
			return []byte("table inet flclash_tun\ntable inet docker\n"), nil
		}
		if call == "ip -j link show" {
			return []byte(`[{"ifname":"flclash0"}]`), nil
		}
		if strings.Contains(call, "rule show") {
			return []byte(`[{"priority":0},{"priority":31001},{"priority":32766}]`), nil
		}
		if strings.Contains(call, "route show") {
			return []byte("[]"), nil
		}
		return nil, nil
	}
	if err = n.RestoreTun(); err != nil || len(calls) != 0 {
		t.Fatal("无归属时修改了网络")
	}
	n.j.Tun = true
	if err = n.RestoreTun(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	if strings.Contains(joined, "priority 32766") || strings.Contains(joined, "flush ruleset") || strings.Contains(joined, "table inet mihomo") {
		t.Fatal("清理越界")
	}
	if !strings.Contains(joined, "delete table inet flclash_tun") || !strings.Contains(joined, "rule del priority 31001") {
		t.Fatal("未清理归属资源")
	}
	count := len(calls)
	if err = n.RestoreTun(); err != nil || len(calls) != count {
		t.Fatal("重复清理不幂等")
	}
}

func TestCleanupFailureKeepsOwnership(t *testing.T) {
	n, _ := newNetwork(t.TempDir())
	n.j.Tun = true
	n.run = func(name string, args ...string) ([]byte, error) {
		if name == "nft" && strings.Join(args, " ") == "list tables" {
			return []byte("table inet flclash_tun"), nil
		}
		if strings.Contains(strings.Join(args, " "), "delete table") {
			return nil, errors.New("注入删除失败")
		}
		if strings.Contains(strings.Join(args, " "), "rule show") {
			return []byte("[]"), nil
		}
		return []byte("[]"), nil
	}
	if n.RestoreTun() == nil || !n.j.Tun {
		t.Fatal("清理失败丢失了归属")
	}
}

func TestRuleConflict(t *testing.T) {
	for _, raw := range []string{`[{"priority":31000}]`, `[{"priority":41050}]`, `[{"priority":50,"table":31001}]`, `[{"priority":50,"fwmark":"0x3f01"}]`} {
		if checkRuleConflicts([]byte(raw)) == nil {
			t.Fatal("没有拒绝保留编号冲突")
		}
	}
	if err := checkRuleConflicts([]byte(`[{"priority":0},{"priority":32766,"table":"main"}]`)); err != nil {
		t.Fatal(err)
	}
}

func TestForwardRulesNarrowAndIdempotent(t *testing.T) {
	n, _ := newNetwork(t.TempDir())
	present := map[string]bool{}
	insertions := 0
	n.run = func(name string, args ...string) ([]byte, error) {
		if len(args) > 2 && args[2] == "-S" {
			return nil, nil
		}
		if len(args) > 4 && args[2] == "-C" {
			if present[name+strings.Join(args[4:], " ")] {
				return nil, nil
			}
			return nil, errors.New("规则不存在")
		}
		if len(args) > 5 && args[2] == "-I" {
			insertions++
			present[name+strings.Join(args[5:], " ")] = true
			return nil, nil
		}
		return nil, errors.New("非预期命令")
	}
	r := NetworkReport{Exit4: "eth0", Exit6: "eth0"}
	for i := 0; i < 2; i++ {
		if err := n.allowGatewayForward([]string{"192.168.20.0/24", "fd12:3456:789a::/64"}, r); err != nil {
			t.Fatal(err)
		}
	}
	if insertions != 8 || len(n.j.ForwardRules) != 8 {
		t.Fatalf("规则重复或丢失: %d", insertions)
	}
	for _, rule := range n.j.ForwardRules {
		text := strings.Join(rule, " ")
		if !strings.Contains(text, "flclash-gateway") || (!strings.Contains(text, "192.168.20.0/24") && !strings.Contains(text, "fd12:3456:789a::/64")) {
			t.Fatal("转发规则范围过宽")
		}
	}
}

func TestSysctlRestorationDoesNotOverwriteOthers(t *testing.T) {
	for _, tc := range []struct {
		boot, current string
		writes        int
	}{{"本次开机", "1", 1}, {"本次开机", "2", 0}, {"另一次开机", "1", 0}} {
		n, _ := newNetwork(t.TempDir())
		n.j.BootID = "本次开机"
		n.j.Sysctls["net.ipv4.ip_forward"] = [2]string{"0", "1"}
		n.bootID = func() (string, error) { return tc.boot, nil }
		writes := 0
		n.run = func(name string, args ...string) ([]byte, error) {
			if name != "sysctl" {
				t.Fatal("修改了未登记对象")
			}
			if args[0] == "-w" {
				writes++
				if args[1] != "net.ipv4.ip_forward=0" {
					t.Fatal("未恢复原值")
				}
			}
			return []byte(tc.current), nil
		}
		if err := n.RestoreAll(); err != nil {
			t.Fatal(err)
		}
		if writes != tc.writes {
			t.Fatalf("恢复覆盖外部状态: %d", writes)
		}
	}
}

func TestFailedSubscriptionPreservesProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "订阅失效", 500) }))
	defer srv.Close()
	m := &Manager{dir: t.TempDir(), home: t.TempDir(), settings: testSettings(), logs: &Logs{}}
	m.settings.Profiles = []Profile{{ID: "a", Name: "原档案", URL: srv.URL, YAML: sampleConfig}}
	if err := m.updateProfile("a"); err == nil {
		t.Fatal("失败订阅未返回错误")
	}
	if m.settings.Profiles[0].YAML != sampleConfig || m.settings.Profiles[0].Error == "" {
		t.Fatal("失败更新覆盖旧配置或没有提示")
	}
}

func TestApplyRollbackKeepsLastGood(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	dir := t.TempDir()
	n, _ := newNetwork(dir)
	m := &Manager{dir: dir, home: dir, settings: testSettings(), net: n, logs: &Logs{}, core: &Core{RPC: newRPC(a, nil), exited: make(chan struct{})}}
	go func() {
		for {
			call, err := wireRead(b)
			if err != nil {
				return
			}
			var result any = true
			if call["method"] == "validateConfig" || call["method"] == "setupConfig" {
				result = ""
			}
			if call["method"] == "setupConfig" {
				config, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
				if strings.Contains(string(config), "错误节点") {
					result = "配置语义错误"
				}
			}
			if wireWrite(b, map[string]any{"id": call["id"], "result": result}) != nil {
				return
			}
		}
	}()
	if err := m.apply(sampleConfig, false); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err := m.apply(strings.ReplaceAll(sampleConfig, "示例节点", "错误节点"), false); err == nil {
		t.Fatal("错误配置未失败")
	}
	current, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
	lastGood, _ := os.ReadFile(filepath.Join(dir, "last-good.yaml"))
	if string(current) != string(good) || string(lastGood) != string(good) {
		t.Fatal("失败应用覆盖了有效配置")
	}
}

func TestApplyStartsListenerOnlyOncePerCore(t *testing.T) {
	dir := t.TempDir()
	n, err := newNetwork(dir)
	if err != nil {
		t.Fatal(err)
	}
	n.mode = "ipv4"
	n.run = func(string, ...string) ([]byte, error) {
		return []byte(`[{"dev":"flclash0"}]`), nil
	}
	m := &Manager{dir: dir, home: dir, settings: testSettings(), net: n, logs: &Logs{}}
	starts := 0
	attachCore(t, m, func(call map[string]any) any {
		switch call["method"] {
		case "validateConfig", "setupConfig":
			return ""
		case "startListener":
			starts++
			return true
		default:
			return true
		}
	})
	if err = m.apply(sampleConfig, false); err != nil {
		t.Fatal(err)
	}
	if err = m.apply(sampleConfig, true); err != nil {
		t.Fatal(err)
	}
	if starts != 1 {
		t.Fatalf("同一核心重复启动监听器: %d", starts)
	}
}

func TestRealCoreProtocolAndRollback(t *testing.T) {
	binary := os.Getenv("FLCLASH_TEST_CORE")
	if binary == "" {
		t.Skip("未设置 FLCLASH_TEST_CORE，跳过真实核心集成测试")
	}
	dir := t.TempDir()
	l, address, err := testCoreListener()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	logs := &Logs{}
	cmd := exec.Command(binary, address)
	cmd.Dir = dir
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	defer func() { _ = cmd.Process.Kill(); <-exited }()
	timer := time.AfterFunc(15*time.Second, func() { l.Close() })
	defer timer.Stop()
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rpc := newRPC(conn, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = rpc.Call(ctx, "initClash", map[string]any{"home-dir": dir, "version": 2026081701}, nil); err != nil {
		t.Fatal(err)
	}
	n, _ := newNetwork(dir)
	m := &Manager{dir: dir, home: dir, settings: testSettings(), net: n, logs: logs, core: &Core{RPC: rpc, cmd: cmd, exited: exited}}
	if err = m.apply(sampleConfig, false); err != nil {
		t.Fatalf("真实核心配置失败: %v\n%s", err, strings.Join(logs.List(), "\n"))
	}
	var proxies struct {
		All []string `json:"all"`
	}
	if err = rpc.Call(ctx, "getProxies", nil, &proxies); err != nil || len(proxies.All) == 0 {
		t.Fatalf("节点协议不符: %v %+v", err, proxies)
	}
	bad := strings.Replace(sampleConfig, "proxies: [示例节点, DIRECT]", "proxies: [不存在的节点]", 1)
	if err = m.apply(bad, false); err == nil {
		t.Fatal("真实核心未拒绝语义错误配置")
	}
	if !m.core.Alive() || m.degraded != "" {
		t.Fatalf("未恢复有效配置: %s", m.degraded)
	}
	if err = rpc.Text(ctx, "changeProxy", map[string]any{"group-name": "代理组", "proxy-name": "DIRECT"}); err != nil {
		t.Fatal(err)
	}
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer probe.Close()
	m.settings.HealthURL = probe.URL
	handler := m.Handler()
	request, err := json.Marshal(apiRequest{Proxy: "DIRECT", Session: m.session, Revision: &m.revision})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("POST", prefix+"/api/proxies/delay", strings.NewReader(string(request))))
	var delay struct {
		Value   int    `json:"value"`
		Session string `json:"session"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &delay); err != nil || response.Code != 200 || delay.Value < 0 || delay.Session != m.session {
		t.Fatalf("真实核心到本机回环地址的延迟协议不符: %d %s", response.Code, response.Body.String())
	}
	if err = m.core.Stop(); err != nil {
		t.Fatal(err)
	}
}
