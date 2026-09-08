package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func consoleManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	n, err := newNetwork(dir)
	if err != nil {
		t.Fatal(err)
	}
	n.tunAvailable = func() error { return nil }
	n.bootID = func() (string, error) { return "测试开机", nil }
	n.run = ipv4Machine
	s := testSettings()
	s.NetworkMode, s.NetworkConfirmed = "dual", true
	return &Manager{dir: dir, home: dir, net: n, settings: s, logs: &Logs{}, session: randomID()}
}

func ipv4Machine(name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	switch {
	case call == "ip -j -4 route show default":
		return []byte(`[{"dev":"eth0"}]`), nil
	case call == "ip link show dev flclash0", strings.HasPrefix(call, "nft list table inet"), name == "docker", name == "ovs-vsctl":
		return nil, errors.New("测试对象不存在")
	default:
		return []byte("[]"), nil
	}
}

func attachCore(t *testing.T, m *Manager, answer func(map[string]any) any) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	m.core = &Core{RPC: newRPC(a, nil), exited: make(chan struct{})}
	go func() {
		for {
			call, err := wireRead(b)
			if err != nil {
				return
			}
			if wireWrite(b, map[string]any{"id": call["id"], "result": answer(call)}) != nil {
				return
			}
		}
	}()
}

func TestNetworkModesGenerateMatchingFamilies(t *testing.T) {
	for _, mode := range []string{"", "dual", "ipv4"} {
		t.Run(mode, func(t *testing.T) {
			s := testSettings()
			s.NetworkMode = mode
			raw, err := prepareConfig(sampleConfig, s, t.TempDir(), true, []string{"192.168.5.0/24", "2001:db8:1::/64"})
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err = yaml.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			dual := mode != "ipv4"
			if cfg["ipv6"] != dual || cfg["dns"].(map[string]any)["ipv6"] != dual {
				t.Fatal("核心或 DNS 地址族不匹配")
			}
			tun := cfg["tun"].(map[string]any)
			if dual != (len(tun["inet6-address"].([]any)) > 0) {
				t.Fatal("IPv6 TUN 地址不匹配")
			}
			if !dual {
				for _, key := range []string{"dns-hijack", "route-exclude-address"} {
					for _, item := range tun[key].([]any) {
						if strings.Contains(item.(string), "::") {
							t.Fatal("IPv4 配置含 IPv6 接管项")
						}
					}
				}
			}
		})
	}
}

func TestMissingIPv6OnlyBlocksDual(t *testing.T) {
	for _, mode := range []string{"dual", "ipv4"} {
		m := consoleManager(t)
		m.net.mode = mode
		r := m.net.Detect()
		if r.Ready != (mode == "ipv4") {
			t.Fatalf("%s 就绪判断错误: %+v", mode, r.Checks)
		}
		found := false
		for _, c := range r.Checks {
			if c.Family == "ipv6" {
				found = true
				if c.Required != (mode == "dual") {
					t.Fatal("地址族阻塞标记错误")
				}
			}
		}
		if !found {
			t.Fatal("缺少独立的 IPv6 检测信息")
		}
	}
}

func TestIPv4OwnershipAndEstablishment(t *testing.T) {
	m := consoleManager(t)
	n := m.net
	n.mode = "ipv4"
	if err := n.ClaimTun(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(n.j.TunFamilies, []string{"-4"}) {
		t.Fatal("归属未记录实际地址族")
	}
	n.run = func(name string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "-6") {
			t.Fatal("IPv4 建立检查访问了 IPv6")
		}
		return []byte(`[{"dev":"flclash0"}]`), nil
	}
	if err := n.ConfirmTun(); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreUsesJournalNotSelectedMode(t *testing.T) {
	for _, recorded := range [][]string{nil, {"-4"}, {"-4", "-6"}} {
		m := consoleManager(t)
		n := m.net
		n.mode = "ipv4"
		n.j.Tun = true
		n.j.TunFamilies = recorded
		var calls []string
		n.run = func(name string, args ...string) ([]byte, error) {
			call := name + " " + strings.Join(args, " ")
			calls = append(calls, call)
			if call == "nft list tables" {
				return []byte("table inet flclash_tun\ntable inet docker"), nil
			}
			if strings.Contains(call, "rule show") {
				return []byte(`[{"priority":31000},{"priority":32766}]`), nil
			}
			return []byte("[]"), nil
		}
		if err := n.RestoreTun(); err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(calls, "\n")
		if strings.Contains(joined, "-6") != (len(recorded) != 1) {
			t.Fatal("恢复使用了界面选项，而非实际归属")
		}
		for _, forbidden := range []string{"priority 32766", "delete table inet docker", "flush ruleset", "sysctl"} {
			if strings.Contains(joined, forbidden) {
				t.Fatal("清理越界: " + forbidden)
			}
		}
	}
}

func TestIPv4GatewayNeverChangesIPv6(t *testing.T) {
	m := consoleManager(t)
	n := m.net
	n.mode = "ipv4"
	n.report.Exit4 = "eth0"
	var calls []string
	n.run = func(name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		if strings.HasPrefix(call, "nft list table inet") || strings.Contains(call, " -C ") {
			return nil, errors.New("测试对象不存在")
		}
		if name == "sysctl" {
			return []byte("0"), nil
		}
		return nil, nil
	}
	if err := n.Gateway([]string{"192.168.5.0/24"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range calls {
		if strings.Contains(c, "ipv6") || strings.Contains(c, "ip6tables") || strings.Contains(c, " -6 ") {
			t.Fatal("IPv4 模式修改 IPv6: " + c)
		}
	}
	b, err := os.ReadFile(filepath.Join(m.dir, "gateway.nft"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "ip6 ") {
		t.Fatal("IPv4 网关包含 IPv6 防火墙规则")
	}
	count := len(calls)
	if n.Gateway([]string{"fd12:3456:789a::/64"}) == nil || len(calls) != count {
		t.Fatal("没有在修改网络前拒绝 IPv6 网段")
	}
}

func TestSettingsPatchAndModeSwitchRestrictions(t *testing.T) {
	m := consoleManager(t)
	m.settings.GatewayCIDRs = []string{"192.168.5.0/24"}
	mode := "global"
	if err := m.saveSettings(apiRequest{Mode: &mode}); err != nil {
		t.Fatal(err)
	}
	if m.settings.HealthGroup != "代理组" || len(m.settings.GatewayCIDRs) != 1 {
		t.Fatal("保存模式覆盖了未提交字段")
	}
	if m.healthGroup() != "GLOBAL" {
		t.Fatal("全局检测没有使用实际 GLOBAL 出口")
	}
	mode = "rule"
	if err := m.saveSettings(apiRequest{Mode: &mode}); err != nil {
		t.Fatal(err)
	}
	if m.healthGroup() != "代理组" {
		t.Fatal("全局模式覆盖了规则模式的主要策略组")
	}
	family := "ipv4"
	confirmed := true
	if errorCode(m.saveSettings(apiRequest{NetworkMode: &family}), "settings") != "network_confirmation_required" {
		t.Fatal("切换没有要求明确确认")
	}
	for _, phase := range []string{"active", "enabled", "tun", "gateway"} {
		m.active = phase == "active"
		m.settings.Enabled = phase == "enabled"
		m.net.j.Tun = phase == "tun"
		m.net.j.Gateway = phase == "gateway"
		if errorCode(m.saveSettings(apiRequest{NetworkMode: &family, NetworkConfirmed: &confirmed}), "settings") != "network_mode_in_use" {
			t.Fatalf("%s 时允许切换", phase)
		}
	}
	m.net.j.Gateway = false
	if err := m.saveSettings(apiRequest{NetworkMode: &family, NetworkConfirmed: &confirmed}); err != nil {
		t.Fatal(err)
	}
	if m.settings.NetworkMode != "ipv4" || m.net.mode != "ipv4" {
		t.Fatal("模式未同步保存")
	}
	cidrs := []string{"fd12:3456:789a::/64"}
	if m.saveSettings(apiRequest{GatewayCIDRs: &cidrs}) == nil || m.settings.GatewayCIDRs[0] != "192.168.5.0/24" {
		t.Fatal("冲突网段覆盖旧设置")
	}
}

func TestLegacySettingsAndNewInstall(t *testing.T) {
	dir := t.TempDir()
	s, err := loadSettings(dir)
	if err != nil || s.Enabled || s.NetworkConfirmed || s.NetworkMode != "dual" {
		t.Fatal("新安装默认状态不安全")
	}
	if err := atomicWrite(filepath.Join(dir, "settings.json"), []byte(`{"mode":"rule","profiles":[]}`)); err != nil {
		t.Fatal(err)
	}
	s, err = loadSettings(dir)
	if err != nil || s.NetworkMode != "dual" || !s.NetworkConfirmed {
		t.Fatal("旧双栈设置不兼容")
	}
}

func TestFailedFirstEnableDoesNotRecoverForever(t *testing.T) {
	for _, legacyEnabled := range []bool{false, true} {
		m := consoleManager(t)
		m.settings.Enabled = legacyEnabled
		m.settings.Active = "p"
		m.settings.Profiles = []Profile{{ID: "p", YAML: sampleConfig}}
		if err := m.setEnabled(true); err == nil {
			t.Fatal("缺少 IPv6 时双栈意外开启")
		}
		if m.settings.Enabled || m.active || m.degraded != "" || m.blocked == "" || m.net.j.Tun {
			t.Fatal("前置失败进入了降级或保留开启意图")
		}
		m.net.run = func(string, ...string) ([]byte, error) { t.Fatal("首次失败仍进行恢复尝试"); return nil, nil }
		for i := 0; i < 6; i++ {
			m.health()
		}
		saved, err := loadSettings(m.dir)
		if err != nil || saved.Enabled {
			t.Fatal("关闭意图未持久化")
		}
	}
}

func TestStatusSnapshotStaysReadableDuringLongOperation(t *testing.T) {
	m := consoleManager(t)
	handler := m.Handler()
	m.mu.Lock()
	m.operation = "profiles/update"
	m.publish()
	defer m.mu.Unlock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", prefix+"/api/status", nil))
		done <- w
	}()
	select {
	case w := <-done:
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"operation":"profiles/update"`) || !strings.Contains(w.Body.String(), `"updatedAt"`) {
			t.Fatal("状态没有操作阶段和采样时间")
		}
	case <-time.After(time.Second):
		t.Fatal("状态读取被长操作阻塞")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", prefix+"/api/restart", strings.NewReader("{}")))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "operation_busy") {
		t.Fatal("没有拒绝重复互斥操作")
	}
}

func TestProfileEditPreservesStoredAddressAndRollback(t *testing.T) {
	m := consoleManager(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "测试故障", 503) }))
	defer srv.Close()
	m.settings.Profiles = []Profile{{ID: "p", Name: "原名称", URL: "https://example.com/config", YAML: sampleConfig, Interval: 24}}
	if err := m.editProfile(apiRequest{ID: "p", Name: "新名称", Interval: 12}); err != nil {
		t.Fatal(err)
	}
	old := m.settings.Profiles[0]
	if old.URL != "https://example.com/config" || old.Name != "新名称" {
		t.Fatal("空地址没有保留原订阅")
	}
	if m.editProfile(apiRequest{ID: "p", Name: "失败名称", URL: srv.URL, Interval: 1}) == nil {
		t.Fatal("下载失败未报告")
	}
	if m.settings.Profiles[0] != old {
		t.Fatal("替换失败覆盖旧订阅")
	}
	data, err := json.Marshal(m.status())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), old.URL) || strings.Contains(string(data), sampleConfig) {
		t.Fatal("状态泄露了订阅原文")
	}
}

func TestStaleSessionAndSelectionMembership(t *testing.T) {
	m := consoleManager(t)
	m.configured = true
	selections := 0
	attachCore(t, m, func(call map[string]any) any {
		if call["method"] == "getProxies" {
			return map[string]any{"proxies": map[string]any{"手动": proxyGroup{Type: "Selector", Now: "旧节点", All: []string{"旧节点", "新节点"}}, "自动": proxyGroup{Type: "URLTest", All: []string{"新节点"}}}}
		}
		selections++
		return ""
	})
	if _, err := m.handle("proxies/select", apiRequest{Session: "旧会话"}); errorCode(err, "") != "stale_session" {
		t.Fatal("旧服务会话没有被拒绝")
	}
	for _, group := range []string{"自动", "不存在"} {
		if m.changeSelection(context.Background(), apiRequest{Group: group, Proxy: "新节点"}) == nil {
			t.Fatal("接受了无效选择")
		}
	}
	if m.changeSelection(context.Background(), apiRequest{Group: "手动", Proxy: "外部节点"}) == nil {
		t.Fatal("接受了组外节点")
	}
	if selections != 0 {
		t.Fatal("无效选择到达了核心")
	}
	if err := m.changeSelection(context.Background(), apiRequest{Group: "手动", Proxy: "新节点"}); err != nil {
		t.Fatal(err)
	}
	if selections != 1 || m.settings.Selected["手动"] != "新节点" {
		t.Fatal("选择未正确保存")
	}
}

func TestRollbackNeverResurrectsUnclaimedTun(t *testing.T) {
	s := testSettings()
	s.NetworkMode = "ipv4"
	raw, err := prepareConfig(sampleConfig, s, t.TempDir(), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = rollbackConfig(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["tun"].(map[string]any)["enable"] != false {
		t.Fatal("冷启动回滚恢复了无归属接管")
	}
}

func TestCurrentSessionDelaySurvivesStatusRoundTrip(t *testing.T) {
	m := consoleManager(t)
	m.configured = true
	attachCore(t, m, func(call map[string]any) any {
		return map[string]any{"value": 42}
	})
	h := m.Handler()
	status := httptest.NewRecorder()
	h.ServeHTTP(status, httptest.NewRequest("GET", prefix+"/api/status", nil))
	var snapshot struct {
		Session  string `json:"session"`
		Revision uint64 `json:"revision"`
	}
	if err := json.Unmarshal(status.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Session == "" || snapshot.Session != m.session {
		t.Fatal("状态快照没有携带当前核心会话")
	}
	body, err := json.Marshal(apiRequest{Proxy: "测试节点", Session: snapshot.Session, Revision: &snapshot.Revision})
	if err != nil {
		t.Fatal(err)
	}
	result := httptest.NewRecorder()
	h.ServeHTTP(result, httptest.NewRequest("POST", prefix+"/api/proxies/delay", strings.NewReader(string(body))))
	if result.Code != 200 || !strings.Contains(result.Body.String(), `"value":42`) {
		t.Fatalf("当前会话的延迟结果被错误丢弃: %d %s", result.Code, result.Body.String())
	}
}

func TestDelayConcurrencyAndLateResultRejection(t *testing.T) {
	m := consoleManager(t)
	m.configured = true
	m.delaySlots = make(chan struct{}, 2)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	m.core = &Core{RPC: newRPC(a, nil), exited: make(chan struct{})}
	m.publish()
	started := make(chan struct{})
	release := make(chan struct{})
	go func() {
		first, _ := wireRead(b)
		second, _ := wireRead(b)
		close(started)
		<-release
		for _, call := range []map[string]any{first, second} {
			_ = wireWrite(b, map[string]any{"id": call["id"], "result": map[string]any{"value": 42}})
		}
	}()
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, err := m.testDelay(context.Background(), apiRequest{Proxy: "测试节点"}); results <- err }()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("两个延迟请求没有并发进入核心")
	}
	if _, err := m.testDelay(context.Background(), apiRequest{Proxy: "第三个节点"}); errorCode(err, "") != "operation_busy" {
		t.Fatal("没有限制并发为两个")
	}
	m.mu.Lock()
	m.revision++
	m.publish()
	m.mu.Unlock()
	close(release)
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if errorCode(err, "") != "stale_session" {
				t.Fatal("旧配置延迟结果未被丢弃")
			}
		case <-time.After(time.Second):
			t.Fatal("延迟请求没有收敛")
		}
	}
	if len(m.delaySlots) != 0 {
		t.Fatal("延迟请求并发槽泄漏")
	}
}
