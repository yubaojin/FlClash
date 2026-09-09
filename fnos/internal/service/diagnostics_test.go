package service

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func testConnection(id, source, destination string, port int, at time.Time) Connection {
	c := Connection{ID: id, Start: at, ObservedAt: at, Chains: []string{"节点甲", "代理组"}, Active: true}
	c.Metadata.SourceIP, c.Metadata.DestinationIP = source, destination
	c.Metadata.SourcePort, c.Metadata.DestinationPort = json.Number(fmt.Sprint(port)), "443"
	c.Metadata.Network = "tcp"
	normalizeConnection(&c)
	return c
}

func TestConnectionSourceAvoidsFalseContainerOwnership(t *testing.T) {
	targets := []NetworkTarget{
		{ID: "nas", SourceID: "nas", SourceName: "NAS／共享宿主网络", Running: true, Addresses: []string{"192.168.1.2"}},
		{ID: "a", SourceID: "a", SourceName: "容器甲", Running: true, Addresses: []string{"172.17.0.2"}},
		{ID: "b", SourceID: "shared", SourceName: "共享网络", Running: true, Addresses: []string{"172.17.0.3"}},
		{ID: "c", SourceID: "shared", SourceName: "共享网络", Running: true, Addresses: []string{"172.17.0.3"}},
	}
	for _, item := range []struct{ ip, id string }{{"172.17.0.2", "a"}, {"172.17.0.3", "shared"}, {"192.168.1.2", "nas"}, {"10.1.1.1", "unknown"}} {
		if id, _ := sourceFor(testConnection("1", item.ip, "1.1.1.1", 32000, time.Now()), targets); id != item.id {
			t.Fatalf("来源 %s 被错误归属到 %s", item.ip, id)
		}
	}
	targets = append(targets, NetworkTarget{SourceID: "other", Running: true, Addresses: []string{"172.17.0.2"}})
	if id, _ := sourceFor(testConnection("1", "172.17.0.2", "1.1.1.1", 32000, time.Now()), targets); id != "unknown" {
		t.Fatal("冲突地址被错误归属")
	}
	targets[1].Ambiguous = true
	if id, _ := sourceFor(testConnection("1", "172.17.0.2", "1.1.1.1", 32000, time.Now()), targets[:4]); id != "unknown" {
		t.Fatal("多网络来源被伪装为确定归属")
	}
}

func TestConnectionCacheBoundedAndSessionSafe(t *testing.T) {
	o := &Observability{coreID: "new", connections: map[string]Connection{}}
	at := time.Now()
	for i := 0; i < 1010; i++ {
		c := testConnection(fmt.Sprint(i), "172.17.0.2", "1.1.1.1", i+1000, at)
		b, _ := json.Marshal(c)
		o.receive("new", b)
	}
	if len(o.connections) != 1000 {
		t.Fatalf("连接缓存超过限制：%d", len(o.connections))
	}
	b, _ := json.Marshal(testConnection("stale", "172.17.0.2", "1.1.1.1", 2, at))
	o.receive("old", b)
	if _, ok := o.connections["stale"]; ok {
		t.Fatal("旧核心事件污染新会话")
	}
	o.prune(at.Add(11 * time.Minute))
	if len(o.connections) != 0 {
		t.Fatal("过期连接未清理")
	}
}

func TestProbeEvidenceMatchesEntireTupleAndTime(t *testing.T) {
	at := time.Now()
	c := testConnection("1", "172.17.0.2", "1.1.1.1", 32000, at)
	flow := ProbeFlow{Source: "172.17.0.2:32000", Destination: "1.1.1.1:443", Network: "tcp", At: at}
	if !matchesProbe(flow, c, at.Add(-time.Second)) {
		t.Fatal("有效检测连接未关联")
	}
	for _, change := range []func(*Connection){func(c *Connection) { c.Metadata.SourcePort = "32001" }, func(c *Connection) { c.Metadata.DestinationIP = "1.0.0.1" }, func(c *Connection) { c.Metadata.Network = "udp" }, func(c *Connection) { c.Start = at.Add(-time.Minute) }} {
		other := c
		change(&other)
		if matchesProbe(flow, other, at.Add(-time.Second)) {
			t.Fatal("不相关连接被当作检测证据")
		}
	}
}

func TestDiagnosticHTTP401AndTLSValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer server.Close()
	step := requestProbe(context.Background(), server.URL, "ipv4", []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if step.State != "passed" || step.Code != "authentication_required" || len(step.Flows) != 1 {
		t.Fatalf("401 被误判：%+v", step)
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer tlsServer.Close()
	step = requestProbe(context.Background(), tlsServer.URL, "ipv4", []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if step.Code != "tls_failed" {
		t.Fatalf("没有拒绝不可信 TLS：%+v", step)
	}
}

func TestIPv4ProbeDoesNotTestIPv6AndUsesHosts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	var steps []ProbeStep
	in := ProbeInput{URL: server.URL, Mode: "ipv4"}
	performProbe(context.Background(), in, func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "-6") {
			t.Fatal("IPv4 检测访问了 IPv6")
		}
		if strings.Contains(strings.Join(args, " "), "address") {
			return []byte(`[{"addr_info":[{}]}]`), nil
		}
		return []byte(`[{}]`), nil
	}, func(s ProbeStep) { steps = append(steps, s) })
	if len(steps) != 6 || steps[5].Code != "excluded" || steps[4].HTTPStatus != 204 {
		t.Fatalf("地址族或 HTTP 检测结果错误：%+v", steps)
	}
	if ips := hostsAddresses("127.0.0.1 test.local\n::1 test.local", "test.local", "ipv4"); len(ips) != 1 || !ips[0].Is4() {
		t.Fatal("未按地址族处理 hosts")
	}
}

func TestDiagnosticAsyncCancelAndContextInvalidation(t *testing.T) {
	m := consoleManager(t)
	o := m.observe()
	o.runner = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("未安装 Docker") }
	started := make(chan struct{})
	o.probe = func(ctx context.Context, _ NetworkTarget, _, _ string, emit func(ProbeStep)) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	h := m.Handler()
	first, err := m.startDiagnostic("nas", "health")
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err = m.startDiagnostic("nas", "health"); errorCode(err, "") != "diagnostic_busy" {
		t.Fatal("接受了并行诊断")
	}
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", prefix+"/api/status", nil))
	if r.Code != 200 {
		t.Fatal("长检测阻塞状态读取")
	}
	m.mu.Lock()
	m.settings.Mode = "global"
	m.publish()
	m.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		o.mu.Lock()
		running := o.running != nil
		o.mu.Unlock()
		if !running {
			break
		}
		time.Sleep(time.Millisecond)
	}
	value, err := o.diagnosticResult(first.ID)
	if err != nil {
		t.Fatal(err)
	}
	d := value.(Diagnostic)
	if !d.Stale || d.State != "cancelled" || d.Code != "context_changed" {
		t.Fatalf("旧检测未失效：%+v", d)
	}
}

func TestDiagnosticCompletedNotReportedCancelledAndExportRedacted(t *testing.T) {
	m := consoleManager(t)
	o := m.observe()
	o.runner = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("Docker 不可用") }
	o.probe = func(ctx context.Context, target NetworkTarget, raw, mode string, emit func(ProbeStep)) error {
		emit(probeStep("https", "ipv4", "访问检测目标", "reachable", "内部地址 192.168.1.8 token=SECRET", "", true))
		return nil
	}
	d, err := m.startDiagnostic("nas", "health")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		o.mu.Lock()
		running := o.running != nil
		o.mu.Unlock()
		if !running {
			break
		}
		time.Sleep(time.Millisecond)
	}
	value, _ := o.diagnosticResult(d.ID)
	result := value.(Diagnostic)
	if result.State != "done" {
		t.Fatalf("成功检测被标成取消：%+v", result)
	}
	exported, err := o.exportDiagnostic(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET", "192.168.1.8", m.settings.HealthURL} {
		if strings.Contains(exported, secret) {
			t.Fatal("导出包含敏感内容")
		}
	}
}

func TestProbeOutputAndContainerValidation(t *testing.T) {
	if validContainerID("abc;reboot") || validContainerID("--help") {
		t.Fatal("容器标识未校验")
	}
	s := probeStep("https", "ipv4", "连接", "reachable", "", "", true)
	s.Flows = []ProbeFlow{{Source: "172.17.0.2:32000", Destination: "1.1.1.1:443", Network: "tcp", At: time.Now()}}
	b, _ := json.Marshal(encodeProbeStep(s))
	var result ProbeStep
	if err := decodeProbeOutput(strings.NewReader(string(b)), func(s ProbeStep) { result = s }); err != nil || len(result.Flows) != 1 {
		t.Fatal("子进程关联证据丢失")
	}
	if decodeProbeOutput(strings.NewReader("bad"), func(ProbeStep) {}) == nil {
		t.Fatal("接受了错误输出")
	}
	if _, err := io.Copy(&boundedBuffer{limit: 2}, strings.NewReader("1234")); err == nil {
		t.Fatal("命令输出未限制")
	}
}

func TestDNSUsesRealUDPAndTCPWithoutSystemHosts(t *testing.T) {
	answer := func(raw []byte) []byte {
		var query dnsmessage.Message
		if err := query.Unpack(raw); err != nil {
			t.Error(err)
			return nil
		}
		query.Header.Response = true
		query.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}}}}
		b, err := query.Pack()
		if err != nil {
			t.Error(err)
		}
		return b
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 4096)
		n, addr, err := udp.ReadFrom(b)
		if err == nil {
			_, _ = udp.WriteTo(answer(b[:n]), addr)
		}
	}()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		conn, err := tcp.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			return
		}
		b := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err = io.ReadFull(conn, b); err != nil {
			return
		}
		b = answer(b)
		_, _ = conn.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...))
	}()
	for _, item := range []struct{ protocol, address string }{{"udp", udp.LocalAddr().String()}, {"tcp", tcp.Addr().String()}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		ips, err := exchangeDNS(ctx, item.address, item.protocol, "localhost", dnsmessage.TypeA)
		cancel()
		if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.10" {
			t.Fatalf("%s 未实际查询 DNS：%v %v", item.protocol, ips, err)
		}
	}
}

func TestCloseWaitsForDiagnosticProcessRecovery(t *testing.T) {
	m := consoleManager(t)
	o := m.observe()
	o.runner = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("Docker 不可用") }
	started, recovered := make(chan struct{}), make(chan struct{})
	o.probe = func(ctx context.Context, _ NetworkTarget, _, _ string, _ func(ProbeStep)) error {
		close(started)
		<-ctx.Done()
		close(recovered)
		return ctx.Err()
	}
	_, err := m.startDiagnostic("nas", "health")
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-recovered:
	default:
		t.Fatal("未回收检测进程即停用应用")
	}
}

func TestDiagnosticExportRequiresExistingID(t *testing.T) {
	m := consoleManager(t)
	for _, id := range []string{"", "missing"} {
		if _, err := m.observe().exportDiagnostic(id); errorCode(err, "diagnostics/export") != "diagnostic_missing" {
			t.Fatalf("空或失效的记录不能导出：%v", err)
		}
	}
}

func TestFailedProbeIsVisibleAsWarningEvent(t *testing.T) {
	m := consoleManager(t)
	o := m.observe()
	o.runner = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("Docker 不可用") }
	o.probe = func(_ context.Context, _ NetworkTarget, _, _ string, emit func(ProbeStep)) error {
		emit(probeStep("https", "ipv4", "访问检测目标", "request_timeout", "访问目标超时", "测试当前节点", false))
		return nil
	}
	d, err := m.startDiagnostic("nas", "health")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.done:
	case <-time.After(2 * time.Second):
		t.Fatal("检测未结束")
	}
	events := o.eventList()
	if len(events) != 1 || events[0].Level != "warning" || events[0].Code != "diagnostic_checks_failed" {
		t.Fatalf("失败的检测没有可读警告事件：%+v", events)
	}
}

func TestTargetDiscoveryConcurrentReadersWaitForSameResult(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	m := consoleManager(t)
	o := m.observe()
	o.runner = func(context.Context, string, ...string) ([]byte, error) {
		close(entered)
		<-release
		return nil, errors.New("Docker 不可用")
	}
	first := make(chan TargetReport, 1)
	go func() { first <- o.targetList(context.Background(), true) }()
	<-entered
	second := make(chan TargetReport, 1)
	go func() { second <- o.targetList(context.Background(), true) }()
	select {
	case <-second:
		t.Fatal("并发发现返回空对象报告")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	if len((<-first).Items) != 1 || len((<-second).Items) != 1 {
		t.Fatal("未共享发现结果")
	}
}
