package service

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const appVersion = "0.3.0"

func operationTitle(path string) string {
	titles := map[string]string{"control": "代理状态调整", "restart": "核心重启", "profiles": "配置导入", "profiles/update": "订阅更新", "profiles/edit": "配置保存", "profiles/select": "配置使用", "profiles/delete": "配置删除", "settings": "设置保存", "proxies/select": "节点切换", "network/recover": "网络恢复"}
	if title := titles[path]; title != "" {
		return title
	}
	return "操作"
}

func operationNext(path string) string {
	if strings.HasPrefix(path, "profiles") {
		return "检查配置与订阅后重试，原有效配置保留"
	}
	if strings.HasPrefix(path, "proxies") {
		return "刷新策略组并检测所选节点"
	}
	return "打开网络页，查看需要处理的项目并重新检测"
}

func networkCheckID(name string) string {
	ids := map[string]string{"TUN 设备": "tun_device", "IPv4 默认路由": "ipv4_route", "IPv6 默认路由": "ipv6_route", "nftables": "nftables", "网络接口检测": "interfaces", "局域网保留地址": "lan_exclusions", "IPv4 策略路由": "ipv4_rules", "IPv6 策略路由": "ipv6_rules", "TUN 名称冲突": "tun_conflict", "flclash_tun 归属": "tun_owner", "flclash_gateway 归属": "gateway_owner", "保留路由表 -4": "ipv4_table", "保留路由表 -6": "ipv6_table", "Docker 检测": "docker_available", "Docker 类型与网段": "docker_networks", "Docker 网段": "docker_subnets", "OVS 网桥": "ovs_bridges"}
	if id := ids[name]; id != "" {
		return id
	}
	return "check_" + providerKey(name)
}

type Connection struct {
	ID       string `json:"id"`
	Metadata struct {
		Network         string      `json:"network"`
		SourceIP        string      `json:"sourceIP"`
		SourcePort      json.Number `json:"sourcePort"`
		DestinationIP   string      `json:"destinationIP"`
		DestinationPort json.Number `json:"destinationPort"`
		Host            string      `json:"host"`
	} `json:"metadata"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Start       time.Time `json:"start"`
	Chains      []string  `json:"chains"`
	Rule        string    `json:"rule"`
	RulePayload string    `json:"rulePayload"`
	ObservedAt  time.Time `json:"observedAt"`
	Active      bool      `json:"active"`
	SourceID    string    `json:"sourceID"`
	SourceName  string    `json:"sourceName"`
	Path        string    `json:"path"`
	Exit        string    `json:"exit"`
}

type RunEvent struct {
	ID     string    `json:"id"`
	At     time.Time `json:"at"`
	Code   string    `json:"code"`
	Level  string    `json:"level"`
	Title  string    `json:"title"`
	Detail string    `json:"detail"`
	Next   string    `json:"next"`
}

type Observability struct {
	mu             sync.Mutex
	coreID         string
	contextID      string
	connections    map[string]Connection
	connectionAt   time.Time
	sampling       bool
	events         []RunEvent
	tasks          []*Diagnostic
	running        *Diagnostic
	targetMu       sync.Mutex
	targets        TargetReport
	targetsLoading bool
	targetsDone    chan struct{}
	runner         readRunner
	probe          probeRunner
}

func (m *Manager) observe() *Observability {
	m.observeOnce.Do(func() {
		m.observation = &Observability{connections: map[string]Connection{}, runner: readCommand, probe: executeProbe}
	})
	return m.observation
}

func (o *Observability) event(code, level, title, detail, next string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, RunEvent{randomID(), time.Now(), code, level, title, redact(detail), next})
	if len(o.events) > 200 {
		o.events = o.events[len(o.events)-200:]
	}
}

func (o *Observability) eventList() []RunEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := append([]RunEvent{}, o.events...)
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

func (m *Manager) syncObservation() {
	o := m.observe()
	coreID := ""
	if m.core.Alive() {
		coreID = m.core.identity
	}
	changing := map[string]bool{"control": true, "restart": true, "settings": true, "profiles/select": true, "profiles/update": true, "proxies/select": true, "network/recover": true}[m.operation]
	b, _ := json.Marshal([]any{m.session, m.revision, coreID, m.settings.Active, m.settings.Mode, m.settings.NetworkMode, m.settings.HealthURL, m.settings.Selected, m.active, m.closing, changing})
	o.mu.Lock()
	defer o.mu.Unlock()
	contextID := providerKey(string(b))
	if o.contextID != contextID {
		o.contextID = contextID
		for _, task := range o.tasks {
			task.Stale = true
		}
		if o.running != nil {
			o.running.cancel()
		}
	}
	if o.coreID != coreID {
		o.coreID = coreID
		o.connections = map[string]Connection{}
		o.connectionAt = time.Time{}
	}
}

func (o *Observability) prune(now time.Time) {
	for id, c := range o.connections {
		if now.Sub(c.ObservedAt) > 10*time.Minute {
			delete(o.connections, id)
		}
	}
	if len(o.connections) <= 1000 {
		return
	}
	list := make([]Connection, 0, len(o.connections))
	for _, c := range o.connections {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ObservedAt.Before(list[j].ObservedAt) })
	for _, c := range list[:len(list)-1000] {
		delete(o.connections, c.ID)
	}
}

func safeLabel(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
	if len(value) > limit {
		value = value[:limit]
	}
	return strings.ToValidUTF8(value, "")
}

func normalizeConnection(c *Connection) {
	c.Metadata.Host = safeLabel(c.Metadata.Host, 253)
	c.Rule = safeLabel(c.Rule, 64)
	c.RulePayload = safeLabel(c.RulePayload, 512)
	if len(c.Chains) > 16 {
		c.Chains = c.Chains[:16]
	}
	for i := range c.Chains {
		c.Chains[i] = safeLabel(c.Chains[i], 256)
	}
	c.Path, c.Exit = "unknown", "未确认"
	if len(c.Chains) > 0 {
		c.Exit = c.Chains[0]
		c.Path = "proxy"
		if c.Exit == "DIRECT" {
			c.Path = "direct"
		}
		if c.Exit == "REJECT" || c.Exit == "REJECT-DROP" {
			c.Path = "reject"
		}
	}
}

func (o *Observability) receive(coreID string, raw json.RawMessage) {
	var c Connection
	if len(raw) > 64<<10 || json.Unmarshal(raw, &c) != nil || c.ID == "" {
		return
	}
	normalizeConnection(&c)
	c.ObservedAt, c.Active = time.Now(), true
	o.mu.Lock()
	defer o.mu.Unlock()
	if coreID != o.coreID {
		return
	}
	o.connections[c.ID] = c
	o.prune(c.ObservedAt)
}

func (o *Observability) ingest(coreID string, list []Connection, at time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if coreID != o.coreID {
		return
	}
	for id, c := range o.connections {
		if c.ObservedAt.Before(at) {
			c.Active = false
			o.connections[id] = c
		}
	}
	for _, c := range list {
		if c.ID == "" {
			continue
		}
		normalizeConnection(&c)
		c.ObservedAt, c.Active = at, true
		o.connections[c.ID] = c
	}
	o.connectionAt = at
	o.prune(time.Now())
}

func (m *Manager) sampleConnections(ctx context.Context) {
	o := m.observe()
	o.mu.Lock()
	if o.sampling || time.Since(o.connectionAt) < 1500*time.Millisecond {
		o.mu.Unlock()
		return
	}
	o.sampling = true
	o.mu.Unlock()
	defer func() { o.mu.Lock(); o.sampling = false; o.mu.Unlock() }()
	if !m.mu.TryRLock() {
		return
	}
	c := m.core
	m.mu.RUnlock()
	if !c.Alive() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var snapshot struct {
		Connections []Connection `json:"connections"`
	}
	at := time.Now()
	if c.RPC.Call(ctx, "getConnections", nil, &snapshot) == nil {
		o.ingest(c.identity, snapshot.Connections, at)
	}
}

func sourceFor(c Connection, targets []NetworkTarget) (string, string) {
	ip, err := netip.ParseAddr(c.Metadata.SourceIP)
	if err != nil {
		return "unknown", "来源未确定"
	}
	if ip.IsLoopback() {
		return "nas", "NAS／共享宿主网络"
	}
	matches := map[string]string{}
	for _, target := range targets {
		if !target.Running {
			continue
		}
		if started, err := time.Parse(time.RFC3339Nano, target.StartedAt); err == nil && c.Start.Before(started) {
			continue
		}
		for _, address := range target.Addresses {
			p, err := netip.ParseAddr(address)
			if err != nil || p.Unmap() != ip.Unmap() {
				continue
			}
			if target.Ambiguous {
				return "unknown", "来源未确定（多网络）"
			}
			matches[target.SourceID] = target.SourceName
		}
	}
	if len(matches) == 1 {
		for id, name := range matches {
			return id, name
		}
	}
	return "unknown", "来源未确定"
}

func (o *Observability) connectionList(source, query, path string, offset, limit int) map[string]any {
	o.targetMu.Lock()
	targets := append([]NetworkTarget{}, o.targets.Items...)
	o.targetMu.Unlock()
	o.mu.Lock()
	o.prune(time.Now())
	list := make([]Connection, 0, len(o.connections))
	for _, c := range o.connections {
		list = append(list, c)
	}
	at, coreID := o.connectionAt, o.coreID
	o.mu.Unlock()
	filtered := make([]Connection, 0, len(list))
	query = strings.ToLower(query)
	for _, c := range list {
		c.SourceID, c.SourceName = sourceFor(c, targets)
		if source != "" && c.SourceID != source {
			continue
		}
		if path != "" && c.Path != path {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(c.Metadata.Host+" "+c.Metadata.DestinationIP+" "+c.SourceName+" "+c.Exit+" "+c.Rule+" "+c.RulePayload), query) {
			continue
		}
		filtered = append(filtered, c)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Start.Equal(filtered[j].Start) {
			return filtered[i].ID < filtered[j].ID
		}
		return filtered[i].Start.After(filtered[j].Start)
	})
	total := len(filtered)
	offset = min(max(offset, 0), total)
	limit = min(max(limit, 1), 100)
	return map[string]any{"items": filtered[offset:min(offset+limit, total)], "total": total, "offset": offset, "limit": limit, "updatedAt": at, "coreSession": coreID, "stale": coreID == "" || time.Since(at) > 10*time.Second, "bounded": true}
}
