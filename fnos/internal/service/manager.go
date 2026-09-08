package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type Manager struct {
	snapshot                      atomic.Pointer[json.RawMessage]
	configured                    bool
	revision                      uint64
	session                       string
	operation, blocked            string
	traffic                       json.RawMessage
	trafficAt                     time.Time
	delaySlots                    chan struct{}
	mu                            sync.RWMutex
	dir, home, binary, runtimeDir string
	settings                      Settings
	core                          *Core
	net                           *Network
	logs                          *Logs
	degraded                      string
	active                        bool
	checked                       bool
	closing                       bool
	failures, successes           int
}

func NewManager(dir, binary, data, runtimeDir string, logs *Logs) (*Manager, error) {
	for _, path := range []string{dir, filepath.Join(dir, "core"), filepath.Join(dir, "core", "providers")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			return nil, err
		}
	}
	s, err := loadSettings(dir)
	if err != nil {
		return nil, err
	}
	n, err := newNetwork(dir)
	if err != nil {
		return nil, err
	}
	if err = n.RestoreAll(); err != nil {
		return nil, fmt.Errorf("启动前网络恢复失败: %w", err)
	}
	m := &Manager{dir: dir, home: filepath.Join(dir, "core"), runtimeDir: runtimeDir, binary: binary, settings: s, net: n, logs: logs, session: randomID()}
	n.mode = s.NetworkMode
	for _, name := range []string{"GEOIP.dat", "GEOIP.metadb", "GEOSITE.dat", "ASN.mmdb"} {
		b, err := os.ReadFile(filepath.Join(data, name))
		if err != nil {
			return nil, err
		}
		if err = atomicWrite(filepath.Join(m.home, name), b); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *Manager) persist() error { return saveJSON(filepath.Join(m.dir, "settings.json"), m.settings) }
func (m *Manager) profile(id string) *Profile {
	for i := range m.settings.Profiles {
		if m.settings.Profiles[i].ID == id {
			return &m.settings.Profiles[i]
		}
	}
	return nil
}

func (m *Manager) ensureCore() error {
	if m.core.Alive() {
		return nil
	}
	if m.core != nil {
		if err := m.core.Stop(); err != nil {
			return err
		}
		m.core = nil
	}
	m.configured = false
	if err := m.net.RestoreTun(); err != nil {
		return err
	}
	c, err := launchCore(m.binary, m.home, filepath.Join(m.runtimeDir, "core.sock"), m.logs)
	if err != nil {
		return err
	}
	m.core = c
	return nil
}

func (m *Manager) apply(raw string, enabled bool) error {
	if err := m.ensureCore(); err != nil {
		return err
	}
	startListeners := !m.configured
	prepared, err := prepareConfig(raw, m.settings, m.home, enabled, m.net.report.LAN)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	path := filepath.Join(m.home, "config.yaml")
	old, oldErr := os.ReadFile(path)
	if oldErr != nil && !errors.Is(oldErr, os.ErrNotExist) {
		return oldErr
	}
	old, err = rollbackConfig(old, m.active)
	if err != nil {
		return err
	}
	if err = atomicWrite(path, prepared); err != nil {
		return err
	}
	m.revision++
	m.publish()
	err = m.core.RPC.Text(ctx, "validateConfig", path)
	if err == nil {
		err = m.core.RPC.Text(ctx, "setupConfig", map[string]any{"selected-map": m.settings.Selected, "test-url": m.settings.HealthURL})
	}
	if err == nil && startListeners {
		err = m.core.RPC.Call(ctx, "startListener", nil, nil)
	}
	if err == nil && enabled {
		err = m.net.ConfirmTun()
	}
	if err == nil {
		err = atomicWrite(filepath.Join(m.dir, "last-good.yaml"), prepared)
	}
	if err != nil {
		rollbackErr := errors.New("没有上一份运行配置")
		if len(old) > 0 {
			rollbackErr = atomicWrite(path, old)
			if rollbackErr == nil {
				rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 30*time.Second)
				rollbackErr = m.core.RPC.Text(rollbackCtx, "setupConfig", map[string]any{"selected-map": m.settings.Selected, "test-url": m.settings.HealthURL})
				if rollbackErr == nil && startListeners {
					rollbackErr = m.core.RPC.Call(rollbackCtx, "startListener", nil, nil)
				}
				if rollbackErr == nil && m.active {
					rollbackErr = m.net.ConfirmTun()
				}
				rollbackCancel()
			}
		}
		if rollbackErr != nil {
			m.degrade("配置回滚失败: " + rollbackErr.Error())
		} else {
			m.configured = true
		}
		return fmt.Errorf("配置应用失败，保留原档案: %s", redact(err.Error()))
	}
	m.active = enabled
	m.configured = true
	if !m.settings.Enabled {
		m.blocked = ""
	}
	return nil
}

func (m *Manager) degrade(reason string) {
	if m.settings.Enabled {
		m.degraded = redact(reason)
		m.logs.Add("直连降级: " + reason)
	} else {
		m.blocked = redact(reason)
		m.logs.Add("配置不可用: " + reason)
	}
	m.active = false
	m.configured = false
	m.revision++
	if m.core != nil {
		if err := m.core.Stop(); err != nil {
			m.degraded += "；" + redact(err.Error())
			return
		}
		m.core = nil
	}
	if err := m.net.RestoreTun(); err != nil {
		m.degraded += "；网络清理未完成: " + redact(err.Error())
	}
}

func (m *Manager) enable() error {
	p := m.profile(m.settings.Active)
	if p == nil {
		return errors.New("请先导入并选择配置档案")
	}
	if !m.settings.NetworkConfirmed {
		return fail("network_confirmation_required", "请先确认网络模式及 IPv6 覆盖范围")
	}
	if report := m.net.Detect(); !report.Ready {
		m.checked = false
		return fail("network_not_ready", "所选网络模式的前置条件未满足，请查看网络检测结果")
	}
	m.checked = true
	if m.settings.Mode != "direct" && m.healthGroup() == "" {
		return fail("health_group_required", "请选择主要策略组")
	}
	if err := m.ensureCore(); err != nil {
		return err
	}
	if !m.active {
		if err := m.apply(p.YAML, false); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var groups struct {
		All []string `json:"all"`
	}
	err := m.core.RPC.Call(ctx, "getProxies", nil, &groups)
	cancel()
	if err != nil {
		return err
	}
	validGroup := false
	for _, name := range groups.All {
		if name == m.healthGroup() {
			validGroup = true
			break
		}
	}
	if !validGroup && m.settings.Mode != "direct" {
		return errors.New("故障检测策略组不在当前配置中，请重新选择")
	}
	if err := m.net.ClaimTun(); err != nil {
		return err
	}
	if err := m.net.Gateway(m.settings.GatewayCIDRs); err != nil {
		m.degrade(err.Error())
		return err
	}
	if err := m.apply(p.YAML, true); err != nil {
		m.degrade(err.Error())
		return err
	}
	m.degraded = ""
	m.blocked = ""
	m.failures = 0
	m.successes = 0
	return nil
}

func (m *Manager) disable() error {
	m.active = false
	m.configured = false
	m.revision++
	if m.core != nil {
		if err := m.core.Stop(); err != nil {
			return err
		}
		m.core = nil
	}
	if err := m.net.RestoreTun(); err != nil {
		return err
	}
	if p := m.profile(m.settings.Active); p != nil {
		return m.apply(p.YAML, false)
	}
	return nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closing = true
	m.operation = "shutdown"
	m.publish()
	if m.core != nil {
		if err := m.core.Stop(); err != nil {
			return err
		}
		m.core = nil
	}
	return m.net.RestoreAll()
}

func (m *Manager) Run(ctx context.Context) {
	m.mu.Lock()
	m.operation = "startup"
	m.publish()
	if m.settings.GatewayEnabled && !m.settings.Enabled {
		if report := m.net.Detect(); report.Ready {
			if err := m.net.Gateway(m.settings.GatewayCIDRs); err != nil {
				m.degraded = "普通转发恢复失败: " + redact(err.Error())
			}
		} else {
			m.blocked = "普通转发未恢复：所选地址族的出口检测未通过"
		}
	}
	if m.settings.Enabled {
		_ = m.setEnabled(true)
	} else if p := m.profile(m.settings.Active); p != nil {
		if err := m.apply(p.YAML, false); err != nil {
			m.blocked = redact(err.Error())
		}
	}
	m.operation = ""
	m.publish()
	m.mu.Unlock()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	healthAt := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if !m.mu.TryLock() {
				continue
			}
			if m.closing {
				m.mu.Unlock()
				return
			}
			if m.active && !m.core.Alive() {
				m.degrade("核心退出或 IPC 断开，已撤销透明代理")
			}
			if time.Since(healthAt) >= 20*time.Second {
				m.operation = "health"
				m.publish()
				m.health()
				healthAt = time.Now()
				m.updateDue()
				m.operation = ""
			}
			m.sampleTraffic()
			m.publish()
			m.mu.Unlock()
		}
	}
}

func (m *Manager) health() {
	if !m.settings.Enabled {
		return
	}
	if m.settings.Mode == "direct" {
		if !m.active {
			m.net.Detect()
			m.checked = true
			if err := m.enable(); err != nil {
				m.degrade(err.Error())
			}
		}
		return
	}
	if !m.core.Alive() {
		p := m.profile(m.settings.Active)
		if p == nil {
			return
		}
		if err := m.apply(p.YAML, false); err != nil {
			m.logs.Add("恢复检测核心失败: " + err.Error())
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var result struct {
		Value int `json:"value"`
	}
	err := m.core.RPC.Call(ctx, "asyncTestDelay", map[string]any{"proxy-name": m.healthGroup(), "test-url": m.settings.HealthURL, "timeout": 5000}, &result)
	if err != nil || result.Value < 0 {
		m.failures++
		m.successes = 0
		if m.failures >= 3 && m.active {
			m.degrade("检测策略组连续三次不可用；保留普通转发，等待节点恢复")
		}
		return
	}
	m.failures = 0
	m.successes++
	if !m.active && m.successes >= 2 {
		m.net.Detect()
		m.checked = true
		if err = m.enable(); err != nil {
			m.degrade(err.Error())
		}
	}
}

func fetchSubscription(raw string) (string, error) {
	if err := validURL(raw); err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("订阅重定向次数过多")
		}
		if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("拒绝订阅降级到明文 HTTP")
		}
		return validURL(req.URL.String())
	}}
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return "", errors.New("订阅地址无效")
	}
	req.Header.Set("User-Agent", "FlClash/fnOS")
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("订阅下载失败，请检查网络和地址")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("订阅服务器返回 HTTP %d", resp.StatusCode)
	}
	b, err := readLimited(resp.Body)
	return string(b), err
}

func (m *Manager) updateProfile(id string) error {
	p := m.profile(id)
	if p == nil || p.URL == "" {
		return errors.New("该档案没有订阅地址")
	}
	p.LastAttempt = time.Now()
	raw, err := fetchSubscription(p.URL)
	if err == nil {
		_, err = prepareConfig(raw, m.settings, m.home, false, nil)
	}
	if err == nil && m.settings.Active == id {
		err = m.apply(raw, m.active)
	}
	if err != nil {
		p.Error = redact(err.Error())
		_ = m.persist()
		return err
	}
	old := *p
	p.YAML = raw
	p.Updated = time.Now()
	p.Error = ""
	if err = m.persist(); err != nil {
		*p = old
		if m.settings.Active == id {
			_ = m.apply(old.YAML, m.active)
		}
		return err
	}
	return nil
}

func (m *Manager) updateDue() {
	for _, p := range m.settings.Profiles {
		if p.Interval > 0 && p.URL != "" && time.Since(p.LastAttempt) >= time.Duration(p.Interval)*time.Hour {
			m.operation = "profiles/update"
			m.publish()
			if err := m.updateProfile(p.ID); err != nil {
				m.logs.Add("定时订阅更新失败: " + err.Error())
			}
			return
		}
	}
}

func (m *Manager) status() map[string]any {
	profiles := make([]Profile, 0, len(m.settings.Profiles))
	for _, p := range m.settings.Profiles {
		p.YAML = ""
		if p.URL != "" {
			p.URL = "已保存订阅地址"
		}
		profiles = append(profiles, p)
	}
	s := m.settings
	s.Profiles = profiles
	return map[string]any{"version": "0.2.1", "settings": s, "coreRunning": m.core.Alive(), "coreReady": m.core.Alive() && m.configured, "revision": m.revision, "session": m.session, "operation": m.operation, "updatedAt": time.Now(), "blocked": m.blocked, "network": m.net.report, "proxyActive": m.active && m.core.Alive(), "degraded": m.degraded, "networkRecoveryPending": m.net.j.Tun && (!m.active || !m.core.Alive()), "traffic": m.traffic, "trafficAt": m.trafficAt, "gatewayForwarding": m.net.j.Gateway, "acceptance": "网络覆盖按实际测试结果确认"}
}

func (m *Manager) publish() {
	data, err := json.Marshal(m.status())
	if err == nil {
		raw := json.RawMessage(data)
		m.snapshot.Store(&raw)
	}
}

func (m *Manager) healthGroup() string {
	if m.settings.Mode == "global" {
		return "GLOBAL"
	}
	return m.settings.HealthGroup
}

func (m *Manager) sampleTraffic() {
	if !m.core.Alive() || !m.configured {
		m.traffic = nil
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var traffic json.RawMessage
	if err := m.core.RPC.Call(ctx, "getTraffic", false, &traffic); err == nil {
		m.traffic, m.trafficAt = traffic, time.Now()
	}
}
