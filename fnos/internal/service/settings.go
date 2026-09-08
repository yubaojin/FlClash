package service

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"time"
)

type apiFailure struct{ code, message string }

func (e *apiFailure) Error() string   { return e.message }
func fail(code, message string) error { return &apiFailure{code, message} }
func errorCode(err error, path string) string {
	var failure *apiFailure
	if errors.As(err, &failure) {
		return failure.code
	}
	if strings.HasPrefix(path, "profiles") {
		return "profile_failed"
	}
	if strings.HasPrefix(path, "network") {
		return "network_failed"
	}
	return "operation_failed"
}

func validateModeCIDRs(mode string, cidrs []string) error {
	if mode != "ipv4" {
		return nil
	}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil || p.Addr().Is6() {
			return fail("ipv6_gateway_conflict", "仅 IPv4 模式不能登记 IPv6 网段，请先处理已有网关客户端")
		}
	}
	return nil
}

func (m *Manager) saveSettings(r apiRequest) error {
	old := m.settings
	next := old
	if r.Mode != nil {
		next.Mode = *r.Mode
	}
	if r.HealthGroup != nil {
		next.HealthGroup = *r.HealthGroup
	}
	if r.HealthURL != nil {
		next.HealthURL = *r.HealthURL
	}
	if r.GatewayCIDRs != nil {
		next.GatewayCIDRs = append([]string{}, (*r.GatewayCIDRs)...)
	}
	if r.NetworkMode != nil {
		next.NetworkMode = *r.NetworkMode
	}
	if r.NetworkConfirmed != nil {
		next.NetworkConfirmed = *r.NetworkConfirmed
	}
	if next.NetworkMode == "" {
		next.NetworkMode = "dual"
	}
	if next.Mode != "rule" && next.Mode != "global" && next.Mode != "direct" {
		return fail("invalid_mode", "模式必须为规则、全局或直连")
	}
	if next.NetworkMode != "dual" && next.NetworkMode != "ipv4" {
		return fail("invalid_network_mode", "网络模式必须为仅 IPv4 或双栈")
	}
	if len(next.HealthGroup) > 256 {
		return fail("invalid_group", "策略组名称过长")
	}
	if err := validURL(next.HealthURL); err != nil {
		return err
	}
	if err := validateCIDRs(next.GatewayCIDRs); err != nil {
		return err
	}
	if err := validateModeCIDRs(next.NetworkMode, next.GatewayCIDRs); err != nil {
		return err
	}
	changedMode := next.NetworkMode != old.NetworkMode && !(old.NetworkMode == "" && next.NetworkMode == "dual")
	if changedMode && (m.active || m.settings.Enabled || m.net.j.Tun || m.net.j.Gateway) {
		return fail("network_mode_in_use", "请先关闭代理；有保留转发时，恢复客户端原网关并执行网络恢复后再切换网络模式")
	}
	if changedMode && (r.NetworkConfirmed == nil || !*r.NetworkConfirmed) {
		return fail("network_confirmation_required", "请明确确认网络模式及 IPv6 覆盖范围")
	}
	if !reflect.DeepEqual(old.GatewayCIDRs, next.GatewayCIDRs) && m.net.j.Gateway {
		return fail("gateway_in_use", "请先恢复客户端原网关并执行网络恢复，再修改网段")
	}
	m.settings = next
	m.net.mode = next.NetworkMode
	applyChanged := old.Mode != next.Mode || changedMode || old.HealthURL != next.HealthURL
	if p := m.profile(next.Active); p != nil && applyChanged {
		if err := m.apply(p.YAML, m.active); err != nil {
			m.settings = old
			m.net.mode = old.NetworkMode
			return err
		}
	}
	if err := m.persist(); err != nil {
		m.settings = old
		m.net.mode = old.NetworkMode
		if p := m.profile(old.Active); p != nil && applyChanged {
			_ = m.apply(p.YAML, m.active)
		}
		return err
	}
	if changedMode {
		m.checked = false
		m.blocked = ""
		m.net.report = NetworkReport{Mode: next.NetworkMode}
	}
	return nil
}

func (m *Manager) editProfile(r apiRequest) error {
	p := m.profile(r.ID)
	if p == nil {
		return fail("profile_not_found", "配置不存在")
	}
	if strings.TrimSpace(r.Name) == "" || len(r.Name) > 128 || r.Interval < 0 || r.Interval > 720 {
		return fail("invalid_profile", "名称不能为空，更新间隔须为 0—720 小时")
	}
	old, next := *p, *p
	next.Name, next.Interval = r.Name, r.Interval
	if next.URL == "" && r.URL == "" {
		next.Interval = 0
	}
	if r.URL != "" && r.URL != old.URL {
		raw, err := fetchSubscription(r.URL)
		if err != nil {
			return err
		}
		if _, err = prepareConfig(raw, m.settings, m.home, false, nil); err != nil {
			return err
		}
		if m.settings.Active == p.ID {
			if err = m.apply(raw, m.active); err != nil {
				return err
			}
		}
		next.URL, next.YAML, next.Error = r.URL, raw, ""
		next.Updated, next.LastAttempt = time.Now(), time.Now()
	}
	*p = next
	if err := m.persist(); err != nil {
		*p = old
		if m.settings.Active == p.ID && old.YAML != next.YAML {
			_ = m.apply(old.YAML, m.active)
		}
		return err
	}
	return nil
}

func (m *Manager) setEnabled(enabled bool) error {
	if enabled && m.active {
		return nil
	}
	if !enabled {
		old := m.settings.Enabled
		m.settings.Enabled = false
		if err := m.persist(); err != nil {
			m.settings.Enabled = old
			return err
		}
		m.degraded, m.blocked = "", ""
		return m.disable()
	}
	oldGateway := m.settings.GatewayEnabled
	if err := m.enable(); err != nil {
		m.settings.Enabled = false
		m.blocked = redact(err.Error())
		m.degraded = ""
		var cleanup error
		if m.net.j.Tun {
			cleanup = m.disable()
		}
		if !oldGateway && m.net.j.Gateway {
			cleanup = errors.Join(cleanup, m.net.RestoreAll())
		}
		return errors.Join(err, cleanup, m.persist())
	}
	m.settings.Enabled = true
	m.settings.GatewayEnabled = oldGateway || len(m.settings.GatewayCIDRs) > 0
	if err := m.persist(); err != nil {
		m.settings.Enabled, m.settings.GatewayEnabled = false, oldGateway
		cleanup := m.disable()
		if !oldGateway {
			cleanup = errors.Join(cleanup, m.net.RestoreAll())
		}
		return errors.Join(err, cleanup)
	}
	m.blocked = ""
	return nil
}
