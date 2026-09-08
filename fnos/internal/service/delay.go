package service

import (
	"context"
	"encoding/json"
	"time"
)

func (m *Manager) testDelay(parent context.Context, r apiRequest) (any, error) {
	select {
	case m.delaySlots <- struct{}{}:
		defer func() { <-m.delaySlots }()
	default:
		return nil, fail("operation_busy", "同时最多检测两个节点，请稍后重试")
	}
	if !m.mu.TryRLock() {
		return nil, fail("operation_busy", "核心正在应用配置，请稍后重试")
	}
	c, revision, session, address := m.core, m.revision, m.session, m.settings.HealthURL
	ready := !m.closing && m.configured && c.Alive()
	m.mu.RUnlock()
	if !ready {
		return nil, fail("core_not_ready", "核心配置尚未就绪")
	}
	if (r.Revision != nil && *r.Revision != revision) || (r.Session != "" && r.Session != session) {
		return nil, fail("stale_session", "配置已变化，请刷新节点后重试")
	}
	if len(r.Proxy) == 0 || len(r.Proxy) > 256 {
		return nil, fail("invalid_proxy", "节点名称无效")
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	var result struct {
		Value int `json:"value"`
	}
	err := c.RPC.Call(ctx, "asyncTestDelay", map[string]any{"proxy-name": r.Proxy, "test-url": address, "timeout": 5000}, &result)
	if err != nil {
		return nil, fail("delay_failed", "延迟检测失败，请检查节点或稍后重试")
	}
	var latest struct {
		Revision uint64 `json:"revision"`
		Session  string `json:"session"`
	}
	if raw := m.snapshot.Load(); raw == nil || json.Unmarshal(*raw, &latest) != nil || latest.Revision != revision || latest.Session != session || !c.Alive() {
		return nil, fail("stale_session", "检测期间配置已变化，结果已丢弃")
	}
	return map[string]any{"value": result.Value, "revision": revision, "session": session, "at": time.Now()}, nil
}
