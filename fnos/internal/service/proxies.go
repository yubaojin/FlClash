package service

import (
	"context"
	"slices"
)

type proxyGroup struct {
	Type string   `json:"type"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
}

func (m *Manager) changeSelection(ctx context.Context, r apiRequest) error {
	if len(r.Group) == 0 || len(r.Proxy) == 0 || len(r.Group) > 256 || len(r.Proxy) > 256 {
		return fail("invalid_proxy", "策略组或节点名称无效")
	}
	var data struct {
		Proxies map[string]proxyGroup `json:"proxies"`
	}
	if err := m.core.RPC.Call(ctx, "getProxies", nil, &data); err != nil {
		return err
	}
	group, exists := data.Proxies[r.Group]
	if !exists || group.Type != "Selector" || !slices.Contains(group.All, r.Proxy) {
		return fail("invalid_selection", "只能选择手动策略组中的现有节点，请刷新节点列表")
	}
	if err := m.core.RPC.Text(ctx, "changeProxy", map[string]any{"group-name": r.Group, "proxy-name": r.Proxy}); err != nil {
		return err
	}
	if m.settings.Selected == nil {
		m.settings.Selected = map[string]string{}
	}
	old, had := m.settings.Selected[r.Group]
	m.settings.Selected[r.Group] = r.Proxy
	if err := m.persist(); err != nil {
		if had {
			m.settings.Selected[r.Group] = old
		} else {
			delete(m.settings.Selected, r.Group)
		}
		if rollback := m.core.RPC.Text(ctx, "changeProxy", map[string]any{"group-name": r.Group, "proxy-name": group.Now}); rollback != nil {
			m.degrade("节点选择保存失败且无法恢复原选择: " + rollback.Error())
		}
		return err
	}
	return nil
}
