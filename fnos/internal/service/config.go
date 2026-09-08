package service

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const tunDevice = "flclash0"
const tunTable = "flclash_tun"
const routeTable = 31001
const ruleStart = 31000
const fallbackRule = 41050

var privateRanges = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}

func prepareConfig(raw string, s Settings, home string, enabled bool, lan []string) ([]byte, error) {
	var source map[string]any
	if len(raw) == 0 || len(raw) > 8<<20 {
		return nil, errors.New("配置为空或超过 8 MiB")
	}
	if err := yaml.Unmarshal([]byte(raw), &source); err != nil {
		return nil, errors.New("YAML 格式错误: " + redact(err.Error()))
	}
	if source == nil {
		return nil, errors.New("配置必须是 YAML 对象")
	}
	config := map[string]any{}
	for _, key := range []string{"proxies", "proxy-groups", "proxy-providers", "rule-providers", "rules", "sub-rules", "hosts", "sniffer"} {
		if v, ok := source[key]; ok {
			config[key] = v
		}
	}
	if config["proxies"] == nil && config["proxy-providers"] == nil {
		return nil, errors.New("配置中没有 proxies 或 proxy-providers")
	}
	for _, section := range []string{"proxy-providers", "rule-providers"} {
		if rawProviders, exists := config[section]; exists {
			providers, ok := rawProviders.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s 必须是对象", section)
			}
			for name, value := range providers {
				p, ok := value.(map[string]any)
				if !ok {
					return nil, errors.New("集合配置必须是对象")
				}
				kind, _ := p["type"].(string)
				if kind != "http" && kind != "inline" {
					return nil, errors.New("第一版仅支持 HTTP 或内联集合；本地文件集合请先合并到配置")
				}
				if kind == "http" {
					u, _ := p["url"].(string)
					if err := validURL(u); err != nil {
						return nil, err
					}
				}
				p["path"] = filepath.ToSlash(filepath.Join(home, "providers", providerKey(section+name)+".yaml"))
			}
		}
	}
	if err := rejectPaths(config); err != nil {
		return nil, err
	}
	config["mode"] = s.Mode
	dual := s.NetworkMode != "ipv4"
	config["ipv6"] = dual
	config["log-level"] = "info"
	config["allow-lan"] = false
	config["bind-address"] = "127.0.0.1"
	config["mixed-port"] = 0
	config["external-controller"] = ""
	config["external-controller-unix"] = ""
	config["profile"] = map[string]any{"store-selected": false, "store-fake-ip": false}
	config["geodata-mode"] = false
	config["geo-auto-update"] = false
	config["dns"] = map[string]any{
		"enable": true, "listen": "", "ipv6": dual, "enhanced-mode": "redir-host",
		"use-hosts": true, "use-system-hosts": true,
		"default-nameserver": []string{"system"}, "nameserver": []string{"system"},
		"proxy-server-nameserver": []string{"system"}, "direct-nameserver": []string{"system"},
	}
	excluded := append(append([]string{}, privateRanges...), lan...)
	config["tun"] = map[string]any{
		"enable": enabled, "device": tunDevice, "stack": "mixed", "mtu": 1500,
		"auto-route": true, "auto-redirect": true, "auto-detect-interface": true,
		"strict-route": false, "inet4-address": []string{"198.18.0.1/30"},
		"inet6-address":        []string{"fdfe:dcba:9876::1/126"},
		"iproute2-table-index": routeTable, "iproute2-rule-index": ruleStart,
		"auto-redirect-iproute2-fallback-rule-index": fallbackRule,
		"auto-redirect-input-mark":                   0x3f01, "auto-redirect-output-mark": 0x3f02,
		"route-exclude-address": excluded,
		"dns-hijack":            []string{"any:53", "tcp://any:53", "[::]:53", "tcp://[::]:53"},
	}
	if !dual {
		tun := config["tun"].(map[string]any)
		tun["inet6-address"] = []string{}
		tun["dns-hijack"] = []string{"any:53", "tcp://any:53"}
		var only4 []string
		for _, value := range excluded {
			if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is4() {
				only4 = append(only4, value)
			}
		}
		tun["route-exclude-address"] = only4
	}
	return yaml.Marshal(config)
}

func rejectPaths(v any) error {
	switch value := v.(type) {
	case map[string]any:
		if value["type"] == "ssh" {
			if key, ok := value["private-key"].(string); ok && key != "" && !strings.Contains(key, "PRIVATE KEY") {
				return errors.New("SSH 私钥必须内联，不能引用本地文件")
			}
		}
		for key, child := range value {
			if key == "private-key-path" || key == "certificate-path" || key == "ca" || key == "ca-str" {
				return fmt.Errorf("第一版不接受文件凭据字段 %s", key)
			}
			if err := rejectPaths(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := rejectPaths(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func rollbackConfig(raw []byte, active bool) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	var config map[string]any
	if err := yaml.Unmarshal(raw, &config); err != nil {
		return nil, err
	}
	tun, ok := config["tun"].(map[string]any)
	if !ok {
		return nil, errors.New("旧运行配置缺少受控 TUN 参数")
	}
	tun["enable"] = active
	return yaml.Marshal(config)
}

func validateCIDRs(cidrs []string) error {
	if len(cidrs) > 32 {
		return errors.New("最多登记 32 个网关客户端网段")
	}
	for _, value := range cidrs {
		p, err := netip.ParsePrefix(value)
		allowed := false
		if err == nil {
			for _, space := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
				rangePrefix := netip.MustParsePrefix(space)
				if p.Bits() >= rangePrefix.Bits() && rangePrefix.Contains(p.Masked().Addr()) {
					allowed = true
				}
			}
		}
		if !allowed || (p.Addr().Is6() && p.Bits() < 48) {
			return errors.New("网关客户端必须填写明确的私有 IPv4/IPv6 网段，禁止默认路由网段")
		}
		if strings.ContainsAny(value, "\n\r\";") {
			return errors.New("网段格式无效")
		}
	}
	return nil
}
