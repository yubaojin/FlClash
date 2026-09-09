package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type readRunner func(context.Context, string, ...string) ([]byte, error)

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedBuffer) Len() int      { return b.buffer.Len() }
func (b *boundedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedBuffer) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(struct{ io.Writer }{b}, r)
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("读取内容超过大小限制")
	}
	return b.buffer.Write(p)
}

func readCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	setChildAttributes(cmd, 0, 0)
	cmd.WaitDelay = time.Second
	output := &boundedBuffer{limit: 4 << 20}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type NetworkTarget struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Mode       string   `json:"mode"`
	Running    bool     `json:"running"`
	CanProbe   bool     `json:"canProbe"`
	Code       string   `json:"code"`
	Detail     string   `json:"detail"`
	SourceID   string   `json:"sourceID"`
	SourceName string   `json:"sourceName"`
	Addresses  []string `json:"addresses"`
	Networks   []string `json:"networks"`
	DNS        []string `json:"dns"`
	Ambiguous  bool     `json:"ambiguous"`
	PID        int      `json:"-"`
	StartedAt  string   `json:"-"`
	ResolvPath string   `json:"-"`
	HostsPath  string   `json:"-"`
	Namespace  string   `json:"-"`
}

type TargetReport struct {
	Items     []NetworkTarget `json:"items"`
	At        time.Time       `json:"at"`
	Code      string          `json:"code,omitempty"`
	Detail    string          `json:"detail,omitempty"`
	Truncated bool            `json:"truncated"`
}

type containerInfo struct {
	ID         string
	Name       string
	Running    bool
	PID        int
	StartedAt  string
	Mode       string
	ResolvPath string
	HostsPath  string
	Networks   map[string]struct{ NetworkID, IPAddress, GlobalIPv6Address string }
}

const containerFormat = `{"ID":{{json .Id}},"Name":{{json .Name}},"Running":{{json .State.Running}},"PID":{{json .State.Pid}},"StartedAt":{{json .State.StartedAt}},"Mode":{{json .HostConfig.NetworkMode}},"ResolvPath":{{json .ResolvConfPath}},"HostsPath":{{json .HostsPath}},"Networks":{{json .NetworkSettings.Networks}}}`

func inspectContainer(ctx context.Context, run readRunner, id string) (containerInfo, error) {
	var c containerInfo
	if !validContainerID(id) {
		return c, errors.New("容器标识无效")
	}
	b, err := run(ctx, "docker", "container", "inspect", "--format", containerFormat, id)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	if err == nil && c.ID != id {
		err = errors.New("容器身份已变化")
	}
	return c, err
}

func validContainerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func readSmallFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if len(b) > 64<<10 {
		return nil, errors.New("网络配置文件过大")
	}
	return b, err
}

func parseNameservers(raw []byte) []string {
	var result []string
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip, err := netip.ParseAddr(fields[1]); err == nil {
				result = append(result, ip.String())
			}
		}
		if len(result) == 3 {
			break
		}
	}
	return result
}

func nasTarget() NetworkTarget {
	t := NetworkTarget{ID: "nas", Name: "NAS／共享宿主网络", Kind: "nas", Mode: "host", Running: true, CanProbe: true, Code: "ready", Detail: "检测 NAS 网络路径；host 容器共享这条路径", SourceID: "nas", SourceName: "NAS／共享宿主网络", Addresses: []string{}, Networks: []string{}, ResolvPath: "/etc/resolv.conf", HostsPath: "/etc/hosts"}
	if addresses, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addresses {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				t.Addresses = append(t.Addresses, p.Addr().String())
			}
		}
	}
	if b, err := readSmallFile(t.ResolvPath); err == nil {
		t.DNS = parseNameservers(b)
	}
	return t
}

func discoverTargets(ctx context.Context, run readRunner) TargetReport {
	r := TargetReport{Items: []NetworkTarget{nasTarget()}, At: time.Now()}
	b, err := run(ctx, "docker", "container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}")
	if err != nil {
		r.Code, r.Detail = "docker_unavailable", "Docker 未启动或当前不可读取；仍可检测 NAS"
		return r
	}
	ids := strings.Fields(string(b))
	if len(ids) > 256 {
		ids, r.Truncated = ids[:256], true
	}
	drivers := map[string]string{}
	if networks, err := run(ctx, "docker", "network", "ls", "--no-trunc", "--format", "{{.ID}} {{.Driver}}"); err == nil {
		for _, line := range strings.Split(string(networks), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 {
				drivers[f[0]] = f[1]
			}
		}
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			r.Truncated = true
			break
		}
		c, err := inspectContainer(ctx, run, id)
		if err != nil {
			r.Code, r.Detail = "inventory_partial", "部分容器信息读取失败，请刷新列表"
			continue
		}
		t := NetworkTarget{ID: c.ID, Name: safeLabel(strings.TrimPrefix(c.Name, "/"), 128), Kind: "container", Mode: c.Mode, Running: c.Running, SourceID: c.ID, Addresses: []string{}, Networks: []string{}, PID: c.PID, StartedAt: c.StartedAt, ResolvPath: c.ResolvPath, HostsPath: c.HostsPath}
		t.SourceName = t.Name
		allowed := len(c.Networks) > 0
		var unsupported []string
		for name, network := range c.Networks {
			driver := drivers[network.NetworkID]
			t.Networks = append(t.Networks, safeLabel(name, 128)+" ("+driver+")")
			if driver != "bridge" {
				allowed = false
				unsupported = append(unsupported, driver)
			}
			for _, ip := range []string{network.IPAddress, network.GlobalIPv6Address} {
				if p, err := netip.ParseAddr(ip); err == nil {
					t.Addresses = append(t.Addresses, p.String())
				}
			}
		}
		sort.Strings(t.Networks)
		sort.Strings(t.Addresses)
		t.Ambiguous = len(c.Networks) > 1
		if c.Mode == "host" {
			allowed = true
			t.SourceID, t.SourceName = "nas", "NAS／共享宿主网络"
		}
		switch {
		case !c.Running:
			t.Code, t.Detail = "stopped", "容器未运行，启动后可检测"
		case c.Mode == "none":
			t.Code, t.Detail = "isolated", "无外部网络；请在 Docker 中确认所需网络模式"
		case !allowed && !strings.HasPrefix(c.Mode, "container:"):
			t.Code, t.Detail = "network_unsupported", "当前网络无法自动验证；请查看接入指引"
			if len(unsupported) > 0 {
				sort.Strings(unsupported)
				t.Detail = "网络类型 " + strings.Join(unsupported, " / ") + " 无法保证经 NAS 路由；请调整为受支持的 bridge 网络后重新验证"
			}
		default:
			t.Namespace, err = namespaceIdentity(c.PID)
			if err != nil {
				t.Code, t.Detail = "namespace_unavailable", "无法读取容器网络环境，请刷新后重试"
			} else {
				t.CanProbe, t.Code, t.Detail = true, "ready", "验证对象实际 DNS 与 HTTPS 路径；不修改容器网络"
				if _, err := exec.LookPath("nsenter"); err != nil {
					t.CanProbe, t.Code, t.Detail = false, "probe_unavailable", "系统缺少 nsenter，无法自动检测；可在容器内手动验证"
				}
			}
		}
		if b, err := readSmallFile(c.ResolvPath); err == nil {
			t.DNS = parseNameservers(b)
		}
		r.Items = append(r.Items, t)
	}
	byID := map[string]int{}
	for i := range r.Items {
		byID[r.Items[i].ID] = i
	}
	for i := range r.Items {
		t := &r.Items[i]
		if !strings.HasPrefix(t.Mode, "container:") {
			continue
		}
		reference := strings.TrimPrefix(t.Mode, "container:")
		parent, ok := byID[reference]
		if !ok {
			matches := 0
			for index, candidate := range r.Items {
				if candidate.Kind == "container" && (candidate.Name == reference || len(reference) >= 12 && strings.HasPrefix(candidate.ID, reference)) {
					parent, matches = index, matches+1
				}
			}
			ok = matches == 1
		}
		if !ok {
			t.CanProbe, t.Code, t.Detail = false, "shared_network_unknown", "共享网络的所属容器未找到，请刷新后检查 Docker 网络"
			continue
		}
		p := r.Items[parent]
		t.Addresses, t.Networks, t.Ambiguous = p.Addresses, p.Networks, p.Ambiguous
		if p.SourceID == "nas" {
			t.SourceID, t.SourceName = p.SourceID, p.SourceName
		}
		if !p.CanProbe {
			t.CanProbe, t.Code, t.Detail = false, p.Code, p.Detail
		}
	}
	groups := map[string][]int{}
	for i, t := range r.Items {
		if t.Namespace != "" && t.SourceID != "nas" {
			groups[t.Namespace] = append(groups[t.Namespace], i)
		}
	}
	for ns, indexes := range groups {
		if len(indexes) < 2 {
			continue
		}
		var names []string
		for _, i := range indexes {
			names = append(names, r.Items[i].Name)
		}
		sort.Strings(names)
		for _, i := range indexes {
			r.Items[i].SourceID, r.Items[i].SourceName = "shared-"+providerKey(ns), "共享网络："+strings.Join(names, "、")
		}
	}
	return r
}

func (o *Observability) targetList(ctx context.Context, force bool) TargetReport {
	o.targetMu.Lock()
	if o.targetsLoading {
		done := o.targetsDone
		o.targetMu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
		}
		o.targetMu.Lock()
		r := o.targets
		o.targetMu.Unlock()
		return r
	}
	if !force && time.Since(o.targets.At) < 15*time.Second {
		r := o.targets
		o.targetMu.Unlock()
		return r
	}
	o.targetsLoading = true
	o.targetsDone = make(chan struct{})
	o.targetMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	r := discoverTargets(ctx, o.runner)
	o.targetMu.Lock()
	o.targets, o.targetsLoading = r, false
	close(o.targetsDone)
	o.targetMu.Unlock()
	return r
}
