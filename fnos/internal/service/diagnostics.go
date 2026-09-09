package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ProbeStep struct {
	ID         string      `json:"id"`
	Family     string      `json:"family"`
	Title      string      `json:"title"`
	State      string      `json:"state"`
	Code       string      `json:"code"`
	Detail     string      `json:"detail"`
	Error      string      `json:"error,omitempty"`
	Next       string      `json:"next,omitempty"`
	At         time.Time   `json:"at"`
	HTTPStatus int         `json:"httpStatus,omitempty"`
	Flows      []ProbeFlow `json:"-"`
}

type ProbeFlow struct {
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Network     string    `json:"network"`
	At          time.Time `json:"at"`
}

type PathEvidence struct {
	Family       string   `json:"family"`
	Path         string   `json:"path"`
	Exit         string   `json:"exit"`
	Rule         string   `json:"rule"`
	Chains       []string `json:"chains"`
	ConnectionID string   `json:"connectionID"`
}

type Diagnostic struct {
	ID          string         `json:"id"`
	TargetID    string         `json:"targetID"`
	TargetName  string         `json:"targetName"`
	Destination string         `json:"destination"`
	Preset      string         `json:"preset"`
	NetworkMode string         `json:"networkMode"`
	State       string         `json:"state"`
	Stage       string         `json:"stage"`
	Started     time.Time      `json:"started"`
	Finished    time.Time      `json:"finished,omitempty"`
	Stale       bool           `json:"stale"`
	Steps       []ProbeStep    `json:"steps"`
	Paths       []PathEvidence `json:"paths"`
	Code        string         `json:"code"`
	Summary     string         `json:"summary"`
	contextID   string
	coreID      string
	cancel      context.CancelFunc
	done        chan struct{}
}

type probeRunner func(context.Context, NetworkTarget, string, string, func(ProbeStep)) error

func cloneDiagnostic(task *Diagnostic) Diagnostic {
	r := *task
	r.Steps = append([]ProbeStep{}, task.Steps...)
	r.Paths = append([]PathEvidence{}, task.Paths...)
	return r
}

func (o *Observability) diagnosticResult(id string) (any, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if id != "" {
		for _, task := range o.tasks {
			if task.ID == id {
				return cloneDiagnostic(task), nil
			}
		}
		return nil, fail("diagnostic_missing", "检测记录不存在或服务已重启，请重新检测")
	}
	items := make([]Diagnostic, 0, len(o.tasks))
	for i := len(o.tasks) - 1; i >= 0; i-- {
		items = append(items, cloneDiagnostic(o.tasks[i]))
	}
	return map[string]any{"items": items}, nil
}

func (m *Manager) startDiagnostic(targetID, preset string) (Diagnostic, error) {
	if targetID != "nas" && !validContainerID(targetID) {
		return Diagnostic{}, fail("invalid_target", "请选择现有 NAS 或容器")
	}
	if preset != "health" && preset != "docker" {
		return Diagnostic{}, fail("invalid_probe", "请选择故障检测地址或 Docker 仓库")
	}
	if !m.mu.TryLock() {
		return Diagnostic{}, fail("operation_busy", "后台正在调整配置，请稍后开始检测")
	}
	defer m.mu.Unlock()
	if m.closing {
		return Diagnostic{}, fail("service_closing", "应用正在停用")
	}
	o := m.observe()
	m.syncObservation()
	raw := m.settings.HealthURL
	if preset == "docker" {
		raw = "https://registry-1.docker.io/v2/"
	}
	if err := validURL(raw); err != nil {
		return Diagnostic{}, err
	}
	u, _ := url.Parse(raw)
	o.mu.Lock()
	if o.running != nil {
		o.mu.Unlock()
		return Diagnostic{}, fail("diagnostic_busy", "已有检测正在进行，可等待完成或取消")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	task := &Diagnostic{ID: randomID(), TargetID: targetID, TargetName: "正在识别对象", Destination: u.Hostname(), Preset: preset, NetworkMode: m.settings.NetworkMode, State: "running", Stage: "识别网络环境", Started: time.Now(), Steps: []ProbeStep{}, Paths: []PathEvidence{}, contextID: o.contextID, coreID: o.coreID, cancel: cancel, done: make(chan struct{})}
	o.tasks = append(o.tasks, task)
	if len(o.tasks) > 20 {
		o.tasks = o.tasks[len(o.tasks)-20:]
	}
	o.running = task
	result := cloneDiagnostic(task)
	o.mu.Unlock()
	go m.runDiagnostic(ctx, task, raw)
	return result, nil
}

func (o *Observability) cancelDiagnostic(id string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.running == nil || o.running.ID != id {
		return fail("diagnostic_missing", "该检测已结束或不存在")
	}
	o.running.cancel()
	return nil
}

func (m *Manager) runDiagnostic(ctx context.Context, task *Diagnostic, raw string) {
	o := m.observe()
	var runErr error
	defer func() {
		defer close(task.done)
		contextErr := ctx.Err()
		task.cancel()
		o.mu.Lock()
		task.Finished, task.Stage = time.Now(), "检测完成"
		task.State, task.Code, task.Summary = "done", "completed", "请分别查看联网结果和代理路径"
		if runErr != nil {
			task.State, task.Code, task.Summary = "failed", errorCode(runErr, "diagnostics"), "检测未完成，请检查对象状态后重试"
			var f *apiFailure
			if errors.As(runErr, &f) {
				task.Summary = f.message
			}
		}
		if contextErr != nil {
			task.State, task.Code, task.Summary = "cancelled", "cancelled", "检测已取消"
			if errors.Is(contextErr, context.DeadlineExceeded) {
				task.State, task.Code, task.Summary = "failed", "diagnostic_timeout", "检测已超时，请查看已完成项目"
			}
		}
		if task.Stale {
			task.Code, task.Summary = "context_changed", "运行配置或网络环境已变化，结果已过期，请重新检测"
		}
		o.running = nil
		code, summary := task.Code, task.Summary
		level, title := "info", "网络检测结束"
		if task.State == "failed" || task.Stale {
			level, title = "warning", "网络检测未完成"
		} else if task.State == "done" {
			for _, step := range task.Steps {
				if step.State == "failed" {
					code, level, title, summary = "diagnostic_checks_failed", "warning", "网络检测有项目未通过", "请在检测详情中查看影响、下一步操作和技术原因；代理路径单独确认"
					break
				}
			}
		}
		o.mu.Unlock()
		o.event(code, level, title, summary, "查看网络页检测详情")
	}()
	report := o.targetList(ctx, true)
	var target NetworkTarget
	for _, t := range report.Items {
		if t.ID == task.TargetID {
			target = t
			break
		}
	}
	if target.ID == "" {
		runErr = fail("target_missing", "检测对象不存在或 Docker 信息暂时不可用，请刷新列表")
		return
	}
	o.mu.Lock()
	task.TargetName = target.Name
	task.Stage = "检查地址、路由和 DNS"
	o.mu.Unlock()
	if !target.CanProbe {
		runErr = fail(target.Code, target.Detail)
		return
	}
	var flows []ProbeFlow
	runErr = o.probe(ctx, target, raw, task.NetworkMode, func(step ProbeStep) {
		o.mu.Lock()
		defer o.mu.Unlock()
		if task.Stale || ctx.Err() != nil {
			return
		}
		flows = append(flows, step.Flows...)
		step.Flows = nil
		task.Steps = append(task.Steps, step)
		task.Stage = step.Title
	})
	if ctx.Err() != nil {
		return
	}
	if target.Kind == "container" && runErr == nil {
		c, err := inspectContainer(ctx, o.runner, target.ID)
		if err != nil || !c.Running || c.PID != target.PID || c.StartedAt != target.StartedAt {
			o.mu.Lock()
			task.Stale = true
			o.mu.Unlock()
			runErr = fail("target_changed", "容器已停止或重启，请重新检测")
		}
	}
	m.sampleConnections(ctx)
	select {
	case <-ctx.Done():
		return
	case <-time.After(150 * time.Millisecond):
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if task.Stale {
		return
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		evidence := PathEvidence{Family: family, Path: "unknown", Exit: "路径未确认", Chains: []string{}}
		if family == "ipv6" && task.NetworkMode == "ipv4" {
			evidence.Path, evidence.Exit = "excluded", "不参与接管"
		} else {
			for _, flow := range flows {
				addr, err := netip.ParseAddrPort(flow.Source)
				if err != nil || addr.Addr().Is4() != (family == "ipv4") {
					continue
				}
				for _, c := range o.connections {
					if task.coreID == o.coreID && matchesProbe(flow, c, task.Started) {
						evidence.Path, evidence.Exit, evidence.Rule, evidence.Chains, evidence.ConnectionID = c.Path, c.Exit, c.Rule, append([]string{}, c.Chains...), c.ID
						break
					}
				}
			}
		}
		task.Paths = append(task.Paths, evidence)
	}
}

func matchesProbe(flow ProbeFlow, c Connection, start time.Time) bool {
	src, err := netip.ParseAddrPort(flow.Source)
	if err != nil {
		return false
	}
	dst, err := netip.ParseAddrPort(flow.Destination)
	if err != nil {
		return false
	}
	csrc, err := netip.ParseAddr(c.Metadata.SourceIP)
	if err != nil {
		return false
	}
	cdst, err := netip.ParseAddr(c.Metadata.DestinationIP)
	if err != nil {
		return false
	}
	return csrc.Unmap() == src.Addr().Unmap() && cdst.Unmap() == dst.Addr().Unmap() && c.Metadata.SourcePort.String() == strconv.Itoa(int(src.Port())) && c.Metadata.DestinationPort.String() == strconv.Itoa(int(dst.Port())) && strings.EqualFold(c.Metadata.Network, flow.Network) && !c.Start.Before(start) && c.Start.Sub(flow.At) < 8*time.Second && flow.At.Sub(c.Start) < 8*time.Second
}

func (o *Observability) exportDiagnostic(id string) (string, error) {
	if id == "" {
		return "", fail("diagnostic_missing", "请选择一条检测记录后导出")
	}
	result, err := o.diagnosticResult(id)
	if err != nil {
		return "", err
	}
	task := result.(Diagnostic)
	var out strings.Builder
	fmt.Fprintf(&out, "FlClash 飞牛 %s 诊断摘要\n检测：%s\n对象：对象-1\n目标：目标-1\n范围：%s\n状态：%s\n开始：%s\n结果过期：%t\n", appVersion, task.ID, task.NetworkMode, task.Code, task.Started.Format(time.RFC3339), task.Stale)
	for _, step := range task.Steps {
		fmt.Fprintf(&out, "%s / %s：%s (%s)", step.Family, step.Title, step.State, step.Code)
		if step.HTTPStatus != 0 {
			fmt.Fprintf(&out, " HTTP %d", step.HTTPStatus)
		}
		out.WriteByte('\n')
	}
	nodes := map[string]int{}
	for _, path := range task.Paths {
		label := path.Exit
		if path.Path == "proxy" {
			if nodes[label] == 0 {
				nodes[label] = len(nodes) + 1
			}
			label = fmt.Sprintf("出口-%d", nodes[label])
		}
		fmt.Fprintf(&out, "%s 路径：%s / %s\n", path.Family, path.Path, label)
	}
	for _, event := range o.eventList() {
		if !event.At.Before(task.Started) && (task.Finished.IsZero() || !event.At.After(task.Finished.Add(time.Second))) {
			fmt.Fprintf(&out, "事件：%s %s %s\n", event.At.Format(time.RFC3339), event.Level, event.Code)
		}
	}
	out.WriteString("仅代表本次目标的网络环境检测；DNS UDP 通过不等于所有 UDP 协议通过。\n未包含订阅、凭据、配置内容或完整访问历史。\n")
	return out.String(), nil
}

func parsePage(r *http.Request) (int, int, error) {
	q := r.URL.Query()
	if len(q.Get("q")) > 256 || len(q.Get("source")) > 128 {
		return 0, 0, fail("invalid_filter", "筛选条件过长")
	}
	offset, limit := 0, 50
	var err error
	if q.Get("offset") != "" {
		offset, err = strconv.Atoi(q.Get("offset"))
		if err != nil || offset < 0 {
			return 0, 0, fail("invalid_page", "分页参数无效")
		}
	}
	if q.Get("limit") != "" {
		limit, err = strconv.Atoi(q.Get("limit"))
		if err != nil || limit < 1 || limit > 100 {
			return 0, 0, fail("invalid_page", "每页数量范围为 1—100")
		}
	}
	return offset, limit, nil
}

func (m *Manager) observationHTTP(w http.ResponseWriter, r *http.Request, path string, req apiRequest) bool {
	o := m.observe()
	var result any
	var err error
	switch path {
	case "connections":
		var offset, limit int
		offset, limit, err = parsePage(r)
		if err == nil {
			m.sampleConnections(r.Context())
			result = o.connectionList(r.URL.Query().Get("source"), r.URL.Query().Get("q"), r.URL.Query().Get("path"), offset, limit)
		}
	case "network/targets":
		result = o.targetList(r.Context(), r.URL.Query().Get("refresh") == "1")
	case "events":
		result = o.eventList()
	case "diagnostics/start":
		result, err = m.startDiagnostic(req.TargetID, req.Preset)
	case "diagnostics/cancel":
		err = o.cancelDiagnostic(req.ID)
		result = map[string]bool{"ok": err == nil}
	case "diagnostics/result":
		result, err = o.diagnosticResult(r.URL.Query().Get("id"))
	case "diagnostics/export":
		var body string
		body, err = o.exportDiagnostic(r.URL.Query().Get("id"))
		if err == nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="FlClash-diagnostic.txt"`)
			_, _ = w.Write([]byte(body))
			return true
		}
	default:
		return false
	}
	if err != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": redact(err.Error()), "code": errorCode(err, path)})
	} else {
		reply(w, http.StatusOK, result)
	}
	return true
}

func flowFor(conn net.Conn, at time.Time) ProbeFlow {
	return ProbeFlow{Source: conn.LocalAddr().String(), Destination: conn.RemoteAddr().String(), Network: "tcp", At: at}
}

func encodeProbeStep(step ProbeStep) map[string]any {
	b, _ := json.Marshal(step)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if len(step.Flows) > 0 {
		out["flows"] = step.Flows
	}
	return out
}
