package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*
var webFiles embed.FS

const prefix = "/app/flclash"

type apiRequest struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	URL              string    `json:"url"`
	YAML             string    `json:"yaml"`
	Interval         int       `json:"intervalHours"`
	Enabled          bool      `json:"enabled"`
	Mode             *string   `json:"mode"`
	Group            string    `json:"group"`
	Proxy            string    `json:"proxy"`
	HealthGroup      *string   `json:"healthGroup"`
	HealthURL        *string   `json:"healthURL"`
	GatewayCIDRs     *[]string `json:"gatewayCIDRs"`
	NetworkMode      *string   `json:"networkMode"`
	NetworkConfirmed *bool     `json:"networkModeConfirmed"`
	Revision         *uint64   `json:"revision"`
	Session          string    `json:"session"`
	GatewayRestored  bool      `json:"gatewayRestored"`
}

var routes = map[string]string{
	"status": "GET", "profiles": "POST", "profiles/update": "POST", "profiles/edit": "POST", "profiles/select": "POST", "profiles/delete": "POST",
	"settings": "POST", "control": "POST", "restart": "POST", "proxies": "GET", "proxies/select": "POST", "proxies/delay": "POST",
	"network": "GET", "network/detect": "POST", "network/recover": "POST", "logs": "GET",
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (m *Manager) Handler() http.Handler {
	m.mu.Lock()
	if m.session == "" {
		m.session = randomID()
	}
	if m.delaySlots == nil {
		m.delaySlots = make(chan struct{}, 2)
	}
	m.publish()
	m.mu.Unlock()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, prefix+"/api/")
		method, exists := routes[path]
		if !exists || method != r.Method {
			reply(w, 404, map[string]string{"error": "接口不存在"})
			return
		}
		var req apiRequest
		if r.Method == "POST" {
			r.Body = http.MaxBytesReader(w, r.Body, 12<<20)
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			if err := d.Decode(&req); err != nil {
				reply(w, 400, map[string]string{"error": "请求格式错误或过大"})
				return
			}
			if err := d.Decode(new(any)); err != io.EOF {
				reply(w, 400, map[string]string{"error": "请求包含多余内容"})
				return
			}
		}
		if path == "status" {
			reply(w, 200, *m.snapshot.Load())
			return
		}
		if path == "logs" {
			reply(w, 200, m.logs.List())
			return
		}
		if path == "proxies/delay" {
			result, err := m.testDelay(r.Context(), req)
			if err != nil {
				reply(w, 400, map[string]string{"error": redact(err.Error()), "code": errorCode(err, path)})
				return
			}
			reply(w, 200, result)
			return
		}
		if !m.mu.TryLock() {
			reply(w, 409, map[string]string{"error": "后台正在处理另一项操作，请稍后重试", "code": "operation_busy"})
			return
		}
		defer m.mu.Unlock()
		if m.closing {
			reply(w, 503, map[string]string{"error": "应用正在停用"})
			return
		}
		m.operation = path
		m.publish()
		result, err := m.handle(path, req)
		m.operation = ""
		m.publish()
		if err != nil {
			m.logs.Add(err.Error())
			reply(w, 400, map[string]string{"error": redact(err.Error()), "code": errorCode(err, path)})
			return
		}
		if result == nil {
			result = map[string]bool{"ok": true}
		}
		reply(w, 200, result)
	})
}

func (m *Manager) handle(path string, r apiRequest) (any, error) {
	switch path {
	case "status":
		return m.status(), nil
	case "logs":
		return m.logs.List(), nil
	case "network":
		return m.net.report, nil
	case "network/detect":
		result := m.net.Detect()
		m.checked = result.Ready
		if result.Ready {
			m.blocked = ""
		}
		return result, nil
	case "profiles":
		if len(m.settings.Profiles) >= 32 || strings.TrimSpace(r.Name) == "" || len(r.Name) > 128 {
			return nil, errors.New("档案名称不能为空，最多 32 个档案")
		}
		if r.Interval < 0 || r.Interval > 720 {
			return nil, errors.New("更新间隔范围为 0—720 小时，0 表示关闭")
		}
		raw := r.YAML
		if r.URL != "" {
			var err error
			raw, err = fetchSubscription(r.URL)
			if err != nil {
				return nil, err
			}
		}
		if _, err := prepareConfig(raw, m.settings, m.home, false, nil); err != nil {
			return nil, err
		}
		p := Profile{ID: randomID(), Name: r.Name, URL: r.URL, YAML: raw, Interval: r.Interval, Updated: time.Now(), LastAttempt: time.Now()}
		m.settings.Profiles = append(m.settings.Profiles, p)
		if err := m.persist(); err != nil {
			m.settings.Profiles = m.settings.Profiles[:len(m.settings.Profiles)-1]
			return nil, err
		}
		return map[string]string{"id": p.ID}, nil
	case "profiles/update":
		return nil, m.updateProfile(r.ID)
	case "profiles/edit":
		return nil, m.editProfile(r)
	case "profiles/select":
		p := m.profile(r.ID)
		if p == nil {
			return nil, errors.New("档案不存在")
		}
		old := m.settings.Active
		if err := m.apply(p.YAML, m.active); err != nil {
			return nil, err
		}
		m.settings.Active = p.ID
		if err := m.persist(); err != nil {
			m.settings.Active = old
			if previous := m.profile(old); previous != nil {
				_ = m.apply(previous.YAML, m.active)
			}
			return nil, err
		}
		return nil, nil
	case "profiles/delete":
		if r.ID == m.settings.Active {
			return nil, errors.New("当前档案不能删除，请先切换档案")
		}
		old := append([]Profile{}, m.settings.Profiles...)
		for i, p := range m.settings.Profiles {
			if p.ID == r.ID {
				m.settings.Profiles = append(m.settings.Profiles[:i], m.settings.Profiles[i+1:]...)
				break
			}
		}
		if err := m.persist(); err != nil {
			m.settings.Profiles = old
			return nil, err
		}
		return nil, nil
	case "settings":
		return nil, m.saveSettings(r)
	case "control":
		return nil, m.setEnabled(r.Enabled)
	case "restart":
		if err := m.disable(); err != nil {
			return nil, err
		}
		if m.settings.Enabled {
			if err := m.enable(); err != nil {
				m.degrade(err.Error())
				return nil, err
			}
		}
		return nil, nil
	case "network/recover":
		if m.net.j.Gateway && !r.GatewayRestored {
			return nil, errors.New("请先将虚拟机和特殊容器恢复原网关，再确认恢复")
		}
		old := m.settings.Enabled
		oldGateway := m.settings.GatewayEnabled
		m.settings.Enabled = false
		m.settings.GatewayEnabled = false
		if err := m.persist(); err != nil {
			m.settings.Enabled = old
			m.settings.GatewayEnabled = oldGateway
			return nil, err
		}
		if err := m.disable(); err != nil {
			return nil, err
		}
		if err := m.net.RestoreAll(); err != nil {
			return nil, err
		}
		m.degraded, m.blocked = "", ""
		return nil, nil
	case "proxies", "proxies/select":
		if !m.core.Alive() || !m.configured {
			return nil, fail("core_not_ready", "核心配置尚未就绪，请使用有效配置")
		}
		if (r.Revision != nil && *r.Revision != m.revision) || (r.Session != "" && r.Session != m.session) {
			return nil, fail("stale_session", "配置已变化，请刷新节点后重试")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if path == "proxies" {
			var data map[string]any
			if err := m.core.RPC.Call(ctx, "getProxies", nil, &data); err != nil {
				return nil, err
			}
			data["revision"] = m.revision
			data["session"] = m.session
			return data, nil
		}
		return nil, m.changeSelection(ctx, r)
	}
	return nil, errors.New("接口不存在")
}

func GatewayHandler(internalSocket string) http.Handler {
	csrfKey := []byte(rand.Text())
	files, _ := fs.Sub(webFiles, "web")
	static := http.StripPrefix(prefix+"/", http.FileServer(http.FS(files)))
	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = "http"
			r.URL.Host = "flclash"
			r.Host = "flclash"
			r.Header.Del("Cookie")
			r.Header.Del("Authorization")
		},
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", internalSocket)
		}, ResponseHeaderTimeout: 110 * time.Second},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			reply(w, 503, map[string]string{"error": "后台服务不可用，请检查应用中心运行状态"})
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'")
		_, err := strconv.ParseUint(r.Header.Get("X-Trim-Userid"), 10, 32)
		if err != nil || r.Header.Get("X-Trim-Isadmin") != "true" || r.Header.Get("X-Trim-Username") == "" {
			reply(w, 403, map[string]string{"error": "仅允许通过飞牛统一网关登录的 NAS 管理员访问"})
			return
		}
		mac := hmac.New(sha256.New, csrfKey)
		_, _ = mac.Write([]byte(r.Header.Get("X-Trim-Userid") + "\x00" + r.Header.Get("X-Trim-Username")))
		token := hex.EncodeToString(mac.Sum(nil))
		if r.URL.Path == prefix+"/api/session" && r.Method == "GET" {
			reply(w, 200, map[string]string{"csrfToken": token})
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			origin, parseErr := url.Parse(r.Header.Get("Origin"))
			contentType, _, contentErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
			fetchSite := r.Header.Get("Sec-Fetch-Site")
			if r.Header.Get("X-FlClash-Request") != "1" || contentErr != nil || contentType != "application/json" || !hmac.Equal([]byte(r.Header.Get("X-FlClash-CSRF")), []byte(token)) || (fetchSite != "" && fetchSite != "same-origin") || (r.Header.Get("Origin") != "" && (parseErr != nil || origin.Host == "" || (origin.Scheme != "http" && origin.Scheme != "https"))) {
				reply(w, 403, map[string]string{"error": "请求来源校验失败"})
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/api/") {
			path := strings.TrimPrefix(r.URL.Path, prefix+"/api/")
			if method, ok := routes[path]; !ok || method != r.Method {
				http.NotFound(w, r)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 12<<20)
			proxy.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == prefix {
			http.Redirect(w, r, prefix+"/", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == prefix+"/logo.png" && (r.Method == "GET" || r.Method == "HEAD") {
			exe, err := os.Executable()
			if err != nil {
				http.NotFound(w, r)
				return
			}
			http.ServeFile(w, r, filepath.Join(filepath.Dir(exe), "..", "ui", "images", "icon_64.png"))
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != prefix+"/" && r.URL.Path != prefix+"/app.js" && r.URL.Path != prefix+"/model.js" && r.URL.Path != prefix+"/style.css" {
			http.NotFound(w, r)
			return
		}
		static.ServeHTTP(w, r)
	})
}

func localClient(runtimeDir string) *http.Client {
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(runtimeDir, "control.sock"))
	}}}
}
