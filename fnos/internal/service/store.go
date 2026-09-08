package service

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".flclash-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func saveJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, data)
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func providerKey(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:16]) }

type Profile struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url,omitempty"`
	YAML        string    `json:"yaml,omitempty"`
	Interval    int       `json:"intervalHours"`
	Updated     time.Time `json:"updated"`
	LastAttempt time.Time `json:"lastAttempt"`
	Error       string    `json:"error,omitempty"`
}

type Settings struct {
	NetworkMode      string            `json:"networkMode"`
	NetworkConfirmed bool              `json:"networkModeConfirmed"`
	GatewayEnabled   bool              `json:"gatewayEnabled"`
	Active           string            `json:"active"`
	Enabled          bool              `json:"enabled"`
	Mode             string            `json:"mode"`
	Selected         map[string]string `json:"selected"`
	HealthGroup      string            `json:"healthGroup"`
	HealthURL        string            `json:"healthURL"`
	GatewayCIDRs     []string          `json:"gatewayCIDRs"`
	Profiles         []Profile         `json:"profiles"`
}

func loadSettings(dir string) (Settings, error) {
	s := Settings{Mode: "rule", NetworkMode: "dual", Selected: map[string]string{}, HealthURL: "https://www.gstatic.com/generate_204", Profiles: []Profile{}}
	b, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	s.NetworkConfirmed = true
	err = json.Unmarshal(b, &s)
	if s.NetworkMode != "dual" && s.NetworkMode != "ipv4" {
		return s, errors.New("保存的网络模式无效")
	}
	if s.Selected == nil {
		s.Selected = map[string]string{}
	}
	return s, err
}

func validURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Fragment != "" {
		return errors.New("只允许不带用户名密码和片段的 HTTP/HTTPS 地址")
	}
	return nil
}

var urlPattern = regexp.MustCompile(`(?i)(https?|ss|vmess|vless|trojan|socks5?)://[^\s"'<>]+`)
var secretPattern = regexp.MustCompile(`(?i)(authorization|password|passwd|secret|token|api[_-]?key|subscription)["'=: ]+[^\s,;}]+`)

func redact(s string) string {
	s = urlPattern.ReplaceAllString(s, "[地址已隐藏]")
	s = secretPattern.ReplaceAllString(s, "[凭据已隐藏]")
	if len(s) > 2048 {
		s = s[:2048] + "…"
	}
	return strings.ToValidUTF8(s, "")
}

type Logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *Logs) Add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, time.Now().Format(time.RFC3339)+" "+redact(s))
	if len(l.lines) > 500 {
		l.lines = l.lines[len(l.lines)-500:]
	}
}
func (l *Logs) List() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string{}, l.lines...)
}
func (l *Logs) Write(b []byte) (int, error) {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) != "" {
			l.Add(line)
		}
	}
	return len(b), nil
}

func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, (8<<20)+1))
	if err == nil && len(b) > 8<<20 {
		err = errors.New("配置不能超过 8 MiB")
	}
	return b, err
}
