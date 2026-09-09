package service

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type ProbeInput struct {
	URL   string   `json:"url"`
	Mode  string   `json:"mode"`
	DNS   []string `json:"dns"`
	Hosts string   `json:"hosts"`
}

func probeStep(id, family, title, code, detail, next string, ok bool) ProbeStep {
	state := "failed"
	if ok {
		state = "passed"
	}
	return ProbeStep{ID: id, Family: family, Title: title, State: state, Code: code, Detail: detail, Next: next, At: time.Now()}
}

func resolveProbe(ctx context.Context, servers []string, transport, family, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() == (family == "ipv4") {
			return []netip.Addr{ip}, nil
		}
		return nil, errors.New("检测目标没有所选地址族")
	}
	queryType := dnsmessage.TypeA
	if family == "ipv6" {
		queryType = dnsmessage.TypeAAAA
	}
	var lastError error
	for _, server := range servers {
		ip, err := netip.ParseAddr(server)
		if err != nil {
			continue
		}
		addresses, err := exchangeDNS(ctx, net.JoinHostPort(ip.String(), "53"), transport, host, queryType)
		if err == nil && len(addresses) > 0 {
			return addresses, nil
		}
		lastError = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if lastError != nil {
		return nil, lastError
	}
	return nil, errors.New("DNS 未返回所选地址族的可用地址")
}

func exchangeDNS(ctx context.Context, address, transport, host string, queryType dnsmessage.Type) ([]netip.Addr, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, err
	}
	var idBytes [2]byte
	if _, err = rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: queryType, Class: dnsmessage.ClassINET}}}
	packet, err := query.Pack()
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, transport, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if transport == "tcp" {
		packet = append([]byte{byte(len(packet) >> 8), byte(len(packet))}, packet...)
	}
	if _, err = conn.Write(packet); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	if transport == "tcp" {
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		response = response[:binary.BigEndian.Uint16(size[:])]
		_, err = io.ReadFull(conn, response)
	} else {
		var n int
		n, err = conn.Read(response)
		response = response[:n]
	}
	if err != nil {
		return nil, err
	}
	var answer dnsmessage.Message
	if err = answer.Unpack(response); err != nil {
		return nil, err
	}
	if !answer.Response || answer.ID != id || answer.Truncated || answer.RCode != dnsmessage.RCodeSuccess || len(answer.Questions) != 1 || answer.Questions[0] != query.Questions[0] {
		return nil, errors.New("DNS 响应无效、被截断或返回错误")
	}
	names := map[string]bool{strings.ToLower(name.String()): true}
	for range 8 {
		for _, resource := range answer.Answers {
			if alias, ok := resource.Body.(*dnsmessage.CNAMEResource); ok && names[strings.ToLower(resource.Header.Name.String())] {
				names[strings.ToLower(alias.CNAME.String())] = true
			}
		}
	}
	var addresses []netip.Addr
	for _, resource := range answer.Answers {
		if !names[strings.ToLower(resource.Header.Name.String())] || resource.Header.Class != dnsmessage.ClassINET {
			continue
		}
		switch body := resource.Body.(type) {
		case *dnsmessage.AResource:
			if queryType == dnsmessage.TypeA {
				addresses = append(addresses, netip.AddrFrom4(body.A))
			}
		case *dnsmessage.AAAAResource:
			if queryType == dnsmessage.TypeAAAA {
				addresses = append(addresses, netip.AddrFrom16(body.AAAA))
			}
		}
		if len(addresses) >= 16 {
			break
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("DNS 未返回所选地址族")
	}
	return addresses, nil
}

func hostsAddresses(raw, host, family string) []netip.Addr {
	var result []netip.Addr
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(f) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil || ip.Is4() != (family == "ipv4") {
			continue
		}
		for _, name := range f[1:] {
			if strings.EqualFold(name, host) {
				result = append(result, ip)
				break
			}
		}
	}
	return result
}

func requestProbe(ctx context.Context, raw, family string, addresses []netip.Addr) ProbeStep {
	step := probeStep("https", family, "访问检测目标", "http_failed", "未能连接检测目标", "检查节点与目标服务，再查看相关连接", false)
	u, err := url.Parse(raw)
	if err != nil || len(addresses) == 0 {
		step.Code, step.Detail = "address_unavailable", "没有可用的目标地址"
		return step
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	var flows []ProbeFlow
	var flowMu sync.Mutex
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSHandshakeTimeout: 5 * time.Second, MaxResponseHeaderBytes: 32 << 10, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var last error
		for _, ip := range addresses {
			at := time.Now()
			conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if err == nil {
				flowMu.Lock()
				flows = append(flows, flowFor(conn, at))
				flowMu.Unlock()
				return conn, nil
			}
			last = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, last
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return step
	}
	req.Header.Set("User-Agent", "FlClash-fnOS-Diagnostics/"+appVersion)
	resp, err := client.Do(req)
	flowMu.Lock()
	step.Flows = append([]ProbeFlow{}, flows...)
	flowMu.Unlock()
	if err != nil {
		var certificate *tls.CertificateVerificationError
		step.Error = redact(err.Error())
		var unknown x509.UnknownAuthorityError
		var host x509.HostnameError
		if errors.As(err, &certificate) || errors.As(err, &unknown) || errors.As(err, &host) {
			step.Code, step.Detail, step.Next = "tls_failed", "TLS 证书校验失败", "检查 NAS 时间及目标证书；不会跳过证书验证"
		} else if ctx.Err() != nil {
			step.Code, step.Detail = "request_timeout", "访问目标超时"
		}
		return step
	}
	defer resp.Body.Close()
	_, bodyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	step.HTTPStatus = resp.StatusCode
	step.State, step.Code, step.Detail, step.Next = "passed", "reachable", "已连到目标服务", ""
	if resp.StatusCode == 401 {
		step.Code, step.Detail = "authentication_required", "服务已可达；后续业务请求需要认证"
	} else if resp.StatusCode >= 400 {
		step.State, step.Code, step.Detail = "warning", "service_response", "网络已可达，目标返回业务错误状态"
	} else if resp.StatusCode >= 300 {
		step.State, step.Code, step.Detail = "warning", "redirect_response", "网络已可达，目标要求重定向；本次未跟随跳转"
	}
	if bodyErr != nil {
		step.State, step.Code, step.Detail = "warning", "body_incomplete", "连接已建立，但响应读取未完成"
	}
	if u.Scheme == "http" {
		step.Detail += "；当前地址为 HTTP，未验证 TLS"
	}
	return step
}

func performProbe(ctx context.Context, in ProbeInput, run readRunner, emit func(ProbeStep)) {
	u, _ := url.Parse(in.URL)
	for _, family := range []string{"ipv4", "ipv6"} {
		if family == "ipv6" && in.Mode == "ipv4" {
			s := probeStep("family", family, "IPv6 范围", "excluded", "不参与本次接管，系统 IPv6 保持原样", "", true)
			s.State = "skipped"
			emit(s)
			continue
		}
		if ctx.Err() != nil {
			return
		}
		flag := "-4"
		if family == "ipv6" {
			flag = "-6"
		}
		for _, item := range []struct {
			id, title string
			args      []string
		}{{"address", "检查网络地址", []string{"-j", flag, "address", "show", "scope", "global"}}, {"route", "检查默认路由", []string{"-j", flag, "route", "show", "default"}}} {
			b, err := run(ctx, "ip", item.args...)
			var records []json.RawMessage
			ok := err == nil && json.Unmarshal(b, &records) == nil && len(records) > 0
			if ok && item.id == "address" {
				var addresses []struct {
					Info []json.RawMessage `json:"addr_info"`
				}
				_ = json.Unmarshal(b, &addresses)
				ok = false
				for _, a := range addresses {
					if len(a.Info) > 0 {
						ok = true
					}
				}
			}
			code, detail, next := item.id+"_available", "已检测到当前地址族的"+map[string]string{"address": "网络地址", "route": "默认路由"}[item.id], ""
			if !ok {
				code, detail, next = item.id+"_unavailable", "当前地址族的网络条件未满足", "检查容器网络或 NAS 出口设置"
			}
			emit(probeStep(item.id, family, item.title, code, detail, next, ok))
		}
		var addresses []netip.Addr
		for _, protocol := range []string{"udp", "tcp"} {
			if ctx.Err() != nil {
				return
			}
			stepCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			ips, err := resolveProbe(stepCtx, in.DNS, protocol, family, u.Hostname())
			cancel()
			code, detail, next := "dns_resolved", "已返回所选地址族的目标地址", ""
			if err != nil {
				code, detail, next = "dns_failed", "DNS 未返回可用地址或查询超时", "检查对象实际 DNS；不要统一替换为 Docker 内部 DNS"
			}
			s := probeStep("dns_"+protocol, family, "DNS "+strings.ToUpper(protocol), code, detail, next, err == nil)
			if err != nil {
				s.Error = redact(err.Error())
			}
			if net.ParseIP(u.Hostname()) != nil {
				s.State, s.Code, s.Detail = "skipped", "literal_address", "目标使用 IP 地址，无需查询 DNS"
			}
			emit(s)
			if len(ips) > 0 && len(addresses) == 0 {
				addresses = ips
			}
		}
		if local := hostsAddresses(in.Hosts, u.Hostname(), family); len(local) > 0 {
			addresses = local
			emit(probeStep("hosts", family, "本地名称解析", "hosts_match", "检测目标命中对象的 hosts 配置", "", true))
		}
		if ctx.Err() != nil {
			return
		}
		stepCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		emit(requestProbe(stepCtx, in.URL, family, addresses))
		cancel()
	}
}

func runProbeCLI() error {
	var in ProbeInput
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 96<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || validURL(in.URL) != nil || (in.Mode != "ipv4" && in.Mode != "dual") || len(in.DNS) > 3 || len(in.Hosts) > 64<<10 {
		return errors.New("检测输入无效")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 59*time.Second)
	defer cancel()
	encoder := json.NewEncoder(os.Stdout)
	performProbe(ctx, in, readCommand, func(s ProbeStep) {
		if encoder.Encode(encodeProbeStep(s)) != nil {
			cancel()
		}
	})
	return ctx.Err()
}

func decodeProbeOutput(reader io.Reader, emit func(ProbeStep)) error {
	scanner := bufio.NewScanner(io.LimitReader(reader, 256<<10))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	count := 0
	for scanner.Scan() {
		var record struct {
			ProbeStep
			Flows []ProbeFlow `json:"flows"`
		}
		if json.Unmarshal(scanner.Bytes(), &record) != nil || len(record.Flows) > 16 {
			return errors.New("检测进程输出格式无效")
		}
		record.ProbeStep.Flows = record.Flows
		emit(record.ProbeStep)
		count++
		if count > 24 {
			return errors.New("检测进程输出项目过多")
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if count == 0 {
		return errors.New("检测进程未返回结果")
	}
	return nil
}
