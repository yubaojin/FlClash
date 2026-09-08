package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type commandRunner func(string, ...string) ([]byte, error)

func command(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return b, fmt.Errorf("%s 执行失败: %s", name, redact(string(b)))
	}
	return b, nil
}

type Check struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Detail   string `json:"detail"`
	Family   string `json:"family"`
	Required bool   `json:"required"`
}
type Coverage struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}
type NetworkReport struct {
	Mode     string          `json:"mode"`
	At       time.Time       `json:"at"`
	Ready    bool            `json:"ready"`
	Checks   []Check         `json:"checks"`
	Coverage []Coverage      `json:"coverage"`
	LAN      []string        `json:"lan"`
	Exit4    string          `json:"exit4"`
	Exit6    string          `json:"exit6"`
	Links    json.RawMessage `json:"links"`
}

type journal struct {
	TunFamilies  []string             `json:"tunFamilies,omitempty"`
	BootID       string               `json:"bootID"`
	Tun          bool                 `json:"tun"`
	Gateway      bool                 `json:"gateway"`
	Sysctls      map[string][2]string `json:"sysctls"`
	ForwardRules [][]string           `json:"forwardRules,omitempty"`
}

type Network struct {
	mode         string
	dir          string
	run          commandRunner
	j            journal
	report       NetworkReport
	bootID       func() (string, error)
	tunAvailable func() error
}

func newNetwork(dir string) (*Network, error) {
	n := &Network{dir: dir, run: command, j: journal{Sysctls: map[string][2]string{}}, bootID: func() (string, error) {
		b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		return strings.TrimSpace(string(b)), err
	}}
	n.tunAvailable = func() error { _, err := os.Stat("/dev/net/tun"); return err }
	b, err := os.ReadFile(filepath.Join(dir, "network-journal.json"))
	if err == nil {
		err = json.Unmarshal(b, &n.j)
	}
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if n.j.Sysctls == nil {
		n.j.Sysctls = map[string][2]string{}
	}
	return n, err
}

func (n *Network) save() error { return saveJSON(filepath.Join(n.dir, "network-journal.json"), n.j) }

func networkFamilies(mode string) []string {
	if mode == "ipv4" {
		return []string{"-4"}
	}
	return []string{"-4", "-6"}
}

func (n *Network) ownedFamilies() ([]string, error) {
	if len(n.j.TunFamilies) == 0 {
		return []string{"-4", "-6"}, nil
	}
	for _, family := range n.j.TunFamilies {
		if family != "-4" && family != "-6" {
			return nil, errors.New("接管归属日志的地址族无效")
		}
	}
	return n.j.TunFamilies, nil
}

func (n *Network) deleteOwnedTable(name string) error {
	b, err := n.run("nft", "list", "tables")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "table inet "+name {
			_, err = n.run("nft", "delete", "table", "inet", name)
			return err
		}
	}
	return nil
}

func (n *Network) Detect() NetworkReport {
	r := NetworkReport{Mode: n.mode, At: time.Now(), Ready: true, Checks: []Check{}, Coverage: []Coverage{}, LAN: []string{}, Links: json.RawMessage("[]")}
	if r.Mode == "" {
		r.Mode = "dual"
	}
	add := func(name string, err error, detail string, addressFamily ...string) {
		family := "common"
		if len(addressFamily) > 0 {
			family = addressFamily[0]
		}
		required := family != "ipv6" || n.mode != "ipv4"
		r.Checks = append(r.Checks, Check{Name: name, OK: err == nil, Detail: detail, Family: family, Required: required})
		if err != nil && required {
			r.Ready = false
		}
	}
	err := n.tunAvailable()
	add("TUN 设备", err, errorText(err))
	for _, family := range []string{"-4", "-6"} {
		b, e := n.run("ip", "-j", family, "route", "show", "default")
		var routes []struct {
			Dev string `json:"dev"`
		}
		if e == nil {
			e = json.Unmarshal(b, &routes)
		}
		if e == nil && len(routes) == 0 {
			e = errors.New("未检测到默认出口路由")
		}
		required := family != "-6" || n.mode != "ipv4"
		r.Checks = append(r.Checks, Check{Name: "IPv" + strings.TrimPrefix(family, "-") + " 默认路由", OK: e == nil, Detail: errorText(e), Family: "ipv" + strings.TrimPrefix(family, "-"), Required: required})
		if e != nil && required {
			r.Ready = false
		}
		if e == nil {
			if family == "-4" {
				r.Exit4 = routes[0].Dev
			} else {
				r.Exit6 = routes[0].Dev
			}
		}
	}
	_, err = n.run("nft", "list", "tables")
	add("nftables", err, errorText(err))
	b, err := n.run("ip", "-j", "-d", "link", "show")
	add("网络接口检测", err, errorText(err))
	if err == nil && json.Valid(b) {
		r.Links = b
	}
	b, err = n.run("ip", "-j", "address", "show")
	var addresses []struct {
		IfName string `json:"ifname"`
		Info   []struct {
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
			Scope  string `json:"scope"`
		} `json:"addr_info"`
	}
	if err == nil {
		err = json.Unmarshal(b, &addresses)
	}
	add("局域网保留地址", err, errorText(err))
	for _, link := range addresses {
		if link.IfName == tunDevice {
			continue
		}
		for _, a := range link.Info {
			if ip, e := netip.ParseAddr(a.Local); e == nil {
				r.LAN = append(r.LAN, netip.PrefixFrom(ip, a.Prefix).Masked().String())
			}
		}
	}
	for _, family := range networkFamilies(n.mode) {
		b, e := n.run("ip", "-j", family, "rule", "show")
		if e == nil && !n.j.Tun {
			e = checkRuleConflicts(b)
		}
		add("IPv"+strings.TrimPrefix(family, "-")+" 策略路由", e, errorText(e), "ipv"+strings.TrimPrefix(family, "-"))
	}
	if !n.j.Tun {
		_, exists := n.run("ip", "link", "show", "dev", tunDevice)
		var e error
		if exists == nil {
			e = errors.New("存在同名 TUN，不能接管")
		}
		add("TUN 名称冲突", e, errorText(e))
		for _, name := range []string{tunTable, "flclash_gateway"} {
			if name == "flclash_gateway" && n.j.Gateway {
				continue
			}
			_, exists = n.run("nft", "list", "table", "inet", name)
			e = nil
			if exists == nil {
				e = errors.New("存在未登记的同名防火墙表")
			}
			add(name+" 归属", e, errorText(e))
		}
		for _, family := range networkFamilies(n.mode) {
			b, e := n.run("ip", "-j", family, "route", "show", "table", strconv.Itoa(routeTable))
			if e == nil && strings.TrimSpace(string(b)) != "[]" {
				e = errors.New("保留路由表已被使用")
			}
			if e != nil && strings.Contains(string(b), "does not exist") {
				e = nil
			}
			add("保留路由表 "+family, e, errorText(e), "ipv"+strings.TrimPrefix(family, "-"))
		}
	}
	r.Coverage = append(r.Coverage,
		Coverage{"宿主机及 Docker 镜像下载", "待接入", "条件检测不是流量验证；需分别测试 IPv4/IPv6、TCP/UDP、DNS"},
		Coverage{"Docker host / bridge", "待接入", "host 共用宿主机；bridge 需验证转发、防火墙、容器互访和端口映射"},
		Coverage{"飞牛虚拟机 / OVS", "待接入", "检测到接口不能推断虚拟机默认路由；须在虚拟机内确认双栈网关"},
		Coverage{"macvlan / ipvlan / 网卡直通", "当前不支持", "请改为经 NAS 路由的受支持网络，再进行双栈连通性测试"})
	if networkIDs, e := n.run("docker", "network", "ls", "--format", "{{.ID}}"); e != nil {
		r.Checks = append(r.Checks, Check{Name: "Docker 检测", OK: false, Detail: "未安装、未启动或当前命令不可用；不影响宿主机检测", Family: "common"})
	} else {
		ids := strings.Fields(string(networkIDs))
		if len(ids) > 64 {
			ids = ids[:64]
		}
		if len(ids) > 0 {
			b, e := n.run("docker", append([]string{"network", "inspect"}, ids...)...)
			var networks []struct {
				Name   string
				Driver string
				IPAM   struct{ Config []struct{ Subnet string } }
			}
			if e == nil {
				e = json.Unmarshal(b, &networks)
			}
			if e != nil {
				r.Checks = append(r.Checks, Check{Name: "Docker 网段", OK: false, Detail: "无法读取 Docker 网络详情", Family: "common"})
			} else {
				var details []string
				for _, network := range networks {
					var subnets []string
					for _, cfg := range network.IPAM.Config {
						if p, e := netip.ParsePrefix(cfg.Subnet); e == nil {
							subnets = append(subnets, p.Masked().String())
							r.LAN = append(r.LAN, p.Masked().String())
						}
					}
					details = append(details, network.Name+" ("+network.Driver+") "+strings.Join(subnets, ", "))
				}
				r.Checks = append(r.Checks, Check{Name: "Docker 类型与网段", OK: true, Detail: strings.Join(details, "\n"), Family: "common"})
			}
		}
	}
	if b, e := n.run("ovs-vsctl", "list-br"); e == nil {
		r.Checks = append(r.Checks, Check{Name: "OVS 网桥", OK: true, Detail: string(b), Family: "common"})
	}
	n.report = r
	return r
}

func errorText(err error) string {
	if err == nil {
		return "检测通过（不代表流量已验证）"
	}
	return redact(err.Error())
}

func checkRuleConflicts(b []byte) error {
	var rules []struct {
		Priority int    `json:"priority"`
		Table    any    `json:"table"`
		Mark     string `json:"fwmark"`
	}
	if err := json.Unmarshal(b, &rules); err != nil {
		return err
	}
	for _, r := range rules {
		if (r.Priority >= ruleStart && r.Priority <= ruleStart+20) || r.Priority == fallbackRule || fmt.Sprint(r.Table) == strconv.Itoa(routeTable) || r.Mark == "0x3f01" || r.Mark == "0x3f02" {
			return errors.New("保留路由编号或标记冲突，拒绝覆盖")
		}
	}
	return nil
}

func (n *Network) ClaimTun() error {
	if n.j.Tun {
		return nil
	}
	r := n.Detect()
	if !r.Ready {
		return fail("network_not_ready", "所选网络模式的前置检测未通过，请查看网络页面")
	}
	n.j.Tun = true
	n.j.TunFamilies = networkFamilies(n.mode)
	boot, err := n.bootID()
	if err != nil {
		n.j.Tun = false
		return err
	}
	n.j.BootID = boot
	if err = n.save(); err != nil {
		n.j.Tun = false
		return err
	}
	return nil
}

func (n *Network) ConfirmTun() error {
	for i := 0; i < 30; i++ {
		_, link := n.run("ip", "link", "show", "dev", tunDevice)
		_, table := n.run("nft", "list", "table", "inet", tunTable)
		if link == nil && table == nil {
			for _, f := range networkFamilies(n.mode) {
				b, e := n.run("ip", "-j", f, "route", "show", "table", strconv.Itoa(routeTable))
				if e != nil || strings.TrimSpace(string(b)) == "[]" {
					return errors.New("TUN 所需地址族的路由表未建立")
				}
			}
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("核心未成功建立 TUN 和 nftables 接管")
}

func (n *Network) RestoreTun() error {
	if !n.j.Tun {
		return nil
	}
	var failures []error
	families, err := n.ownedFamilies()
	if err != nil {
		return err
	}
	if err := n.deleteOwnedTable(tunTable); err != nil {
		failures = append(failures, err)
	}
	for _, family := range families {
		b, e := n.run("ip", "-j", family, "rule", "show")
		var rules []struct {
			Priority int `json:"priority"`
		}
		if e == nil {
			e = json.Unmarshal(b, &rules)
		}
		if e != nil {
			failures = append(failures, e)
			continue
		}
		for _, r := range rules {
			if (r.Priority >= ruleStart && r.Priority <= ruleStart+20) || r.Priority == fallbackRule {
				if _, e = n.run("ip", family, "rule", "del", "priority", strconv.Itoa(r.Priority)); e != nil {
					failures = append(failures, e)
				}
			}
		}
		b, e = n.run("ip", "-j", family, "route", "show", "table", strconv.Itoa(routeTable))
		if e != nil && !strings.Contains(string(b), "does not exist") {
			failures = append(failures, e)
		}
		if e == nil && strings.TrimSpace(string(b)) != "[]" {
			if _, e = n.run("ip", family, "route", "flush", "table", strconv.Itoa(routeTable)); e != nil {
				failures = append(failures, e)
			}
		}
	}
	links, linkErr := n.run("ip", "-j", "link", "show")
	var allLinks []struct {
		Name string `json:"ifname"`
	}
	if linkErr == nil {
		linkErr = json.Unmarshal(links, &allLinks)
	}
	if linkErr != nil {
		failures = append(failures, linkErr)
	}
	for _, link := range allLinks {
		if link.Name == tunDevice {
			if _, err := n.run("ip", "link", "del", "dev", tunDevice); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	n.j.Tun = false
	if err := n.save(); err != nil {
		n.j.Tun = true
		return err
	}
	return nil
}

var safeInterface = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

func (n *Network) setSysctl(key, desired string) error {
	old, err := n.run("sysctl", "-n", key)
	if err != nil {
		return err
	}
	if _, exists := n.j.Sysctls[key]; !exists {
		n.j.Sysctls[key] = [2]string{strings.TrimSpace(string(old)), desired}
		if err = n.save(); err != nil {
			delete(n.j.Sysctls, key)
			return err
		}
	}
	_, err = n.run("sysctl", "-w", key+"="+desired)
	return err
}

func (n *Network) Gateway(cidrs []string) error {
	if len(cidrs) == 0 {
		return nil
	}
	if err := validateCIDRs(cidrs); err != nil {
		return err
	}
	if err := validateModeCIDRs(n.mode, cidrs); err != nil {
		return err
	}
	r := n.report
	if !safeInterface.MatchString(r.Exit4) || (n.mode != "ipv4" && !safeInterface.MatchString(r.Exit6)) {
		return errors.New("请先检测所选模式的出口")
	}
	if !n.j.Gateway {
		if _, err := n.run("nft", "list", "table", "inet", "flclash_gateway"); err == nil {
			return errors.New("网关表已被其他实例占用")
		}
		n.j.Gateway = true
		boot, err := n.bootID()
		if err != nil {
			n.j.Gateway = false
			return err
		}
		n.j.BootID = boot
		if err := n.save(); err != nil {
			n.j.Gateway = false
			return err
		}
	}
	if n.mode != "ipv4" {
		if err := n.setSysctl("net/ipv6/conf/"+r.Exit6+"/accept_ra", "2"); err != nil {
			return err
		}
	}
	if err := n.setSysctl("net.ipv4.ip_forward", "1"); err != nil {
		return err
	}
	if n.mode != "ipv4" {
		if err := n.setSysctl("net.ipv6.conf.all.forwarding", "1"); err != nil {
			return err
		}
	}
	var script strings.Builder
	if _, e := n.run("nft", "list", "table", "inet", "flclash_gateway"); e == nil {
		script.WriteString("delete table inet flclash_gateway\n")
	}
	script.WriteString("table inet flclash_gateway {\n chain postrouting { type nat hook postrouting priority srcnat + 5; policy accept;\n")
	for _, c := range cidrs {
		prefix, _ := netip.ParsePrefix(c)
		family, device := "ip", r.Exit4
		if prefix.Addr().Is6() {
			family, device = "ip6", r.Exit6
		}
		fmt.Fprintf(&script, " %s saddr %s oifname %q masquerade\n", family, prefix.Masked(), device)
	}
	script.WriteString(" }\n}\n")
	path := filepath.Join(n.dir, "gateway.nft")
	if err := atomicWrite(path, []byte(script.String())); err != nil {
		return err
	}
	_, err := n.run("nft", "-f", path)
	if err != nil {
		return err
	}
	return n.allowGatewayForward(cidrs, r)
}

func (n *Network) allowGatewayForward(cidrs []string, r NetworkReport) error {
	for _, c := range cidrs {
		p, _ := netip.ParsePrefix(c)
		binary, device := "iptables", r.Exit4
		if p.Addr().Is6() {
			binary, device = "ip6tables", r.Exit6
		}
		if _, err := n.run(binary, "-w", "5", "-S", "FORWARD"); err != nil {
			return errors.New("网关转发需要可用的 iptables/ip6tables 兼容接口；没有修改全局策略")
		}
		for _, out := range []string{device, tunDevice} {
			for _, spec := range [][]string{
				{"-s", p.Masked().String(), "-o", out, "-m", "comment", "--comment", "flclash-gateway", "-j", "ACCEPT"},
				{"-d", p.Masked().String(), "-i", out, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", "flclash-gateway", "-j", "ACCEPT"},
			} {
				entry := append([]string{binary}, spec...)
				known := false
				for _, old := range n.j.ForwardRules {
					if strings.Join(old, "\x00") == strings.Join(entry, "\x00") {
						known = true
						break
					}
				}
				_, exists := n.run(binary, append([]string{"-w", "5", "-C", "FORWARD"}, spec...)...)
				if exists == nil && !known {
					return errors.New("存在未登记的同名转发规则，拒绝覆盖")
				}
				if !known {
					n.j.ForwardRules = append(n.j.ForwardRules, entry)
					if err := n.save(); err != nil {
						return err
					}
				}
				if exists != nil {
					if _, err := n.run(binary, append([]string{"-w", "5", "-I", "FORWARD", "1"}, spec...)...); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func (n *Network) RestoreAll() error {
	if err := n.RestoreTun(); err != nil {
		return err
	}
	if n.j.Gateway {
		if err := n.deleteOwnedTable("flclash_gateway"); err != nil {
			return err
		}
	}
	for _, entry := range n.j.ForwardRules {
		if len(entry) < 2 || (entry[0] != "iptables" && entry[0] != "ip6tables") {
			return errors.New("转发恢复日志格式无效")
		}
		if _, err := n.run(entry[0], "-w", "5", "-S", "FORWARD"); err != nil {
			return err
		}
		if _, err := n.run(entry[0], append([]string{"-w", "5", "-C", "FORWARD"}, entry[1:]...)...); err == nil {
			if _, err = n.run(entry[0], append([]string{"-w", "5", "-D", "FORWARD"}, entry[1:]...)...); err != nil {
				return err
			}
		}
	}
	boot, err := n.bootID()
	if err != nil {
		return err
	}
	if boot == n.j.BootID {
		for key, pair := range n.j.Sysctls {
			current, err := n.run("sysctl", "-n", key)
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(current)) == pair[1] {
				if _, err = n.run("sysctl", "-w", key+"="+pair[0]); err != nil {
					return err
				}
			}
		}
	}
	old := n.j
	n.j = journal{Sysctls: map[string][2]string{}}
	if err := n.save(); err != nil {
		n.j = old
		return err
	}
	return nil
}
