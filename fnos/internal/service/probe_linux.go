package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

func namespaceIdentity(pid int) (string, error) {
	if pid < 1 {
		return "", errors.New("容器没有运行中的进程")
	}
	return os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
}

func executeProbe(ctx context.Context, target NetworkTarget, raw, mode string, emit func(ProbeStep)) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var namespace *os.File
	if target.Kind == "container" {
		c, err := inspectContainer(ctx, readCommand, target.ID)
		if err != nil || !c.Running || c.PID != target.PID || c.StartedAt != target.StartedAt {
			return fail("target_changed", "容器身份已变化，请刷新后重试")
		}
		namespace, err = os.Open(fmt.Sprintf("/proc/%d/ns/net", c.PID))
		if err != nil {
			return fail("namespace_unavailable", "无法固定容器网络环境，未执行检测")
		}
		defer namespace.Close()
		identity, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(namespace.Fd())))
		if err != nil || identity != target.Namespace {
			return fail("target_changed", "容器网络环境已变化，请刷新后重试")
		}
	}
	resolv, err := readSmallFile(target.ResolvPath)
	if err != nil {
		return fail("dns_config_unavailable", "无法读取对象实际 DNS 配置，未使用宿主机 DNS 替代")
	}
	hosts, err := readSmallFile(target.HostsPath)
	if err != nil {
		return fail("hosts_unavailable", "无法读取对象实际 hosts 配置，请检查容器状态")
	}
	in, _ := json.Marshal(ProbeInput{URL: raw, Mode: mode, DNS: parseNameservers(resolv), Hosts: string(hosts)})
	cmd := exec.CommandContext(ctx, exe, "probe")
	if namespace != nil {
		nsenter, err := exec.LookPath("nsenter")
		if err != nil {
			return fail("probe_unavailable", "系统缺少 nsenter，无法自动检测容器")
		}
		cmd = exec.CommandContext(ctx, nsenter, "--net=/proc/self/fd/3", "--", exe, "probe")
		cmd.ExtraFiles = []*os.File{namespace}
	}
	cmd.Stdin = bytes.NewReader(in)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return fail("probe_start_failed", "检测进程无法启动，请查看系统检测条件")
	}
	decodeErr := decodeProbeOutput(stdout, emit)
	if decodeErr != nil {
		_ = cmd.Cancel()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if decodeErr != nil {
		return fail("probe_output_failed", decodeErr.Error())
	}
	if waitErr != nil {
		return fail("probe_failed", "检测进程提前结束，请刷新对象后重试")
	}
	return nil
}
