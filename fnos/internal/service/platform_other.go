//go:build !linux

package service

import (
	"context"
	"errors"
	"net"
	"os/exec"
)

func namespaceIdentity(int) (string, error) {
	return "", errors.New("网络命名空间仅在 Linux 可用")
}
func executeProbe(context.Context, NetworkTarget, string, string, func(ProbeStep)) error {
	return fail("probe_unavailable", "真实网络检测仅在 Linux 飞牛环境可用")
}

func syncDirectory(string) error                   { return nil }
func setChildAttributes(*exec.Cmd, uint32, uint32) {}
func verifyPeer(*net.UnixConn, int, uint32) error {
	return errors.New("核心进程身份校验仅在 Linux 可用")
}
func RunCLI([]string) error {
	return errors.New("运行服务仅支持 Linux x86_64；本机可执行单元测试和交叉构建")
}
