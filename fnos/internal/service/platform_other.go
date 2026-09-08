//go:build !linux

package service

import (
	"errors"
	"net"
	"os/exec"
)

func syncDirectory(string) error                   { return nil }
func setChildAttributes(*exec.Cmd, uint32, uint32) {}
func verifyPeer(*net.UnixConn, int, uint32) error {
	return errors.New("核心进程身份校验仅在 Linux 可用")
}
func RunCLI([]string) error {
	return errors.New("运行服务仅支持 Linux x86_64；本机可执行单元测试和交叉构建")
}
