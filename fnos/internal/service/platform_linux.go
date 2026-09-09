package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func setChildAttributes(cmd *exec.Cmd, uid, gid uint32) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if uid != 0 {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{gid}}
	}
}

func verifyPeer(conn *net.UnixConn, pid int, uid uint32) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var credentials *syscall.Ucred
	var peerErr error
	err = raw.Control(func(fd uintptr) {
		credentials, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}
	if credentials.Uid != uid || (pid != 0 && int(credentials.Pid) != pid) {
		return errors.New("本地通信进程身份不匹配")
	}
	return nil
}

type peerListener struct {
	*net.UnixListener
	uid       uint32
	allowRoot bool
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		if verifyPeer(c, 0, l.uid) == nil || (l.allowRoot && verifyPeer(c, 0, 0) == nil) {
			return c, nil
		}
		c.Close()
	}
}

func listen(path string, mode os.FileMode, gid int) (*net.UnixListener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("套接字路径存在非套接字文件")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chown(path, 0, gid); err == nil {
		err = os.Chmod(path, mode)
	}
	if err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func lockOwner(runtimeDir string, nonblock bool) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(runtimeDir, "supervisor.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	flag := syscall.LOCK_EX
	if nonblock {
		flag |= syscall.LOCK_NB
	}
	if err = syscall.Flock(int(f.Fd()), flag); err != nil {
		f.Close()
		return nil, errors.New("监督服务已存在或恢复正在执行")
	}
	return f, nil
}

func RunCLI(args []string) error {
	if len(args) == 1 && args[0] == "probe" {
		return runProbeCLI()
	}
	if len(args) != 4 {
		return errors.New("用法: FlClashFnos start|stop|status|supervise|web|guard|recover 安装目录 数据目录 运行目录")
	}
	action, target, data, runtimeDir := args[0], filepath.Clean(args[1]), filepath.Clean(args[2]), filepath.Clean(args[3])
	if !filepath.IsAbs(target) || !filepath.IsAbs(data) || runtimeDir != "/run/flclash" || target == "/" || data == "/" {
		return errors.New("应用目录参数无效")
	}
	if action == "web" {
		return runWeb(runtimeDir)
	}
	if os.Geteuid() != 0 {
		return errors.New("监督服务必须由飞牛以 root 启动，Web 子进程将降权运行")
	}
	if filepath.Base(data) != "private" || filepath.Base(filepath.Dir(data)) != "data" || filepath.Base(filepath.Dir(filepath.Dir(data))) != "flclash" {
		return errors.New("私有数据目录必须位于 flclash/data/private")
	}
	for path := data; path != "/"; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("数据目录祖先 %s 不是 root 只写目录，拒绝特权访问", path)
		}
	}
	if err := os.MkdirAll(runtimeDir, 0750); err != nil {
		return err
	}
	if err := os.MkdirAll(data, 0700); err != nil {
		return err
	}
	if action == "guard" {
		f := os.NewFile(3, "监督存活管道")
		if f == nil {
			return errors.New("恢复守卫缺少管道")
		}
		_, _ = io.Copy(io.Discard, f)
		f.Close()
		lock, err := lockOwner(runtimeDir, false)
		if err != nil {
			return err
		}
		defer lock.Close()
		n, err := newNetwork(data)
		if err != nil {
			return err
		}
		return n.RestoreTun()
	}
	client := localClient(runtimeDir)
	status := func() bool {
		resp, err := client.Get("http://flclash/health")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	}
	switch action {
	case "status":
		if !status() {
			return errors.New("应用未运行")
		}
		return nil
	case "start":
		if status() {
			return nil
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		log, err := os.OpenFile(filepath.Join(data, "startup.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer log.Close()
		cmd := exec.Command(exe, "supervise", target, data, runtimeDir)
		cmd.Stdout = log
		cmd.Stderr = log
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err = cmd.Start(); err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		for i := 0; i < 150; i++ {
			if status() {
				return nil
			}
			select {
			case err = <-done:
				if err != nil {
					return errors.New("服务启动失败，请查看应用数据目录 startup.log")
				}
				return errors.New("服务意外结束")
			case <-time.After(200 * time.Millisecond):
			}
		}
		return errors.New("启动确认超时，请检查应用状态，不要重复启动")
	case "stop":
		if !status() {
			lock, err := lockOwner(runtimeDir, true)
			if err != nil {
				return err
			}
			defer lock.Close()
			n, err := newNetwork(data)
			if err != nil {
				return err
			}
			return n.RestoreAll()
		}
		resp, err := client.Post("http://flclash/shutdown", "application/json", strings.NewReader("{}"))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return errors.New("停止失败，网络恢复尚未完成")
		}
		for i := 0; i < 150; i++ {
			lock, err := lockOwner(runtimeDir, true)
			if err == nil {
				lock.Close()
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return errors.New("无法确认监督服务退出")
	case "recover":
		lock, err := lockOwner(runtimeDir, true)
		if err != nil {
			return err
		}
		defer lock.Close()
		n, err := newNetwork(data)
		if err != nil {
			return err
		}
		return n.RestoreAll()
	case "supervise":
		return supervise(target, data, runtimeDir)
	default:
		return errors.New("未知服务操作")
	}
}

func httpServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
}

func supervise(target, data, runtimeDir string) error {
	lock, err := lockOwner(runtimeDir, true)
	if err != nil {
		return err
	}
	defer lock.Close()
	for _, relative := range []string{".", "bin", "bin/FlClashFnos", "bin/FlClashCore"} {
		info, err := os.Stat(filepath.Join(target, relative))
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("安装目录或可执行文件不是 root 只写，请重新安装修复权限")
		}
	}
	u, err := user.Lookup("flclash")
	if err != nil {
		return errors.New("飞牛尚未创建 flclash 应用用户")
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil || uid == 0 {
		return errors.New("应用用户 UID 无效")
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return err
	}
	if err = os.Chown(runtimeDir, 0, int(gid)); err != nil {
		return err
	}
	if err = os.Chmod(runtimeDir, 0750); err != nil {
		return err
	}
	if err = os.Chown(data, 0, 0); err != nil {
		return err
	}
	if err = os.Chmod(data, 0700); err != nil {
		return err
	}
	logs := &Logs{}
	m, err := NewManager(data, filepath.Join(target, "bin", "FlClashCore"), filepath.Join(target, "data"), runtimeDir, logs)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	readGuard, writeGuard, err := os.Pipe()
	if err != nil {
		return err
	}
	defer writeGuard.Close()
	guard := exec.Command(exe, "guard", target, data, runtimeDir)
	guard.ExtraFiles = []*os.File{readGuard}
	if err = guard.Start(); err != nil {
		readGuard.Close()
		return err
	}
	readGuard.Close()
	go func() { _ = guard.Wait() }()
	internal, err := listen(filepath.Join(runtimeDir, "api.sock"), 0660, int(gid))
	if err != nil {
		return err
	}
	defer internal.Close()
	api := httpServer(m.Handler())
	defer api.Close()
	go func() { _ = api.Serve(peerListener{internal, uint32(uid), true}) }()
	gateway, err := listen(filepath.Join(target, "app.sock"), 0600, 0)
	if err != nil {
		return err
	}
	defer gateway.Close()
	fd, err := gateway.File()
	if err != nil {
		return err
	}
	web := exec.Command(exe, "web", target, data, runtimeDir)
	web.ExtraFiles = []*os.File{fd}
	web.Stdout = logs
	web.Stderr = logs
	setChildAttributes(web, uint32(uid), uint32(gid))
	if err = web.Start(); err != nil {
		fd.Close()
		return err
	}
	fd.Close()
	webDone := make(chan struct{})
	go func() { _ = web.Wait(); close(webDone) }()
	defer func() { _ = web.Process.Kill(); <-webDone }()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go m.Run(ctx)
	stop := make(chan struct{}, 1)
	control, err := listen(filepath.Join(runtimeDir, "control.sock"), 0600, 0)
	if err != nil {
		cancel()
		_ = m.Close()
		return err
	}
	defer control.Close()
	ctl := httpServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && r.Method == "GET" {
			select {
			case <-webDone:
				reply(w, 503, "Web 服务已退出")
			default:
				reply(w, 200, "运行中")
			}
			return
		}
		if r.URL.Path == "/shutdown" && r.Method == "POST" {
			if err := m.Close(); err != nil {
				reply(w, 500, "网络恢复失败")
				return
			}
			reply(w, 200, "已停止")
			select {
			case stop <- struct{}{}:
			default:
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer ctl.Close()
	go func() { _ = ctl.Serve(peerListener{control, 0, false}) }()
	select {
	case <-ctx.Done():
	case <-webDone:
		logs.Add("Web 服务异常退出")
	case <-stop:
	}
	cancel()
	if err = m.Close(); err != nil {
		return fmt.Errorf("停止时网络恢复失败: %w", err)
	}
	return nil
}

func runWeb(runtimeDir string) error {
	if os.Geteuid() == 0 {
		return errors.New("拒绝以 root 运行 Web 服务")
	}
	f := os.NewFile(3, "飞牛网关套接字")
	if f == nil {
		return errors.New("缺少飞牛网关套接字")
	}
	l, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return err
	}
	u, ok := l.(*net.UnixListener)
	if !ok {
		l.Close()
		return errors.New("管理服务仅允许 Unix Socket")
	}
	defer l.Close()
	return httpServer(GatewayHandler(filepath.Join(runtimeDir, "api.sock"))).Serve(peerListener{u, 0, false})
}
