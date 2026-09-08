package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Core struct {
	RPC    *RPC
	cmd    *exec.Cmd
	exited chan struct{}
	logs   *Logs
}

func launchCore(binary, home, socket string, logs *Logs) (*Core, error) {
	_ = os.Remove(socket)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer l.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return nil, err
	}
	c := &Core{cmd: exec.Command(binary, socket), exited: make(chan struct{}), logs: logs}
	c.cmd.Env = append(os.Environ(), "DISABLE_NFTABLES=false")
	c.cmd.Dir = home
	c.cmd.Stdout = logs
	c.cmd.Stderr = logs
	setChildAttributes(c.cmd, 0, 0)
	if err = c.cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		err := c.cmd.Wait()
		if err != nil {
			logs.Add("核心退出: " + err.Error())
		}
		close(c.exited)
	}()
	_ = l.SetDeadline(time.Now().Add(15 * time.Second))
	conn, err := l.AcceptUnix()
	if err != nil {
		_ = c.Stop()
		return nil, errors.New("核心未能连接本地 IPC")
	}
	if err = verifyPeer(conn, c.cmd.Process.Pid, 0); err != nil {
		conn.Close()
		_ = c.Stop()
		return nil, err
	}
	c.RPC = newRPC(conn, func(raw json.RawMessage) {
		var batch []struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &batch) != nil {
			var one struct {
				Type string          `json:"type"`
				Data json.RawMessage `json:"data"`
			}
			if json.Unmarshal(raw, &one) == nil {
				batch = append(batch, one)
			}
		}
		for _, msg := range batch {
			if msg.Type == "log" {
				logs.Add(string(msg.Data))
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var ok bool
	err = c.RPC.Call(ctx, "initClash", map[string]any{"home-dir": filepath.ToSlash(home), "version": 2026081701}, &ok)
	if err == nil && !ok {
		err = errors.New("核心初始化失败")
	}
	if err != nil {
		_ = c.Stop()
		return nil, err
	}
	_ = c.RPC.Call(ctx, "startLog", nil, nil)
	return c, nil
}

func (c *Core) Alive() bool {
	if c == nil {
		return false
	}
	select {
	case <-c.exited:
		return false
	default:
	}
	if c.RPC == nil {
		return false
	}
	select {
	case <-c.RPC.done:
		return false
	default:
		return true
	}
}

func (c *Core) Stop() error {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return nil
	}
	if c.RPC != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = c.RPC.Call(ctx, "shutdown", nil, nil)
		cancel()
		_ = c.RPC.conn.Close()
	}
	select {
	case <-c.exited:
		return nil
	case <-time.After(time.Second):
	}
	_ = c.cmd.Process.Kill()
	select {
	case <-c.exited:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("无法确认核心已退出，禁止启动第二个核心")
	}
}
