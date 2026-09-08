package service

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const maxFrame = 64 << 20

type response struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Method    string          `json:"method"`
	Arguments json.RawMessage `json:"arguments"`
}

type RPC struct {
	conn    net.Conn
	writes  sync.Mutex
	mu      sync.Mutex
	pending map[string]chan response
	next    atomic.Uint64
	done    chan struct{}
	event   func(json.RawMessage)
}

func newRPC(conn net.Conn, event func(json.RawMessage)) *RPC {
	r := &RPC{conn: conn, pending: make(map[string]chan response), done: make(chan struct{}), event: event}
	go r.read()
	return r
}

func (r *RPC) read() {
	defer close(r.done)
	defer r.conn.Close()
	for {
		var size uint32
		if err := binary.Read(r.conn, binary.LittleEndian, &size); err != nil || size == 0 || size > maxFrame {
			return
		}
		buf := make([]byte, int(size))
		if _, err := io.ReadFull(r.conn, buf); err != nil {
			return
		}
		var msg response
		if json.Unmarshal(buf, &msg) != nil {
			return
		}
		if msg.Method == "message" {
			if r.event != nil {
				r.event(msg.Arguments)
			}
			continue
		}
		r.mu.Lock()
		ch := r.pending[msg.ID]
		r.mu.Unlock()
		if ch != nil {
			select {
			case ch <- msg:
			default:
			}
		}
	}
}

func (r *RPC) Call(ctx context.Context, method string, args any, out any) error {
	id := strconv.FormatUint(r.next.Add(1), 10)
	ch := make(chan response, 1)
	r.mu.Lock()
	r.pending[id] = ch
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.pending, id); r.mu.Unlock() }()
	buf, err := json.Marshal(map[string]any{"id": id, "method": method, "arguments": args})
	if err != nil {
		return err
	}
	if len(buf) > maxFrame {
		return errors.New("核心请求超过大小限制")
	}
	r.writes.Lock()
	_ = r.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err = binary.Write(r.conn, binary.LittleEndian, uint32(len(buf)))
	if err == nil {
		_, err = io.Copy(r.conn, bytesReader(buf))
	}
	r.writes.Unlock()
	if err != nil {
		_ = r.conn.Close()
		return err
	}
	select {
	case msg := <-ch:
		if msg.Error != nil {
			return fmt.Errorf("核心 %s: %s", msg.Error.Code, msg.Error.Message)
		}
		if out != nil {
			return json.Unmarshal(msg.Result, out)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		return errors.New("核心 IPC 已断开")
	}
}

func (r *RPC) Text(ctx context.Context, method string, args any) error {
	var message string
	if err := r.Call(ctx, method, args, &message); err != nil {
		return err
	}
	if message != "" {
		return errors.New(message)
	}
	return nil
}
