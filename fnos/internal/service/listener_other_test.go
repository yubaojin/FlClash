//go:build !windows

package service

import "net"

func testCoreListener() (net.Listener, string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return l, port, nil
}
