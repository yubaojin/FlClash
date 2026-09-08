package service

import (
	"github.com/Microsoft/go-winio"
	"net"
)

func testCoreListener() (net.Listener, string, error) {
	address := `\\.\pipe\FlClashFnosTest_` + randomID()
	l, err := winio.ListenPipe(address, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"})
	return l, address, err
}
