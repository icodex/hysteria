package utils_test

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

type MockEchoHyClient struct{}

func (c *MockEchoHyClient) TCP(addr string) (net.Conn, error) {
	return &mockEchoTCPConn{
		BufChan: make(chan []byte, 10),
		doneCh:  make(chan struct{}),
	}, nil
}

func (c *MockEchoHyClient) UDP() (client.HyUDPConn, error) {
	return &mockEchoUDPConn{
		BufChan: make(chan mockEchoUDPPacket, 10),
		doneCh:  make(chan struct{}),
	}, nil
}

func (c *MockEchoHyClient) Close() error {
	return nil
}

type mockEchoTCPConn struct {
	BufChan chan []byte
	doneCh  chan struct{}
	done    atomic.Bool
	once    sync.Once
}

func (c *mockEchoTCPConn) Read(b []byte) (n int, err error) {
	select {
	case buf := <-c.BufChan:
		if buf == nil {
			// EOF
			return 0, io.EOF
		}
		return copy(b, buf), nil
	case <-c.doneCh:
		return 0, io.EOF
	}
}

func (c *mockEchoTCPConn) Write(b []byte) (n int, err error) {
	// 必须拷贝:b 是调用方的复用缓冲,直接入队会与调用方的下一次写入构成数据竞争
	buf := make([]byte, len(b))
	copy(buf, b)
	select {
	case c.BufChan <- buf:
		return len(b), nil
	case <-c.doneCh:
		return 0, net.ErrClosed
	}
}

func (c *mockEchoTCPConn) Close() error {
	if c.done.CompareAndSwap(false, true) {
		c.once.Do(func() { close(c.doneCh) })
	}
	return nil
}

func (c *mockEchoTCPConn) LocalAddr() net.Addr {
	// Not implemented
	return nil
}

func (c *mockEchoTCPConn) RemoteAddr() net.Addr {
	// Not implemented
	return nil
}

func (c *mockEchoTCPConn) SetDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *mockEchoTCPConn) SetReadDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *mockEchoTCPConn) SetWriteDeadline(t time.Time) error {
	// Not implemented
	return nil
}

type mockEchoUDPPacket struct {
	Data []byte
	Addr string
}

type mockEchoUDPConn struct {
	BufChan chan mockEchoUDPPacket
	doneCh  chan struct{}
	done    atomic.Bool
	once    sync.Once
}

func (c *mockEchoUDPConn) Receive() ([]byte, string, error) {
	select {
	case p := <-c.BufChan:
		if p.Data == nil {
			// EOF
			return nil, "", io.EOF
		}
		return p.Data, p.Addr, nil
	case <-c.doneCh:
		return nil, "", io.EOF
	}
}

func (c *mockEchoUDPConn) Send(bytes []byte, s string) error {
	// 同 Write:拷贝入队,避免与调用方缓冲的别名竞争
	data := make([]byte, len(bytes))
	copy(data, bytes)
	select {
	case c.BufChan <- mockEchoUDPPacket{Data: data, Addr: s}:
		return nil
	case <-c.doneCh:
		return net.ErrClosed
	}
}

func (c *mockEchoUDPConn) Close() error {
	if c.done.CompareAndSwap(false, true) {
		c.once.Do(func() { close(c.doneCh) })
	}
	return nil
}
