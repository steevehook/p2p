package server

import (
	"io"
	"net"
	"time"
)

type mockConn struct {
	io.Reader
	io.Writer
}

func (d *mockConn) Close() error {
	return nil
}

func (d *mockConn) LocalAddr() net.Addr {
	return mockAddr("local")
}

func (d *mockConn) RemoteAddr() net.Addr {
	return mockAddr("remote")
}

func (d *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (d *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (d *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type mockAddr string

func (d mockAddr) Network() string {
	return string(d)
}

func (d mockAddr) String() string {
	return string(d)
}
