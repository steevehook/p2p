package server

import (
	"io"
	"net"
	"time"

	"github.com/stretchr/testify/mock"
)

type dummyConn struct {
	io.Reader
	io.Writer
}

func (d *dummyConn) Close() error {
	return nil
}

func (d *dummyConn) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (d *dummyConn) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

func (d *dummyConn) SetDeadline(t time.Time) error {
	return nil
}

func (d *dummyConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (d *dummyConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type dummyAddr string

func (d dummyAddr) Network() string {
	return string(d)
}

func (d dummyAddr) String() string {
	return string(d)
}

type readerMock struct {
	mock.Mock
}

func (r *readerMock) Read(bs []byte) (n int, err error) {
	args := r.Called(bs)
	return args.Int(0), args.Error(1)
}

type writerMock struct {
	mock.Mock
}

func (w *writerMock) Write(bs []byte) (n int, err error) {
	args := w.Called(bs)
	return args.Int(0), args.Error(1)
}
