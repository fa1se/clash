package sniff

import (
	"bufio"
	"net"
	"time"
)

type BufConn struct {
	r *bufio.Reader
	c net.Conn
}

func (bc BufConn) Read(b []byte) (int, error)         { return bc.r.Read(b) }
func (bc BufConn) Peek(n int) ([]byte, error)         { return bc.r.Peek(n) }
func (bc BufConn) Write(b []byte) (int, error)        { return bc.c.Write(b) }
func (bc BufConn) Close() error                       { return bc.c.Close() }
func (bc BufConn) LocalAddr() net.Addr                { return bc.c.LocalAddr() }
func (bc BufConn) RemoteAddr() net.Addr               { return bc.c.RemoteAddr() }
func (bc BufConn) SetDeadline(t time.Time) error      { return bc.c.SetDeadline(t) }
func (bc BufConn) SetReadDeadline(t time.Time) error  { return bc.c.SetReadDeadline(t) }
func (bc BufConn) SetWriteDeadline(t time.Time) error { return bc.c.SetWriteDeadline(t) }

func NewBufConn(c net.Conn) BufConn {
	return BufConn{bufio.NewReader(c), c}
}
