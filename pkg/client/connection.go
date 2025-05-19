package client

import (
	"fmt"
	"net"
)

func newConnection(conn net.Conn) *connection {
	return &connection{
		conn: conn,
	}
}

type connection struct {
	conn net.Conn
}

func (c *connection) writeLine(line string) {
	_, _ = fmt.Fprintln(c.conn, line)
}

func (c *connection) close() {
	if err := c.conn.Close(); err != nil {
		fmt.Println("could not close connection:", err)
	}
}
