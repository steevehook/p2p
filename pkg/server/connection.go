package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/steevehook/p2p/pkg/transport"
)

func newConnection(conn net.Conn) *connection {
	return &connection{
		conn:      conn,
		exit:      make(chan struct{}),
		messageCh: make(chan transport.Message[json.RawMessage]),
	}
}

type connection struct {
	id        string
	publicKey string
	conn      net.Conn
	messageCh chan transport.Message[json.RawMessage]
	exit      chan struct{}
}

func (c *connection) withID(id string) *connection {
	c.id = id
	return c
}

func (c *connection) withPublicKey(publicKey string) *connection {
	c.publicKey = publicKey
	return c
}

func (c *connection) writeJSON(message any) {
	bs, err := json.Marshal(message)
	if err != nil {
		slog.Error("could not marshal json", "error", err)
		return
	}
	_, err = c.conn.Write(append(bs, '\n'))
	if err != nil {
		slog.Error("could not write json message", "error", err, "message", string(bs))
	}
}

func (c *connection) readJSON(v any) {
	reader := bufio.NewReader(c.conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		slog.Error("could not read line", "error", err)
		return
	}

	line = strings.TrimSpace(line)
	if line == "" {
		return
	}

	if err = json.Unmarshal([]byte(line), v); err != nil {
		slog.Error("could not unmarshal json", "line", line, "error", err)
		return
	}
}

func (c *connection) close() {
	if err := c.conn.Close(); err != nil {
		slog.Error("could not close connection", "id", c.id, "error", err)
	}
}

type connections struct {
	mu   sync.Mutex
	data map[string]*connection
}

func (c *connections) accept(conn *connection) error {
	var message transport.Message[transport.KeyExchangeMessage]
	conn.readJSON(&message)

	if message.Type != transport.MessageTypeID {
		return fmt.Errorf("received invalid message type: %v", message.Type)
	}
	if message.Payload.ID == "" {
		return errors.New("no client id provided")
	}

	id := message.Payload.ID
	publicKey := message.Payload.PublicKey

	_, exists := c.get(id)
	if exists {
		return errors.New("connection already exists")
	}

	c.set(conn.withID(id).withPublicKey(publicKey))
	slog.Info("connection accepted", "id", id)
	return nil
}

func (c *connections) drop(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, exists := c.data[id]
	if !exists {
		slog.Error("could not find connection", "id", id)
		return
	}
	conn.close()
	delete(c.data, id)
	slog.Info("connection dropped", "id", id)
}

func (c *connections) get(id string) (*connection, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, exists := c.data[id]
	return conn, exists
}

func (c *connections) set(conn *connection) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[conn.id] = conn
}

func (c *connections) warn(timeout time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.data) == 0 {
		return
	}

	slog.Info("warning all connections")
	for _, conn := range c.data {
		conn.writeJSON(transport.Message[transport.InfoMessage]{
			Type: transport.MessageTypeInfo,
			Payload: transport.InfoMessage{
				Text: fmt.Sprintf("host wants to shut down the server in: %s", timeout.String()),
			},
		})
	}
}

func (c *connections) close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.data) == 0 {
		return
	}

	slog.Info("closing all connections")
	for _, conn := range c.data {
		conn.close()
	}
}
