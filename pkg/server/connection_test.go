package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/steevehook/p2p/pkg/transport"
	"github.com/stretchr/testify/suite"
)

const (
	testConnID    = "test-conn-id"
	testPublicKey = "test-public-key"
)

type connectionSuite struct {
	suite.Suite
	tcpConn       *dummyConn
	tcpConnReader *bytes.Buffer
	tcpConnWriter *bytes.Buffer
	conn          *connection
}

func (s *connectionSuite) SetupTest() {
	s.tcpConnReader = &bytes.Buffer{}
	s.tcpConnWriter = &bytes.Buffer{}
	s.tcpConn = &dummyConn{
		Reader: s.tcpConnReader,
		Writer: s.tcpConnWriter,
	}
	s.conn = &connection{
		id:        testConnID,
		publicKey: testPublicKey,
		conn:      s.tcpConn,
		messageCh: make(chan transport.Message[json.RawMessage]),
		exit:      make(chan struct{}),
	}
}

func (s *connectionSuite) Test_newConnection() {
	conn := newConnection(s.tcpConn)

	s.Equal(s.tcpConn, conn.conn)
	s.NotNil(conn.exit)
	s.NotNil(conn.messageCh)
}

func (s *connectionSuite) Test_withID() {
	expectedID := "test-id"
	conn := connection{}

	conn.withID(expectedID)

	s.Equal(expectedID, conn.id)
}

func (s *connectionSuite) Test_withPublicKey() {
	expectedPublicKey := "test-public-key"
	conn := connection{}

	conn.withPublicKey(expectedPublicKey)

	s.Equal(expectedPublicKey, conn.publicKey)
}

func (s *connectionSuite) Test_writeJSON() {
	expected := `{"key":"value"}`

	s.conn.writeJSON(map[string]any{
		"key": "value",
	})

	s.JSONEq(expected, s.tcpConnWriter.String())
}

func TestConnection(t *testing.T) {
	suite.Run(t, new(connectionSuite))
}
