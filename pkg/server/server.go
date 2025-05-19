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

func New(options ...option) (*Server, error) {
	srv := &Server{
		port: 9000,
		connections: &connections{
			data: map[string]*connection{},
		},
		connectionsCloseTimeout: 5 * time.Second,
		tcpListenerDeadline:     2 * time.Second,
		quit:                    make(chan struct{}),
		exited:                  make(chan struct{}),
	}
	for _, opt := range options {
		opt.apply(srv)
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", srv.port))
	if err != nil {
		slog.Error("could not listen on port", "port", srv.port, "error", err)
		return nil, err
	}
	srv.listener = l

	go srv.serve()
	return srv, nil
}

type Server struct {
	port                    int
	listener                net.Listener
	connections             *connections
	connectionsCloseTimeout time.Duration
	tcpListenerDeadline     time.Duration
	quit                    chan struct{}
	exited                  chan struct{}
	stop                    sync.Once
}

func (srv *Server) Stop() {
	srv.stop.Do(func() {
		slog.Info("stopping the p2p server")
		close(srv.quit)
		<-srv.exited
		slog.Info("p2p server successfully stopped")
	})
}

func (srv *Server) Exited() <-chan struct{} {
	return srv.exited
}

// serve listens for incoming tcp connections and handles them.
func (srv *Server) serve() {
	logger := slog.With("port", srv.port)
	logger.Info("listening for connections")

	for {
		select {
		case <-srv.quit:
			err := srv.listener.Close()
			if err != nil {
				logger.Error("could not close tcp listener", "error", err)
			}

			srv.connections.close()

			close(srv.exited)
			return

		default:
			tcpListener := srv.listener.(*net.TCPListener)
			err := tcpListener.SetDeadline(time.Now().Add(srv.tcpListenerDeadline))
			if err != nil {
				logger.Error("could not set tcp listener deadline", "error", err)
			}

			tcpConn, err := tcpListener.Accept()
			var oppErr *net.OpError
			if errors.As(err, &oppErr) && oppErr.Timeout() {
				continue
			}
			if err != nil {
				logger.Error("could not accept tcp connection", "error", err)
				continue
			}

			conn := newConnection(tcpConn)
			if err = srv.connections.accept(conn); err != nil {
				logger.Error("could not accept connection", "error", err)
				continue
			}

			go srv.handle(conn)
		}
	}
}

// handle handles individual connections that were accepted and identified by the server.
func (srv *Server) handle(conn *connection) {
	defer srv.connections.drop(conn.id)

	messageCh := make(chan transport.Message[json.RawMessage])
	exitCh := make(chan struct{})
	scanner := bufio.NewScanner(conn.conn)

	go func() {
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			var message transport.Message[json.RawMessage]
			if err := json.Unmarshal([]byte(line), &message); err != nil {
				slog.Error("could not unmarshal message", "error", err)
				continue
			}

			switch message.Type {
			case transport.MessageTypeExit:
				close(exitCh)
			case transport.MessageTypeConnect:
				// send the messages to the bridged connection channel
				messageCh <- message
			default:
				// send the messages to the main loop channel
				conn.messageCh <- message
			}
		}
	}()

	for {
		select {
		case <-exitCh:
			close(conn.exit)
			return
		case message := <-messageCh:
			switch message.Type {
			case transport.MessageTypeConnect:
				var connectMessage transport.ConnectMessage
				if err := json.Unmarshal(message.Payload, &connectMessage); err != nil {
					slog.Error("could not unmarshal the connect message", "error", err)
					continue
				}

				if conn.id == connectMessage.TargetID {
					conn.writeJSON(transport.Message[transport.ErrorMessage]{
						Type: transport.MessageTypeError,
						Payload: transport.ErrorMessage{
							Text: "cannot connect to yourself",
						},
					})
					continue
				}

				dstConn, exists := srv.connections.get(connectMessage.TargetID)
				if !exists {
					conn.writeJSON(transport.Message[transport.ErrorMessage]{
						Type: transport.MessageTypeError,
						Payload: transport.ErrorMessage{
							Text: "peer not found",
						},
					})
					continue
				}

				srv.bridge(conn, dstConn, exitCh)
			}
		}
	}
}

// bridge establishes a bidirectional bridge between two connections.
// if any of the connections drops the bridge, the other connection will be notified
// and the bridge will be closed.
func (srv *Server) bridge(src, dst *connection, exit chan struct{}) {
	slog.Info("starting bidirectional bridge", "source", src.id, "destination", dst.id)
	defer slog.Info("stopping bidirectional bridge", "source", src.id, "destination", dst.id)

	src.writeJSON(transport.Message[transport.KeyExchangeMessage]{
		Type: transport.MessageTypeKeyExchange,
		Payload: transport.KeyExchangeMessage{
			ID:        dst.id,
			PublicKey: dst.publicKey,
		},
	})
	dst.writeJSON(transport.Message[transport.KeyExchangeMessage]{
		Type: transport.MessageTypeKeyExchange,
		Payload: transport.KeyExchangeMessage{
			ID:        src.id,
			PublicKey: src.publicKey,
		},
	})

	src.writeJSON(transport.Message[transport.InfoMessage]{
		Type: transport.MessageTypeInfo,
		Payload: transport.InfoMessage{
			Text: fmt.Sprintf("connected to peer %s", dst.id),
		},
	})
	dst.writeJSON(transport.Message[transport.InfoMessage]{
		Type: transport.MessageTypeInfo,
		Payload: transport.InfoMessage{
			Text: fmt.Sprintf("peer %s connected to you", src.id),
		},
	})

	var wg sync.WaitGroup
	done := make(chan struct{})
	forward := func(src, dst *connection) {
		defer wg.Done()
		for {
			select {
			case <-exit:
				return
			case <-done:
				return
			case msg, ok := <-src.messageCh:
				if !ok {
					return
				}
				dst.writeJSON(msg)
			}
		}
	}

	wg.Add(2)
	go forward(src, dst)
	go forward(dst, src)

	go func() {
		select {
		case <-src.exit:
			dst.writeJSON(transport.Message[transport.DisconnectMessage]{
				Type: transport.MessageTypeDisconnect,
				Payload: transport.DisconnectMessage{
					ID: src.id,
				},
			})
		case <-dst.exit:
			src.writeJSON(transport.Message[transport.DisconnectMessage]{
				Type: transport.MessageTypeDisconnect,
				Payload: transport.DisconnectMessage{
					ID: dst.id,
				},
			})
		}
		close(done)
	}()

	wg.Wait()
}
