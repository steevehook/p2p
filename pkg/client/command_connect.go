package client

import (
	"fmt"

	"github.com/steevehook/p2p/pkg/transport"
)

func (c *Client) processConnectCommand(arguments ...string) error {
	if len(arguments) != 1 {
		return fmt.Errorf("usage: connect <peer_id>")
	}

	message := transport.Message[transport.ConnectMessage]{
		Type: transport.MessageTypeConnect,
		Payload: transport.ConnectMessage{
			ID:       c.keyPair.ID(),
			TargetID: arguments[0],
		},
	}
	bs, err := transport.JSONEncode(message)
	if err != nil {
		return err
	}

	c.conn.writeLine(string(bs))
	return nil
}
