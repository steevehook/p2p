package client

import (
	"github.com/steevehook/p2p/pkg/transport"
)

func (c *Client) processExitCommand() error {
	message := transport.Message[transport.ExitMessage]{
		Type: transport.MessageTypeExit,
		Payload: transport.ExitMessage{
			ID: c.keyPair.ID(),
		},
	}

	bs, err := transport.JSONEncode(message)
	if err != nil {
		return err
	}

	c.conn.writeLine(string(bs))
	return nil
}
