package client

import (
	"fmt"

	"github.com/steevehook/p2p/pkg/transport"
)

func (c *Client) processDisconnectMessage(message transport.DisconnectMessage) error {
	c.sharedSecret = nil
	c.aesKey = nil

	fmt.Printf("\n%s", c.info(fmt.Sprintf("peer: %s got disconnected", message.ID)))
	return nil
}
