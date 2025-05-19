package client

import (
	"fmt"

	"github.com/steevehook/p2p/pkg/transport"
)

func (c *Client) processInfoMessage(message transport.InfoMessage) error {
	fmt.Printf("\n%s", c.info(message.Text))
	return nil
}
