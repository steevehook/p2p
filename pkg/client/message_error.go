package client

import (
	"fmt"

	"github.com/steevehook/p2p/pkg/transport"
)

func (c *Client) processErrorMessage(message transport.ErrorMessage) error {
	fmt.Printf("\n%s", c.error(message.Text))
	return nil
}
