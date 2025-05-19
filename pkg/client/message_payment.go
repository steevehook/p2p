package client

import (
	"fmt"

	"github.com/steevehook/p2p/pkg/transport"
)

func (c *Client) processPaymentMessage(message transport.PaymentMessage) error {
	c.wallet.Deposit(message.Amount)
	fmt.Printf("\n%s", c.info(fmt.Sprintf("you were paid %.2f", message.Amount)))
	return nil
}
