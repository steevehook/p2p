package client

import (
	"fmt"
	"strconv"

	"github.com/steevehook/p2p/pkg/transport"
)

func (c *Client) processPayCommand(arguments ...string) error {
	if c.aesKey == nil {
		return fmt.Errorf("not connected to a peer: connect <peer_id>")
	}

	if len(arguments) != 1 {
		return fmt.Errorf("usage: pay <amount>")
	}

	amount, err := strconv.ParseFloat(arguments[0], 64)
	if err != nil {
		return fmt.Errorf("invalid amount: %s", arguments[0])
	}
	if amount <= 0 {
		return fmt.Errorf("amount must be greater than 0")
	}

	message := transport.Message[transport.PaymentMessage]{
		Secure: true,
		Type:   transport.MessageTypePayment,
		Payload: transport.PaymentMessage{
			ID:     c.keyPair.ID(),
			Amount: amount,
		},
	}
	bs, err := transport.JSONEncode(message, c.aesKey)
	if err != nil {
		return err
	}

	c.conn.writeLine(string(bs))
	c.wallet.Withdraw(amount)
	c.printInfo("payment sent")
	return nil
}
