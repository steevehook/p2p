package client

import (
	"fmt"
)

func (c *Client) processBalanceCommand() error {
	c.printInfo(fmt.Sprintf("%.2f", c.wallet.GetBalance()))
	return nil
}
