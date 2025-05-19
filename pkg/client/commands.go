package client

import (
	"fmt"
)

const (
	helpCommandName    = "help"
	balanceCommandName = "balance"
	payCommandName     = "pay"
	connectCommandName = "connect"
	exitCommandName    = "exit"
)

var commands = map[string]struct {
	description string
	usage       string
	run         func(*Client, []string) error
}{
	helpCommandName: {
		description: "Displays this message",
		usage:       "help",
	},
	balanceCommandName: {
		description: "Displays the current balance of the wallet",
		usage:       "balance",
		run: func(c *Client, arguments []string) error {
			return c.processBalanceCommand()
		},
	},
	payCommandName: {
		description: "Pay a specified amount to the connected peer",
		usage:       "pay <amount>",
		run: func(c *Client, arguments []string) error {
			return c.processPayCommand(arguments...)
		},
	},
	connectCommandName: {
		description: "Connect to a peer with the specified id",
		usage:       "connect <peer_id>",
		run: func(c *Client, arguments []string) error {
			return c.processConnectCommand(arguments...)
		},
	},
	exitCommandName: {
		description: "Exits the client session",
		usage:       "exit",
		run: func(c *Client, arguments []string) error {
			return c.processExitCommand()
		},
	},
}

func (c *Client) processCommand(command string, arguments ...string) error {
	if command == helpCommandName {
		return c.processHelpCommand()
	}

	cmd, exists := commands[command]
	if exists {
		return cmd.run(c, arguments)
	}

	return fmt.Errorf("unknown command: %s", command)
}
