package client

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
)

func (c *Client) processHelpCommand() error {
	type commandInfo struct {
		name        string
		description string
		usage       string
	}

	commandList := make([]commandInfo, 0, len(commands))
	for name, cmd := range commands {
		commandList = append(commandList, commandInfo{
			name:        name,
			description: cmd.description,
			usage:       cmd.usage,
		})
	}

	sort.Slice(commandList, func(i, j int) bool {
		return commandList[i].name < commandList[j].name
	})

	var sb strings.Builder
	w := tabwriter.NewWriter(&sb, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "COMMAND\tDESCRIPTION\tUSAGE\n")
	_, _ = fmt.Fprintf(w, "-------\t-----------\t-----\n")
	for _, cmd := range commandList {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", cmd.name, cmd.description, cmd.usage)
	}
	_ = w.Flush()

	c.printRegular(sb.String())
	return nil
}
