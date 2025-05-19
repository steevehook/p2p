package client

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/steevehook/p2p/pkg/crypto"
	"github.com/steevehook/p2p/pkg/transport"
	"github.com/steevehook/p2p/pkg/wallets"
)

func New(options ...option) (*Client, error) {
	client := &Client{
		address: "localhost:9000",
		quit:    make(chan struct{}),
		exited:  make(chan struct{}),
	}
	for _, opt := range options {
		opt.apply(client)
	}

	keyPair, err := crypto.NewKeyPair()
	if err != nil {
		return nil, err
	}
	client.keyPair = keyPair
	client.wallet = wallets.NewWallet(keyPair.ID())

	conn, err := net.Dial("tcp", client.address)
	if err != nil {
		return nil, err
	}
	client.conn = newConnection(conn)

	go client.start()
	return client, nil
}

type Client struct {
	conn         *connection
	address      string
	keyPair      *crypto.KeyPair
	sharedSecret crypto.SharedSecret
	aesKey       crypto.AESKey
	wallet       *wallets.Wallet
	quit         chan struct{}
	exited       chan struct{}
	stop         sync.Once
}

func (c *Client) Stop() {
	c.stop.Do(func() {
		close(c.quit)
		<-c.exited

		message := transport.Message[transport.ExitMessage]{
			Type: transport.MessageTypeExit,
			Payload: transport.ExitMessage{
				ID: c.keyPair.ID(),
			},
		}
		bs, _ := transport.JSONEncode(message)
		c.conn.writeLine(string(bs))
		c.conn.close()
	})
}

func (c *Client) Exited() <-chan struct{} {
	return c.exited
}

func (c *Client) start() {
	id := c.keyPair.ID()
	message := transport.Message[transport.IDMessage]{
		Type: transport.MessageTypeID,
		Payload: transport.IDMessage{
			ID:        id,
			PublicKey: c.keyPair.Base64XPublicKey(),
		},
	}
	bs, _ := transport.JSONEncode(message)
	c.conn.writeLine(string(bs))
	c.printRegular(fmt.Sprintf("welcome to the p2p server\n%s", id))

	go c.read()
	c.write()

	<-c.quit
	close(c.exited)
}

// read reads all the messages either from the server or from the peered connection
// and dispatches them to the appropriate command.
func (c *Client) read() {
	reader := bufio.NewReader(c.conn.conn)

	for {
		select {
		case <-c.quit:
			return
		default:
			err := c.conn.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if err != nil {
				fmt.Println("could not set read deadline:", err)
				c.Stop()
				return
			}

			line, err := reader.ReadBytes('\n')
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				if err == io.EOF {
					fmt.Println("\nserver closed the connection")
				} else if !strings.Contains(err.Error(), "use of closed network connection") {
					fmt.Println("\nread error:", err)
				}
				c.Stop()
			}

			var message transport.Message[json.RawMessage]
			err = transport.JSONDecode(line, &message, c.aesKey)
			if err != nil {
				c.printRegular(fmt.Sprintf("could not decode message: %v", err))
				continue
			}

			err = c.processMessage(message)
			if err != nil {
				c.printError(fmt.Sprintf("message processing error: %v", err))
			}
		}
	}
}

// write reads the user input from stdin and sends the appropriate message
// to either the server or to the peer connection.
func (c *Client) write() {
	input := make(chan string)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			input <- scanner.Text()
		}
		close(input)
	}()

	for {
		select {
		case <-c.quit:
			return
		case text, ok := <-input:
			if !ok {
				return
			}

			line := strings.TrimSpace(text)
			values := strings.Split(line, " ")
			command := strings.ToLower(values[0])

			err := c.processCommand(command, values[1:]...)
			if err != nil {
				c.printError(fmt.Sprintf("command error: %v", err))
				continue
			}
		}
	}
}

func (c *Client) printRegular(text string) {
	prompt := c.prompt()
	if len(text) == 0 {
		fmt.Printf("%s ", prompt)
		return
	}

	fmt.Printf("%s\n%s ", text, prompt)
}

func (c *Client) printInfo(text string) {
	fmt.Print(c.info(text))
}

func (c *Client) printError(text string) {
	fmt.Print(c.error(text))
}

func (c *Client) prompt() string {
	prompt := ">"
	if c.aesKey != nil {
		prompt = ">>>"
	}

	return prompt
}

func (c *Client) info(text string) string {
	prompt := c.prompt()
	return fmt.Sprintf("ℹ️ %s\n%s ", text, prompt)
}

func (c *Client) error(text string) string {
	prompt := c.prompt()
	return fmt.Sprintf("❌  %s\n%s ", text, prompt)
}
