package client

import (
	"encoding/json"
	"fmt"

	"github.com/steevehook/p2p/pkg/transport"
)

func (c *Client) processMessage(message transport.Message[json.RawMessage]) error {
	switch message.Type {
	case transport.MessageTypeInfo:
		return c.processInfoMessage(decode[transport.InfoMessage](message))
	case transport.MessageTypeError:
		return c.processErrorMessage(decode[transport.ErrorMessage](message))
	case transport.MessageTypeKeyExchange:
		return c.processKeyExchangeMessage(decode[transport.KeyExchangeMessage](message))
	case transport.MessageTypeDisconnect:
		return c.processDisconnectMessage(decode[transport.DisconnectMessage](message))
	case transport.MessageTypePayment:
		return c.processPaymentMessage(decode[transport.PaymentMessage](message))
	}

	return fmt.Errorf("unknown message type: %s", message.Type)
}

func decode[T any](message transport.Message[json.RawMessage]) T {
	var payload T
	_ = json.Unmarshal(message.Payload, &payload)
	return payload
}
