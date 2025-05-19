package client

import (
	"github.com/steevehook/p2p/pkg/crypto"
	"github.com/steevehook/p2p/pkg/transport"
)

func (c *Client) processKeyExchangeMessage(message transport.KeyExchangeMessage) error {
	publicKey, err := crypto.Base64DecodePublicKey(message.PublicKey)
	if err != nil {
		return err
	}

	sharedSecret, err := crypto.ComputeX25519SharedSecret(c.keyPair.XPrivateKey, publicKey)
	if err != nil {
		return err
	}
	c.sharedSecret = sharedSecret

	aesKey, err := crypto.DeriveAESKey(sharedSecret, nil, nil)
	if err != nil {
		return err
	}
	c.aesKey = aesKey

	return nil
}
