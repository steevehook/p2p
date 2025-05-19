package transport

import (
	"encoding/json"
	"fmt"

	"github.com/steevehook/p2p/pkg/crypto"
)

type MessageType string

type Message[T any] struct {
	Secure  bool        `json:"secure"`
	Type    MessageType `json:"type"`
	Payload T           `json:"payload"`
}

func JSONEncode[T any](message Message[T], aesKey ...crypto.AESKey) ([]byte, error) {
	var key crypto.AESKey
	if len(aesKey) > 0 {
		key = aesKey[0]
	}
	if key != nil {
		message.Secure = true
	}

	if key == nil {
		bs, err := json.Marshal(message)
		if err != nil {
			return nil, fmt.Errorf("json marshal insecure error: %w", err)
		}
		return bs, nil
	}

	payload, err := json.Marshal(message.Payload)
	if err != nil {
		return nil, fmt.Errorf("json marshal payload error: %w", err)
	}

	encrypted, err := crypto.AESEncrypt(payload, key)
	if err != nil {
		return nil, fmt.Errorf("aes encrypt error: %w", err)
	}

	encryptedMessage := Message[string]{
		Secure:  true,
		Type:    message.Type,
		Payload: encrypted,
	}
	bs, err := json.Marshal(encryptedMessage)
	if err != nil {
		return nil, fmt.Errorf("json marshal secure error: %w", err)
	}
	return bs, nil
}

func JSONDecode(bs []byte, v any, aesKey ...crypto.AESKey) error {
	var key crypto.AESKey
	if len(aesKey) > 0 {
		key = aesKey[0]
	}

	var envelope Message[json.RawMessage]
	if err := json.Unmarshal(bs, &envelope); err != nil {
		return fmt.Errorf("json unmarshal envelope error: %w", err)
	}
	if !envelope.Secure {
		if err := json.Unmarshal(bs, v); err != nil {
			return fmt.Errorf("json unmarshal insecure error: %w", err)
		}
		return nil
	}

	var encrypted string
	if err := json.Unmarshal(envelope.Payload, &encrypted); err != nil {
		return fmt.Errorf("unquote encrypted payload: %w", err)
	}

	decrypted, err := crypto.AESDecrypt(encrypted, key)
	if err != nil {
		return err
	}
	envelope.Payload = decrypted

	bs, err = json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("json marshal error: %w", err)
	}

	if err = json.Unmarshal(bs, v); err != nil {
		return fmt.Errorf("json unmarshal secure error: %w", err)
	}

	return nil
}
