package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithServerAddress(t *testing.T) {
	expectedAddress := "localhost:8000"
	client := &Client{}

	WithServerAddress(expectedAddress).apply(client)

	assert.Equal(t, expectedAddress, client.address)
}
