package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithPort(t *testing.T) {
	expectedPort := 8000
	srv := &Server{}

	WithPort(expectedPort).apply(srv)

	assert.Equal(t, expectedPort, srv.port)
}
