package client

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

// Tests are the best practice I know, did not have time to write them.
// but hey, feel free to check the other test files :P

type clientSuite struct {
	suite.Suite
}

func TestClient(t *testing.T) {
	suite.Run(t, new(clientSuite))
}
