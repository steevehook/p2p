package transport

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
)

var testAESKey = []byte{
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
	0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
}

type transportSuite struct {
	suite.Suite
}

func (s *transportSuite) Test_JSONEncode_Insecure() {
	expectedJSON := `{"secure":false,"type":"test","payload":"test payload"}`
	message := Message[string]{
		Secure:  false,
		Type:    "test",
		Payload: "test payload",
	}

	bs, err := JSONEncode(message)

	s.NoError(err)
	s.JSONEq(expectedJSON, string(bs))
}

func (s *transportSuite) Test_JSONEncode_Secure() {
	var expectedMessage Message[string]
	message := Message[int]{
		Secure:  true,
		Type:    "test",
		Payload: 5,
	}

	bs, err := JSONEncode(message, testAESKey)
	s.Require().NoError(json.Unmarshal(bs, &expectedMessage))

	s.NoError(err)
	s.Equal(MessageType("test"), expectedMessage.Type)
	s.Equal(true, expectedMessage.Secure)
	s.IsType("", expectedMessage.Payload)
}

func (s *transportSuite) Test_JSONEncode_SecureMissingFlag() {
	var expectedMessage Message[string]
	message := Message[int]{
		Type:    "test",
		Payload: 5,
	}

	bs, err := JSONEncode(message, testAESKey)
	s.Require().NoError(json.Unmarshal(bs, &expectedMessage))
	fmt.Println("bs", string(bs))

	s.NoError(err)
	s.Equal(MessageType("test"), expectedMessage.Type)
	s.Equal(true, expectedMessage.Secure)
	s.IsType("", expectedMessage.Payload)
}

func (s *transportSuite) Test_JSONDecode_Insecure() {
	expectedMessage := Message[string]{
		Secure:  false,
		Type:    "test",
		Payload: "test payload",
	}
	bs := []byte(`{"secure":false,"type":"test","payload":"test payload"}`)

	var message Message[string]
	err := JSONDecode(bs, &message)

	s.NoError(err)
	s.Equal(expectedMessage, message)
}

func (s *transportSuite) Test_JSONDecode_Secure() {
	expectedMessage := Message[int]{
		Secure:  true,
		Type:    "test",
		Payload: 5,
	}
	bs := []byte(`{"secure":true,"type":"test","payload":"cKL1wkXbN3Tf/8obDEyyXSJKVVMR2UHM4UWheok="}`)

	var message Message[int]
	err := JSONDecode(bs, &message, testAESKey)

	s.NoError(err)
	s.Equal(expectedMessage, message)
}

func TestTransport(t *testing.T) {
	suite.Run(t, new(transportSuite))
}
