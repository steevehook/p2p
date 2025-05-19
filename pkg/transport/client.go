package transport

const (
	MessageTypeInfo        MessageType = "info"
	MessageTypeError       MessageType = "error"
	MessageTypeKeyExchange MessageType = "key_exchange"
	MessageTypeDisconnect  MessageType = "disconnect"
	MessageTypePayment     MessageType = "payment"
)

type InfoMessage struct {
	Text string `json:"text"`
}

type ErrorMessage struct {
	Text string `json:"text"`
}

type KeyExchangeMessage struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"`
}

type DisconnectMessage struct {
	ID string `json:"id"`
}

type PaymentMessage struct {
	ID     string  `json:"id"`
	Amount float64 `json:"amount"`
}
