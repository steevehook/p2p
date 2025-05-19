package transport

const (
	MessageTypeID      MessageType = "id"
	MessageTypeConnect MessageType = "connect"
	MessageTypeExit    MessageType = "exit"
)

type IDMessage struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"`
}

type ConnectMessage struct {
	ID       string `json:"id"`
	TargetID string `json:"targetId"`
}

type ExitMessage struct {
	ID string `json:"id"`
}
