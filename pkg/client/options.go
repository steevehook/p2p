package client

type option interface {
	apply(*Client)
}

func WithServerAddress(address string) option {
	return &serverAddressOption{
		address: address,
	}
}

type serverAddressOption struct {
	address string
}

func (o *serverAddressOption) apply(c *Client) {
	if o.address == "" {
		return
	}

	c.address = o.address
}
