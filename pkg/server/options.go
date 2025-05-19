package server

type option interface {
	apply(*Server)
}

func WithPort(port int) option {
	return &portOption{
		port: port,
	}
}

type portOption struct {
	port int
}

func (p *portOption) apply(srv *Server) {
	srv.port = p.port
}
