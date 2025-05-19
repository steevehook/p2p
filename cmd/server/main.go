package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/steevehook/p2p/pkg/server"
)

func main() {
	port := flag.Int("port", 9000, "server port")

	flag.Parse()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	p2pServer, err := server.New(server.WithPort(*port))
	if err != nil {
		slog.Error("could not create the p2p server", "error", err)
		os.Exit(1)
	}

	select {
	case <-stop:
		p2pServer.Stop()
	case <-p2pServer.Exited():
		return
	}
}
