package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/steevehook/p2p/pkg/client"
)

func main() {
	address := flag.String("address", "localhost:9000", "server address")

	flag.Parse()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	p2pClient, err := client.New(client.WithServerAddress(*address))
	if err != nil {
		fmt.Println("could not create the p2p client:", err)
		os.Exit(1)
	}

	go func() {
		if err = p2pClient.Start(); err != nil {
			fmt.Println("could not start the p2p client:", err)
			os.Exit(1)
		}
	}()

	select {
	case <-stop:
		fmt.Println("\nclient was stopped")
		p2pClient.Stop()
	case <-p2pClient.Exited():
		return
	}
}
