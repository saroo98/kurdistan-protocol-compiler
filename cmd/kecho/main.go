package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"kurdistan/internal/relay"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9000", "loopback listen address")
	flag.Parse()
	if !relay.IsLoopbackAddress(*listen) {
		fmt.Fprintln(os.Stderr, "--listen must be a loopback address")
		os.Exit(1)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	logger := log.New(os.Stderr, "kecho: ", log.LstdFlags)
	logger.Printf("listening on %s", ln.Addr())
	if err := relay.ServeEcho(ctx, ln, logger); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
