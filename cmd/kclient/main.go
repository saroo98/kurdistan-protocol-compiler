package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"

	"kurdistan/internal/ir"
	"kurdistan/internal/relay"
	ktrace "kurdistan/internal/trace"
)

func main() {
	profilePath := flag.String("profile", "", "profile path")
	server := flag.String("server", "127.0.0.1:7000", "loopback server address")
	message := flag.String("message", "", "message to send to local echo demo")
	tracePath := flag.String("trace", "", "optional trace JSONL path")
	flag.Parse()
	if *profilePath == "" {
		fmt.Fprintln(os.Stderr, "--profile is required")
		os.Exit(2)
	}
	if !relay.IsLoopbackAddress(*server) {
		fmt.Fprintln(os.Stderr, "--server must be a loopback address")
		os.Exit(1)
	}
	p, err := ir.LoadProfile(*profilePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rec, err := ktrace.OpenRecorder(*tracePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer rec.Close()
	input := []byte(*message)
	echo, err := relay.ClientRoundTrip(context.Background(), p, *server, input, rec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !bytes.Equal(input, echo) {
		fmt.Fprintln(os.Stderr, "echo response mismatch")
		os.Exit(1)
	}
	fmt.Printf("round_trip_verified: bytes=%d\n", len(input))
}
