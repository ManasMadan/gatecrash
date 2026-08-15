// Command gatecrash-demo runs a whole event in one process and narrates it.
//
// It exists because "offline-first multi-stage ticketing with a tamper-evident
// log" is a sentence nobody believes until they watch it happen. This builds a
// venue, issues tickets, brings up a real box with a real SQLite database and a
// real HTTP server, enrols scanners through the real enrollment ceremony, and then
// walks a crowd through the gates — printing what a bouncer would see at each
// step.
//
// Everything it drives goes over HTTP against the same handlers the box serves in
// production. Nothing is stubbed. The only thing that is not real is the clock,
// which is driven forwards so an evening fits in a second.
//
//	go run ./cmd/gatecrash-demo
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flags := flag.NewFlagSet("gatecrash-demo", flag.ContinueOnError)
	keep := flags.String("keep", "", "keep the box's data directory here instead of a temp dir")
	quiet := flags.Bool("quiet", false, "print only the summary")
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if err := runDemo(*keep, *quiet); err != nil {
		fmt.Fprintf(os.Stderr, "\ngatecrash-demo: %v\n", err)
		os.Exit(1)
	}
}
