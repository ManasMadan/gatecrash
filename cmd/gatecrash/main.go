// Command gatecrash is the box: one static binary that runs an entire event.
//
// It serves the scanner API, the attendee ticket wallet, the organizer dashboard,
// mDNS, a wildcard DNS resolver, a captive portal, a DHCP server and a UDP beacon
// — all from one process, on a Raspberry Pi, with no internet.
//
// Subcommands:
//
//	serve     run the box (the default)
//	ingest    load a signed manifest and exit
//	verify    replay the audit chain and report
//	export    write the signed attendance report
//	doctor    check the box's own state and exit
//	version   print the build
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ManasMadan/gatecrash/internal/version"
)

func main() {
	// Exit codes are meaningful because a systemd unit and a watchdog both read
	// them: 0 is a clean stop, 1 is a failure worth restarting for, 2 is a usage
	// error that restarting will not fix.
	if err := run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "gatecrash: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return serve(nil)
	}

	switch os.Args[1] {
	case "serve":
		return serve(os.Args[2:])
	case "ingest":
		return ingest(os.Args[2:])
	case "verify":
		return verify(os.Args[2:])
	case "export":
		return export(os.Args[2:])
	case "doctor":
		return doctor(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(version.String())
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		// A bare flag with no subcommand means the operator is running the box, so
		// treat it as `serve`. Anything else is a typo worth naming.
		if os.Args[1][0] == '-' {
			return serve(os.Args[1:])
		}
		usage()
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gatecrash — an events platform that works when the internet doesn't

Usage:
  gatecrash [serve] [flags]      run the box
  gatecrash ingest <manifest>    load a signed manifest and exit
  gatecrash verify               replay the audit chain and report
  gatecrash export [file]        write the signed attendance report
  gatecrash doctor               check the box's own state
  gatecrash version              print the build

Run "gatecrash serve -h" for the flags.

Everything has a working default. A box with no configuration at all boots, mints
its own certificate authority, serves on :8443, and waits for a manifest.
`)
}

// signalContext returns a context cancelled on SIGINT or SIGTERM.
//
// Both, because SIGINT is a person with a terminal and SIGTERM is systemd, and a
// box that only handles one of them either cannot be stopped by hand or cannot be
// restarted by its own service manager. The second signal exits immediately: an
// operator pressing Ctrl-C twice means it now.
func signalContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signals
		cancel()
		<-signals
		fmt.Fprintln(os.Stderr, "gatecrash: second signal, exiting now")
		os.Exit(130)
	}()

	return ctx, func() {
		signal.Stop(signals)
		cancel()
	}
}

// randomToken returns a token for the dashboard when none was configured.
//
// Generated rather than defaulted, because a box with a hardcoded admin token is a
// box with no admin token. It is printed on the console at boot, which is the one
// channel an operator standing next to the hardware definitely has.
func randomToken() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating an admin token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
