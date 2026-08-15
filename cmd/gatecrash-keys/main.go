// Command gatecrash-keys is the organizer's toolkit: it makes keys, issues
// tickets, and signs the manifest the box ingests.
//
// It runs on the organizer's own machine and never on the box, because it holds
// the one secret the box must not have: the private key that mints tickets. A box
// that could sign its own manifest could invent tickets, and then the audit log
// would be evidence of nothing.
//
// Subcommands:
//
//	keygen     make an organizer key pair and a root master key
//	venue      write a starter venue plan to edit
//	issue      issue tickets against a venue plan
//	manifest   sign a manifest from a plan and a ticket list
//	seal       encrypt a manifest under a passphrase for transport
//	inspect    describe a manifest without trusting it
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/ManasMadan/gatecrash/internal/version"
)

func main() {
	if err := run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "gatecrash-keys: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return errors.New("no command given")
	}
	switch os.Args[1] {
	case "keygen":
		return keygen(os.Args[2:])
	case "venue":
		return starterVenue(os.Args[2:])
	case "issue":
		return issue(os.Args[2:])
	case "manifest":
		return signManifest(os.Args[2:])
	case "seal":
		return seal(os.Args[2:])
	case "inspect":
		return inspect(os.Args[2:])
	case "version", "--version":
		fmt.Println(version.String())
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gatecrash-keys — the organizer's toolkit

Usage:
  gatecrash-keys keygen -out keys.json           make an organizer key pair
  gatecrash-keys venue -out venue.json           write a starter venue plan
  gatecrash-keys issue -keys k -venue v -n 500   issue tickets
  gatecrash-keys manifest -keys k -venue v \
      -tickets t -event "Name" -out manifest.json
  gatecrash-keys seal -in manifest.json -out sealed.json
  gatecrash-keys inspect manifest.json

This runs on your machine and never on the box. The box gets the manifest; you
keep the key. A box that could sign its own manifest could invent tickets.
`)
}

// writeJSONFile writes indented JSON, refusing to clobber an existing file.
//
// Refusing rather than overwriting because every file this command writes is
// either a key or a ticket list, and silently replacing either is a category of
// mistake with no undo.
func writeJSONFile(path string, mode os.FileMode, body any) error {
	if path == "-" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(body)
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; move it out of the way first", path)
	}

	raw, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), mode)
}

// readJSONFile reads a JSON file.
func readJSONFile(path string, into any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	return nil
}
