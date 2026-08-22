// Command gatecrash-sim is the deterministic simulator.
//
// It is a first-class deliverable rather than a test folder, and the reason is what
// it can claim. A test suite says "the cases I thought of pass". This says "ten
// thousand seeded event-days, with partitions and power cuts and clocks two minutes
// apart, produced zero double admissions — and here is the seed that reproduces any
// one of them byte for byte".
//
// Two subcommands, for the two things worth simulating:
//
//	gatecrash-sim event  --seeds 10000     the redemption engine under injected faults
//	gatecrash-sim crowd  --sweep           the mesh, across density and relay constant
//
// Neither reads a clock, a network, or a random source it was not handed. A failure
// that cannot be replayed is a failure nobody can fix.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/simulation"
	"github.com/ManasMadan/gatecrash/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gatecrash-sim:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}

	switch args[0] {
	case "event":
		return runEvent(args[1:])
	case "crowd":
		return runCrowd(args[1:])
	case "version", "--version", "-v":
		fmt.Println(version.String())
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Print(`gatecrash-sim — the deterministic simulator

Usage:
  gatecrash-sim event [flags]     seeded event-days against the real redemption engine
  gatecrash-sim crowd [flags]     the mesh protocol against a model of a crowd

Run either with -h for its flags.

Every run is fully described by its seed. When one fails, the seed printed beside
it reproduces the whole event-day exactly, which is the only property that makes a
simulator worth having.
`)
}

func runEvent(args []string) error {
	flags := flag.NewFlagSet("event", flag.ContinueOnError)
	seeds := flags.Int("seeds", 100, "how many event-days to run")
	from := flags.Uint64("seed", 1, "the first seed; set this and -seeds 1 to replay one run")
	tickets := flags.Int("tickets", 300, "tickets issued")
	scans := flags.Int("scans", 3000, "scan attempts per event-day")
	scanners := flags.Int("scanners", 6, "gate devices")
	mode := flags.String("mode", "both", "strict, degraded, or both")
	workers := flags.Int("workers", runtime.NumCPU(), "how many event-days to run at once")
	asJSON := flags.Bool("json", false, "emit results as JSON")
	quiet := flags.Bool("quiet", false, "only report failures")

	// The fault probabilities, exposed so a failing seed can be narrowed down by
	// turning one off at a time.
	retry := flags.Float64("retry", 0.08, "chance a scan is redelivered with the same scan id")
	reuse := flags.Float64("reuse", 0.10, "chance a ticket is presented again")
	reorder := flags.Float64("reorder", 0.05, "chance a scan arrives out of order")
	offline := flags.Float64("offline", 0.06, "chance a scan was admitted offline by the scanner")
	skew := flags.Float64("skew", 0.03, "chance a scanner's clock jumps")
	powerCut := flags.Float64("power-cut", 0.002, "chance the box loses power")
	writeFail := flags.Float64("write-fail", 0.01, "chance a write is rejected")

	if err := flags.Parse(args); err != nil {
		return err
	}

	modes, err := parseModes(*mode)
	if err != nil {
		return err
	}

	base := simulation.EventConfig{
		Tickets:  *tickets,
		Scans:    *scans,
		Scanners: *scanners,
		Faults: simulation.Faults{
			Retry: *retry, Reuse: *reuse, Reorder: *reorder,
			Offline: *offline, Skew: *skew,
			PowerCut: *powerCut, WriteFail: *writeFail,
		},
	}

	started := time.Now()
	var (
		mu         sync.Mutex
		failures   []simulation.EventResult
		totals     simulation.EventResult
		runs       int
		verdicts   = map[engine.Verdict]int{}
		powerCuts  int
		flaggedAll int
	)

	for _, m := range modes {
		jobs := make(chan uint64)
		var wg sync.WaitGroup

		for worker := 0; worker < atLeast(1, *workers); worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for seed := range jobs {
					cfg := base
					cfg.Seed = seed
					cfg.Mode = m
					result := simulation.RunEvent(cfg)

					mu.Lock()
					runs++
					totals.Scans += result.Scans
					totals.Admitted += result.Admitted
					totals.Refused += result.Refused
					totals.Errors += result.Errors
					powerCuts += result.PowerCuts
					flaggedAll += result.Flagged
					for verdict, count := range result.Verdicts {
						verdicts[verdict] += count
					}
					if !result.OK() {
						failures = append(failures, result)
					} else if !*quiet && !*asJSON && *seeds <= 20 {
						fmt.Println(result)
					}
					mu.Unlock()
				}
			}()
		}

		for i := 0; i < *seeds; i++ {
			jobs <- *from + uint64(i)
		}
		close(jobs)
		wg.Wait()
	}

	sort.Slice(failures, func(i, j int) bool { return failures[i].Config.Seed < failures[j].Config.Seed })

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"runs": runs, "scans": totals.Scans, "admitted": totals.Admitted,
			"refused": totals.Refused, "errors": totals.Errors,
			"power_cuts": powerCuts, "flagged": flaggedAll,
			"failures": failures, "elapsed_ms": time.Since(started).Milliseconds(),
		})
	}

	fmt.Printf("\n%d event-days in %s\n", runs, time.Since(started).Round(time.Millisecond))
	fmt.Printf("  scans      %d\n", totals.Scans)
	fmt.Printf("  admitted   %d\n", totals.Admitted)
	fmt.Printf("  refused    %d\n", totals.Refused)
	fmt.Printf("  rejected   %d writes the box would not acknowledge\n", totals.Errors)
	fmt.Printf("  power cuts %d\n", powerCuts)
	fmt.Printf("  flagged    %d double uses detected\n", flaggedAll)

	fmt.Println("\n  verdicts")
	for _, verdict := range sortedVerdicts(verdicts) {
		fmt.Printf("    %-24s %d\n", verdict, verdicts[verdict])
	}

	if len(failures) == 0 {
		fmt.Printf("\nno invariant was violated in %d event-days.\n", runs)
		return nil
	}

	fmt.Printf("\n%d event-days violated an invariant:\n", len(failures))
	for _, failure := range failures {
		fmt.Printf("\n  %s\n", failure)
		for _, violation := range failure.Violations {
			fmt.Printf("    %s\n", violation)
		}
		fmt.Printf("    replay with: gatecrash-sim event -seed %d -seeds 1 -mode %s\n",
			failure.Config.Seed, failure.Config.Mode)
	}
	return fmt.Errorf("%d of %d event-days failed", len(failures), runs)
}

func runCrowd(args []string) error {
	flags := flag.NewFlagSet("crowd", flag.ContinueOnError)
	nodes := flags.Int("nodes", 500, "phones in the field")
	width := flags.Float64("width", 60, "field width in metres")
	height := flags.Float64("height", 40, "field height in metres")
	radioRange := flags.Float64("range", 20, "radio range in metres at even odds")
	k := flags.Float64("k", 3, "the relay constant")
	messages := flags.Int("messages", 10, "messages originated during the run")
	duration := flags.Duration("duration", 2*time.Minute, "how long the run lasts")
	boxes := flags.Int("boxes", 0, "venue boxes acting as bridged super-nodes")
	seed := flags.Uint64("seed", 7, "the seed")
	sweep := flags.Bool("sweep", false, "sweep density and relay constant, and print the table")
	asJSON := flags.Bool("json", false, "emit results as JSON")

	if err := flags.Parse(args); err != nil {
		return err
	}

	base := simulation.CrowdConfig{
		Width: *width, Height: *height, Range: *radioRange,
		Messages: *messages, Duration: *duration, Seed: *seed,
		Nodes: *nodes, K: *k,
	}
	// Boxes are placed on a line across the middle of the field, which is where a
	// venue would put them: spread out, covering the gaps between clusters.
	for i := 0; i < *boxes; i++ {
		base.Boxes = append(base.Boxes, simulation.Position{
			X: *width * (float64(i) + 0.5) / float64(*boxes),
			Y: *height / 2,
		})
	}

	var results []simulation.CrowdResult
	started := time.Now()

	if *sweep {
		results = simulation.Sweep(base, []int{50, 200, 500, 1000, 2000}, []float64{1, 2, 3, 5, 8})
	} else {
		results = []simulation.CrowdResult{simulation.RunCrowd(base)}
	}

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"results": results, "elapsed_ms": time.Since(started).Milliseconds(),
		})
	}

	for _, result := range results {
		fmt.Println(result)
	}
	fmt.Printf("\n%d runs in %s\n", len(results), time.Since(started).Round(time.Millisecond))

	if *sweep {
		fmt.Print(`
Reading the table: delivered is the fraction of (message, phone) pairs that
arrived at all, and tx/msg is the airtime each message cost. The pair is the whole
point — delivery alone is maximised by everybody relaying everything, which is the
broadcast storm this parameter exists to avoid.

The sparse rows are not a storm-control result. A thin crowd is simply not
connected, so delivery there is bounded by whether a path exists, and what helps
is the store-and-forward buffer rather than a larger relay constant.
`)
	}
	return nil
}

func parseModes(value string) ([]engine.Mode, error) {
	switch strings.ToLower(value) {
	case "strict":
		return []engine.Mode{engine.ModeStrict}, nil
	case "degraded":
		return []engine.Mode{engine.ModeDegraded}, nil
	case "both", "":
		return []engine.Mode{engine.ModeStrict, engine.ModeDegraded}, nil
	default:
		return nil, fmt.Errorf("unknown mode %q: want strict, degraded or both", value)
	}
}

func sortedVerdicts(counts map[engine.Verdict]int) []engine.Verdict {
	out := make([]engine.Verdict, 0, len(counts))
	for verdict := range counts {
		out = append(out, verdict)
	}
	sort.Slice(out, func(i, j int) bool {
		if counts[out[i]] != counts[out[j]] {
			return counts[out[i]] > counts[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

// atLeast is `max` under another name: shadowing the builtin works and makes every
// later reader check which one they are looking at.
func atLeast(a, b int) int {
	if a > b {
		return a
	}
	return b
}
