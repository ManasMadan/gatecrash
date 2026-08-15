package main

import "testing"

// TestDemoRunsCleanly is the widest integration test in the repository.
//
// It boots a real box — real SQLite, real engine, real HTTP handlers — and walks a
// scripted event through every path the product has: seated admission, wrong door,
// prerequisites out of order, rotating codes, screenshots, forgeries, re-entry,
// drink tokens, staff alarms, and a settlement proof. Every assertion inside the
// demo is a real check; any of them failing fails this test.
//
// It runs in CI on every push, which means the narrated walkthrough in the README
// is never out of date with the code: if the product stops behaving the way the
// demo says it does, the build goes red.
func TestDemoRunsCleanly(t *testing.T) {
	if err := runDemo(t.TempDir(), true); err != nil {
		t.Fatalf("the demo did not complete: %v", err)
	}
}
