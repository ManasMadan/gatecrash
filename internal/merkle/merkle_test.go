package merkle

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

func leaves(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		out[i] = HashLeaf([]byte(fmt.Sprintf("admission-%d", i)))
	}
	return out
}

func TestEmptyRootIsTheHashOfNothing(t *testing.T) {
	want := sha256.Sum256(nil)
	if got := EmptyRoot(); got != Hash(want) {
		t.Fatalf("EmptyRoot is %s, want %x", got, want)
	}
	if got := Root(nil); got != EmptyRoot() {
		t.Fatalf("Root(nil) is %s, want the empty root", got)
	}
}

func TestSingleLeafTreeRootIsTheLeaf(t *testing.T) {
	leaf := HashLeaf([]byte("only admission"))
	if got := Root([]Hash{leaf}); got != leaf {
		t.Fatalf("a one-leaf root is %s, want the leaf %s", got, leaf)
	}
}

func TestLeafAndNodeHashesAreDomainSeparated(t *testing.T) {
	// Without the prefix bytes an internal node's hash can be presented as a
	// leaf, which lets a forger build a second tree with the same root. This is
	// the second-preimage attack RFC 6962's prefixes exist to close.
	left, right := HashLeaf([]byte("a")), HashLeaf([]byte("b"))
	node := HashNode(left, right)

	concatenated := make([]byte, 0, Size*2)
	concatenated = append(concatenated, left[:]...)
	concatenated = append(concatenated, right[:]...)

	if HashLeaf(concatenated) == node {
		t.Fatal("a leaf hash over two children equals their node hash; the tree is malleable")
	}
	if HashLeaf(nil) == EmptyRoot() {
		t.Fatal("the empty leaf hash collides with the empty root")
	}
}

func TestRootChangesWhenAnythingChanges(t *testing.T) {
	base := leaves(9)
	root := Root(base)

	// Mutating a leaf.
	mutated := append([]Hash(nil), base...)
	mutated[4] = HashLeaf([]byte("tampered"))
	if Root(mutated) == root {
		t.Error("editing a leaf did not change the root")
	}

	// Reordering two leaves. This is the attack that matters most here: an
	// organizer reordering admissions to move a scan either side of a cutoff.
	swapped := append([]Hash(nil), base...)
	swapped[2], swapped[3] = swapped[3], swapped[2]
	if Root(swapped) == root {
		t.Error("swapping two leaves did not change the root")
	}

	// Dropping a leaf.
	if Root(base[:len(base)-1]) == root {
		t.Error("dropping a leaf did not change the root")
	}

	// Appending a leaf.
	if Root(append(append([]Hash(nil), base...), HashLeaf([]byte("extra")))) == root {
		t.Error("appending a leaf did not change the root")
	}
}

// TestOddNodesArePromotedNotDuplicated guards against the bug that gave Bitcoin
// CVE-2012-2459: with duplicated odd nodes, two different leaf lists produce
// the same root. Here that would mean two different attendance counts backed by
// one published root, which is precisely what the checkpoint is supposed to
// make impossible.
func TestOddNodesArePromotedNotDuplicated(t *testing.T) {
	three := leaves(3)
	// The duplicating construction would treat [a b c] as [a b c c], so the
	// four-leaf tree with c repeated must not share a root with the real one.
	duplicated := []Hash{three[0], three[1], three[2], three[2]}
	if Root(three) == Root(duplicated) {
		t.Fatal("a three-leaf tree collides with a four-leaf tree that repeats the last leaf")
	}
}

func TestProveAndVerifyEveryLeafAtEverySize(t *testing.T) {
	// Sizes one through sixty-five, so every power of two, every power of two
	// plus one, and every odd shape in between is covered. The promoted-odd-node
	// rule makes the tree shape depend on the count, so a proof that works at
	// size eight can easily be broken at size nine.
	for size := 1; size <= 65; size++ {
		all := leaves(size)
		root := Root(all)
		for index := 0; index < size; index++ {
			proof, err := Prove(all, index)
			if err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
			if !Verify(root, all[index], proof) {
				t.Fatalf("size %d index %d: a valid proof did not verify", size, index)
			}
		}
	}
}

func TestProofIsLogarithmic(t *testing.T) {
	// The O(log n) claim is in the README: an attendance dispute is settled with
	// a handful of hashes, not the whole log.
	const size = 100_000
	all := leaves(size)
	proof, err := Prove(all, 54_321)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Siblings) > 17 {
		t.Fatalf("a proof in a %d-leaf tree carries %d siblings, which is not logarithmic", size, len(proof.Siblings))
	}
	t.Logf("%d leaves: %d siblings, %d bytes", size, len(proof.Siblings), len(proof.Siblings)*Size)
}

func TestVerifyRejectsTamperedProofs(t *testing.T) {
	all := leaves(37)
	root := Root(all)
	const index = 11
	valid, err := Prove(all, index)
	if err != nil {
		t.Fatal(err)
	}

	clone := func() Proof {
		out := valid
		out.Siblings = append([]Hash(nil), valid.Siblings...)
		return out
	}

	if !Verify(root, all[index], clone()) {
		t.Fatal("the control case failed")
	}

	t.Run("wrong leaf", func(t *testing.T) {
		if Verify(root, all[index+1], clone()) {
			t.Error("a proof verified against the wrong leaf")
		}
	})
	t.Run("wrong root", func(t *testing.T) {
		if Verify(HashLeaf([]byte("not the root")), all[index], clone()) {
			t.Error("a proof verified against the wrong root")
		}
	})
	t.Run("mutated sibling", func(t *testing.T) {
		bad := clone()
		bad.Siblings[0] = HashLeaf([]byte("forged"))
		if Verify(root, all[index], bad) {
			t.Error("a proof with a forged sibling verified")
		}
	})
	t.Run("reordered siblings", func(t *testing.T) {
		bad := clone()
		bad.Siblings[0], bad.Siblings[1] = bad.Siblings[1], bad.Siblings[0]
		if Verify(root, all[index], bad) {
			t.Error("a proof with reordered siblings verified")
		}
	})
	t.Run("padded siblings", func(t *testing.T) {
		// A proof with hashes left over is a proof of something else with a
		// suffix bolted on. Accepting it would let a forger pad a valid proof.
		bad := clone()
		bad.Siblings = append(bad.Siblings, HashLeaf([]byte("padding")))
		if Verify(root, all[index], bad) {
			t.Error("a padded proof verified")
		}
	})
	t.Run("truncated siblings", func(t *testing.T) {
		bad := clone()
		bad.Siblings = bad.Siblings[:len(bad.Siblings)-1]
		if Verify(root, all[index], bad) {
			t.Error("a truncated proof verified")
		}
	})
	t.Run("wrong index", func(t *testing.T) {
		bad := clone()
		bad.Index = index + 1
		if Verify(root, all[index], bad) {
			t.Error("a proof verified with the wrong index")
		}
	})
	t.Run("size that changes the path", func(t *testing.T) {
		// Size is a shape hint, not an authenticated field: the root is what
		// commits to the tree. A size that leaves the path shape unchanged is
		// therefore harmless and still verifies, which is correct — the leaf
		// really is under that root. A size that changes the path must fail,
		// because then the hashes are being combined in the wrong order.
		bad := clone()
		bad.Size = 12
		if Verify(root, all[index], bad) {
			t.Error("a proof verified with a size that changes the path shape")
		}
	})
	t.Run("size that does not change the path is harmless", func(t *testing.T) {
		// Documenting the flip side so nobody later mistakes it for a hole. For
		// index 11 the levels of a 37-leaf and a 38-leaf tree collapse
		// identically, so the same siblings recompute the same root, and that
		// root is only reachable from the real tree.
		bad := clone()
		bad.Size = 38
		if !Verify(root, all[index], bad) {
			t.Error("expected a shape-neutral size change to still verify against the real root")
		}
	})
	t.Run("nonsense bounds", func(t *testing.T) {
		for _, bad := range []Proof{
			{Index: -1, Size: 10},
			{Index: 10, Size: 10},
			{Index: 0, Size: 0},
			{Index: 0, Size: -1},
		} {
			if Verify(root, all[index], bad) {
				t.Errorf("a proof with index=%d size=%d verified", bad.Index, bad.Size)
			}
		}
	})
}

func TestProveRejectsAnIndexOutsideTheTree(t *testing.T) {
	all := leaves(5)
	for _, index := range []int{-1, 5, 99} {
		if _, err := Prove(all, index); !errors.Is(err, ErrOutOfRange) {
			t.Errorf("Prove(index=%d) gave %v, want ErrOutOfRange", index, err)
		}
	}
}

func TestSingleLeafProofCarriesNoSiblings(t *testing.T) {
	only := leaves(1)
	proof, err := Prove(only, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Siblings) != 0 {
		t.Fatalf("a one-leaf proof carries %d siblings, want none", len(proof.Siblings))
	}
	if !Verify(Root(only), only[0], proof) {
		t.Fatal("a one-leaf proof did not verify")
	}
	// And a one-leaf proof with a sibling bolted on must be refused.
	proof.Siblings = []Hash{HashLeaf([]byte("x"))}
	if Verify(Root(only), only[0], proof) {
		t.Fatal("a one-leaf proof with a spurious sibling verified")
	}
}

func TestHashTextRoundTrip(t *testing.T) {
	want := HashLeaf([]byte("settlement"))
	got, err := ParseHash(want.String())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("hash did not round trip through hex")
	}
	for _, bad := range []string{"", "abc", want.String() + "00", "zz" + want.String()[2:]} {
		if _, err := ParseHash(bad); !errors.Is(err, ErrBadHash) {
			t.Errorf("ParseHash(%q) gave %v, want ErrBadHash", bad, err)
		}
	}
}

func TestRootIsStableAcrossCalls(t *testing.T) {
	// Root reuses the leaf slice's backing array for the first level, which is
	// exactly the kind of optimisation that quietly corrupts the caller's data.
	all := leaves(17)
	before := append([]Hash(nil), all...)
	first := Root(all)
	second := Root(all)
	if first != second {
		t.Fatal("two calls over the same leaves gave different roots")
	}
	for i := range all {
		if all[i] != before[i] {
			t.Fatalf("Root mutated the caller's leaf %d", i)
		}
	}
}

func BenchmarkRoot1000(b *testing.B) {
	all := leaves(1000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Root(all)
	}
}

func BenchmarkProve(b *testing.B) {
	all := leaves(1000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Prove(all, i%1000); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	all := leaves(100_000)
	root := Root(all)
	proof, err := Prove(all, 12_345)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(root, all[12_345], proof) {
			b.Fatal("verify failed")
		}
	}
}
