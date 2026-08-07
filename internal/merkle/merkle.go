// Package merkle builds the checkpoint trees that make an attendance count
// provable.
//
// The redemption log is a hash chain, which already makes tampering evident:
// change any row and every subsequent row_hash is wrong. But a chain only
// proves things by replaying all of it, and "send me your whole log" is not an
// answer you can give an artist's manager at 2am. So every thousand rows the box
// seals a Merkle checkpoint and publishes the root.
//
// What that buys is the useful shape of proof: given the root the organizer
// published, the box can produce an O(log n) inclusion proof that a specific
// admission is in the log, and anyone can verify it with a handful of hashes and
// no access to the log at all. A post-event dispute about the door split stops
// being a shouting match and becomes twenty hashes on a napkin.
//
// The construction follows RFC 6962 (Certificate Transparency): leaf and
// internal hashes are domain-separated by a prefix byte, and odd nodes are
// promoted rather than duplicated.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Size is the length of a hash in bytes.
const Size = sha256.Size

// Hash is a SHA-256 digest.
type Hash [Size]byte

// Domain separation prefixes, as in RFC 6962 section 2.1.
//
// Without them the tree is malleable: an attacker who can choose leaves can
// present an internal node's hash as a leaf and produce a second tree with the
// same root, which is the classic second-preimage attack on unprefixed Merkle
// trees. One byte closes it.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// String renders the hash as lowercase hex, which is the form printed on the
// organizer's settlement sheet and pasted into an email.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// MarshalText implements encoding.TextMarshaler.
func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *Hash) UnmarshalText(b []byte) error {
	parsed, err := ParseHash(string(b))
	if err != nil {
		return err
	}
	*h = parsed
	return nil
}

// IsZero reports whether the hash is unset.
func (h Hash) IsZero() bool { return h == Hash{} }

// ErrBadHash is returned for text that is not a hex-encoded SHA-256 digest.
var ErrBadHash = errors.New("merkle: bad hash")

// ParseHash reads a hex-encoded digest.
func ParseHash(text string) (Hash, error) {
	if len(text) != hex.EncodedLen(Size) {
		return Hash{}, fmt.Errorf("%w: %q is %d characters, want %d", ErrBadHash, text, len(text), hex.EncodedLen(Size))
	}
	raw, err := hex.DecodeString(text)
	if err != nil {
		return Hash{}, fmt.Errorf("%w: %q: %v", ErrBadHash, text, err)
	}
	var out Hash
	copy(out[:], raw)
	return out, nil
}

// HashLeaf hashes a leaf's contents.
func HashLeaf(data []byte) Hash {
	digest := sha256.New()
	digest.Write([]byte{leafPrefix})
	digest.Write(data)
	var out Hash
	copy(out[:], digest.Sum(nil))
	return out
}

// HashNode hashes an internal node from its two children.
func HashNode(left, right Hash) Hash {
	digest := sha256.New()
	digest.Write([]byte{nodePrefix})
	digest.Write(left[:])
	digest.Write(right[:])
	var out Hash
	copy(out[:], digest.Sum(nil))
	return out
}

// EmptyRoot is the root of a tree with no leaves: SHA-256 of the empty string,
// as RFC 6962 defines it. A checkpoint over zero admissions is a real thing —
// a gate that opened and admitted nobody — and it needs a well-defined root
// rather than a special case.
func EmptyRoot() Hash {
	var out Hash
	copy(out[:], sha256.New().Sum(nil))
	return out
}

// Root computes the Merkle root over a list of already-hashed leaves.
//
// Odd nodes are promoted to the next level rather than duplicated. Duplicating
// is the mistake that gave Bitcoin CVE-2012-2459: two different leaf lists can
// hash to the same root, which in this system would mean two different
// attendance counts backed by the same published root.
func Root(leaves []Hash) Hash {
	if len(leaves) == 0 {
		return EmptyRoot()
	}
	level := make([]Hash, len(leaves))
	copy(level, leaves)

	for len(level) > 1 {
		next := level[:0:0]
		if cap(next) < (len(level)+1)/2 {
			next = make([]Hash, 0, (len(level)+1)/2)
		}
		for i := 0; i+1 < len(level); i += 2 {
			next = append(next, HashNode(level[i], level[i+1]))
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1])
		}
		level = next
	}
	return level[0]
}

// Proof is an inclusion proof: the sibling hashes needed to recompute the root
// from one leaf, ordered from the leaf upward.
type Proof struct {
	// Index is the leaf's position in the tree.
	Index int `json:"index"`

	// Size is the number of leaves in the tree. Both index and size are part of
	// the proof because the promoted-odd-node rule means the shape of the tree,
	// and therefore which side each sibling sits on, depends on the total count.
	Size int `json:"size"`

	// Siblings are the hashes to combine, leaf-first.
	Siblings []Hash `json:"siblings"`
}

// ErrOutOfRange is returned when a proof is requested for a leaf that does not
// exist.
var ErrOutOfRange = errors.New("merkle: leaf index out of range")

// Prove builds an inclusion proof for one leaf.
func Prove(leaves []Hash, index int) (Proof, error) {
	if index < 0 || index >= len(leaves) {
		return Proof{}, fmt.Errorf("%w: index %d in a tree of %d", ErrOutOfRange, index, len(leaves))
	}

	proof := Proof{Index: index, Size: len(leaves)}
	level := make([]Hash, len(leaves))
	copy(level, leaves)
	position := index

	for len(level) > 1 {
		// A promoted odd node has no sibling at this level, so nothing is
		// recorded and it simply rises.
		if position == len(level)-1 && len(level)%2 == 1 {
			position /= 2
			level = collapse(level)
			continue
		}
		sibling := position ^ 1
		proof.Siblings = append(proof.Siblings, level[sibling])
		position /= 2
		level = collapse(level)
	}
	return proof, nil
}

// collapse reduces one level of the tree, promoting an odd trailing node.
func collapse(level []Hash) []Hash {
	next := make([]Hash, 0, (len(level)+1)/2)
	for i := 0; i+1 < len(level); i += 2 {
		next = append(next, HashNode(level[i], level[i+1]))
	}
	if len(level)%2 == 1 {
		next = append(next, level[len(level)-1])
	}
	return next
}

// Verify recomputes the root from a leaf and its proof and reports whether it
// matches. This is the whole point of the package: the verifier needs the leaf,
// twenty hashes and the published root, and nothing else. No log, no database,
// no trust in the box.
func Verify(root, leaf Hash, proof Proof) bool {
	if proof.Index < 0 || proof.Size <= 0 || proof.Index >= proof.Size {
		return false
	}
	if proof.Size == 1 {
		return len(proof.Siblings) == 0 && leaf == root
	}

	running := leaf
	position, size := proof.Index, proof.Size
	used := 0

	for size > 1 {
		if position == size-1 && size%2 == 1 {
			// Promoted node: rises untouched, consuming no sibling.
			position /= 2
			size = (size + 1) / 2
			continue
		}
		if used >= len(proof.Siblings) {
			return false
		}
		sibling := proof.Siblings[used]
		used++
		if position%2 == 0 {
			running = HashNode(running, sibling)
		} else {
			running = HashNode(sibling, running)
		}
		position /= 2
		size = (size + 1) / 2
	}
	// A proof with hashes left over is not a proof of this leaf in this tree; it
	// is a proof of something else with a suffix attached, and accepting it
	// would let a forger pad a valid proof.
	return used == len(proof.Siblings) && running == root
}
