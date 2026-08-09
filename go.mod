module github.com/ManasMadan/gatecrash

// crypto/hkdf landed in the standard library in 1.24, which is what lets the
// ticket key schedule ship without a third-party HKDF.
go 1.25.0

require golang.org/x/crypto v0.55.0

require golang.org/x/sys v0.47.0 // indirect
