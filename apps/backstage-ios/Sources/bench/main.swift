import BackstageCrypto
import Foundation

// How long one channel-key derivation takes. The number that decides whether the Argon2id
// parameters are usable: this runs while somebody stands in a queue waiting to join a
// channel, on hardware several times slower than a laptop.
let started = Date()
let rounds = 5
for i in 0..<rounds {
    _ = try MeshCrypto.deriveChannelKey(
        eventID: "SUNDOWN", channel: "gate-\(i)", passphrase: "orange lanyard")
}
let each = Date().timeIntervalSince(started) / Double(rounds)
print(String(format: "%.1f ms per channel key derivation", each * 1000))
