address 0x1 {

/// Module which verifies Merkle proofs.
module Merkle {
    native public fun verify_sha3(data: vector<u8>): vector<u8>;
}
}
