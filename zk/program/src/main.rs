#![no_main]
sp1_zkvm::entrypoint!(main);

use apex_predicate_lib::{eval::evaluate_all, types::Packet, types::Predicate};
use sha2::{Digest, Sha256};

pub fn main() {
    // Private witness: full packet trace — not revealed to the verifier.
    let packets: Vec<Packet> = sp1_zkvm::io::read();

    // Public inputs
    let predicate_bytes: Vec<u8> = sp1_zkvm::io::read();
    let predicate_hash: [u8; 32] = sp1_zkvm::io::read();

    // Security property: the predicate we evaluate IS the one committed in the
    // bundle header. Without this assertion a prover could substitute a weaker
    // predicate and still produce a valid proof — the swap-P attack Q6 exists
    // to prevent. This line is where the security property lives.
    let computed: [u8; 32] = Sha256::digest(&predicate_bytes).into();
    assert_eq!(computed, predicate_hash);

    let predicate = Predicate::decode(&predicate_bytes).expect("invalid predicate encoding");
    let compliant = evaluate_all(&predicate, &packets);

    // Public outputs committed to the proof
    sp1_zkvm::io::commit(&compliant);
    sp1_zkvm::io::commit(&predicate_hash);
}
