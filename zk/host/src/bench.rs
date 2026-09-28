use apex_predicate_lib::{
    eval::evaluate_all,
    types::{FieldId, Op, Packet, Predicate, ScalarValue, Value},
};
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use std::time::Instant;

const ELF: &[u8] = include_bytes!(
    "../../target/elf-compilation/riscv64im-succinct-zkvm-elf/release/apex-predicate-program"
);

fn make_predicate() -> Predicate {
    Predicate::And(vec![
        Predicate::Leaf {
            field: FieldId::Amount,
            op: Op::Lte,
            value: Value::Scalar(ScalarValue::U64(1_000_000)),
        },
        Predicate::Leaf {
            field: FieldId::FunctionName,
            op: Op::Neq,
            value: Value::Scalar(ScalarValue::Bytes(b"withdraw".to_vec())),
        },
    ])
}

fn make_trace(n: usize) -> Vec<Packet> {
    (0..n)
        .map(|i| Packet {
            packet_type: 0x03,
            function_name: Some(format!("settle_{}", i).into_bytes()),
            amount: Some((i as u64 % 900_000) + 1),
            endpoint: None,
            status_code: None,
        })
        .collect()
}

async fn run(n: usize) {
    let predicate = make_predicate();
    let predicate_bytes = predicate.encode();
    let predicate_hash: [u8; 32] = Sha256::digest(&predicate_bytes).into();
    let packets = make_trace(n);

    assert!(
        evaluate_all(&predicate, &packets),
        "fixture violates predicate — fix the trace"
    );

    let client = ProverClient::builder().mock().build().await;
    let pk = client.setup(Elf::Static(ELF)).await.expect("setup failed");

    let mut stdin = SP1Stdin::new();
    stdin.write(&packets);
    stdin.write(&predicate_bytes);
    stdin.write(&predicate_hash);

    println!("n={n}: proving ...");
    let t0 = Instant::now();
    let proof = client
        .prove(&pk, stdin)
        .compressed()
        .await
        .expect("prove failed");
    let elapsed = t0.elapsed();
    println!("n={n}: proof generated in {:.2?}", elapsed);

    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("verify failed");
    println!("n={n}: verified ok");
}

#[tokio::main]
async fn main() {
    for n in [10, 100, 1_000] {
        run(n).await;
        println!();
    }
}
