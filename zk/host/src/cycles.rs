use apex_predicate_lib::{
    types::{FieldId, Op, Packet, Predicate, ScalarValue, Value},
};
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!(
    "../../target/elf-compilation/riscv64im-succinct-zkvm-elf/release/apex-predicate-program"
);

fn per_packet_predicate() -> Predicate {
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

// AND of per-packet check + cumulative spending cap
fn aggregate_predicate(n: usize) -> Predicate {
    Predicate::And(vec![
        Predicate::Leaf {
            field: FieldId::Amount,
            op: Op::Lte,
            value: Value::Scalar(ScalarValue::U64(1_000_000)),
        },
        Predicate::SessionSum {
            field: FieldId::Amount,
            filter: None,
            op: Op::Lt,
            threshold: (n as u64) * 900_001, // always-passing cap for benchmark
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

async fn count(label: &str, predicate: Predicate, n: usize) {
    let predicate_bytes = predicate.encode();
    let predicate_hash: [u8; 32] = Sha256::digest(&predicate_bytes).into();
    let packets = make_trace(n);

    let client = ProverClient::builder().cpu().build().await;

    let mut stdin = SP1Stdin::new();
    stdin.write(&packets);
    stdin.write(&predicate_bytes);
    stdin.write(&predicate_hash);

    let (_, report) = client
        .execute(Elf::Static(ELF), stdin)
        .await
        .expect("execute failed");

    println!("{label} n={n:>5}: {:>12} cycles", report.total_instruction_count());
}

#[tokio::main]
async fn main() {
    println!("=== per-packet predicate (And[Leaf, Leaf]) ===");
    for n in [10, 100, 1_000, 10_000] {
        count("per-packet", per_packet_predicate(), n).await;
    }
    println!();
    println!("=== aggregate predicate (And[Leaf, SessionSum]) ===");
    for n in [10, 100, 1_000, 10_000] {
        count("aggregate", aggregate_predicate(n), n).await;
    }
}
