use apex_predicate_lib::{
    types::{FieldId, Op, Packet, Predicate, ScalarValue, Value},
};
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};

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

async fn count(n: usize) {
    let predicate = make_predicate();
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

    println!("n={n:>5}: {:>12} cycles", report.total_instruction_count());
}

#[tokio::main]
async fn main() {
    for n in [10, 100, 1_000, 10_000] {
        count(n).await;
    }
}
