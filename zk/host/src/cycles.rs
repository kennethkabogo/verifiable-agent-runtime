use apex_predicate_lib::types::{FieldId, Op, Packet, Predicate, ScalarValue, Value};
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!("../../fixtures/apex-predicate-program.elf");

// ── baseline predicates ───────────────────────────────────────────────────────

fn and_two_leaves() -> Predicate {
    Predicate::And(vec![
        leaf_amount_lte(1_000_000),
        leaf_fname_neq(b"withdraw"),
    ])
}

fn aggregate_predicate(n: usize) -> Predicate {
    Predicate::And(vec![
        leaf_amount_lte(1_000_000),
        Predicate::SessionSum {
            field: FieldId::Amount,
            filter: None,
            op: Op::Lt,
            threshold: (n as u64) * 900_001,
        },
    ])
}

// ── InSet predicates (varying set size to verify 8×inset_elems coefficient) ──

fn inset_small() -> Predicate {
    leaf_fname_inset(&["deposit", "withdraw"])
}

fn inset_medium() -> Predicate {
    leaf_fname_inset(&["deposit", "withdraw", "transfer", "redeem", "claim"])
}

fn inset_large() -> Predicate {
    leaf_fname_inset(&[
        "deposit", "withdraw", "transfer", "redeem", "claim",
        "swap", "bridge", "mint", "burn", "stake",
        "unstake", "harvest", "compound", "liquidate", "repay",
        "borrow", "supply", "flash", "arbitrage", "rebalance",
    ])
}

// ── adversarial predicates ────────────────────────────────────────────────────

fn or_two_leaves() -> Predicate {
    Predicate::Or(vec![
        leaf_amount_lte(1_000_000),
        leaf_fname_neq(b"withdraw"),
    ])
}

fn not_leaf() -> Predicate {
    Predicate::Not(Box::new(leaf_fname_eq(b"withdraw")))
}

fn and_of_or() -> Predicate {
    // And(Or(Leaf, Leaf), Leaf) — depth-2, mixed
    Predicate::And(vec![
        Predicate::Or(vec![
            leaf_amount_lte(1_000_000),
            leaf_amount_gt(500_000),
        ]),
        leaf_fname_neq(b"withdraw"),
    ])
}

fn or_of_ands() -> Predicate {
    // Or(And(Leaf, Leaf), And(Leaf, Leaf)) — depth-2, Or is the root
    Predicate::Or(vec![
        Predicate::And(vec![
            leaf_amount_lte(1_000_000),
            leaf_fname_neq(b"withdraw"),
        ]),
        Predicate::And(vec![
            leaf_amount_gt(0),
            leaf_fname_eq(b"settle"),
        ]),
    ])
}

// ── leaf constructors ─────────────────────────────────────────────────────────

fn leaf_amount_lte(v: u64) -> Predicate {
    Predicate::Leaf { field: FieldId::Amount, op: Op::Lte, value: Value::Scalar(ScalarValue::U64(v)) }
}
fn leaf_amount_gt(v: u64) -> Predicate {
    Predicate::Leaf { field: FieldId::Amount, op: Op::Gt, value: Value::Scalar(ScalarValue::U64(v)) }
}
fn leaf_fname_neq(s: &[u8]) -> Predicate {
    Predicate::Leaf { field: FieldId::FunctionName, op: Op::Neq, value: Value::Scalar(ScalarValue::Bytes(s.to_vec())) }
}
fn leaf_fname_eq(s: &[u8]) -> Predicate {
    Predicate::Leaf { field: FieldId::FunctionName, op: Op::Eq, value: Value::Scalar(ScalarValue::Bytes(s.to_vec())) }
}
fn leaf_fname_inset(names: &[&str]) -> Predicate {
    Predicate::Leaf {
        field: FieldId::FunctionName,
        op: Op::InSet,
        value: Value::Set(names.iter().map(|s| ScalarValue::Bytes(s.as_bytes().to_vec())).collect()),
    }
}

// ── trace generators ──────────────────────────────────────────────────────────

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

// Or left branch (Amount <= 1_000_000) is always true — right never evaluated
fn make_sc_trace(n: usize) -> Vec<Packet> {
    (0..n)
        .map(|_i| Packet {
            packet_type: 0x03,
            function_name: Some(b"withdraw".to_vec()), // right would fail if reached
            amount: Some(1),                           // always <= 1M, left true
            endpoint: None,
            status_code: None,
        })
        .collect()
}

// Or left branch (Amount <= 1_000_000) is always false — right must evaluate
fn make_full_eval_trace(n: usize) -> Vec<Packet> {
    (0..n)
        .map(|i| Packet {
            packet_type: 0x03,
            function_name: Some(format!("settle_{}", i).into_bytes()), // right true
            amount: Some(1_000_001 + (i as u64 % 1_000_000)),          // always > 1M, left false
            endpoint: None,
            status_code: None,
        })
        .collect()
}

// ── formula predictor ─────────────────────────────────────────────────────────
//
// Corrected formula (re-derived via adversarial benchmarks, Oct 2026).
// Upper bound: 18,000 + n×970 + total_bytes + n×8×inset_elems + n×106×leaf_count
// Or short-circuit saves ~106 cycles/packet/skipped-leaf; leaf_count is worst-case.

fn leaf_count(p: &Predicate) -> usize {
    match p {
        Predicate::Leaf { .. } => 1,
        Predicate::And(ch) | Predicate::Or(ch) => ch.iter().map(leaf_count).sum(),
        Predicate::Not(inner) => leaf_count(inner),
        Predicate::SessionSum { .. } | Predicate::SessionCount { .. } => 1,
    }
}

fn inset_total_size(p: &Predicate) -> usize {
    match p {
        Predicate::Leaf { op, value, .. } if matches!(op, Op::InSet | Op::NotInSet) => {
            if let Value::Set(s) = value { s.len() } else { 0 }
        }
        Predicate::Leaf { .. } => 0,
        Predicate::And(ch) | Predicate::Or(ch) => ch.iter().map(inset_total_size).sum(),
        Predicate::Not(inner) => inset_total_size(inner),
        _ => 0,
    }
}

fn encoded_packet_bytes(p: &Packet) -> usize {
    2 // packet_type + flags
    + p.function_name.as_ref().map_or(0, |v| 2 + v.len())
    + p.amount.map_or(0, |_| 8)
    + p.endpoint.as_ref().map_or(0, |v| 2 + v.len())
    + p.status_code.map_or(0, |_| 2)
}

fn predict(predicate: &Predicate, trace: &[Packet]) -> u64 {
    let n = trace.len();
    let total_bytes: usize = trace.iter().map(encoded_packet_bytes).sum();
    let leaves = leaf_count(predicate);
    let inset = inset_total_size(predicate);
    // Fitted from adversarial benchmarks: C_byte≈1 (not 15), C_leaf≈106, C_overhead≈970.
    // leaves_evaluated is worst-case (all leaves); Or short-circuit saves ~106 cycles/packet/skipped-leaf.
    (18_000 + n * 970 + total_bytes + n * 8 * inset + n * 106 * leaves) as u64
}

// ── CSV helpers ───────────────────────────────────────────────────────────────

/// Quotes a field per RFC 4180: wrap in quotes, double any embedded quote.
/// Needed because labels contain commas, e.g. "And[Amount<=1M, FnName!=withdraw]".
fn csv_quote(field: &str) -> String {
    format!("\"{}\"", field.replace('"', "\"\""))
}

const CSV_HEADER: &str =
    "label,n,total_bytes,leaves,inset,predicted,actual,delta_pct";

// ── SP1 runner ────────────────────────────────────────────────────────────────

/// Runs one predicate/trace pair through SP1, prints a human-readable
/// comparison line, and returns the same result as a CSV row.
async fn compare(label: &str, predicate: Predicate, trace: Vec<Packet>) -> String {
    let predicted = predict(&predicate, &trace);
    let n = trace.len();
    let total_bytes: usize = trace.iter().map(encoded_packet_bytes).sum();
    let leaves = leaf_count(&predicate);
    let inset = inset_total_size(&predicate);

    let predicate_bytes = predicate.encode();
    let predicate_hash: [u8; 32] = Sha256::digest(&predicate_bytes).into();

    let client = ProverClient::builder().cpu().build().await;
    let mut stdin = SP1Stdin::new();
    stdin.write(&trace);
    stdin.write(&predicate_bytes);
    stdin.write(&predicate_hash);

    let (_, report) = client
        .execute(Elf::Static(ELF), stdin)
        .await
        .expect("execute failed");

    let actual = report.total_instruction_count();
    let delta = (actual as f64 - predicted as f64) / predicted as f64 * 100.0;
    let flag = if delta.abs() > 5.0 { " <<<" } else { "" };

    println!(
        "{label:50} n={n:>5}  actual={actual:>12}  predicted={predicted:>12}  delta={delta:>+8.2}%{flag}"
    );

    format!(
        "{},{n},{total_bytes},{leaves},{inset},{predicted},{actual},{delta:.4}",
        csv_quote(label)
    )
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let ns = [1, 5, 10, 50, 100, 500, 1_000, 5_000, 10_000];
    let mut rows: Vec<String> = vec![CSV_HEADER.to_string()];

    println!("=== BASELINE: And[Leaf, Leaf] ===");
    for &n in &ns {
        rows.push(compare("And[Amount<=1M, FnName!=withdraw]", and_two_leaves(), make_trace(n)).await);
    }

    println!();
    println!("=== Or[Leaf, Leaf] — short-circuit dominant (left always true) ===");
    for &n in &ns {
        rows.push(compare("Or[Amount<=1M, FnName!=withdraw] sc", or_two_leaves(), make_sc_trace(n)).await);
    }

    println!();
    println!("=== Or[Leaf, Leaf] — full evaluation (left always false) ===");
    for &n in &ns {
        rows.push(compare("Or[Amount<=1M, FnName!=withdraw] full", or_two_leaves(), make_full_eval_trace(n)).await);
    }

    println!();
    println!("=== Not[Leaf] ===");
    for &n in &ns {
        rows.push(compare("Not[FnName==withdraw]", not_leaf(), make_trace(n)).await);
    }

    println!();
    println!("=== And[Or[Leaf, Leaf], Leaf] — depth-2 mixed ===");
    for &n in &ns {
        rows.push(compare("And[Or[Amount<=1M, Amount>500K], FnName!=withdraw]", and_of_or(), make_trace(n)).await);
    }

    println!();
    println!("=== Or[And[Leaf, Leaf], And[Leaf, Leaf]] — depth-2 Or of Ands ===");
    for &n in &ns {
        rows.push(compare("Or[And[Amount<=1M,FnName!=wd], And[Amount>0,FnName==settle]]", or_of_ands(), make_trace(n)).await);
    }

    println!();
    println!("=== AGGREGATE: And[Leaf, SessionSum] ===");
    for &n in &ns {
        rows.push(compare("And[Amount<=1M, SessionSum<cap]", aggregate_predicate(n), make_trace(n)).await);
    }

    println!();
    println!("=== InSet[2 elems] — miss (function_name never in set) ===");
    for &n in &ns {
        rows.push(compare("InSet[fname, 2 elems] miss", inset_small(), make_trace(n)).await);
    }

    println!();
    println!("=== InSet[5 elems] — miss ===");
    for &n in &ns {
        rows.push(compare("InSet[fname, 5 elems] miss", inset_medium(), make_trace(n)).await);
    }

    println!();
    println!("=== InSet[20 elems] — miss ===");
    for &n in &ns {
        rows.push(compare("InSet[fname, 20 elems] miss", inset_large(), make_trace(n)).await);
    }

    let csv_path = "cycles_results.csv";
    std::fs::write(csv_path, rows.join("\n") + "\n").expect("failed to write CSV output");
    println!();
    println!("Wrote {} rows to {csv_path}", rows.len() - 1);
}
