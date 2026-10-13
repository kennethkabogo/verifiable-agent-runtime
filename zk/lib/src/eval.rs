use crate::types::{FieldId, Op, Packet, Predicate, ScalarValue, Value};

pub fn evaluate(pred: &Predicate, packet: &Packet) -> bool {
    match pred {
        Predicate::And(children) => children.iter().all(|c| evaluate(c, packet)),
        Predicate::Or(children) => children.iter().any(|c| evaluate(c, packet)),
        Predicate::Not(inner) => {
            if has_session_aggregate(inner) {
                true // deferred to session phase — do not negate the deferred sentinel
            } else {
                !evaluate(inner, packet)
            }
        }
        Predicate::Leaf { field, op, value } => eval_leaf(field, op, value, packet),
        // Session-level predicates are not per-packet; deferred to evaluate_session_constraints.
        Predicate::SessionSum { .. } | Predicate::SessionCount { .. } => true,
    }
}

/// Predicate must hold for ALL packets AND all session-level aggregate constraints.
///
/// Panics if the predicate shape is invalid (e.g., Or mixing aggregate and per-packet
/// children). Call `validate_predicate_shape` at decode time to catch this earlier.
pub fn evaluate_all(pred: &Predicate, packets: &[Packet]) -> bool {
    if let Err(e) = validate_predicate_shape(pred) {
        panic!("invalid predicate shape: {e}");
    }
    packets.iter().all(|p| evaluate(pred, p)) && evaluate_session_constraints(pred, packets)
}

/// Evaluates session-level aggregate predicates over the full packet trace.
/// Per-packet leaf predicates return true here — they were already checked by evaluate().
fn evaluate_session_constraints(pred: &Predicate, packets: &[Packet]) -> bool {
    match pred {
        Predicate::Leaf { .. } => true,
        Predicate::And(children) => children.iter().all(|c| evaluate_session_constraints(c, packets)),
        Predicate::Or(children) => children.iter().any(|c| evaluate_session_constraints(c, packets)),
        Predicate::Not(inner) => {
            // Not(per-packet predicate) is vacuously true at session level — it was checked
            // per-packet already. Only negate if there is an aggregate node underneath.
            if has_session_aggregate(inner) {
                !evaluate_session_constraints(inner, packets)
            } else {
                true
            }
        }
        Predicate::SessionSum { field, filter, op, threshold } => {
            let sum = packets.iter()
                .filter(|p| filter.as_ref().map_or(true, |f| evaluate(f, p)))
                .filter_map(|p| extract_numeric(field, p))
                .fold(0u64, |acc, v| acc.saturating_add(v));
            cmp_u64(op, sum, *threshold)
        }
        Predicate::SessionCount { filter, op, threshold } => {
            let count = packets.iter()
                .filter(|p| filter.as_ref().map_or(true, |f| evaluate(f, p)))
                .count() as u64;
            cmp_u64(op, count, *threshold)
        }
    }
}

fn has_session_aggregate(pred: &Predicate) -> bool {
    match pred {
        Predicate::SessionSum { .. } | Predicate::SessionCount { .. } => true,
        Predicate::And(c) | Predicate::Or(c) => c.iter().any(|x| has_session_aggregate(x)),
        Predicate::Not(inner) => has_session_aggregate(inner),
        Predicate::Leaf { .. } => false,
    }
}

fn has_per_packet_leaf(pred: &Predicate) -> bool {
    match pred {
        Predicate::Leaf { .. } => true,
        Predicate::And(c) | Predicate::Or(c) => c.iter().any(|x| has_per_packet_leaf(x)),
        Predicate::Not(inner) => has_per_packet_leaf(inner),
        Predicate::SessionSum { .. } | Predicate::SessionCount { .. } => false,
    }
}

/// Returns Err if the predicate contains a node that mixes session-aggregate and
/// per-packet sub-predicates under Or or Not.
///
/// The two-phase evaluator uses `true` as a sentinel for per-packet leaves in the
/// session phase and for session aggregates in the per-packet phase. `Or` with `any()`
/// short-circuits on a `true` sentinel, silently bypassing the other arm. `Not` defers
/// the entire inner subtree to the session phase when any aggregate is present, dropping
/// per-packet leaf checks inside that subtree entirely.
///
/// The check uses `has_per_packet_leaf` (not `!has_session_aggregate`) to catch
/// children that internally mix both kinds, e.g. `And(Leaf, SessionSum)`.
pub fn validate_predicate_shape(p: &Predicate) -> Result<(), &'static str> {
    match p {
        Predicate::Or(children) => {
            let has_agg  = children.iter().any(|c| has_session_aggregate(c));
            let has_leaf = children.iter().any(|c| has_per_packet_leaf(c));
            if has_agg && has_leaf {
                return Err("Or may not mix session-aggregate and per-packet children");
            }
            for c in children { validate_predicate_shape(c)?; }
        }
        Predicate::Not(inner) => {
            if has_session_aggregate(inner) && has_per_packet_leaf(inner) {
                return Err("Not may not wrap a subtree that mixes session-aggregate and per-packet children");
            }
            validate_predicate_shape(inner)?;
        }
        Predicate::And(children) => {
            for c in children { validate_predicate_shape(c)?; }
        }
        _ => {}
    }
    Ok(())
}

fn extract_numeric(field: &FieldId, packet: &Packet) -> Option<u64> {
    match field {
        FieldId::Amount => packet.amount,
        FieldId::StatusCode => packet.status_code.map(|v| v as u64),
        FieldId::PacketType => Some(packet.packet_type as u64),
        FieldId::FunctionName | FieldId::Endpoint => None,
    }
}

fn eval_leaf(field: &FieldId, op: &Op, value: &Value, packet: &Packet) -> bool {
    match (field, value) {
        (FieldId::PacketType, Value::Scalar(ScalarValue::U8(v))) =>
            cmp_u64(op, packet.packet_type as u64, *v as u64),
        (FieldId::PacketType, Value::Set(set)) => {
            let hit = set.iter().any(|sv| matches!(sv, ScalarValue::U8(v) if *v == packet.packet_type));
            set_result(op, hit)
        }
        (FieldId::Amount, Value::Scalar(ScalarValue::U64(v))) =>
            packet.amount.map_or(false, |a| cmp_u64(op, a, *v)),
        (FieldId::Amount, Value::Set(set)) => {
            let Some(a) = packet.amount else { return false; };
            set_result(op, set.iter().any(|sv| matches!(sv, ScalarValue::U64(v) if *v == a)))
        }
        (FieldId::StatusCode, Value::Scalar(ScalarValue::U16(v))) =>
            packet.status_code.map_or(false, |s| cmp_u64(op, s as u64, *v as u64)),
        (FieldId::StatusCode, Value::Set(set)) => {
            let Some(s) = packet.status_code else { return false; };
            set_result(op, set.iter().any(|sv| matches!(sv, ScalarValue::U16(v) if *v == s)))
        }
        (FieldId::FunctionName, Value::Scalar(ScalarValue::Bytes(v))) =>
            packet.function_name.as_ref().map_or(false, |n| cmp_bytes(op, n, v)),
        (FieldId::FunctionName, Value::Set(set)) => {
            let Some(name) = &packet.function_name else { return false; };
            set_result(op, set.iter().any(|sv| matches!(sv, ScalarValue::Bytes(b) if b == name)))
        }
        (FieldId::Endpoint, Value::Scalar(ScalarValue::Bytes(v))) =>
            packet.endpoint.as_ref().map_or(false, |e| cmp_bytes(op, e, v)),
        (FieldId::Endpoint, Value::Set(set)) => {
            let Some(ep) = &packet.endpoint else { return false; };
            set_result(op, set.iter().any(|sv| matches!(sv, ScalarValue::Bytes(b) if b == ep)))
        }
        _ => false, // type mismatch — fail closed
    }
}

fn cmp_u64(op: &Op, lhs: u64, rhs: u64) -> bool {
    match op {
        Op::Eq  => lhs == rhs,
        Op::Neq => lhs != rhs,
        Op::Lt  => lhs <  rhs,
        Op::Lte => lhs <= rhs,
        Op::Gt  => lhs >  rhs,
        Op::Gte => lhs >= rhs,
        _ => false,
    }
}

fn cmp_bytes(op: &Op, lhs: &[u8], rhs: &[u8]) -> bool {
    match op {
        Op::Eq  => lhs == rhs,
        Op::Neq => lhs != rhs,
        _ => false,
    }
}

fn set_result(op: &Op, hit: bool) -> bool {
    match op {
        Op::InSet    => hit,
        Op::NotInSet => !hit,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn tool_call(name: &str) -> Packet {
        Packet {
            packet_type: 0x03,
            function_name: Some(name.as_bytes().to_vec()),
            amount: None,
            endpoint: None,
            status_code: None,
        }
    }

    fn settlement(amount: u64) -> Packet {
        Packet {
            packet_type: 0x05,
            function_name: None,
            amount: Some(amount),
            endpoint: None,
            status_code: None,
        }
    }

    #[test]
    fn function_neq_passes() {
        let p = Predicate::Leaf {
            field: FieldId::FunctionName,
            op: Op::Neq,
            value: Value::Scalar(ScalarValue::Bytes(b"restricted_fn".to_vec())),
        };
        assert!(evaluate(&p, &tool_call("safe_fn")));
        assert!(!evaluate(&p, &tool_call("restricted_fn")));
    }

    #[test]
    fn amount_threshold() {
        let p = Predicate::Leaf {
            field: FieldId::Amount,
            op: Op::Lte,
            value: Value::Scalar(ScalarValue::U64(1_000_000)),
        };
        assert!(evaluate(&p, &settlement(999_999)));
        assert!(evaluate(&p, &settlement(1_000_000)));
        assert!(!evaluate(&p, &settlement(1_000_001)));
    }

    #[test]
    fn function_not_in_set() {
        let p = Predicate::Leaf {
            field: FieldId::FunctionName,
            op: Op::NotInSet,
            value: Value::Set(vec![
                ScalarValue::Bytes(b"fn_a".to_vec()),
                ScalarValue::Bytes(b"fn_b".to_vec()),
            ]),
        };
        assert!(evaluate(&p, &tool_call("fn_c")));
        assert!(!evaluate(&p, &tool_call("fn_a")));
    }

    #[test]
    fn and_combinator() {
        let p = Predicate::And(vec![
            Predicate::Leaf {
                field: FieldId::Amount,
                op: Op::Gte,
                value: Value::Scalar(ScalarValue::U64(100)),
            },
            Predicate::Leaf {
                field: FieldId::Amount,
                op: Op::Lte,
                value: Value::Scalar(ScalarValue::U64(1_000)),
            },
        ]);
        assert!(evaluate(&p, &settlement(500)));
        assert!(!evaluate(&p, &settlement(50)));
        assert!(!evaluate(&p, &settlement(2_000)));
    }

    #[test]
    fn not_combinator() {
        let p = Predicate::Not(Box::new(Predicate::Leaf {
            field: FieldId::FunctionName,
            op: Op::Eq,
            value: Value::Scalar(ScalarValue::Bytes(b"banned".to_vec())),
        }));
        assert!(evaluate(&p, &tool_call("allowed")));
        assert!(!evaluate(&p, &tool_call("banned")));
    }

    #[test]
    fn absent_field_fails_leaf() {
        let p = Predicate::Leaf {
            field: FieldId::Amount,
            op: Op::Lte,
            value: Value::Scalar(ScalarValue::U64(1_000)),
        };
        let no_amount = Packet {
            packet_type: 0x03,
            function_name: Some(b"some_fn".to_vec()),
            amount: None,
            endpoint: None,
            status_code: None,
        };
        assert!(!evaluate(&p, &no_amount));
    }

    #[test]
    fn roundtrip_encode_decode() {
        let p = Predicate::And(vec![
            Predicate::Leaf {
                field: FieldId::FunctionName,
                op: Op::NotInSet,
                value: Value::Set(vec![
                    ScalarValue::Bytes(b"transfer".to_vec()),
                    ScalarValue::Bytes(b"withdraw".to_vec()),
                ]),
            },
            Predicate::Leaf {
                field: FieldId::Amount,
                op: Op::Lte,
                value: Value::Scalar(ScalarValue::U64(500_000)),
            },
        ]);
        let encoded = p.encode();
        let decoded = Predicate::decode(&encoded).expect("roundtrip failed");
        assert_eq!(p, decoded);
    }

    #[test]
    fn evaluate_all_passes() {
        let p = Predicate::Leaf {
            field: FieldId::Amount,
            op: Op::Lte,
            value: Value::Scalar(ScalarValue::U64(1_000)),
        };
        let packets = vec![settlement(100), settlement(500), settlement(1_000)];
        assert!(evaluate_all(&p, &packets));
    }

    #[test]
    fn evaluate_all_one_violation() {
        let p = Predicate::Leaf {
            field: FieldId::Amount,
            op: Op::Lte,
            value: Value::Scalar(ScalarValue::U64(1_000)),
        };
        let packets = vec![settlement(100), settlement(1_001), settlement(200)];
        assert!(!evaluate_all(&p, &packets));
    }

    // ── Session aggregate tests ──────────────────────────────────────────────

    #[test]
    fn session_sum_under_cap() {
        let p = Predicate::SessionSum {
            field: FieldId::Amount,
            filter: None,
            op: Op::Lt,
            threshold: 10_000,
        };
        // 2000 + 3000 + 4000 = 9000 < 10000
        let packets = vec![settlement(2_000), settlement(3_000), settlement(4_000)];
        assert!(evaluate_all(&p, &packets));
    }

    #[test]
    fn session_sum_over_cap() {
        let p = Predicate::SessionSum {
            field: FieldId::Amount,
            filter: None,
            op: Op::Lt,
            threshold: 10_000,
        };
        // 4000 + 4000 + 4000 = 12000 >= 10000
        let packets = vec![settlement(4_000), settlement(4_000), settlement(4_000)];
        assert!(!evaluate_all(&p, &packets));
    }

    #[test]
    fn session_sum_exactly_at_cap_lte() {
        let p = Predicate::SessionSum {
            field: FieldId::Amount,
            filter: None,
            op: Op::Lte,
            threshold: 10_000,
        };
        // 5000 + 5000 = 10000 <= 10000
        let packets = vec![settlement(5_000), settlement(5_000)];
        assert!(evaluate_all(&p, &packets));
    }

    #[test]
    fn session_count_under_limit() {
        let p = Predicate::SessionCount {
            filter: None,
            op: Op::Lt,
            threshold: 10,
        };
        let packets: Vec<Packet> = (0..5).map(|_| settlement(100)).collect();
        assert!(evaluate_all(&p, &packets));
    }

    #[test]
    fn session_count_over_limit() {
        let p = Predicate::SessionCount {
            filter: None,
            op: Op::Lt,
            threshold: 4,
        };
        // 5 packets, limit < 4 → fails
        let packets: Vec<Packet> = (0..5).map(|_| settlement(100)).collect();
        assert!(!evaluate_all(&p, &packets));
    }

    #[test]
    fn session_count_with_filter() {
        // Count only packets where packet_type == 0x05 (settlement)
        let filter = Predicate::Leaf {
            field: FieldId::PacketType,
            op: Op::Eq,
            value: Value::Scalar(ScalarValue::U8(0x05)),
        };
        let p = Predicate::SessionCount {
            filter: Some(Box::new(filter)),
            op: Op::Lt,
            threshold: 4,
        };
        // 3 settlements + 2 tool calls → count = 3 < 4
        let packets = vec![
            settlement(100), settlement(200), settlement(300),
            tool_call("fn_a"), tool_call("fn_b"),
        ];
        assert!(evaluate_all(&p, &packets));
    }

    #[test]
    fn and_per_packet_and_session_sum() {
        // Each settlement must be <= 5000 AND total must be < 10000
        let p = Predicate::And(vec![
            Predicate::Leaf {
                field: FieldId::Amount,
                op: Op::Lte,
                value: Value::Scalar(ScalarValue::U64(5_000)),
            },
            Predicate::SessionSum {
                field: FieldId::Amount,
                filter: None,
                op: Op::Lt,
                threshold: 10_000,
            },
        ]);
        // 3000 + 4000 = 7000 < 10000, both <= 5000 → passes
        assert!(evaluate_all(&p, &vec![settlement(3_000), settlement(4_000)]));
        // 5000 + 5000 = 10000, not < 10000 → fails session constraint
        assert!(!evaluate_all(&p, &vec![settlement(5_000), settlement(5_000)]));
        // 6000 > 5000 → fails per-packet constraint
        assert!(!evaluate_all(&p, &vec![settlement(6_000), settlement(2_000)]));
    }

    // Negation wrapping an aggregate: verify the dangerous direction.
    // If the Not guard skipped negation, a noncompliant trace (inner = true) would
    // falsely evaluate as compliant (outer = true).  This test is constructed so
    // that a broken guard causes assert!(!...) to panic, not just an overly
    // conservative rejection.
    #[test]
    fn not_session_sum_does_not_false_positive() {
        // NOT (session_sum < 10_000) means sum must be >= 10_000 to pass.
        let p = Predicate::Not(Box::new(Predicate::SessionSum {
            field: FieldId::Amount,
            filter: None,
            op: Op::Lt,
            threshold: 10_000,
        }));
        // sum = 5_000 < 10_000 → inner = true → Not = false (non-compliant).
        // A broken guard returning true here would be a live security bug.
        assert!(!evaluate_all(&p, &[settlement(2_000), settlement(3_000)]));
        // sum = 12_000 >= 10_000 → inner = false → Not = true (compliant).
        assert!(evaluate_all(&p, &[settlement(6_000), settlement(6_000)]));
    }

    #[test]
    fn not_session_count_does_not_false_positive() {
        // NOT (session_count < 5) means count must be >= 5 to pass.
        let p = Predicate::Not(Box::new(Predicate::SessionCount {
            filter: None,
            op: Op::Lt,
            threshold: 5,
        }));
        // 3 packets: count = 3 < 5 → inner = true → Not = false (non-compliant).
        let few: Vec<Packet> = (0..3).map(|_| settlement(100)).collect();
        assert!(!evaluate_all(&p, &few));
        // 7 packets: count = 7 >= 5 → inner = false → Not = true (compliant).
        let many: Vec<Packet> = (0..7).map(|_| settlement(100)).collect();
        assert!(evaluate_all(&p, &many));
    }

    // ── validate_predicate_shape tests ──────────────────────────────────────

    #[test]
    fn or_mixed_session_aggregate_is_rejected() {
        // Or(per-packet leaf, SessionSum) — the session aggregate is silently bypassed
        // by the per-packet true-sentinel in evaluate_session_constraints.
        let p = Predicate::Or(vec![
            Predicate::Leaf {
                field: FieldId::Amount,
                op: Op::Lte,
                value: Value::Scalar(ScalarValue::U64(1_000_000)),
            },
            Predicate::SessionSum {
                field: FieldId::Amount,
                filter: None,
                op: Op::Lt,
                threshold: 10_000,
            },
        ]);
        assert!(validate_predicate_shape(&p).is_err());
    }

    #[test]
    fn or_child_with_mixed_internals_is_rejected() {
        // Or(And(Leaf, SessionSum), SessionSum) — the And child has both types internally.
        // The per-packet leaf inside the And is bypassed because the sibling SessionSum
        // sentinel short-circuits the Or in the per-packet phase. The original fix used
        // `!has_session_aggregate(c)` and missed this; the corrected fix uses
        // `has_per_packet_leaf(c)` to detect the leaf inside the And child.
        let p = Predicate::Or(vec![
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
                    threshold: 10_000,
                },
            ]),
            Predicate::SessionSum {
                field: FieldId::Amount,
                filter: None,
                op: Op::Lt,
                threshold: 50_000,
            },
        ]);
        assert!(validate_predicate_shape(&p).is_err());
    }

    #[test]
    fn not_wrapping_mixed_subtree_is_rejected() {
        // Not(And(Leaf, SessionSum)) — the Not arm defers the entire inner subtree to the
        // session phase when any aggregate is present, silently dropping the per-packet
        // leaf check inside the And.
        let p = Predicate::Not(Box::new(Predicate::And(vec![
            Predicate::Leaf {
                field: FieldId::Amount,
                op: Op::Lte,
                value: Value::Scalar(ScalarValue::U64(1_000_000)),
            },
            Predicate::SessionSum {
                field: FieldId::Amount,
                filter: None,
                op: Op::Lt,
                threshold: 10_000,
            },
        ])));
        assert!(validate_predicate_shape(&p).is_err());
    }

    #[test]
    fn or_of_session_aggregates_is_allowed() {
        // Or(SessionSum, SessionCount) — both children are session-level; no sentinel
        // interference. Evaluated correctly: Or passes if either aggregate holds.
        let p = Predicate::Or(vec![
            Predicate::SessionSum {
                field: FieldId::Amount,
                filter: None,
                op: Op::Lt,
                threshold: 5_000,
            },
            Predicate::SessionCount {
                filter: None,
                op: Op::Lt,
                threshold: 10,
            },
        ]);
        assert!(validate_predicate_shape(&p).is_ok());
        // sum = 6000 >= 5000 (first arm false), count = 3 < 10 (second arm true) → passes
        let packets = vec![settlement(2_000), settlement(2_000), settlement(2_000)];
        assert!(evaluate_all(&p, &packets));
        // sum = 6000, count = 12 >= 10 → both arms false → fails
        let many: Vec<Packet> = (0..12).map(|_| settlement(600)).collect();
        assert!(!evaluate_all(&p, &many));
    }

    #[test]
    fn or_of_leaves_is_allowed() {
        // Pure per-packet Or — unaffected by the validation rule.
        let p = Predicate::Or(vec![
            Predicate::Leaf {
                field: FieldId::Amount,
                op: Op::Lte,
                value: Value::Scalar(ScalarValue::U64(1_000_000)),
            },
            Predicate::Leaf {
                field: FieldId::Amount,
                op: Op::Gte,
                value: Value::Scalar(ScalarValue::U64(0)),
            },
        ]);
        assert!(validate_predicate_shape(&p).is_ok());
    }

    #[test]
    fn session_sum_roundtrip_encode_decode() {
        let p = Predicate::And(vec![
            Predicate::SessionSum {
                field: FieldId::Amount,
                filter: Some(Box::new(Predicate::Leaf {
                    field: FieldId::PacketType,
                    op: Op::Eq,
                    value: Value::Scalar(ScalarValue::U8(0x05)),
                })),
                op: Op::Lt,
                threshold: 10_000,
            },
            Predicate::SessionCount {
                filter: None,
                op: Op::Lte,
                threshold: 100,
            },
        ]);
        let encoded = p.encode();
        let decoded = Predicate::decode(&encoded).expect("roundtrip failed");
        assert_eq!(p, decoded);
    }
}
