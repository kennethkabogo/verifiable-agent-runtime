use crate::types::{FieldId, Op, Packet, Predicate, ScalarValue, Value};

pub fn evaluate(pred: &Predicate, packet: &Packet) -> bool {
    match pred {
        Predicate::And(children) => children.iter().all(|c| evaluate(c, packet)),
        Predicate::Or(children) => children.iter().any(|c| evaluate(c, packet)),
        Predicate::Not(inner) => !evaluate(inner, packet),
        Predicate::Leaf { field, op, value } => eval_leaf(field, op, value, packet),
    }
}

/// Predicate must hold for ALL packets (universal quantification over the trace).
pub fn evaluate_all(pred: &Predicate, packets: &[Packet]) -> bool {
    packets.iter().all(|p| evaluate(pred, p))
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
        _ => false, // ordering on variable-length bytes not defined
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
        // A packet with no amount evaluated against an Amount predicate should fail.
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
}
