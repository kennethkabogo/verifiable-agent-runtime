use serde::{Deserialize, Serialize};

// ─── Packet ──────────────────────────────────────────────────────────────────
//
// Minimal packet representation for predicate evaluation.
// Serde/bincode is used for SP1 circuit I/O.
// encode/decode is the APEX wire format (positional binary, big-endian).

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub packet_type: u8,
    pub function_name: Option<Vec<u8>>,
    pub amount: Option<u64>,
    pub endpoint: Option<Vec<u8>>,
    pub status_code: Option<u16>,
}

impl Packet {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.packet_type);
        let flags: u8 = (self.function_name.is_some() as u8)
            | ((self.amount.is_some() as u8) << 1)
            | ((self.endpoint.is_some() as u8) << 2)
            | ((self.status_code.is_some() as u8) << 3);
        out.push(flags);
        if let Some(ref name) = self.function_name {
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(name);
        }
        if let Some(v) = self.amount {
            out.extend_from_slice(&v.to_be_bytes());
        }
        if let Some(ref ep) = self.endpoint {
            out.extend_from_slice(&(ep.len() as u16).to_be_bytes());
            out.extend_from_slice(ep);
        }
        if let Some(v) = self.status_code {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        let packet_type = buf[0];
        let flags = buf[1];
        let mut pos = 2;

        macro_rules! read_bytes_field {
            () => {{
                if pos + 2 > buf.len() {
                    return Err(DecodeError::UnexpectedEof);
                }
                let len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
                pos += 2;
                if pos + len > buf.len() {
                    return Err(DecodeError::UnexpectedEof);
                }
                let v = buf[pos..pos + len].to_vec();
                pos += len;
                v
            }};
        }

        let function_name = if flags & 0x01 != 0 { Some(read_bytes_field!()) } else { None };
        let amount = if flags & 0x02 != 0 {
            if pos + 8 > buf.len() {
                return Err(DecodeError::UnexpectedEof);
            }
            let v = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
            pos += 8;
            Some(v)
        } else {
            None
        };
        let endpoint = if flags & 0x04 != 0 { Some(read_bytes_field!()) } else { None };
        let status_code = if flags & 0x08 != 0 {
            if pos + 2 > buf.len() {
                return Err(DecodeError::UnexpectedEof);
            }
            let v = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            Some(v)
        } else {
            None
        };

        Ok((Packet { packet_type, function_name, amount, endpoint, status_code }, pos))
    }
}

// ─── Predicate wire format ────────────────────────────────────────────────────
//
// Node kind (u8):
//   0x01  Leaf  { field: FieldId(u8), op: Op(u8), value }
//   0x02  And   { count: u8, nodes[count] }
//   0x03  Or    { count: u8, nodes[count] }
//   0x04  Not   { node }
//
// FieldId:
//   0x01  PacketType   — scalar: u8
//   0x02  FunctionName — scalar: u16be-len + bytes
//   0x03  Amount       — scalar: u64be
//   0x04  Endpoint     — scalar: u16be-len + bytes
//   0x05  StatusCode   — scalar: u16be
//
// Op:
//   0x01 Eq  0x02 Neq  0x03 Lt  0x04 Lte  0x05 Gt  0x06 Gte
//   0x07 InSet    { count: u8, scalar[count] }
//   0x08 NotInSet { count: u8, scalar[count] }

#[derive(Debug, Clone, PartialEq)]
pub enum FieldId {
    PacketType   = 0x01,
    FunctionName = 0x02,
    Amount       = 0x03,
    Endpoint     = 0x04,
    StatusCode   = 0x05,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Eq       = 0x01,
    Neq      = 0x02,
    Lt       = 0x03,
    Lte      = 0x04,
    Gt       = 0x05,
    Gte      = 0x06,
    InSet    = 0x07,
    NotInSet = 0x08,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScalarValue {
    U8(u8),
    U16(u16),
    U64(u64),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Scalar(ScalarValue),
    Set(Vec<ScalarValue>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Predicate {
    Leaf { field: FieldId, op: Op, value: Value },
    And(Vec<Predicate>),
    Or(Vec<Predicate>),
    Not(Box<Predicate>),
    // Session-level aggregate predicates — evaluated over the full trace, not per-packet.
    // SessionSum: sum of a numeric field across matching packets, compared against threshold.
    // SessionCount: count of matching packets, compared against threshold.
    SessionSum {
        field: FieldId,
        filter: Option<Box<Predicate>>,
        op: Op,
        threshold: u64,
    },
    SessionCount {
        filter: Option<Box<Predicate>>,
        op: Op,
        threshold: u64,
    },
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DecodeError {
    UnexpectedEof,
    UnknownTag(u8),
    UnknownField(u8),
    UnknownOp(u8),
    EmptySet,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for DecodeError {}

// ─── Encoder / Decoder ───────────────────────────────────────────────────────

impl Predicate {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_node(self, &mut out);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let (pred, _) = decode_node(buf)?;
        Ok(pred)
    }
}

fn encode_scalar(field: &FieldId, sv: &ScalarValue, out: &mut Vec<u8>) {
    match (field, sv) {
        (FieldId::PacketType, ScalarValue::U8(v)) => out.push(*v),
        (FieldId::Amount, ScalarValue::U64(v)) => out.extend_from_slice(&v.to_be_bytes()),
        (FieldId::StatusCode, ScalarValue::U16(v)) => out.extend_from_slice(&v.to_be_bytes()),
        (FieldId::FunctionName, ScalarValue::Bytes(b))
        | (FieldId::Endpoint, ScalarValue::Bytes(b)) => {
            out.extend_from_slice(&(b.len() as u16).to_be_bytes());
            out.extend_from_slice(b);
        }
        _ => panic!("type mismatch in encode_scalar"),
    }
}

fn encode_node(pred: &Predicate, out: &mut Vec<u8>) {
    match pred {
        Predicate::Leaf { field, op, value } => {
            out.push(0x01);
            out.push(field.clone() as u8);
            out.push(op.clone() as u8);
            match value {
                Value::Scalar(sv) => encode_scalar(field, sv, out),
                Value::Set(set) => {
                    out.push(set.len() as u8);
                    for sv in set {
                        encode_scalar(field, sv, out);
                    }
                }
            }
        }
        Predicate::And(children) => {
            out.push(0x02);
            out.push(children.len() as u8);
            for c in children {
                encode_node(c, out);
            }
        }
        Predicate::Or(children) => {
            out.push(0x03);
            out.push(children.len() as u8);
            for c in children {
                encode_node(c, out);
            }
        }
        Predicate::Not(inner) => {
            out.push(0x04);
            encode_node(inner, out);
        }
        Predicate::SessionSum { field, filter, op, threshold } => {
            out.push(0x05);
            out.push(field.clone() as u8);
            if let Some(f) = filter {
                out.push(1u8);
                encode_node(f, out);
            } else {
                out.push(0u8);
            }
            out.push(op.clone() as u8);
            out.extend_from_slice(&threshold.to_be_bytes());
        }
        Predicate::SessionCount { filter, op, threshold } => {
            out.push(0x06);
            if let Some(f) = filter {
                out.push(1u8);
                encode_node(f, out);
            } else {
                out.push(0u8);
            }
            out.push(op.clone() as u8);
            out.extend_from_slice(&threshold.to_be_bytes());
        }
    }
}

fn decode_node(buf: &[u8]) -> Result<(Predicate, usize), DecodeError> {
    if buf.is_empty() {
        return Err(DecodeError::UnexpectedEof);
    }
    match buf[0] {
        0x01 => decode_leaf(&buf[1..]).map(|(p, n)| (p, n + 1)),
        0x02 => decode_combinator(&buf[1..], false).map(|(p, n)| (p, n + 1)),
        0x03 => decode_combinator(&buf[1..], true).map(|(p, n)| (p, n + 1)),
        0x04 => {
            let (inner, n) = decode_node(&buf[1..])?;
            Ok((Predicate::Not(Box::new(inner)), n + 1))
        }
        0x05 => decode_session_sum(&buf[1..]).map(|(p, n)| (p, n + 1)),
        0x06 => decode_session_count(&buf[1..]).map(|(p, n)| (p, n + 1)),
        tag => Err(DecodeError::UnknownTag(tag)),
    }
}

fn decode_session_sum(buf: &[u8]) -> Result<(Predicate, usize), DecodeError> {
    if buf.len() < 2 {
        return Err(DecodeError::UnexpectedEof);
    }
    let field = match buf[0] {
        0x01 => FieldId::PacketType,
        0x02 => FieldId::FunctionName,
        0x03 => FieldId::Amount,
        0x04 => FieldId::Endpoint,
        0x05 => FieldId::StatusCode,
        b => return Err(DecodeError::UnknownField(b)),
    };
    let has_filter = buf[1] != 0;
    let mut pos = 2;
    let filter = if has_filter {
        let (f, n) = decode_node(&buf[pos..])?;
        pos += n;
        Some(Box::new(f))
    } else {
        None
    };
    if pos + 9 > buf.len() {
        return Err(DecodeError::UnexpectedEof);
    }
    let op = match buf[pos] {
        0x01 => Op::Eq,  0x02 => Op::Neq,
        0x03 => Op::Lt,  0x04 => Op::Lte,
        0x05 => Op::Gt,  0x06 => Op::Gte,
        b => return Err(DecodeError::UnknownOp(b)),
    };
    pos += 1;
    let threshold = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
    pos += 8;
    Ok((Predicate::SessionSum { field, filter, op, threshold }, pos))
}

fn decode_session_count(buf: &[u8]) -> Result<(Predicate, usize), DecodeError> {
    if buf.is_empty() {
        return Err(DecodeError::UnexpectedEof);
    }
    let has_filter = buf[0] != 0;
    let mut pos = 1;
    let filter = if has_filter {
        let (f, n) = decode_node(&buf[pos..])?;
        pos += n;
        Some(Box::new(f))
    } else {
        None
    };
    if pos + 9 > buf.len() {
        return Err(DecodeError::UnexpectedEof);
    }
    let op = match buf[pos] {
        0x01 => Op::Eq,  0x02 => Op::Neq,
        0x03 => Op::Lt,  0x04 => Op::Lte,
        0x05 => Op::Gt,  0x06 => Op::Gte,
        b => return Err(DecodeError::UnknownOp(b)),
    };
    pos += 1;
    let threshold = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
    pos += 8;
    Ok((Predicate::SessionCount { filter, op, threshold }, pos))
}

fn decode_combinator(buf: &[u8], is_or: bool) -> Result<(Predicate, usize), DecodeError> {
    if buf.is_empty() {
        return Err(DecodeError::UnexpectedEof);
    }
    let count = buf[0] as usize;
    let mut pos = 1;
    let mut children = Vec::with_capacity(count);
    for _ in 0..count {
        let (child, n) = decode_node(&buf[pos..])?;
        children.push(child);
        pos += n;
    }
    let pred = if is_or { Predicate::Or(children) } else { Predicate::And(children) };
    Ok((pred, pos))
}

fn decode_leaf(buf: &[u8]) -> Result<(Predicate, usize), DecodeError> {
    if buf.len() < 2 {
        return Err(DecodeError::UnexpectedEof);
    }
    let field = match buf[0] {
        0x01 => FieldId::PacketType,
        0x02 => FieldId::FunctionName,
        0x03 => FieldId::Amount,
        0x04 => FieldId::Endpoint,
        0x05 => FieldId::StatusCode,
        b => return Err(DecodeError::UnknownField(b)),
    };
    let op = match buf[1] {
        0x01 => Op::Eq,  0x02 => Op::Neq,
        0x03 => Op::Lt,  0x04 => Op::Lte,
        0x05 => Op::Gt,  0x06 => Op::Gte,
        0x07 => Op::InSet, 0x08 => Op::NotInSet,
        b => return Err(DecodeError::UnknownOp(b)),
    };
    let mut pos = 2;
    let is_set = matches!(op, Op::InSet | Op::NotInSet);

    if is_set {
        if pos >= buf.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let count = buf[pos] as usize;
        pos += 1;
        if count == 0 {
            return Err(DecodeError::EmptySet);
        }
        let mut set = Vec::with_capacity(count);
        for _ in 0..count {
            let (sv, n) = decode_scalar(&field, &buf[pos..])?;
            set.push(sv);
            pos += n;
        }
        Ok((Predicate::Leaf { field, op, value: Value::Set(set) }, pos))
    } else {
        let (sv, n) = decode_scalar(&field, &buf[pos..])?;
        Ok((Predicate::Leaf { field, op, value: Value::Scalar(sv) }, pos + n))
    }
}

fn decode_scalar(field: &FieldId, buf: &[u8]) -> Result<(ScalarValue, usize), DecodeError> {
    match field {
        FieldId::PacketType => {
            if buf.is_empty() {
                return Err(DecodeError::UnexpectedEof);
            }
            Ok((ScalarValue::U8(buf[0]), 1))
        }
        FieldId::Amount => {
            if buf.len() < 8 {
                return Err(DecodeError::UnexpectedEof);
            }
            Ok((ScalarValue::U64(u64::from_be_bytes(buf[..8].try_into().unwrap())), 8))
        }
        FieldId::StatusCode => {
            if buf.len() < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            Ok((ScalarValue::U16(u16::from_be_bytes([buf[0], buf[1]])), 2))
        }
        FieldId::FunctionName | FieldId::Endpoint => {
            if buf.len() < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() < 2 + len {
                return Err(DecodeError::UnexpectedEof);
            }
            Ok((ScalarValue::Bytes(buf[2..2 + len].to_vec()), 2 + len))
        }
    }
}
