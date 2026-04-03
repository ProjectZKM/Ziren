use serde_json::{json, Value};
use std::error::Error;
use std::io::Write;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

// ---------------------------------------------------------------------------
// Minimal RLP encoder (just enough for payload construction)
// ---------------------------------------------------------------------------

fn to_be_bytes_minimal(val: usize) -> Vec<u8> {
    if val == 0 {
        return vec![0];
    }
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap();
    bytes[start..].to_vec()
}

/// RLP-encode a u64 value.
fn rlp_encode_u64(val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![0x80]; // empty byte string
    }
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap();
    let significant = &bytes[start..];
    if significant.len() == 1 && significant[0] < 0x80 {
        significant.to_vec()
    } else {
        let mut out = vec![0x80 + significant.len() as u8];
        out.extend_from_slice(significant);
        out
    }
}

/// RLP-encode a byte string.
fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        data.to_vec()
    } else if data.len() < 56 {
        let mut out = vec![0x80 + data.len() as u8];
        out.extend_from_slice(data);
        out
    } else {
        let len_bytes = to_be_bytes_minimal(data.len());
        let mut out = vec![0xb7 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(data);
        out
    }
}

/// Build an RLP list header for a given content length.
fn rlp_list_header(content_len: usize) -> Vec<u8> {
    if content_len < 56 {
        vec![0xc0 + content_len as u8]
    } else {
        let len_bytes = to_be_bytes_minimal(content_len);
        let mut header = vec![0xf7 + len_bytes.len() as u8];
        header.extend_from_slice(&len_bytes);
        header
    }
}

/// Wrap already-encoded RLP items into a list.
fn rlp_wrap_list(items: &[&[u8]]) -> Vec<u8> {
    let content_len: usize = items.iter().map(|i| i.len()).sum();
    let mut out = rlp_list_header(content_len);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Encode a list of byte strings: list([rlp_bytes(a), rlp_bytes(b), ...]).
fn rlp_encode_bytes_list(items: &[Vec<u8>]) -> Vec<u8> {
    let encoded: Vec<Vec<u8>> = items.iter().map(|b| rlp_encode_bytes(b)).collect();
    let refs: Vec<&[u8]> = encoded.iter().map(|v| v.as_slice()).collect();
    rlp_wrap_list(&refs)
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers
// ---------------------------------------------------------------------------

fn rpc_call(url: &str, method: &str, params: &[Value]) -> Result<Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let client = reqwest::blocking::Client::new();
    let resp: Value = client
        .post(url)
        .json(&body)
        .send()?
        .json()?;
    if let Some(err) = resp.get("error") {
        return Err(format!("RPC error: {err}").into());
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| "missing result field in RPC response".into())
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    Ok(hex::decode(s)?)
}

fn parse_hex_u64(s: &str) -> Result<u64> {
    let s = s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    Ok(u64::from_str_radix(s, 16)?)
}

// ---------------------------------------------------------------------------
// RPC data fetchers
// ---------------------------------------------------------------------------

fn fetch_chain_id(url: &str) -> Result<u64> {
    let result = rpc_call(url, "eth_chainId", &[])?;
    parse_hex_u64(result.as_str().ok_or("eth_chainId: expected hex string")?)
}

fn fetch_block_number(url: &str) -> Result<u64> {
    let result = rpc_call(url, "eth_blockNumber", &[])?;
    parse_hex_u64(result.as_str().ok_or("eth_blockNumber: expected hex string")?)
}

fn fetch_raw_block(url: &str, block_tag: &str) -> Result<Vec<u8>> {
    let result = rpc_call(url, "debug_getRawBlock", &[json!(block_tag)])?;
    decode_hex(result.as_str().ok_or("debug_getRawBlock: expected hex string")?)
}

/// Fetch execution witness and return its ExtWitness RLP bytes.
///
/// Handles response formats from different go-ethereum versions:
///   1. Hex string  – already RLP-encoded ExtWitness bytes.
///   2. JSON object – ExtWitness with JSON header objects or hex-encoded header RLP.
fn fetch_witness_rlp(url: &str, block_tag: &str) -> Result<Vec<u8>> {
    let result = rpc_call(url, "debug_executionWitness", &[json!(block_tag)])?;

    // Format 1: hex string (modern go-ethereum)
    if let Some(hex_str) = result.as_str() {
        return decode_hex(hex_str);
    }

    // Format 2/3: JSON object
    if let Some(obj) = result.as_object() {
        return encode_witness_from_json(obj);
    }

    Err("debug_executionWitness: unexpected response format".into())
}

// ---------------------------------------------------------------------------
// Header JSON → RLP encoder
// ---------------------------------------------------------------------------

/// Decode a hex string from a JSON value, returning empty vec for null.
fn json_hex_bytes(v: &Value) -> Result<Vec<u8>> {
    match v.as_str() {
        Some(s) => decode_hex(s),
        None => Ok(vec![]),
    }
}

/// Decode a hex string as u64 from a JSON value, returning 0 for null.
fn json_hex_u64(v: &Value) -> Result<u64> {
    match v.as_str() {
        Some(s) => parse_hex_u64(s),
        None => Ok(0),
    }
}

/// Decode a hex string as big-endian big integer bytes (no leading zeros).
fn json_hex_bigint_bytes(v: &Value) -> Result<Vec<u8>> {
    match v.as_str() {
        Some(s) => {
            let bytes = decode_hex(s)?;
            // Strip leading zeros
            let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
            Ok(bytes[start..].to_vec())
        }
        None => Ok(vec![]),
    }
}

/// RLP-encode a fixed-size byte array (e.g. Hash=32 bytes, Address=20 bytes, Bloom=256 bytes).
/// These are encoded as byte strings (never single-byte shortcut for values >= 0x80).
fn rlp_encode_fixed_bytes(data: &[u8]) -> Vec<u8> {
    rlp_encode_bytes(data)
}

/// RLP-encode a big integer from its big-endian byte representation (no leading zeros).
/// Same encoding as uint64 but from arbitrary-length bytes.
fn rlp_encode_bigint(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return vec![0x80]; // zero
    }
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.to_vec();
    }
    let mut out = vec![0x80 + bytes.len() as u8];
    out.extend_from_slice(bytes);
    out
}

/// RLP-encode an optional *uint64 field. Returns None if the JSON value is null,
/// meaning this optional field should be omitted (rlp:"optional" trailing).
fn rlp_encode_optional_u64(v: &Value) -> Result<Option<Vec<u8>>> {
    if v.is_null() {
        Ok(None)
    } else {
        Ok(Some(rlp_encode_u64(json_hex_u64(v)?)))
    }
}

/// RLP-encode an optional *common.Hash field.
fn rlp_encode_optional_hash(v: &Value) -> Result<Option<Vec<u8>>> {
    if v.is_null() {
        Ok(None)
    } else {
        Ok(Some(rlp_encode_fixed_bytes(&json_hex_bytes(v)?)))
    }
}

/// RLP-encode an optional *big.Int field.
fn rlp_encode_optional_bigint(v: &Value) -> Result<Option<Vec<u8>>> {
    if v.is_null() {
        Ok(None)
    } else {
        Ok(Some(rlp_encode_bigint(&json_hex_bigint_bytes(v)?)))
    }
}

/// RLP-encode a go-ethereum Header JSON object.
///
/// Field order matches go-ethereum's `core/types.Header` struct definition,
/// with rlp:"optional" trailing fields omitted when null.
fn rlp_encode_header_json(h: &Value) -> Result<Vec<u8>> {
    // Required fields (always present)
    let mut fields: Vec<Vec<u8>> = vec![
        rlp_encode_fixed_bytes(&json_hex_bytes(h.get("parentHash").unwrap_or(&Value::Null))?),     // ParentHash  common.Hash
        rlp_encode_fixed_bytes(&json_hex_bytes(h.get("sha3Uncles").unwrap_or(&Value::Null))?),     // UncleHash   common.Hash
        rlp_encode_fixed_bytes(&json_hex_bytes(h.get("miner").unwrap_or(&Value::Null))?),          // Coinbase    common.Address
        rlp_encode_fixed_bytes(&json_hex_bytes(h.get("stateRoot").unwrap_or(&Value::Null))?),      // Root        common.Hash
        rlp_encode_fixed_bytes(&json_hex_bytes(h.get("transactionsRoot").unwrap_or(&Value::Null))?), // TxHash    common.Hash
        rlp_encode_fixed_bytes(&json_hex_bytes(h.get("receiptsRoot").unwrap_or(&Value::Null))?),   // ReceiptHash common.Hash
        rlp_encode_fixed_bytes(&json_hex_bytes(h.get("logsBloom").unwrap_or(&Value::Null))?),      // Bloom       Bloom
        rlp_encode_bigint(&json_hex_bigint_bytes(h.get("difficulty").unwrap_or(&Value::Null))?),   // Difficulty  *big.Int
        rlp_encode_bigint(&json_hex_bigint_bytes(h.get("number").unwrap_or(&Value::Null))?),       // Number      *big.Int
        rlp_encode_u64(json_hex_u64(h.get("gasLimit").unwrap_or(&Value::Null))?),                  // GasLimit    uint64
        rlp_encode_u64(json_hex_u64(h.get("gasUsed").unwrap_or(&Value::Null))?),                   // GasUsed     uint64
        rlp_encode_u64(json_hex_u64(h.get("timestamp").unwrap_or(&Value::Null))?),                 // Time        uint64
        rlp_encode_bytes(&json_hex_bytes(h.get("extraData").unwrap_or(&Value::Null))?),            // Extra       []byte
        rlp_encode_fixed_bytes(&json_hex_bytes(h.get("mixHash").unwrap_or(&Value::Null))?),        // MixDigest   common.Hash
        rlp_encode_fixed_bytes(&json_hex_bytes(h.get("nonce").unwrap_or(&Value::Null))?),          // Nonce       BlockNonce (8 bytes)
    ];

    // Optional fields (rlp:"optional") — must be appended in order,
    // trailing nulls are omitted.
    let optional: Vec<(&str, Box<dyn Fn(&Value) -> Result<Option<Vec<u8>>>>)> = vec![
        ("baseFeePerGas",        Box::new(|v| rlp_encode_optional_bigint(v))),    // BaseFee          *big.Int
        ("withdrawalsRoot",      Box::new(|v| rlp_encode_optional_hash(v))),      // WithdrawalsHash  *common.Hash
        ("blobGasUsed",          Box::new(|v| rlp_encode_optional_u64(v))),       // BlobGasUsed      *uint64
        ("excessBlobGas",        Box::new(|v| rlp_encode_optional_u64(v))),       // ExcessBlobGas    *uint64
        ("parentBeaconBlockRoot", Box::new(|v| rlp_encode_optional_hash(v))),     // ParentBeaconRoot *common.Hash
        ("requestsHash",         Box::new(|v| rlp_encode_optional_hash(v))),      // RequestsHash     *common.Hash
    ];

    // Find last non-null optional field to know how many to include.
    let mut last_present = 0;
    for (i, (key, _)) in optional.iter().enumerate() {
        let v = h.get(*key).unwrap_or(&Value::Null);
        if !v.is_null() {
            last_present = i + 1;
        }
    }

    // Append optional fields up to the last present one.
    for (i, (key, encoder)) in optional.iter().enumerate() {
        if i >= last_present {
            break;
        }
        let v = h.get(*key).unwrap_or(&Value::Null);
        match encoder(v)? {
            Some(encoded) => fields.push(encoded),
            None => fields.push(rlp_encode_bytes(&[])), // null in the middle → encode as empty
        }
    }

    let refs: Vec<&[u8]> = fields.iter().map(|f| f.as_slice()).collect();
    Ok(rlp_wrap_list(&refs))
}

// ---------------------------------------------------------------------------
// Witness JSON → RLP
// ---------------------------------------------------------------------------

/// Construct ExtWitness RLP from a JSON object.
///
/// Supports two header formats:
///   - JSON header objects (from debug_executionWitness API)
///   - Hex-encoded header RLP strings (alternative format)
fn encode_witness_from_json(obj: &serde_json::Map<String, Value>) -> Result<Vec<u8>> {
    let headers = obj.get("headers")
        .and_then(|v| v.as_array())
        .ok_or("witness: missing headers array")?;
    let codes = obj.get("codes")
        .and_then(|v| v.as_array())
        .ok_or("witness: missing codes array")?;
    let state = obj.get("state")
        .and_then(|v| v.as_array())
        .ok_or("witness: missing state array")?;
    let empty_vec = vec![];
    let keys = obj.get("keys")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_vec);

    // Encode headers — support both JSON objects and hex RLP strings.
    let mut header_items: Vec<Vec<u8>> = Vec::new();
    for h in headers {
        if let Some(hex_str) = h.as_str() {
            // Hex-encoded RLP string
            header_items.push(decode_hex(hex_str)?);
        } else if h.is_object() {
            // JSON header object → RLP encode
            header_items.push(rlp_encode_header_json(h)?);
        } else {
            return Err("witness: header must be hex string or JSON object".into());
        }
    }

    let codes_bytes: Result<Vec<Vec<u8>>> = codes.iter()
        .map(|v| json_hex_bytes(v))
        .collect();
    let state_bytes: Result<Vec<Vec<u8>>> = state.iter()
        .map(|v| json_hex_bytes(v))
        .collect();
    let keys_bytes: Result<Vec<Vec<u8>>> = keys.iter()
        .map(|v| json_hex_bytes(v))
        .collect();

    // ExtWitness RLP: list([headers_list, codes_list, state_list, keys_list])
    let header_refs: Vec<&[u8]> = header_items.iter().map(|v| v.as_slice()).collect();
    let headers_list = rlp_wrap_list(&header_refs);
    let codes_list = rlp_encode_bytes_list(&codes_bytes?);
    let state_list = rlp_encode_bytes_list(&state_bytes?);
    let keys_list = rlp_encode_bytes_list(&keys_bytes?);

    Ok(rlp_wrap_list(&[&headers_list, &codes_list, &state_list, &keys_list]))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Resolve a block argument ("latest", decimal, or hex) to (block_number, block_tag).
fn resolve_block(url: &str, block_arg: &str) -> Result<(u64, String)> {
    let block_arg = block_arg.trim();
    if block_arg.eq_ignore_ascii_case("latest") {
        let num = fetch_block_number(url)?;
        Ok((num, format!("0x{num:x}")))
    } else if block_arg.starts_with("0x") || block_arg.starts_with("0X") {
        let num = parse_hex_u64(block_arg)?;
        Ok((num, format!("0x{num:x}")))
    } else {
        let num: u64 = block_arg.parse()?;
        Ok((num, format!("0x{num:x}")))
    }
}

/// Fetch a keeper payload from an Ethereum JSON-RPC endpoint.
///
/// Returns the RLP-encoded payload bytes (identical format to the Go payloadgen tool).
pub fn fetch_payload(url: &str, block_arg: &str, save: bool) -> Result<(u64, Vec<u8>)> {
    let chain_id = fetch_chain_id(url)?;
    let (block_num, block_tag) = resolve_block(url, block_arg)?;

    println!("Fetching payload: chain_id={chain_id} block=0x{block_num:x}");

    let block_rlp = fetch_raw_block(url, &block_tag)?;
    let witness_rlp = fetch_witness_rlp(url, &block_tag)?;

    // Payload RLP: list([chainID, block, witness])
    let chain_id_encoded = rlp_encode_u64(chain_id);
    let content_len = chain_id_encoded.len() + block_rlp.len() + witness_rlp.len();
    let mut payload = rlp_list_header(content_len);
    payload.extend_from_slice(&chain_id_encoded);
    payload.extend_from_slice(&block_rlp);
    payload.extend_from_slice(&witness_rlp);

    let size_mb = payload.len() as f64 / (1024.0 * 1024.0);
    println!("Payload ready: block=0x{block_num:x} size={size_mb:.2}MB chain_id={chain_id}");

    if save {
        let filename = format!("{block_num:x}_payload.rlp");
        let mut file = std::fs::File::create(&filename)?;
        file.write_all(&payload)?;
        println!("Payload saved to {filename}");
    }

    Ok((block_num, payload))
}

/// Fetch the latest block number.
pub fn latest_block_number(url: &str) -> Result<u64> {
    fetch_block_number(url)
}
