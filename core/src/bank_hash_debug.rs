//! Bank hash mismatch debugging protocol for Mithril coordination.
//!
//! When enabled, after each slot is frozen Agave waits (with timeout) for a
//! status message from Mithril via a shared Redis instance. If Mithril reports
//! a bank hash mismatch, Agave dumps the post-execution account state for that
//! slot into Redis so Mithril can diff against its own state.
//!
//! This module is completely inert when the feature is disabled (no Redis
//! connection is made).

use {
    base64::{engine::general_purpose::STANDARD as BASE64, Engine},
    log::*,
    redis::ConnectionLike,
    serde::Serialize,
    solana_account::ReadableAccount,
    solana_clock::Slot,
    solana_runtime::bank::Bank,
    std::{
        sync::Mutex,
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the bank hash debug protocol.
#[derive(Clone, Debug)]
pub struct BankHashDebugConfig {
    /// Redis URL, e.g. "redis://10.0.1.5:6379"
    pub redis_url: String,
    /// How long to wait for Mithril's status message before giving up (ms).
    pub mithril_wait_timeout_ms: u64,
    /// Whether the debug protocol is active.
    pub enabled: bool,
}

impl Default for BankHashDebugConfig {
    fn default() -> Self {
        Self {
            redis_url: String::new(),
            mithril_wait_timeout_ms: 30_000,
            enabled: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum BankHashDebugError {
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("timeout waiting for Mithril status")]
    Timeout,
    #[error("slot mismatch: expected {expected}, got {got}")]
    SlotMismatch { expected: Slot, got: Slot },
}

// ---------------------------------------------------------------------------
// Dump format
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AccountDump {
    pubkey: String,
    lamports: u64,
    owner: String,
    executable: bool,
    rent_epoch: u64,
    data_base64: String,
}

#[derive(Serialize)]
struct SlotDump {
    slot: Slot,
    agave_bank_hash: String,
    encoding: &'static str,
    timestamp_unix_ms: u64,
    accounts: Vec<AccountDump>,
}

// ---------------------------------------------------------------------------
// Redis stream / key constants
// ---------------------------------------------------------------------------

const STREAM_MITHRIL_TO_AGAVE: &str = "bh_debug:mithril_to_agave";
const STREAM_AGAVE_TO_MITHRIL: &str = "bh_debug:agave_to_mithril";
const DUMP_KEY_PREFIX: &str = "bh_debug:dump:";
const DUMP_TTL_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
// BankHashDebugger
// ---------------------------------------------------------------------------

pub struct BankHashDebugger {
    config: BankHashDebugConfig,
    redis_client: redis::Client,
    /// Tracks the last-seen Redis stream message ID.
    last_stream_id: Mutex<String>,
}

impl BankHashDebugger {
    pub fn new(config: BankHashDebugConfig) -> Result<Self, BankHashDebugError> {
        let redis_client = redis::Client::open(config.redis_url.as_str())?;
        Ok(Self {
            config,
            redis_client,
            last_stream_id: Mutex::new("$".to_string()),
        })
    }

    /// Called after `bank.freeze()` for every slot.
    ///
    /// Blocks (synchronously) until Mithril responds or the timeout elapses.
    /// Returns immediately (no-op) if `config.enabled == false`.
    pub fn process_frozen_bank(
        &self,
        slot: Slot,
        bank: &Bank,
    ) -> Result<(), BankHashDebugError> {
        if !self.config.enabled {
            return Ok(());
        }

        info!(
            target: "bank_hash_debug",
            "Slot {}: waiting for Mithril status (timeout={}ms)",
            slot, self.config.mithril_wait_timeout_ms
        );

        let mut con = match self.redis_client.get_connection_with_timeout(
            Duration::from_millis(self.config.mithril_wait_timeout_ms),
        ) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    target: "bank_hash_debug",
                    "Slot {}: failed to connect to Redis: {}", slot, e
                );
                return Ok(());
            }
        };
        con.set_read_timeout(Some(Duration::from_millis(
            self.config.mithril_wait_timeout_ms,
        )))
        .ok();

        // --- Read from Mithril's stream ----------------------------------
        let last_id = {
            let guard = self.last_stream_id.lock().unwrap();
            guard.clone()
        };

        let result: redis::RedisResult<redis::Value> = redis::cmd("XREAD")
            .arg("COUNT")
            .arg(1)
            .arg("BLOCK")
            .arg(self.config.mithril_wait_timeout_ms)
            .arg("STREAMS")
            .arg(STREAM_MITHRIL_TO_AGAVE)
            .arg(&last_id)
            .query(&mut con);

        let response = match result {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    target: "bank_hash_debug",
                    "Slot {}: Redis XREAD error: {}", slot, e
                );
                return Ok(());
            }
        };

        // Parse the XREAD response.
        // XREAD returns: [ [stream_name, [ [id, [field, value, ...]], ... ]], ... ]
        // or Nil on timeout.
        let (msg_id, fields) = match parse_xread_response(&response) {
            Some(parsed) => parsed,
            None => {
                warn!(
                    target: "bank_hash_debug",
                    "Slot {}: Mithril did not respond within timeout", slot
                );
                return Ok(());
            }
        };

        // Update last-seen ID
        {
            let mut guard = self.last_stream_id.lock().unwrap();
            *guard = msg_id;
        }

        // Extract fields
        let msg_slot: Option<Slot> = fields
            .get("slot")
            .and_then(|s| s.parse().ok());
        let status = fields.get("status").cloned().unwrap_or_default();

        // Validate slot
        if let Some(msg_slot) = msg_slot {
            if msg_slot != slot {
                warn!(
                    target: "bank_hash_debug",
                    "Slot {}: received message for slot {} instead, ignoring", slot, msg_slot
                );
                return Ok(());
            }
        } else {
            warn!(
                target: "bank_hash_debug",
                "Slot {}: message missing or unparseable slot field", slot
            );
            return Ok(());
        }

        match status.as_str() {
            "ok" => {
                info!(
                    target: "bank_hash_debug",
                    "Slot {}: Mithril reports OK", slot
                );
                // Send ack
                self.xadd_ack(&mut con, slot);
            }
            "mismatch" => {
                info!(
                    target: "bank_hash_debug",
                    "Slot {}: bank hash MISMATCH detected, dumping accounts", slot
                );
                self.handle_mismatch(&mut con, slot, bank);
            }
            other => {
                warn!(
                    target: "bank_hash_debug",
                    "Slot {}: unknown status '{}', treating as OK", slot, other
                );
                self.xadd_ack(&mut con, slot);
            }
        }

        Ok(())
    }

    // --- helpers ---------------------------------------------------------

    fn xadd_ack(&self, con: &mut dyn ConnectionLike, slot: Slot) {
        let result: redis::RedisResult<String> = redis::cmd("XADD")
            .arg(STREAM_AGAVE_TO_MITHRIL)
            .arg("*")
            .arg("slot")
            .arg(slot.to_string())
            .arg("event")
            .arg("ack")
            .query(con);

        if let Err(e) = result {
            warn!(
                target: "bank_hash_debug",
                "Slot {}: failed to XADD ack: {}", slot, e
            );
        }
    }

    fn handle_mismatch(
        &self,
        con: &mut dyn ConnectionLike,
        slot: Slot,
        bank: &Bank,
    ) {
        // Collect account state changes for this slot from the accounts cache.
        let dump = match self.collect_slot_dump(slot, bank) {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    target: "bank_hash_debug",
                    "Slot {}: failed to collect account dump: {}", slot, e
                );
                // Send a dump_failed event
                let _: redis::RedisResult<String> = redis::cmd("XADD")
                    .arg(STREAM_AGAVE_TO_MITHRIL)
                    .arg("*")
                    .arg("slot")
                    .arg(slot.to_string())
                    .arg("event")
                    .arg("dump_failed")
                    .arg("error")
                    .arg(e.to_string())
                    .query(con);
                return;
            }
        };

        let json = match serde_json::to_string(&dump) {
            Ok(j) => j,
            Err(e) => {
                warn!(
                    target: "bank_hash_debug",
                    "Slot {}: failed to serialize dump: {}", slot, e
                );
                return;
            }
        };

        let dump_key = format!("{}{}", DUMP_KEY_PREFIX, slot);

        // Store dump in Redis with TTL
        let set_result: redis::RedisResult<()> = redis::cmd("SET")
            .arg(&dump_key)
            .arg(&json)
            .arg("EX")
            .arg(DUMP_TTL_SECS)
            .query(con);
        if let Err(e) = set_result {
            warn!(
                target: "bank_hash_debug",
                "Slot {}: failed to store dump in Redis: {}", slot, e
            );
            return;
        }

        info!(
            target: "bank_hash_debug",
            "Slot {}: dump written to Redis key {} ({} accounts, {} bytes)",
            slot, dump_key, dump.accounts.len(), json.len()
        );

        // Notify Mithril
        let result: redis::RedisResult<String> = redis::cmd("XADD")
            .arg(STREAM_AGAVE_TO_MITHRIL)
            .arg("*")
            .arg("slot")
            .arg(slot.to_string())
            .arg("event")
            .arg("dump_ready")
            .arg("dump_key")
            .arg(&dump_key)
            .query(con);

        if let Err(e) = result {
            warn!(
                target: "bank_hash_debug",
                "Slot {}: failed to XADD dump_ready: {}", slot, e
            );
        }
    }

    fn collect_slot_dump(
        &self,
        slot: Slot,
        bank: &Bank,
    ) -> Result<SlotDump, BankHashDebugError> {
        let accounts_db = &bank.accounts().accounts_db;
        let slot_cache = accounts_db.accounts_cache.slot_cache(slot);

        let mut account_dumps = Vec::new();

        if let Some(slot_cache) = slot_cache {
            for entry in slot_cache.iter() {
                let pubkey = entry.key();
                let cached = entry.value();
                let account = &cached.account;
                account_dumps.push(AccountDump {
                    pubkey: pubkey.to_string(),
                    lamports: account.lamports(),
                    owner: account.owner().to_string(),
                    executable: account.executable(),
                    rent_epoch: account.rent_epoch(),
                    data_base64: BASE64.encode(account.data()),
                });
            }
        } else {
            warn!(
                target: "bank_hash_debug",
                "Slot {}: no slot cache found, dump will be empty", slot
            );
        }

        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Ok(SlotDump {
            slot,
            agave_bank_hash: bank.hash().to_string(),
            encoding: "json",
            timestamp_unix_ms,
            accounts: account_dumps,
        })
    }
}

// ---------------------------------------------------------------------------
// XREAD response parser
// ---------------------------------------------------------------------------

/// Parse the XREAD response to extract the first message's ID and fields.
///
/// XREAD returns:
/// ```text
/// [ [stream_name, [ [msg_id, [f1, v1, f2, v2, ...]], ... ]], ... ]
/// ```
/// Returns `None` if the response is nil/empty (timeout).
fn parse_xread_response(
    value: &redis::Value,
) -> Option<(String, std::collections::HashMap<String, String>)> {
    // The top-level is an array of streams
    let streams = match value {
        redis::Value::Array(arr) => arr,
        redis::Value::Nil => return None,
        _ => return None,
    };

    // First stream
    let stream = streams.first()?;
    let stream_arr = match stream {
        redis::Value::Array(arr) => arr,
        _ => return None,
    };

    // stream_arr = [stream_name, messages_array]
    let messages = stream_arr.get(1)?;
    let messages_arr = match messages {
        redis::Value::Array(arr) => arr,
        _ => return None,
    };

    // First message
    let msg = messages_arr.first()?;
    let msg_arr = match msg {
        redis::Value::Array(arr) => arr,
        _ => return None,
    };

    // msg_arr = [msg_id, [fields...]]
    let msg_id = extract_string(msg_arr.first()?)?;
    let fields_val = msg_arr.get(1)?;
    let fields_arr = match fields_val {
        redis::Value::Array(arr) => arr,
        _ => return None,
    };

    // Parse field-value pairs
    let mut fields = std::collections::HashMap::new();
    let mut i = 0;
    while i + 1 < fields_arr.len() {
        if let (Some(key), Some(val)) = (
            extract_string(&fields_arr[i]),
            extract_string(&fields_arr[i + 1]),
        ) {
            fields.insert(key, val);
        }
        i += 2;
    }

    Some((msg_id, fields))
}

fn extract_string(value: &redis::Value) -> Option<String> {
    match value {
        redis::Value::BulkString(bytes) => String::from_utf8(bytes.clone()).ok(),
        redis::Value::SimpleString(s) => Some(s.clone()),
        redis::Value::Int(i) => Some(i.to_string()),
        _ => None,
    }
}
