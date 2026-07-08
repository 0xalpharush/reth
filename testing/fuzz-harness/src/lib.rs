//! Typed fuzz harness ABI for reth.

#![allow(missing_docs)]

use std::fmt;

use alloy_consensus::{
    transaction::{SignerRecoverable, Transaction},
    TxEnvelope,
};
use alloy_eips::Decodable2718;
use revm::primitives::hardfork::SpecId;
use serde::{
    de::{Error as DeError, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

pub type FuzzStatus = i32;

pub const FUZZ_REJECT: FuzzStatus = 0;
pub const FUZZ_ACCEPT: FuzzStatus = 1;
pub const TYPED_HARNESS_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NonEmpty<T> {
    items: Vec<T>,
}

impl<T> NonEmpty<T> {
    pub fn new(items: Vec<T>) -> Result<Self, Vec<T>> {
        if items.is_empty() {
            Err(items)
        } else {
            Ok(Self { items })
        }
    }
}

impl<'de, T> Deserialize<'de> for NonEmpty<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NonEmptyVisitor<T> {
            marker: std::marker::PhantomData<T>,
        }

        impl<'de, T> Visitor<'de> for NonEmptyVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = NonEmpty<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a non-empty sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let first = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("expected at least one element"))?;
                let mut items = vec![first];
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(NonEmpty { items })
            }
        }

        deserializer.deserialize_seq(NonEmptyVisitor { marker: std::marker::PhantomData })
    }
}

impl<T> Serialize for NonEmpty<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.items.serialize(serializer)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ErrorClass {
    None = 0,
    InvalidInput = 1,
    RlpDecode = 2,
    Rejected = 3,
    Reverted = 4,
    Unimplemented = 5,
    Internal = 6,
    Invariant = 7,
}

impl Default for ErrorClass {
    fn default() -> Self {
        Self::None
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EthFork {
    Frontier = 0,
    Homestead = 1,
    Tangerine = 2,
    SpuriousDragon = 3,
    Byzantium = 4,
    Constantinople = 5,
    Petersburg = 6,
    Istanbul = 7,
    Berlin = 8,
    London = 9,
    Paris = 10,
    Shanghai = 11,
    Cancun = 12,
    Prague = 13,
    Osaka = 14,
    Amsterdam = 15,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum HarnessInputKind {
    Transaction = 0,
    State = 1,
    Blockchain = 2,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum EthereumHarnessInput {
    Transaction(EthereumTransactionInput),
    State(EthereumStateInput),
    Blockchain(EthereumBlockchainInput),
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct EthereumTransactionInput {
    pub chain_id: u64,
    pub fork: EthFork,
    pub tx: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct EthereumStateInput {
    pub chain_id: u64,
    pub fork: EthFork,
    pub pre_state: StateInput,
    pub env: BlockContextInput,
    pub tx: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct EthereumBlockchainInput {
    pub chain_id: u64,
    pub fork: EthFork,
    pub genesis: GenesisSpec,
    pub blocks: NonEmpty<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StateInput {
    pub accounts: Vec<AccountInput>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AccountInput {
    pub address: [u8; 20],
    pub balance: [u8; 32],
    pub nonce: u64,
    pub code: Vec<u8>,
    pub storage: Vec<StorageInput>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StorageInput {
    pub slot: [u8; 32],
    pub value: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BlockContextInput {
    pub block_number: u64,
    pub timestamp: u64,
    pub timestamp_millis_part: u64,
    pub basefee: u64,
    pub gas_limit: u64,
    pub beneficiary: [u8; 20],
    pub hardfork: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct GenesisSpec {
    pub alloc: StateInput,
    pub env: BlockContextInput,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TransactionOutcome {
    pub error: ErrorClass,
    pub sender: Option<[u8; 20]>,
    pub tx_type: Option<u8>,
    pub intrinsic_gas: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EthereumHarnessOutcome {
    Transaction(TransactionOutcome),
    State(EthereumExecutionOutcome),
    Blockchain(EthereumExecutionOutcome),
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EthereumExecutionOutcome {
    pub error: ErrorClass,
    pub receipts: Vec<TxReceiptOutput>,
    pub state_root: Option<[u8; 32]>,
    pub final_state: Option<StateInput>,
    pub state_diff: StateDiff,
    pub invariant_failures: Vec<InvariantFailure>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EthereumHarnessCapabilities {
    pub schema_version: u32,
    pub implementation: String,
    pub git_revision: String,
    pub supported_forks: NonEmpty<EthFork>,
    pub supported_inputs: NonEmpty<HarnessInputKind>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct InvariantFailure {
    pub id: String,
    pub message: String,
    pub scope: InvariantScope,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum InvariantScope {
    Transaction { block_index: u64, tx_index: u64 },
    Block { block_index: u64 },
    Execution,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StateDiff {
    pub accounts: Vec<AccountDiff>,
    pub storage: Vec<StorageChangeOutput>,
    pub txs: Vec<TxStateDiff>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TxStateDiff {
    pub block_index: u64,
    pub tx_index: u64,
    pub accounts: Vec<AccountDiff>,
    pub storage: Vec<StorageChangeOutput>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AccountDiff {
    pub address: [u8; 20],
    pub balance: Option<[u8; 32]>,
    pub nonce: Option<u64>,
    pub code: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TxReceiptOutput {
    pub block_index: u64,
    pub tx_index: u64,
    pub success: bool,
    pub cumulative_gas_used: u64,
    pub gas_used: u64,
    pub effective_gas_price: u128,
    pub output: Vec<u8>,
    pub logs: Vec<LogOutput>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LogOutput {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StorageChangeOutput {
    pub address: [u8; 20],
    pub slot: [u8; 32],
    pub before: [u8; 32],
    pub after: [u8; 32],
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ethereum_fuzz_execute_with_result_v1(
    out_ptr: *mut u8,
    out_len: usize,
    out_written: *mut usize,
    in_ptr: *const u8,
    in_len: usize,
) -> FuzzStatus {
    if in_ptr.is_null() {
        return FUZZ_REJECT;
    }
    let input = unsafe { std::slice::from_raw_parts(in_ptr, in_len) };
    let Ok(input) = bincode::deserialize::<EthereumHarnessInput>(input) else {
        return FUZZ_REJECT;
    };
    let EthereumHarnessInput::Transaction(input) = input else {
        return FUZZ_REJECT;
    };
    if input.chain_id == 0 || input.tx.is_empty() || !fork_supports_tx(input.fork, &input.tx) {
        return FUZZ_REJECT;
    }

    let outcome = EthereumHarnessOutcome::Transaction(execute_transaction(input));
    let Ok(bytes) = bincode::serialize(&outcome) else {
        return FUZZ_REJECT;
    };
    unsafe { write_fuzz_output(out_ptr, out_len, out_written, &bytes) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ethereum_fuzz_capabilities_v1(
    out_ptr: *mut u8,
    out_len: usize,
    out_written: *mut usize,
) -> FuzzStatus {
    let capabilities = EthereumHarnessCapabilities {
        schema_version: TYPED_HARNESS_SCHEMA_VERSION,
        implementation: "reth".to_string(),
        git_revision: match option_env!("RETH_GIT_REVISION") {
            Some(revision) => revision.to_string(),
            None => "unknown".to_string(),
        },
        supported_forks: NonEmpty::new(vec![
            EthFork::Frontier,
            EthFork::Homestead,
            EthFork::Tangerine,
            EthFork::SpuriousDragon,
            EthFork::Byzantium,
            EthFork::Constantinople,
            EthFork::Petersburg,
            EthFork::Istanbul,
            EthFork::Berlin,
            EthFork::London,
            EthFork::Paris,
            EthFork::Shanghai,
            EthFork::Cancun,
            EthFork::Prague,
            EthFork::Osaka,
        ])
        .expect("reth harness advertises at least one fork"),
        supported_inputs: NonEmpty::new(vec![HarnessInputKind::Transaction])
            .expect("reth harness advertises at least one input kind"),
    };
    let Ok(bytes) = bincode::serialize(&capabilities) else {
        return FUZZ_REJECT;
    };
    unsafe { write_fuzz_output(out_ptr, out_len, out_written, &bytes) }
}

fn execute_transaction(input: EthereumTransactionInput) -> TransactionOutcome {
    match TxEnvelope::decode_2718_exact(input.tx.as_slice()) {
        Ok(tx) => match tx.recover_signer() {
            Ok(sender) => TransactionOutcome {
                error: ErrorClass::None,
                sender: Some(sender.into_array()),
                tx_type: Some(tx.tx_type() as u8),
                intrinsic_gas: Some(intrinsic_gas(input.fork, &tx)),
            },
            Err(_) => TransactionOutcome {
                error: ErrorClass::RlpDecode,
                tx_type: Some(tx.tx_type() as u8),
                ..TransactionOutcome::default()
            },
        },
        Err(_) => {
            TransactionOutcome { error: ErrorClass::RlpDecode, ..TransactionOutcome::default() }
        }
    }
}

fn intrinsic_gas(fork: EthFork, tx: &TxEnvelope) -> u64 {
    let (access_list_accounts, access_list_storages) = match tx.access_list() {
        Some(list) => (
            list.0.len() as u64,
            list.0.iter().map(|item| item.storage_keys.len()).sum::<usize>() as u64,
        ),
        None => (0, 0),
    };
    let authorization_list_num = match tx.authorization_list() {
        Some(list) => list.len() as u64,
        None => 0,
    };
    revm::interpreter::gas::calculate_initial_tx_gas(
        spec_id(fork),
        tx.input(),
        tx.is_create(),
        access_list_accounts,
        access_list_storages,
        authorization_list_num,
    )
    .initial_total_gas()
}

fn fork_supports_tx(fork: EthFork, tx: &[u8]) -> bool {
    match tx.first().copied() {
        Some(0x01) => fork >= EthFork::Berlin,
        Some(0x02) => fork >= EthFork::London,
        Some(0x03) => fork >= EthFork::Cancun,
        Some(0x04) => fork >= EthFork::Prague,
        Some(0x00 | 0x05..=0x7f) => true,
        Some(_) => true,
        None => false,
    }
}

fn spec_id(fork: EthFork) -> SpecId {
    match fork {
        EthFork::Frontier => SpecId::FRONTIER,
        EthFork::Homestead => SpecId::HOMESTEAD,
        EthFork::Tangerine => SpecId::TANGERINE,
        EthFork::SpuriousDragon => SpecId::SPURIOUS_DRAGON,
        EthFork::Byzantium => SpecId::BYZANTIUM,
        EthFork::Constantinople | EthFork::Petersburg => SpecId::PETERSBURG,
        EthFork::Istanbul => SpecId::ISTANBUL,
        EthFork::Berlin => SpecId::BERLIN,
        EthFork::London => SpecId::LONDON,
        EthFork::Paris => SpecId::MERGE,
        EthFork::Shanghai => SpecId::SHANGHAI,
        EthFork::Cancun => SpecId::CANCUN,
        EthFork::Prague => SpecId::PRAGUE,
        EthFork::Osaka | EthFork::Amsterdam => SpecId::OSAKA,
    }
}

unsafe fn write_fuzz_output(
    dst: *mut u8,
    dst_len: usize,
    written: *mut usize,
    bytes: &[u8],
) -> FuzzStatus {
    if written.is_null() {
        return FUZZ_REJECT;
    }
    unsafe { *written = bytes.len() };
    if dst.is_null() || dst_len < bytes.len() {
        return FUZZ_REJECT;
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
    FUZZ_ACCEPT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_advertise_transaction_only_until_sealed_genesis_is_in_schema() {
        let mut output = vec![0; 4096];
        let mut written = 0usize;
        let status = unsafe {
            ethereum_fuzz_capabilities_v1(output.as_mut_ptr(), output.len(), &mut written)
        };
        assert_eq!(status, FUZZ_ACCEPT);
        let capabilities: EthereumHarnessCapabilities =
            bincode::deserialize(&output[..written]).expect("capabilities decode");
        assert_eq!(capabilities.supported_inputs.items, vec![HarnessInputKind::Transaction]);
    }

    #[test]
    fn state_and_blockchain_are_rejected_until_parent_genesis_header_is_available() {
        let state = EthereumHarnessInput::State(EthereumStateInput {
            chain_id: 1,
            fork: EthFork::Cancun,
            pre_state: StateInput { accounts: Vec::new() },
            env: BlockContextInput {
                block_number: 1,
                timestamp: 1,
                timestamp_millis_part: 0,
                basefee: 0,
                gas_limit: 30_000_000,
                beneficiary: [0; 20],
                hardfork: EthFork::Cancun as u8,
            },
            tx: vec![0xc0],
        });
        let input = bincode::serialize(&state).expect("state input serializes");
        let mut output = vec![0; 4096];
        let mut written = 0usize;
        let status = unsafe {
            ethereum_fuzz_execute_with_result_v1(
                output.as_mut_ptr(),
                output.len(),
                &mut written,
                input.as_ptr(),
                input.len(),
            )
        };
        assert_eq!(status, FUZZ_REJECT);
    }
}
