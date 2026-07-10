//! Typed fuzz harness ABI for reth.

#![allow(missing_docs)]

use std::{collections::BTreeMap, fmt, sync::Arc};

use alloy_consensus::{
    constants::{EMPTY_OMMER_ROOT_HASH, EMPTY_ROOT_HASH},
    transaction::{Recovered, SignerRecoverable, Transaction},
    Block, Header, TxEnvelope,
};
use alloy_eips::Decodable2718;
use alloy_genesis::GenesisAccount;
use alloy_primitives::{Address, Bytes, B256, B64, U256};
use alloy_rlp::Decodable;
use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder};
use reth_consensus::{Consensus, HeaderValidator};
use reth_db_common::init::{insert_genesis_hashes, insert_genesis_history, insert_genesis_state};
use reth_ethereum_consensus::{validate_block_post_execution, EthBeaconConsensus};
use reth_ethereum_primitives::{Block as EthBlock, Receipt, TransactionSigned};
use reth_evm::{database::StateProviderDatabase, execute::Executor, ConfigureEvm};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::hashed_post_state_from_execution_state;
use reth_primitives_traits::SealedHeader;
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use reth_provider::{
    test_utils::create_test_provider_factory_with_chain_spec, BlockWriter, DatabaseProviderFactory,
    ExecutionOutcome, HistoryWriter, OriginalValuesKnown, StateWriteConfig, StateWriter,
    StaticFileProviderFactory, StaticFileSegment, StaticFileWriter, StorageSettingsCache,
};
use reth_trie::{KeccakKeyHasher, StateRoot};
use reth_trie_db::DatabaseStateRoot;
use serde::{
    de::{Error as DeError, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

macro_rules! compute_state_root {
    ($provider:expr, $output:expr) => {{
        let hashed_state =
            hashed_post_state_from_execution_state::<KeccakKeyHasher>($output.state.inner());
        let sorted = hashed_state.clone_into_sorted();
        reth_trie_db::with_adapter!($provider, |A| {
            StateRoot::<reth_trie_db::DatabaseTrieCursorFactory<_, A>, _>::overlay_root_with_updates(
                $provider.tx_ref(),
                &sorted,
            )
        })
        .ok()
        .map(|(root, _)| root)
    }};
}

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
    pub header_rlp: Vec<u8>,
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
    let outcome = match input {
        EthereumHarnessInput::Transaction(input) => {
            if input.chain_id == 0
                || input.tx.is_empty()
                || !fork_supports_tx(input.fork, &input.tx)
            {
                return FUZZ_REJECT;
            }
            EthereumHarnessOutcome::Transaction(execute_transaction(input))
        }
        EthereumHarnessInput::State(input) => match execute_state(input) {
            Some(outcome) => EthereumHarnessOutcome::State(outcome),
            None => return FUZZ_REJECT,
        },
        EthereumHarnessInput::Blockchain(input) => match execute_blockchain(input) {
            Some(outcome) => EthereumHarnessOutcome::Blockchain(outcome),
            None => return FUZZ_REJECT,
        },
    };
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
        supported_inputs: NonEmpty::new(vec![
            HarnessInputKind::Transaction,
            HarnessInputKind::State,
            HarnessInputKind::Blockchain,
        ])
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

fn execute_state(input: EthereumStateInput) -> Option<EthereumExecutionOutcome> {
    if input.chain_id == 0 || input.tx.is_empty() || !fork_supports_tx(input.fork, &input.tx) {
        return None;
    }
    let tx = recover_tx(&input.tx)?;
    let chain_spec = chain_spec(input.chain_id, input.fork);
    let factory = create_test_provider_factory_with_chain_spec(chain_spec.clone());
    let provider = factory.database_provider_rw().ok()?;
    let genesis_state = genesis_state(input.pre_state);
    insert_genesis_state(&provider, genesis_state.iter()).ok()?;
    insert_genesis_hashes(&provider, genesis_state.iter()).ok()?;
    insert_genesis_history(&provider, genesis_state.iter()).ok()?;

    let block = state_block(input.fork, input.env, vec![tx])?;
    let base_fee = block.header().base_fee_per_gas;
    let effective_gas_prices =
        block.body().transactions().map(|tx| tx.effective_gas_price(base_fee)).collect::<Vec<_>>();
    let executor_provider = EthEvmConfig::ethereum(chain_spec);
    let state_provider = provider.latest();
    let database = StateProviderDatabase::new(&state_provider);
    let output = match executor_provider.executor(database).execute(&block) {
        Ok(output) => output,
        Err(_) => return Some(execution_error(ErrorClass::Rejected)),
    };
    let state_root = compute_state_root!(provider, output)?;
    Some(execution_outcome(
        ErrorClass::None,
        0,
        &output.result.receipts,
        &effective_gas_prices,
        Some(state_root),
    ))
}

fn execute_blockchain(input: EthereumBlockchainInput) -> Option<EthereumExecutionOutcome> {
    if input.chain_id == 0 || input.genesis.header_rlp.is_empty() {
        return None;
    }
    if input.blocks.items.iter().any(Vec::is_empty) {
        return None;
    }

    let chain_spec = chain_spec(input.chain_id, input.fork);
    let factory = create_test_provider_factory_with_chain_spec(chain_spec.clone());
    let provider = factory.database_provider_rw().ok()?;

    let genesis_header = decode_header(&input.genesis.header_rlp)?;
    let genesis_header = SealedHeader::seal_slow(genesis_header);
    let genesis_block = RecoveredBlock::new_sealed(
        SealedBlock::<EthBlock>::from_sealed_parts(genesis_header, Default::default()),
        Vec::new(),
    );
    provider.insert_block(&genesis_block).ok()?;
    provider
        .static_file_provider()
        .latest_writer(StaticFileSegment::Receipts)
        .and_then(|mut writer| writer.increment_block(0))
        .ok()?;

    let genesis_state = genesis_state(input.genesis.alloc);
    insert_genesis_state(&provider, genesis_state.iter()).ok()?;
    insert_genesis_hashes(&provider, genesis_state.iter()).ok()?;
    insert_genesis_history(&provider, genesis_state.iter()).ok()?;

    let executor_provider = EthEvmConfig::ethereum(chain_spec.clone());
    let mut parent = genesis_block;
    let mut receipts = Vec::new();
    let mut final_state_root = None;

    for (block_index, sealed) in input.blocks.items.iter().enumerate() {
        let block = decode_recovered_block(sealed)?;
        let effective_gas_prices = block
            .body()
            .transactions()
            .map(|tx| tx.effective_gas_price(block.header().base_fee_per_gas))
            .collect::<Vec<_>>();

        provider.insert_block(&block).ok()?;
        provider.static_file_provider().commit().ok()?;
        if pre_execution_checks(chain_spec.clone(), &parent, &block).is_err() {
            return Some(execution_outcome(
                ErrorClass::Rejected,
                block_index as u64,
                &[],
                &[],
                final_state_root,
            ));
        }

        let state_provider = provider.latest();
        let database = StateProviderDatabase::new(&state_provider);
        let output = match executor_provider.executor(database).execute(&block) {
            Ok(output) => output,
            Err(_) => {
                return Some(execution_outcome(
                    ErrorClass::Rejected,
                    block_index as u64,
                    &[],
                    &[],
                    final_state_root,
                ))
            }
        };

        if validate_block_post_execution(&block, &chain_spec, &output, None, None).is_err() {
            return Some(execution_outcome(
                ErrorClass::Rejected,
                block_index as u64,
                &output.result.receipts,
                &effective_gas_prices,
                final_state_root,
            ));
        }

        let state_root = compute_state_root!(provider, output)?;
        if state_root != block.state_root {
            return Some(execution_outcome(
                ErrorClass::Rejected,
                block_index as u64,
                &output.result.receipts,
                &effective_gas_prices,
                Some(state_root),
            ));
        }

        receipts.extend(receipt_outputs(
            block_index as u64,
            &output.result.receipts,
            &effective_gas_prices,
        ));
        let hashed_state =
            hashed_post_state_from_execution_state::<KeccakKeyHasher>(output.state.inner());
        provider
            .write_state(
                &ExecutionOutcome::single(block.number, output),
                OriginalValuesKnown::Yes,
                StateWriteConfig::default(),
            )
            .ok()?;
        provider.write_hashed_state(&hashed_state.into_sorted()).ok()?;
        provider.update_history_indices(block.number..=block.number).ok()?;
        final_state_root = Some(state_root);
        parent = block;
    }

    Some(EthereumExecutionOutcome {
        error: ErrorClass::None,
        receipts,
        state_root: final_state_root.map(b256_to_array),
        final_state: None,
        state_diff: StateDiff::default(),
        invariant_failures: Vec::new(),
    })
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

    let non_zero_calldata_cost = if fork >= EthFork::Istanbul { 16 } else { 68 };
    let calldata_gas = tx
        .input()
        .iter()
        .fold(0u64, |gas, byte| gas + if *byte == 0 { 4 } else { non_zero_calldata_cost });
    let create_gas = if tx.is_create() && fork >= EthFork::Homestead { 32_000 } else { 0 };
    let initcode_gas = if tx.is_create() && fork >= EthFork::Shanghai {
        2 * div_ceil(tx.input().len() as u64, 32)
    } else {
        0
    };
    let access_list_gas = access_list_accounts * 2_400 + access_list_storages * 1_900;
    let authorization_gas = authorization_list_num * 25_000;

    21_000 + calldata_gas + create_gas + initcode_gas + access_list_gas + authorization_gas
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

fn div_ceil(value: u64, divisor: u64) -> u64 {
    if value == 0 {
        0
    } else {
        1 + (value - 1) / divisor
    }
}

fn recover_tx(bytes: &[u8]) -> Option<Recovered<TransactionSigned>> {
    let tx = TransactionSigned::decode_2718_exact(bytes).ok()?;
    let signer = tx.recover_signer().ok()?;
    Some(Recovered::new_unchecked(tx, signer))
}

fn decode_header(bytes: &[u8]) -> Option<Header> {
    Header::decode(&mut &bytes[..]).ok()
}

fn decode_recovered_block(bytes: &[u8]) -> Option<RecoveredBlock<EthBlock>> {
    SealedBlock::<EthBlock>::decode(&mut &bytes[..]).ok()?.try_recover().ok()
}

fn chain_spec(chain_id: u64, fork: EthFork) -> Arc<ChainSpec> {
    let spec = ChainSpecBuilder::mainnet().reset().chain(Chain::from_id(chain_id));
    let spec = match fork {
        EthFork::Frontier => spec.frontier_activated(),
        EthFork::Homestead => spec.homestead_activated(),
        EthFork::Tangerine => spec.tangerine_whistle_activated(),
        EthFork::SpuriousDragon => spec.spurious_dragon_activated(),
        EthFork::Byzantium => spec.byzantium_activated(),
        EthFork::Constantinople => spec.constantinople_activated(),
        EthFork::Petersburg => spec.petersburg_activated(),
        EthFork::Istanbul => spec.istanbul_activated(),
        EthFork::Berlin => spec.berlin_activated(),
        EthFork::London => spec.london_activated(),
        EthFork::Paris => spec.paris_activated(),
        EthFork::Shanghai => spec.shanghai_activated(),
        EthFork::Cancun => spec.cancun_activated(),
        EthFork::Prague => spec.prague_activated(),
        EthFork::Osaka => spec.osaka_activated(),
        EthFork::Amsterdam => spec.amsterdam_activated(),
    };
    Arc::new(spec.build())
}

fn genesis_state(input: StateInput) -> BTreeMap<Address, GenesisAccount> {
    input
        .accounts
        .into_iter()
        .map(|account| {
            let storage = account
                .storage
                .into_iter()
                .map(|entry| (B256::from(entry.slot), B256::from(entry.value)))
                .collect::<BTreeMap<_, _>>();
            (
                Address::new(account.address),
                GenesisAccount {
                    balance: U256::from_be_bytes(account.balance),
                    nonce: Some(account.nonce),
                    code: Some(Bytes::from(account.code)),
                    storage: Some(storage),
                    private_key: None,
                },
            )
        })
        .collect()
}

fn state_block(
    fork: EthFork,
    env: BlockContextInput,
    transactions: Vec<Recovered<TransactionSigned>>,
) -> Option<RecoveredBlock<EthBlock>> {
    let base_fee_per_gas = (fork >= EthFork::London).then_some(env.basefee);
    let withdrawals_root = (fork >= EthFork::Shanghai).then_some(EMPTY_ROOT_HASH);
    let parent_beacon_block_root = (fork >= EthFork::Cancun).then_some(B256::ZERO);
    let header = Header {
        parent_hash: B256::ZERO,
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: Address::new(env.beneficiary),
        state_root: EMPTY_ROOT_HASH,
        transactions_root: EMPTY_ROOT_HASH,
        receipts_root: EMPTY_ROOT_HASH,
        logs_bloom: Default::default(),
        difficulty: U256::ZERO,
        number: env.block_number,
        gas_limit: env.gas_limit,
        gas_used: 0,
        timestamp: env.timestamp,
        extra_data: Bytes::new(),
        mix_hash: B256::ZERO,
        nonce: B64::ZERO,
        base_fee_per_gas,
        withdrawals_root,
        blob_gas_used: (fork >= EthFork::Cancun).then_some(0),
        excess_blob_gas: (fork >= EthFork::Cancun).then_some(0),
        parent_beacon_block_root,
        requests_hash: (fork >= EthFork::Prague).then_some(EMPTY_ROOT_HASH),
        block_access_list_hash: (fork >= EthFork::Amsterdam).then_some(EMPTY_OMMER_ROOT_HASH),
        slot_number: None,
    };
    Some(RecoveredBlock::from(Block::from_transactions(header, transactions)))
}

fn pre_execution_checks(
    chain_spec: Arc<ChainSpec>,
    parent: &RecoveredBlock<EthBlock>,
    block: &RecoveredBlock<EthBlock>,
) -> Result<(), String> {
    let consensus: EthBeaconConsensus<ChainSpec> = EthBeaconConsensus::new(chain_spec);
    let sealed_header = block.sealed_header();
    <EthBeaconConsensus<ChainSpec> as Consensus<EthBlock>>::validate_body_against_header(
        &consensus,
        block.body(),
        sealed_header,
    )
    .map_err(|err| err.to_string())?;
    consensus
        .validate_header_against_parent(sealed_header, parent.sealed_header())
        .map_err(|err| err.to_string())?;
    consensus.validate_header(sealed_header).map_err(|err| err.to_string())?;
    consensus.validate_block_pre_execution(block).map_err(|err| err.to_string())
}

fn execution_error(error: ErrorClass) -> EthereumExecutionOutcome {
    EthereumExecutionOutcome {
        error,
        receipts: Vec::new(),
        state_root: None,
        final_state: None,
        state_diff: StateDiff::default(),
        invariant_failures: Vec::new(),
    }
}

fn execution_outcome(
    error: ErrorClass,
    block_index: u64,
    receipts: &[Receipt],
    effective_gas_prices: &[u128],
    state_root: Option<B256>,
) -> EthereumExecutionOutcome {
    EthereumExecutionOutcome {
        error,
        receipts: receipt_outputs(block_index, receipts, effective_gas_prices),
        state_root: state_root.map(b256_to_array),
        final_state: None,
        state_diff: StateDiff::default(),
        invariant_failures: Vec::new(),
    }
}

fn b256_to_array(value: B256) -> [u8; 32] {
    value.0
}

fn receipt_outputs(
    block_index: u64,
    receipts: &[Receipt],
    effective_gas_prices: &[u128],
) -> Vec<TxReceiptOutput> {
    receipts
        .iter()
        .enumerate()
        .map(|(tx_index, receipt)| {
            let previous_cumulative =
                if tx_index == 0 { 0 } else { receipts[tx_index - 1].cumulative_gas_used };
            TxReceiptOutput {
                block_index,
                tx_index: tx_index as u64,
                success: receipt.success,
                cumulative_gas_used: receipt.cumulative_gas_used,
                gas_used: receipt.cumulative_gas_used - previous_cumulative,
                effective_gas_price: effective_gas_prices[tx_index],
                output: Vec::new(),
                logs: receipt
                    .logs
                    .iter()
                    .map(|log| LogOutput {
                        address: log.address.into_array(),
                        topics: log
                            .data
                            .topics()
                            .iter()
                            .map(|topic| b256_to_array(*topic))
                            .collect(),
                        data: log.data.data.to_vec(),
                    })
                    .collect(),
            }
        })
        .collect()
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
    fn capabilities_advertise_all_unified_ethereum_inputs() {
        let mut output = vec![0; 4096];
        let mut written = 0usize;
        let status = unsafe {
            ethereum_fuzz_capabilities_v1(output.as_mut_ptr(), output.len(), &mut written)
        };
        assert_eq!(status, FUZZ_ACCEPT);
        let capabilities: EthereumHarnessCapabilities =
            bincode::deserialize(&output[..written]).expect("capabilities decode");
        assert_eq!(
            capabilities.supported_inputs.items,
            vec![
                HarnessInputKind::Transaction,
                HarnessInputKind::State,
                HarnessInputKind::Blockchain,
            ]
        );
    }

    #[test]
    fn chain_spec_uses_input_chain_id() {
        let spec = chain_spec(42431, EthFork::Cancun);
        assert_eq!(spec.chain.id(), 42431);
    }

    #[test]
    fn malformed_state_input_is_rejected() {
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

    #[test]
    fn blockchain_input_requires_genesis_header() {
        let blockchain = EthereumHarnessInput::Blockchain(EthereumBlockchainInput {
            chain_id: 1,
            fork: EthFork::Cancun,
            genesis: GenesisSpec {
                alloc: StateInput { accounts: Vec::new() },
                env: BlockContextInput {
                    block_number: 0,
                    timestamp: 1,
                    timestamp_millis_part: 0,
                    basefee: 0,
                    gas_limit: 30_000_000,
                    beneficiary: [0; 20],
                    hardfork: EthFork::Cancun as u8,
                },
                header_rlp: Vec::new(),
            },
            blocks: NonEmpty::new(vec![vec![0xc0]]).expect("one block"),
        });
        let input = bincode::serialize(&blockchain).expect("blockchain input serializes");
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
