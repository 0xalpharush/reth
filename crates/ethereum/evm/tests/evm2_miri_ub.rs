#![allow(missing_docs)]

use alloy_consensus::{transaction::Recovered, TxEip2930};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use evm2::{
    bytecode::Bytecode,
    env::BlockEnvExt,
    ethereum::{ethereum_tx_registry, TxEnvelope},
    evm::{precompile::NoPrecompiles, AccountInfo, InMemoryDB},
    interpreter::op,
    BaseEvmTypes, Evm, SpecId,
};

/// Models the normal Reth execution path: an externally supplied Ethereum transaction calls
/// deployed bytecode through `Evm::transact`. No `Interpreter` or unsafe API is used by the test.
#[test]
fn ordinary_contract_transaction_is_ub_under_miri() {
    let sender = Address::from([0xaa; 20]);
    let contract = Address::from([0xbb; 20]);

    let mut db = InMemoryDB::default();
    db.insert_account_info(
        &sender,
        AccountInfo::default().with_balance(U256::from(1_000_000_000u64)),
    );
    db.insert_account_info(
        &contract,
        AccountInfo::default().with_code(Bytecode::new_legacy(Bytes::from_static(&[
            op::PUSH1,
            0x2a,
            op::PUSH1,
            0x01,
            op::SSTORE,
            op::STOP,
        ]))),
    );

    let tx = Recovered::new_unchecked(
        TxEnvelope::Eip2930(TxEip2930 {
            chain_id: 1,
            nonce: 0,
            gas_price: 1,
            gas_limit: 100_000,
            to: TxKind::Call(contract),
            value: U256::ZERO,
            input: Bytes::new(),
            access_list: AccessList::default(),
        }),
        sender,
    );

    let mut evm = Evm::<BaseEvmTypes>::new(
        SpecId::BERLIN,
        BlockEnvExt::default(),
        ethereum_tx_registry(SpecId::BERLIN),
        db,
        NoPrecompiles::default(),
    );

    let _ = evm.transact(&tx).expect("valid transaction").discard();
}
