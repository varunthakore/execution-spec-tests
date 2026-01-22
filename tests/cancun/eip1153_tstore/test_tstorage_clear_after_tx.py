"""EIP-1153 Transient Storage tests."""

from typing import List, Optional

import pytest

from ethereum_test_tools import (
    Account,
    Alloc,
    Block,
    BlockchainTestFiller,
    Environment,
    EVMCodeType,
    Initcode,
    Transaction,
)
from ethereum_test_types.eof.v1 import Container
from ethereum_test_vm import Opcodes as Op

from tests.fuzzing_utils import get_fuzz_config, random_storage_key, random_storage_value

from .spec import ref_spec_1153

REFERENCE_SPEC_GIT_PATH = ref_spec_1153.git_path
REFERENCE_SPEC_VERSION = ref_spec_1153.version


def get_tstore_key_value_params() -> List[tuple]:
    """Get transient storage key/value parameters with optional fuzzing."""
    config = get_fuzz_config()
    # Hardcoded edge cases: use small values that don't cause issues
    hardcoded = [(1, 1), (0, 1), (2**128, 0xFF), (2**256 - 1, 2**256 - 1)]
    if config.enabled:
        random_keys = list(random_storage_key(min(config.count, 3)))
        random_values = list(random_storage_value(min(config.count, 3)))
        random_pairs = list(zip(random_keys, random_values))
        return hardcoded + random_pairs
    return hardcoded


# Generate fuzzed parameters at module load time
TSTORE_KEY_VALUE_PARAMS = get_tstore_key_value_params()


@pytest.mark.parametrize(
    "storage_key,storage_value",
    TSTORE_KEY_VALUE_PARAMS,
    ids=[f"key_{i}" for i in range(len(TSTORE_KEY_VALUE_PARAMS))],
)
@pytest.mark.valid_from("Cancun")
@pytest.mark.with_all_evm_code_types
def test_tstore_clear_after_deployment_tx(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    evm_code_type: EVMCodeType,
    storage_key: int,
    storage_value: int,
) -> None:
    """
    First creates a contract, which TSTOREs a value in a slot. After creating
    the contract, a new tx will call this contract, storing TLOAD(key) into the
    same slot. The transient storage should be cleared after creating the contract
    (at tx-level), so the storage should stay empty.

    Storage key and value are parametrized with optional fuzzing support.
    """
    env = Environment()

    init_code = Op.TSTORE(storage_key, storage_value)
    deploy_code = Op.SSTORE(storage_key, Op.TLOAD(storage_key))

    code: Optional[Container | Initcode] = None
    if evm_code_type == EVMCodeType.EOF_V1:
        code = Container.Init(
            deploy_container=Container.Code(deploy_code + Op.STOP), initcode_prefix=init_code
        )
    else:
        code = Initcode(deploy_code=deploy_code, initcode_prefix=init_code)

    sender = pre.fund_eoa()

    deployment_tx = Transaction(
        gas_limit=100000,
        data=code,
        to=None,
        sender=sender,
    )

    address = deployment_tx.created_contract

    invoke_contract_tx = Transaction(gas_limit=100000, to=address, sender=sender)

    txs = [deployment_tx, invoke_contract_tx]

    post = {
        address: Account(storage={storage_key: 0x00}),
    }

    blockchain_test(genesis_environment=env, pre=pre, post=post, blocks=[Block(txs=txs)])


@pytest.mark.parametrize(
    "storage_key,storage_value",
    TSTORE_KEY_VALUE_PARAMS,
    ids=[f"key_{i}" for i in range(len(TSTORE_KEY_VALUE_PARAMS))],
)
@pytest.mark.valid_from("Cancun")
@pytest.mark.with_all_evm_code_types
def test_tstore_clear_after_tx(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    storage_key: int,
    storage_value: int,
) -> None:
    """
    First SSTOREs the TLOAD value of a key in the same slot. Then, it TSTOREs
    a value in the same slot. The second tx will re-call the contract. The
    storage should stay empty, because the transient storage is cleared after
    the transaction.

    Storage key and value are parametrized with optional fuzzing support.
    """
    env = Environment()

    code = Op.SSTORE(storage_key, Op.TLOAD(storage_key)) + Op.TSTORE(storage_key, storage_value)
    account = pre.deploy_contract(code)

    sender = pre.fund_eoa()

    poke_tstore_tx = Transaction(
        gas_limit=100000,
        to=account,
        sender=sender,
    )

    re_poke_tstore_tx = Transaction(gas_limit=100000, to=account, sender=sender)

    txs = [poke_tstore_tx, re_poke_tstore_tx]

    post = {
        account: Account(storage={storage_key: 0x00}),
    }

    blockchain_test(genesis_environment=env, pre=pre, post=post, blocks=[Block(txs=txs)])
