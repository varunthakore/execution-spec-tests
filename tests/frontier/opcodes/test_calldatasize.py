"""test `CALLDATASIZE` opcode."""

import pytest

from ethereum_test_forks import Byzantium, Fork
from ethereum_test_tools import Account, Alloc, StateTestFiller, Transaction
from ethereum_test_tools import Macros as Om
from ethereum_test_vm import Opcodes as Op

# Import fuzzing utilities
from tests.fuzzing_utils import get_fuzz_config, random_memory_size


def calldatasize_test_values():
    """
    Generate args_size test values with optional fuzzing.

    Supports randomization via FUZZ_SEED env var:
        Default (no fuzz): uv run fill tests/frontier/opcodes/test_calldatasize.py
        With fuzzing:      FUZZ_SEED=12345 FUZZ_COUNT=10 uv run fill tests/frontier/opcodes/test_calldatasize.py
    """
    config = get_fuzz_config()

    # Hardcoded edge cases
    hardcoded = [0, 2, 16, 33, 257]

    # Filter by FUZZ_MAX_INT if set
    if config.max_int is not None:
        hardcoded = [v for v in hardcoded if v <= config.max_int]

    # Add random values if fuzzing is enabled
    if config.enabled:
        # Use smaller sizes to avoid gas issues (cap at 257 to match original test's max)
        random_sizes = [min(s, 257) for s in random_memory_size(config.count)]
        hardcoded.extend(random_sizes)

    return hardcoded


@pytest.mark.ported_from(
    [
        "https://github.com/ethereum/tests/blob/v13.3/src/GeneralStateTestsFiller/VMTests/vmTests/calldatasizeFiller.yml",
    ],
    pr=["https://github.com/ethereum/execution-spec-tests/pull/1236"],
)
@pytest.mark.parametrize(
    "args_size",
    calldatasize_test_values(),
)
@pytest.mark.parametrize("calldata_source", ["contract", "tx"])
@pytest.mark.slow()
def test_calldatasize(
    state_test: StateTestFiller,
    fork: Fork,
    args_size: int,
    pre: Alloc,
    calldata_source: str,
) -> None:
    """
    Test `CALLDATASIZE` opcode.

    Tests two scenarios:
    - calldata_source is "contract": CALLDATASIZE reads from calldata
                                     passed by another contract
    - calldata_source is "tx": CALLDATASIZE reads directly from
                               transaction calldata

    Based on
    https://github.com/ethereum/tests/blob/
    81862e4848585a438d64f911a19b3825f0f4cd95/src/
    GeneralStateTestsFiller/VMTests/vmTests/calldatasizeFiller.yml
    """
    contract_address = pre.deploy_contract(Op.SSTORE(key=0x0, value=Op.CALLDATASIZE))
    calldata = b"\x01" * args_size

    if calldata_source == "contract":
        to = pre.deploy_contract(
            code=(
                Om.MSTORE(calldata, 0x0)
                + Op.CALL(
                    gas=Op.SUB(Op.GAS(), 0x100),
                    address=contract_address,
                    value=0x0,
                    args_offset=0x0,
                    args_size=args_size,
                    ret_offset=0x0,
                    ret_size=0x0,
                )
            )
        )

        tx = Transaction(
            gas_limit=100_000,
            protected=fork >= Byzantium,
            sender=pre.fund_eoa(),
            to=to,
        )

    else:
        tx = Transaction(
            data=calldata,
            gas_limit=100_000,
            protected=fork >= Byzantium,
            sender=pre.fund_eoa(),
            to=contract_address,
        )

    post = {contract_address: Account(storage={0x00: args_size})}
    state_test(pre=pre, post=post, tx=tx)
