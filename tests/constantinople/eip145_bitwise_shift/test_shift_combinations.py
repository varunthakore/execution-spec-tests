"""Test bitwise shift opcodes in different combinations."""

from typing import Callable

import pytest

from ethereum_test_tools import (
    Account,
    Alloc,
    StateTestFiller,
    Storage,
    Transaction,
)
from ethereum_test_tools import Opcodes as Op

from .spec import Spec, ref_spec_145

# Import fuzzing utilities
from tests.fuzzing_utils import get_fuzz_combinations, random_uint256_biased

REFERENCE_SPEC_GIT_PATH = ref_spec_145.git_path
REFERENCE_SPEC_VERSION = ref_spec_145.version

# Original hardcoded test values (edge cases) - always included
HARDCODED_ARGS = [
    0,
    1,
    2,
    5,
    0xFE,
    0xFF,
    0x100,
    0x101,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE,
    0x8000000000000000000000000000000000000000000000000000000000000000,
    0xA000000000000000000000000000000000000000000000000000000000000000,
    0x5555555555555555555555555555555555555555555555555555555555555555,
    0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,
    0x0000000000000000000000000000000000000000000000000000000000000080,
    0x0000000000000000000000000000000000000000000000000000000000008000,
    0x0000000000000000000000000000000000000000000000000000000080000000,
    0x0000000000000000000000000000000000000000000000008000000000000000,
    0x0000000000000000000000000000000080000000000000000000000000000000,
    0x8000000000000000000000000000000000000000000000000000000000000000,
]

# Build combinations from test args (supports randomization via FUZZ_SEED env var)
# Usage:
#   Default (no fuzz):  uv run fill tests/constantinople/eip145_bitwise_shift/
#   With fuzzing:       FUZZ_SEED=12345 FUZZ_COUNT=20 uv run fill tests/constantinople/eip145_bitwise_shift/
combinations = get_fuzz_combinations(
    hardcoded=HARDCODED_ARGS,
    generator=random_uint256_biased,
    repeat=2,
)


@pytest.mark.parametrize(
    "opcode,operation",
    [
        pytest.param(Op.SAR, Spec.sar, id="sar"),
        pytest.param(Op.SHL, Spec.shl, id="shl"),
        pytest.param(Op.SHR, Spec.shr, id="shr"),
    ],
)
@pytest.mark.valid_from("Constantinople")
@pytest.mark.ported_from(
    [
        "https://github.com/ethereum/tests/blob/v13.3/src/GeneralStateTestsFiller/stShift/shiftCombinationsFiller.yml",
        "https://github.com/ethereum/tests/blob/v13.3/src/GeneralStateTestsFiller/stShift/shiftSignedCombinationsFiller.yml",
    ],
    pr=["https://github.com/ethereum/execution-spec-tests/pull/1683"],
)
def test_combinations(
    state_test: StateTestFiller, pre: Alloc, opcode: Op, operation: Callable
) -> None:
    """Test bitwise shift combinations."""
    result = Storage()
    address_to = pre.deploy_contract(
        code=sum(
            Op.SSTORE(
                result.store_next(operation(shift=a, value=b), f"{str(opcode).lower()}({a}, {b})"),
                opcode(a, b),
            )
            for a, b in combinations
        )
        + Op.SSTORE(result.store_next(1, "code_finished"), 1)
        + Op.STOP,
    )

    tx = Transaction(
        sender=pre.fund_eoa(),
        to=address_to,
        gas_limit=5_000_000,
    )

    state_test(pre=pre, post={address_to: Account(storage=result)}, tx=tx)
