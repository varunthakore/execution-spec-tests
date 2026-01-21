"""
Tests [EIP-5656: MCOPY - Memory copying instruction](https://eips.ethereum.org/EIPS/eip-5656).
"""

from typing import Mapping

import pytest

from ethereum_test_tools import (
    Account,
    Address,
    Alloc,
    Bytecode,
    Environment,
    Hash,
    StateTestFiller,
    Storage,
    Transaction,
    ceiling_division,
    keccak256,
)
from ethereum_test_tools import Opcodes as Op

from .common import REFERENCE_SPEC_GIT_PATH, REFERENCE_SPEC_VERSION, mcopy

# Import fuzzing utilities
from tests.fuzzing_utils import get_fuzz_config, random_memory_offset, random_memory_size

REFERENCE_SPEC_GIT_PATH = REFERENCE_SPEC_GIT_PATH
REFERENCE_SPEC_VERSION = REFERENCE_SPEC_VERSION


@pytest.fixture
def initial_memory() -> bytes:
    """Init memory for the test."""
    return bytes(range(0x00, 0x100))


@pytest.fixture
def final_memory(*, dest: int, src: int, length: int, initial_memory: bytes) -> bytes:
    """Memory after the MCOPY operation."""
    return mcopy(dest=dest, src=src, length=length, memory=initial_memory)


@pytest.fixture
def code_storage() -> Storage:
    """Storage for the code contract."""
    return Storage()


@pytest.fixture
def code_bytecode(
    initial_memory: bytes,
    final_memory: bytes,
    code_storage: Storage,
) -> Bytecode:
    """
    Prepare bytecode and storage for the test, based on the starting memory and
    the final memory that resulted from the copy.
    """
    bytecode = Bytecode()

    # Fill memory with initial values
    for i in range(0, len(initial_memory), 0x20):
        bytecode += Op.MSTORE(i, Op.PUSH32(initial_memory[i : i + 0x20]))

    # Perform the MCOPY according to calldata values
    bytecode += Op.MCOPY(
        Op.CALLDATALOAD(0x00),
        Op.CALLDATALOAD(0x20),
        Op.CALLDATALOAD(0x40),
    )

    final_byte_length = ceiling_division(len(final_memory), 0x20) * 0x20
    # First save msize
    bytecode += Op.SSTORE(
        code_storage.store_next(final_byte_length),
        Op.MSIZE,
    )

    # Then save the hash of the entire memory
    bytecode += Op.SSTORE(
        code_storage.store_next(keccak256(final_memory.ljust(final_byte_length, b"\x00"))),
        Op.SHA3(0, Op.MSIZE),
    )

    # Store all memory in the initial range to verify the MCOPY
    for w in range(0, len(initial_memory) // 0x20):
        bytecode += Op.SSTORE(
            code_storage.store_next(final_memory[w * 0x20 : w * 0x20 + 0x20]),
            Op.MLOAD(w * 0x20),
        )

    # If the memory was extended beyond the initial range, store the last word
    # of the resulting memory into storage too
    if len(final_memory) > len(initial_memory):
        last_word = ceiling_division(len(final_memory), 0x20) - 1
        bytecode += Op.SSTORE(
            code_storage.store_next(
                final_memory[last_word * 0x20 : (last_word + 1) * 0x20].ljust(32, b"\x00")
            ),
            Op.MLOAD(last_word * 0x20),
        )

    return bytecode


@pytest.fixture
def code_address(pre: Alloc, code_bytecode: Bytecode) -> Address:
    """Address of the contract that is going to perform the MCOPY operation."""
    return pre.deploy_contract(code_bytecode)


@pytest.fixture
def tx(  # noqa: D103
    pre: Alloc, code_address: Address, dest: int, src: int, length: int
) -> Transaction:
    return Transaction(
        sender=pre.fund_eoa(),
        to=code_address,
        data=Hash(dest) + Hash(src) + Hash(length),
        gas_limit=1_000_000,
    )


@pytest.fixture
def post(code_address: Address, code_storage: Storage) -> Mapping:  # noqa: D103
    return {
        code_address: Account(storage=code_storage),
    }


# Hardcoded edge cases for MCOPY (always included)
MCOPY_HARDCODED_CASES = [
    ((0x00, 0x00, 0x00), "zero_inputs"),
    ((2**256 - 1, 0x00, 0x00), "zero_length_out_of_bounds_destination"),
    ((0x00, 0x00, 0x01), "single_byte_rewrite"),
    ((0x00, 0x00, 0x20), "full_word_rewrite"),
    ((0x01, 0x00, 0x01), "single_byte_forward_overwrite"),
    ((0x01, 0x00, 0x20), "full_word_forward_overwrite"),
    ((0x11, 0x11, 0x01), "mid_word_single_byte_rewrite"),
    ((0x11, 0x11, 0x20), "mid_word_single_word_rewrite"),
    ((0x11, 0x11, 0x40), "mid_word_multi_word_rewrite"),
    ((0x10, 0x00, 0x40), "two_words_forward_overwrite"),
    ((0x00, 0x10, 0x40), "two_words_backward_overwrite"),
    ((0x0F, 0x10, 0x40), "two_words_backward_overwrite_single_byte_offset"),
    ((0x100, 0x01, 0x01), "single_byte_memory_extension"),
    ((0x100, 0x01, 0x20), "single_word_memory_extension"),
    ((0x100, 0x01, 0x1F), "single_word_minus_one_byte_memory_extension"),
    ((0x100, 0x01, 0x21), "single_word_plus_one_byte_memory_extension"),
    ((0x00, 0x00, 0x100), "full_memory_rewrite"),
    ((0x100, 0x00, 0x100), "full_memory_copy"),
    ((0x200, 0x00, 0x100), "full_memory_copy_offset"),
    ((0x00, 0x100, 0x100), "full_memory_clean"),
    ((0x100, 0x100, 0x01), "out_of_bounds_memory_extension"),
]


def mcopy_test_cases():
    """
    Generate MCOPY test cases with optional fuzzing.

    Supports randomization via FUZZ_SEED env var:
        Default (no fuzz): uv run fill tests/cancun/eip5656_mcopy/
        With fuzzing:      FUZZ_SEED=12345 FUZZ_COUNT=20 uv run fill tests/cancun/eip5656_mcopy/
    """
    config = get_fuzz_config()
    cases = []
    ids = []

    # Add hardcoded cases (filtered by FUZZ_MAX_INT if set)
    for (dest, src, length), name in MCOPY_HARDCODED_CASES:
        if config.max_int is not None:
            if dest > config.max_int or src > config.max_int or length > config.max_int:
                continue
        cases.append((dest, src, length))
        ids.append(name)

    # Add random cases if fuzzing is enabled
    if config.enabled:
        random_dests = random_memory_offset(config.count)
        random_srcs = random_memory_offset(config.count)
        random_lengths = random_memory_size(config.count)
        for i in range(config.count):
            dest = random_dests[i]
            src = random_srcs[i]
            length = random_lengths[i]
            cases.append((dest, src, length))
            ids.append(f"fuzz_{i}_dest_{dest:#x}_src_{src:#x}_len_{length:#x}")

    return cases, ids


_mcopy_cases, _mcopy_ids = mcopy_test_cases()


@pytest.mark.parametrize(
    "dest,src,length",
    _mcopy_cases,
    ids=_mcopy_ids,
)
@pytest.mark.with_all_evm_code_types
@pytest.mark.valid_from("Cancun")
def test_valid_mcopy_operations(
    state_test: StateTestFiller,
    pre: Alloc,
    post: Mapping[str, Account],
    tx: Transaction,
) -> None:
    """
    Perform MCOPY operations using different offsets and lengths.

      - Zero inputs
      - Memory rewrites (copy from and to the same location)
      - Memory overwrites (copy from and to different locations)
      - Memory extensions (copy to a location that is out of bounds)
      - Memory clear (copy from a location that is out of bounds).
    """
    state_test(
        env=Environment(),
        pre=pre,
        post=post,
        tx=tx,
    )


@pytest.mark.parametrize("dest", [0x00, 0x20])
@pytest.mark.parametrize("src", [0x00, 0x20])
@pytest.mark.parametrize("length", [0x00, 0x01])
@pytest.mark.parametrize("initial_memory", [bytes()], ids=["empty_memory"])
@pytest.mark.with_all_evm_code_types
@pytest.mark.valid_from("Cancun")
def test_mcopy_on_empty_memory(
    state_test: StateTestFiller,
    pre: Alloc,
    post: Mapping[str, Account],
    tx: Transaction,
) -> None:
    """
    Perform MCOPY operations on an empty memory, using different offsets and
    lengths.
    """
    state_test(
        env=Environment(),
        pre=pre,
        post=post,
        tx=tx,
    )
