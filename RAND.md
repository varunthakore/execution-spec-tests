# Randomized Test Generation for Fuzzing

This document describes the randomization infrastructure added to `execution-spec-tests` for generating randomized test fixtures suitable for fuzzing EVM implementations.

## Purpose

The primary goal of this randomization infrastructure is to **generate diverse test inputs for fuzzing EVM implementations**.

### Why Fuzzing?

EVM implementations (like geth, reth, erigon, etc.) need to be tested against a wide variety of inputs to ensure correctness and find edge cases. The standard `execution-spec-tests` fixtures use hardcoded values that provide good coverage for known edge cases but miss the vast space of possible inputs.

By adding randomization, we can:

1. **Generate diverse test fixtures** - Each run with a different seed produces unique test cases
2. **Find edge cases** - Random inputs can trigger bugs that handcrafted tests miss
3. **Differential testing** - Run the same randomized fixtures against multiple EVM implementations to find discrepancies
4. **Continuous fuzzing** - Generate new fixtures regularly with different seeds for ongoing testing

### Workflow

1. Generate randomized fixtures with a specific seed: `FUZZ_SEED=12345 uv run fill --clean tests/ -o ./fixtures-fuzz-12345`
2. Run these fixtures against your EVM implementation
3. If bugs are found, the seed allows reproduction of the exact same test cases
4. Package and share fixtures for cross-implementation testing

## Overview

The standard test fixtures have **hardcoded test values**, which limits their usefulness for fuzzing. This extension adds the ability to:

1. Generate random test parameter values
2. Combine hardcoded edge cases with random values
3. Produce different fixtures on each run (with reproducible seeds)

## Files Added/Modified

### New Files

| File | Description |
|------|-------------|
| `tests/conftest.py` | Root pytest configuration with randomization hooks and fixtures |
| `tests/fuzzing_utils.py` | Random value generators and helper functions |
| `RAND.md` | This documentation file |

### Modified Files

| File | Changes |
|------|---------|
| `tests/constantinople/eip145_bitwise_shift/test_shift_combinations.py` | Updated to use `get_fuzz_combinations()` for randomized shift/value test combinations |
| `tests/osaka/eip7939_count_leading_zeros/test_count_leading_zeros.py` | Updated `clz_parameters()` to add random uint256 values for CLZ opcode testing |
| `tests/cancun/eip5656_mcopy/test_mcopy.py` | Updated `mcopy_test_cases()` to add random dest/src/length combinations |
| `tests/cancun/eip1153_tstore/test_tstorage.py` | Updated `get_storage_slots_for_test()` to add random storage slot keys |
| `tests/frontier/opcodes/test_calldatasize.py` | Updated `calldatasize_test_values()` to add random calldata sizes |
| `tests/cancun/eip4844_blobs/test_blobhash_opcode.py` | Updated `get_blobhash_index_values()` to add random blobhash indices |

## Usage

### Quick Start

```bash
# Default behavior (no randomization, uses hardcoded values)
uv run fill --clean tests/

# Enable randomization with environment variables
FUZZ_SEED=12345 uv run fill --clean tests/

# Random seed (different each run)
FUZZ_SEED=$RANDOM uv run fill --clean tests/

# Control number of random values
FUZZ_SEED=12345 FUZZ_COUNT=50 uv run fill --clean tests/

# Cap all integer values for local testing (supports decimal, hex, or power notation)
FUZZ_SEED=12345 FUZZ_MAX_INT=256 uv run fill --clean tests/           # Cap to 256
FUZZ_SEED=12345 FUZZ_MAX_INT=0x100 uv run fill --clean tests/         # Cap to 256 (hex)
FUZZ_SEED=12345 FUZZ_MAX_INT="2**8" uv run fill --clean tests/        # Cap to 256 (power notation)
FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/       # Cap to 65536

# Or use pytest command-line options
uv run fill --clean tests/ --random-seed=12345 --random-count=50
uv run fill --clean tests/ --random-seed=random  # Generate random seed
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FUZZ_SEED` | Random seed for reproducibility. Set to any integer to enable randomization. | Not set (disabled) |
| `FUZZ_COUNT` | Number of random values to generate per parameter | `10` |
| `FUZZ_MAX_INT` | Cap all integer values to this maximum. Supports decimal, hex (`0x100`), or power notation (`2**8`). Useful for local testing with smaller values. | Not set (no cap) |

### Pytest Command-Line Options

| Option | Description |
|--------|-------------|
| `--random-seed=<int\|random>` | Set random seed. Use `random` for auto-generated seed. |
| `--random-count=<int>` | Number of random values to generate |

## Available Random Generators

### Integer Generators

| Function | Description |
|----------|-------------|
| `random_uint256(count)` | Fully random uint256 values |
| `random_uint256_biased(count)` | uint256 with bias toward interesting values (small, powers of 2, large, bit patterns) |
| `random_int256(count)` | Signed int256 values (two's complement) |
| `random_uint8(count)` | uint8 values (0-255) |
| `random_uint64(count)` | uint64 values |
| `random_uint128(count)` | uint128 values |
| `random_small_int(count, max_val)` | Small integers for indices/counters |
| `random_shift_amount(count)` | Shift amounts (0-256) with edge case bias |

### Address Generators

| Function | Description |
|----------|-------------|
| `random_address(count)` | Random 20-byte addresses |
| `random_address_with_special(count)` | Includes precompile addresses (0x01-0x0A) |

### Bytes Generators

| Function | Description |
|----------|-------------|
| `random_bytes(count, max_len)` | Variable length byte sequences |
| `random_bytes32(count)` | Fixed 32-byte values |
| `random_bytes_fixed(count, length)` | Fixed length byte sequences |
| `random_calldata(count, max_len)` | Random calldata (includes empty) |
| `random_calldata_with_selector(count)` | Calldata with 4-byte function selector |
| `random_bytecode(count, max_len)` | Random EVM bytecode-like sequences |

### Hash Generators

| Function | Description |
|----------|-------------|
| `random_hash(count)` | Random 32-byte hash values |
| `random_hash_with_special(count)` | Includes zero hash, max hash, versioned hash |
| `random_blob_hash(count)` | KZG versioned blob hashes (0x01 prefix) |

### Gas and Value Generators

| Function | Description |
|----------|-------------|
| `random_gas(count)` | Gas values with realistic distribution |
| `random_gas_price(count)` | Gas prices in wei |
| `random_value(count)` | Transaction values in wei |
| `random_balance(count)` | Account balances |

### Storage Generators

| Function | Description |
|----------|-------------|
| `random_storage_key(count)` | Storage keys (includes slot 0) |
| `random_storage_value(count)` | Storage values |
| `random_storage_pairs(count)` | (key, value) tuples |

### Block/Transaction Generators

| Function | Description |
|----------|-------------|
| `random_nonce(count)` | Account nonces |
| `random_block_number(count)` | Block numbers |
| `random_timestamp(count)` | Block timestamps |
| `random_tx_type(count)` | Transaction types (0, 1, 2, 3) |
| `random_chain_id(count)` | Chain IDs (common + random) |
| `random_difficulty(count)` | Difficulty values (pre-merge) |
| `random_prevrandao(count)` | Prevrandao values (post-merge) |

### Access List Generators

| Function | Description |
|----------|-------------|
| `random_access_list_entry(count)` | Single access list entries (address, [keys]) |
| `random_access_list(count, max_entries)` | Full access lists |

### Withdrawal Generators (EIP-4895)

| Function | Description |
|----------|-------------|
| `random_withdrawal_amount(count)` | Withdrawal amounts in Gwei |
| `random_validator_index(count)` | Validator indices |

### Code/Initcode Generators

| Function | Description |
|----------|-------------|
| `random_initcode(count, max_len)` | Contract creation code |
| `random_deployed_code(count, max_len)` | Deployed contract bytecode |
| `random_code_size(count)` | Code sizes (biased toward MAX_CODE_SIZE) |
| `random_initcode_size(count)` | Initcode sizes (biased toward MAX_INITCODE_SIZE) |

### Memory/Offset Generators

| Function | Description |
|----------|-------------|
| `random_memory_offset(count)` | Memory offsets with common patterns |
| `random_memory_size(count)` | Memory sizes for copy operations |
| `random_stack_height(count)` | Stack heights (0-1024+) |

### Log/Event Generators

| Function | Description |
|----------|-------------|
| `random_log_topic(count)` | Log topics (32 bytes) |
| `random_log_data(count, max_len)` | Log data |
| `random_num_topics(count)` | Number of topics (0-4) |

### CREATE/CREATE2 Generators

| Function | Description |
|----------|-------------|
| `random_salt(count)` | CREATE2 salt values |

### Precompile Input Generators

| Function | Description |
|----------|-------------|
| `random_ecrecover_input(count)` | ecrecover precompile inputs (128 bytes) |
| `random_bn256_point(count)` | bn256 curve points for ecAdd/ecMul |
| `random_modexp_input(count)` | modexp precompile inputs |
| `random_blake2f_input(count)` | blake2f precompile inputs (213 bytes) |

### EIP-4844 Blob Generators

| Function | Description |
|----------|-------------|
| `random_blob_data(count)` | Blob data (truncated for testing) |
| `random_blob_versioned_hash(count)` | Versioned blob hashes |

### EIP-1559 Fee Generators

| Function | Description |
|----------|-------------|
| `random_base_fee(count)` | Base fee values |
| `random_max_fee_per_gas(count)` | Max fee per gas |
| `random_max_priority_fee(count)` | Max priority fee (tip) |
| `random_max_fee_per_blob_gas(count)` | Max fee per blob gas (EIP-4844) |

### Call/Return Generators

| Function | Description |
|----------|-------------|
| `random_call_depth(count)` | Call depths (0-1024+) |
| `random_return_data(count, max_len)` | Return data |
| `random_revert_data(count)` | Revert data (Error/Panic formats) |

### EIP-7702 Authorization Generators

| Function | Description |
|----------|-------------|
| `random_authorization_chain_id(count)` | Chain IDs for auth tuples |
| `random_authorization_nonce(count)` | Nonces for auth tuples |

### EOF (EVM Object Format) Generators

| Function | Description |
|----------|-------------|
| `random_eof_version(count)` | EOF version numbers |
| `random_eof_code_section_count(count)` | Number of code sections (1-1024) |
| `random_eof_max_stack_height(count)` | Max stack heights (0-1023) |
| `random_rjump_offset(count)` | Relative jump offsets (-32768 to 32767) |
| `random_rjumpv_table_size(count)` | RJUMPV table sizes (1-256) |
| `random_eof_inputs_outputs(count)` | (inputs, outputs) pairs for functions |

### BLS12-381 Precompile Generators (EIP-2537)

| Function | Description |
|----------|-------------|
| `random_bls12_g1_point(count)` | G1 curve points (128 bytes) |
| `random_bls12_g2_point(count)` | G2 curve points (256 bytes) |
| `random_bls12_scalar(count)` | Scalar values (32 bytes) |
| `random_bls12_fp(count)` | Field elements Fp (64 bytes) |
| `random_bls12_fp2(count)` | Extension field Fp2 (128 bytes) |

### P256 Precompile Generators (EIP-7212)

| Function | Description |
|----------|-------------|
| `random_p256_signature(count)` | P256 signature inputs (160 bytes) |

### Selector/Choice Generators

| Function | Description |
|----------|-------------|
| `random_opcode_from_list(opcodes, count)` | Select from opcode list |
| `random_choice(items, count)` | Select from any list |
| `random_subset(items, count, min_size, max_size)` | Random subsets of a list |

### Boolean Generators

| Function | Description |
|----------|-------------|
| `random_bool(count)` | Random True/False |
| `random_bool_biased(count, probability)` | Biased boolean values |

## Helper Functions

### `get_fuzz_params(hardcoded, generator, count=None)`

Combines hardcoded edge-case values with randomly generated values.

```python
from tests.fuzzing_utils import get_fuzz_params, random_uint256_biased

# Hardcoded edge cases are always included
HARDCODED = [0, 1, 2, 0xFF, 0x100, 2**256-1]

# Returns only hardcoded if FUZZ_SEED not set
# Returns hardcoded + random values if FUZZ_SEED is set
test_values = get_fuzz_params(
    hardcoded=HARDCODED,
    generator=random_uint256_biased,
)
```

### `get_fuzz_combinations(hardcoded, generator, repeat=2, count=None)`

Generates combinations for multi-argument tests (Cartesian product).

```python
from tests.fuzzing_utils import get_fuzz_combinations, random_uint256_biased

HARDCODED = [0, 1, 0xFF, 2**256-1]

# For tests that need pairs of values
combinations = get_fuzz_combinations(
    hardcoded=HARDCODED,
    generator=random_uint256_biased,
    repeat=2,  # pairs
)
# Result: [(0,0), (0,1), (0,0xFF), ..., (rand1,rand2), ...]
```

### `get_fuzz_pairs(hardcoded_a, hardcoded_b, generator_a, generator_b, count=None)`

Generates pairs from two different parameter types.

```python
from tests.fuzzing_utils import get_fuzz_pairs, random_uint256, random_gas

pairs = get_fuzz_pairs(
    hardcoded_a=[0, 1, 100],
    hardcoded_b=[21000, 100000],
    generator_a=random_uint256,
    generator_b=random_gas,
)
# Result: [(0, 21000), (0, 100000), (1, 21000), ..., (rand_val, rand_gas), ...]
```

## Example: Adding Randomization to a Test

### Before (hardcoded only)

```python
import itertools
import pytest

list_of_args = [0, 1, 2, 0xFF, 0x100, 2**256-1]
combinations = list(itertools.product(list_of_args, repeat=2))

@pytest.mark.parametrize("a,b", combinations)
def test_something(state_test, a, b):
    ...
```

### After (with randomization support)

```python
import pytest
from tests.fuzzing_utils import get_fuzz_combinations, random_uint256_biased

HARDCODED = [0, 1, 2, 0xFF, 0x100, 2**256-1]

# Automatically adds random values when FUZZ_SEED is set
combinations = get_fuzz_combinations(
    hardcoded=HARDCODED,
    generator=random_uint256_biased,
    repeat=2,
)

@pytest.mark.parametrize("a,b", combinations)
def test_something(state_test, a, b):
    ...
```

## Generating Fixtures for Fuzzing

### Step 1: Generate randomized fixtures

```bash
cd /path/to/execution-spec-tests

# Generate with specific seed (reproducible)
FUZZ_SEED=12345 FUZZ_COUNT=100 uv run fill --clean tests/constantinople/ -o ./fixtures-fuzz-12345

# Generate with random seed
SEED=$RANDOM
echo "Using seed: $SEED"
FUZZ_SEED=$SEED FUZZ_COUNT=100 uv run fill --clean tests/ -o ./fixtures-fuzz-$SEED
```

### Step 2: Package fixtures

```bash
tar -czvf fixtures-fuzz-12345.tar.gz fixtures-fuzz-12345/
```

### Step 3: Use in your fuzzing pipeline

```bash
# In your witness generation pipeline
./scripts/download-and-extract-fixtures.sh  # Or use your custom fixtures
./scripts/generate-fixtures-input.sh ./input/fuzz.json
```

## Reproducibility

To reproduce a specific fuzzing run:

1. Note the seed from the output:
   ```
   🎲 Fuzzing enabled: seed=12345, count=100
   ```

2. Re-run with the same seed:
   ```bash
   FUZZ_SEED=12345 FUZZ_COUNT=100 uv run fill --clean tests/
   ```

## Adding Randomization to More Tests

To add randomization support to other test files:

1. Import the utilities:
   ```python
   from tests.fuzzing_utils import get_fuzz_params, random_uint256_biased
   ```

2. Replace hardcoded lists with `get_fuzz_params()` or `get_fuzz_combinations()`

3. Keep original hardcoded values as the `hardcoded` parameter (edge cases)

4. Choose an appropriate random generator for the parameter type

## Generator Selection Guide

| Parameter Type | Recommended Generator |
|----------------|----------------------|
| Stack values (ADD, MUL, etc.) | `random_uint256_biased` |
| Shift amounts | `random_shift_amount` |
| Memory offsets | `random_memory_offset` |
| Memory sizes | `random_memory_size` |
| Storage keys | `random_storage_key` |
| Storage values | `random_storage_value` |
| Addresses | `random_address_with_special` |
| Gas limits | `random_gas` |
| Gas prices | `random_gas_price` |
| Transaction values | `random_value` |
| Balances | `random_balance` |
| Calldata | `random_calldata` |
| Nonces | `random_nonce` |
| Block numbers | `random_block_number` |
| Timestamps | `random_timestamp` |
| Boolean flags | `random_bool` |
| Hash values | `random_hash` or `random_hash_with_special` |
| Blob hashes | `random_blob_hash` |
| Transaction types | `random_tx_type` |
| Chain IDs | `random_chain_id` |
| Access lists | `random_access_list` |
| Withdrawal amounts | `random_withdrawal_amount` |
| Validator indices | `random_validator_index` |
| Contract code | `random_deployed_code` |
| Initcode | `random_initcode` |
| Code sizes | `random_code_size` |
| Stack heights | `random_stack_height` |
| Call depths | `random_call_depth` |
| Log topics | `random_log_topic` |
| Log data | `random_log_data` |
| CREATE2 salts | `random_salt` |
| Precompile inputs | `random_ecrecover_input`, `random_modexp_input`, etc. |
| Base fee (EIP-1559) | `random_base_fee` |
| Priority fee | `random_max_priority_fee` |
| Blob gas fee | `random_max_fee_per_blob_gas` |
| Return data | `random_return_data` |
| Revert data | `random_revert_data` |
| Prevrandao | `random_prevrandao` |
| EOF stack heights | `random_eof_max_stack_height` |
| EOF jump offsets | `random_rjump_offset` |
| EOF function I/O | `random_eof_inputs_outputs` |
| BLS12 G1 points | `random_bls12_g1_point` |
| BLS12 G2 points | `random_bls12_g2_point` |
| BLS12 scalars | `random_bls12_scalar` |
| P256 signatures | `random_p256_signature` |
| Selecting from list | `random_choice` or `random_opcode_from_list` |

## Limitations

1. **Test logic must support variable inputs**: Some tests have logic tightly coupled to specific values and may not work with random inputs.

2. **Expected outputs**: For state tests, the expected post-state must be computed dynamically or the test must verify invariants rather than exact values.

3. **Negative tests**: Tests that verify error conditions may not be suitable for randomization.

4. **Performance**: Large `FUZZ_COUNT` values with `get_fuzz_combinations()` can create very large test matrices (N² for pairs).

## Testing Fuzzing Hooks

Commands to verify all fuzzing hooks work correctly:

```bash
cd /home/varun/execution-spec-tests

# 1. test_shift_combinations.py
FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/constantinople/eip145_bitwise_shift/test_shift_combinations.py

# 2. test_mcopy.py
FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/cancun/eip5656_mcopy/test_mcopy.py::test_valid_mcopy_operations

# 3. test_tstorage.py (two tests use get_storage_slots_for_test)
FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/cancun/eip1153_tstore/test_tstorage.py::test_transient_storage_unset_values tests/cancun/eip1153_tstore/test_tstorage.py::test_tload_after_tstore

# 4. test_calldatasize.py
FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/frontier/opcodes/test_calldatasize.py

# 5. test_blobhash_opcode.py
FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/cancun/eip4844_blobs/test_blobhash_opcode.py::test_blobhash_gas_cost

# 6. test_count_leading_zeros.py (Osaka fork - requires Osaka EVM support)
FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/osaka/eip7939_count_leading_zeros/test_count_leading_zeros.py
```

## Summary of Changes

### Infrastructure Added

1. **`tests/fuzzing_utils.py`** - Core fuzzing utilities module containing:
   - `FuzzConfig` dataclass for configuration
   - `get_fuzz_config()` - Retrieves fuzzing configuration from environment variables
   - `get_fuzz_params()` - Combines hardcoded edge cases with random values
   - Random generators for various EVM types (uint256, addresses, storage keys, memory offsets, etc.)

2. **`tests/conftest.py`** - Pytest configuration with:
   - Command-line options (`--random-seed`, `--random-count`)
   - Session-scoped fixtures for fuzzing configuration
   - Hooks to print fuzzing status at test start

3. **Environment Variables**:
   - `FUZZ_SEED` - Enables randomization and sets the seed for reproducibility
   - `FUZZ_COUNT` - Number of random values to generate (default: 10)
   - `FUZZ_MAX_INT` - Caps integer values for local testing with smaller value ranges

### Test Files Modified

| File | Test Function(s) | What's Randomized |
|------|------------------|-------------------|
| `test_shift_combinations.py` | `test_shift_combinations` | Shift amounts (0-255), operand values (uint256) |
| `test_count_leading_zeros.py` | `test_clz` | Input values (uint256) for CLZ opcode |
| `test_mcopy.py` | `test_valid_mcopy_operations` | dest, src, length parameters for MCOPY |
| `test_tstorage.py` | `test_transient_storage_unset_values`, `test_tload_after_tstore` | Storage slot keys (uint256) |
| `test_calldatasize.py` | `test_calldatasize` | Calldata sizes (capped at 257 for gas) |
| `test_blobhash_opcode.py` | `test_blobhash_gas_cost` | Blobhash index values (uint256) |

## TODO: Future Randomization Hooks

The following tests are good candidates for adding fuzzing hooks due to their broad coverage and wide usage:

### High Priority

1. **`tests/frontier/opcodes/`** - Basic opcode tests
   - `test_dup.py` - DUP1-DUP16 operations
   - `test_swap.py` - SWAP1-SWAP16 operations
   - `test_calldataload.py` - CALLDATALOAD with various offsets
   - `test_calldatacopy.py` - CALLDATACOPY with various dest/offset/size combinations

2. **`tests/cancun/eip4844_blobs/`** - Blob transaction tests
   - Extend `test_blobhash_opcode.py` to cover more test functions
   - `test_blob_txs.py` - Blob transaction validation

3. **`tests/shanghai/eip3855_push0/`** - PUSH0 opcode tests
   - `test_push0.py` - Already has good structure, needs fuzzing for stack operations

### Medium Priority

4. **`tests/cancun/eip5656_mcopy/`** - Memory copy tests
   - Extend to `test_mcopy_on_empty_memory` with random offsets/lengths

5. **`tests/cancun/eip1153_tstore/`** - Transient storage tests
   - Extend to remaining tests: `test_tload_after_sstore`, `test_tload_after_tstore_is_zero`

6. **`tests/homestead/`** - Homestead fork tests
   - Precompile tests (ecrecover, sha256, ripemd160, identity)
   - DELEGATECALL tests

### Lower Priority (Complex Expected Values)

7. **`tests/byzantium/`** - Byzantium fork tests
   - STATICCALL tests
   - RETURNDATASIZE/RETURNDATACOPY tests

8. **`tests/istanbul/`** - Istanbul fork tests
   - EIP-1344 CHAINID tests
   - EIP-1884 gas cost tests

### Notes for Future Implementation

- Tests with **dynamically computed expected values** (like CLZ) are ideal for fuzzing
- Tests with **invariant checks** (e.g., "storage should be zero after TLOAD on unset key") work well
- Tests with **hardcoded expected outputs** require more work to support fuzzing
- Consider gas limits when randomizing memory/calldata sizes to avoid test failures
