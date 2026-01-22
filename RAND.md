# Randomized Test Generation for Fuzzing

This document describes the randomization infrastructure added to `execution-spec-tests` for generating randomized test fixtures suitable for fuzzing EVM implementations.

## Quick Start

```bash
# Default behavior (no randomization, uses hardcoded values)
uv run fill --clean tests/

# Enable randomization with environment variables
FUZZ_SEED=12345 uv run fill --clean tests/

# Random seed (different each run)
FUZZ_SEED=$RANDOM uv run fill --clean tests/

# Control number of random values
FUZZ_SEED=12345 FUZZ_COUNT=50 uv run fill --clean tests/

# Cap all integer values for local testing
FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FUZZ_SEED` | Random seed for reproducibility. Set to any integer to enable randomization. | Not set (disabled) |
| `FUZZ_COUNT` | Number of random values to generate per parameter | `10` |
| `FUZZ_MAX_INT` | Cap all integer values to this maximum. Supports decimal, hex (`0x100`), or power notation (`2**8`). | Not set (no cap) |

## Available Random Generators

### Integer Generators

| Function | Description |
|----------|-------------|
| `random_uint256(count)` | Fully random uint256 values |
| `random_uint256_biased(count)` | uint256 with bias toward interesting values |
| `random_int256(count)` | Signed int256 values (two's complement) |
| `random_uint8(count)` | uint8 values (0-255) |
| `random_uint64(count)` | uint64 values |
| `random_small_int(count, max_val)` | Small integers for indices/counters |
| `random_shift_amount(count)` | Shift amounts (0-256) with edge case bias |

### Address & Storage Generators

| Function | Description |
|----------|-------------|
| `random_address(count)` | Random 20-byte addresses |
| `random_address_with_special(count)` | Includes precompile addresses (0x01-0x0A) |
| `random_storage_key(count)` | Storage keys (includes slot 0) |
| `random_storage_value(count)` | Storage values |

### Bytes & Hash Generators

| Function | Description |
|----------|-------------|
| `random_bytes(count, max_len)` | Variable length byte sequences |
| `random_bytes32(count)` | Fixed 32-byte values |
| `random_calldata(count, max_len)` | Random calldata (includes empty) |
| `random_hash(count)` | Random 32-byte hash values |
| `random_blob_hash(count)` | KZG versioned blob hashes (0x01 prefix) |

### Transaction & Block Generators

| Function | Description |
|----------|-------------|
| `random_gas(count)` | Gas values with realistic distribution |
| `random_value(count)` | Transaction values in wei |
| `random_balance(count)` | Account balances |
| `random_nonce(count)` | Account nonces |
| `random_timestamp(count)` | Block timestamps |
| `random_access_list(count, max_entries)` | Full access lists |

### EIP-4844 Blob Generators

| Function | Description |
|----------|-------------|
| `random_blob_data(count)` | Blob data (truncated for testing) |
| `random_blob_versioned_hash(count)` | Versioned blob hashes |
| `random_max_fee_per_blob_gas(count)` | Max fee per blob gas |

### EIP-4895 Withdrawal Generators

| Function | Description |
|----------|-------------|
| `random_withdrawal_amount(count)` | Withdrawal amounts in Gwei |
| `random_validator_index(count)` | Validator indices |

### Utility Generators

| Function | Description |
|----------|-------------|
| `random_salt(count)` | CREATE2 salt values |
| `random_memory_offset(count)` | Memory offsets with common patterns |
| `random_memory_size(count)` | Memory sizes for copy operations |
| `random_choice(items, count)` | Select from any list |
| `random_bool(count)` | Random True/False |

## Helper Functions

### `get_fuzz_params(hardcoded, generator, count=None)`

Combines hardcoded edge-case values with randomly generated values.

```python
from tests.fuzzing_utils import get_fuzz_params, random_uint256_biased

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

combinations = get_fuzz_combinations(
    hardcoded=HARDCODED,
    generator=random_uint256_biased,
    repeat=2,  # pairs
)
# Result: [(0,0), (0,1), (0,0xFF), ..., (rand1,rand2), ...]
```

## Adding Randomization to Tests

### Pattern for Blockchain Tests

```python
from tests.fuzzing_utils import get_fuzz_config, random_storage_key, random_storage_value

def get_storage_params():
    """Get storage key/value with optional fuzzing."""
    config = get_fuzz_config()
    hardcoded = [(1, 1), (0, 1), (2**256 - 1, 2**256 - 1)]

    if config.enabled:
        random_keys = list(random_storage_key(config.count))
        random_values = list(random_storage_value(config.count))
        return hardcoded + list(zip(random_keys, random_values))
    return hardcoded

STORAGE_PARAMS = get_storage_params()

@pytest.mark.parametrize("storage_key,storage_value", STORAGE_PARAMS)
def test_tstore_clear_after_tx(blockchain_test, storage_key, storage_value):
    code = Op.SSTORE(storage_key, Op.TLOAD(storage_key)) + Op.TSTORE(storage_key, storage_value)
    ...
```

## Test Files with Fuzzing Hooks

### State Tests (`state_test` fixture)

| File | Test Function(s) | What's Randomized |
|------|------------------|-------------------|
| `test_shift_combinations.py` | `test_shift_combinations` | Shift amounts, operand values |
| `test_count_leading_zeros.py` | `test_clz` | Input values (uint256) |
| `test_mcopy.py` | `test_valid_mcopy_operations` | dest, src, length |
| `test_tstorage.py` | `test_transient_storage_unset_values`, `test_tload_after_tstore` | Storage slot keys |
| `test_calldatasize.py` | `test_calldatasize` | Calldata sizes |
| `test_blobhash_opcode.py` | `test_blobhash_gas_cost` | Blobhash index values |

### Blockchain Tests (`blockchain_test` fixture)

These generate `blockchain_tests` fixtures required for `witness-generator-cli`.

| File | Test Function(s) | What's Randomized |
|------|------------------|-------------------|
| `test_blobhash_opcode.py` | `test_blobhash_scenarios`, `test_blobhash_invalid_blob_index`, `test_blobhash_multiple_txs_in_block` | Blob versioned hashes |
| `test_blob_txs.py` | `test_insufficient_balance_blob_tx`, `test_sufficient_balance_blob_tx`, `test_sufficient_balance_blob_tx_pre_fund_tx` | Transaction values, calldata, access lists |
| `test_tstorage_clear_after_tx.py` | `test_tstore_clear_after_deployment_tx`, `test_tstore_clear_after_tx` | Storage keys and values |
| `test_beacon_root_contract.py` | `test_beacon_root_contract_timestamps` | Timestamps, system address balances |
| `test_withdrawals.py` | `test_use_value_in_contract`, `test_balance_within_block` | Withdrawal amounts, validator indices |

## Testing Commands

### State Tests

```bash
cd /home/varun/execution-spec-tests

FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/constantinople/eip145_bitwise_shift/test_shift_combinations.py
FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/cancun/eip5656_mcopy/test_mcopy.py::test_valid_mcopy_operations
FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/cancun/eip1153_tstore/test_tstorage.py::test_transient_storage_unset_values
FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/frontier/opcodes/test_calldatasize.py
FUZZ_SEED=12345 FUZZ_MAX_INT="2**16" uv run fill --clean tests/cancun/eip4844_blobs/test_blobhash_opcode.py::test_blobhash_gas_cost
```

### Blockchain Tests

```bash
cd /home/varun/execution-spec-tests

# Blob transactions
FUZZ_SEED=12345 uv run fill --clean tests/cancun/eip4844_blobs/test_blobhash_opcode.py::test_blobhash_scenarios
FUZZ_SEED=12345 uv run fill --clean tests/cancun/eip4844_blobs/test_blob_txs.py::test_sufficient_balance_blob_tx

# Transient storage
FUZZ_SEED=12345 uv run fill --clean tests/cancun/eip1153_tstore/test_tstorage_clear_after_tx.py

# Beacon root
FUZZ_SEED=12345 uv run fill --clean tests/cancun/eip4788_beacon_root/test_beacon_root_contract.py::test_beacon_root_contract_timestamps

# Withdrawals
FUZZ_SEED=12345 uv run fill --clean tests/shanghai/eip4895_withdrawals/test_withdrawals.py::test_balance_within_block
```

## TODO: Future Randomization Hooks

### Remaining High Priority

| File | What to Randomize |
|------|-------------------|
| `test_excess_blob_gas.py` | Parent excess blobs, blob counts |
| `test_point_evaluation_precompile.py` | Z/Y values, KZG proofs |
| `test_blobgasfee_opcode.py` | Call gas, tx values |
| `test_selfdestruct_balance_bug.py` | Balances, storage keys |
| `test_dynamic_create2_selfdestruct_collision.py` | Storage locations, CREATE2 salt |

### Notes

- Tests with **invariant checks** (e.g., "storage should be zero after TLOAD on unset key") work well for fuzzing
- Tests with **hardcoded expected outputs** require more work
- Consider gas limits when randomizing memory/calldata sizes
- **Blockchain tests** are preferred for `witness-generator-cli` integration
