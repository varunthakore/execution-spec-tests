"""
Fuzzing utilities for randomized test generation.

This module provides helper functions for generating random test values
that can be used across different test files in execution-spec-tests.

See RAND.md for full documentation and usage examples.
"""

import itertools
import os
import random
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar, Union

T = TypeVar("T")


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class FuzzConfig:
    """Configuration for fuzzing."""

    seed: Optional[int]
    count: int
    enabled: bool
    max_int: Optional[int]  # Cap for integer values (None = no cap)

    @classmethod
    def from_env(cls) -> "FuzzConfig":
        """Load fuzz configuration from environment variables."""
        seed_str = os.environ.get("FUZZ_SEED")

        if seed_str is None:
            return cls(seed=None, count=0, enabled=False, max_int=None)

        seed = int(seed_str)
        count = int(os.environ.get("FUZZ_COUNT", "10"))

        # Parse FUZZ_MAX_INT - supports decimal or hex (0x...) or power notation (2**8)
        max_int_str = os.environ.get("FUZZ_MAX_INT")
        max_int = None
        if max_int_str:
            max_int_str = max_int_str.strip()
            if max_int_str.startswith("0x"):
                max_int = int(max_int_str, 16)
            elif "**" in max_int_str:
                # Support 2**8, 2**16, etc.
                base, exp = max_int_str.split("**")
                max_int = int(base.strip()) ** int(exp.strip())
            else:
                max_int = int(max_int_str)

        return cls(seed=seed, count=count, enabled=True, max_int=max_int)


# Global config loaded once at module import
_fuzz_config: Optional[FuzzConfig] = None


def get_fuzz_config() -> FuzzConfig:
    """Get the global fuzz configuration."""
    global _fuzz_config
    if _fuzz_config is None:
        _fuzz_config = FuzzConfig.from_env()
        if _fuzz_config.enabled:
            random.seed(_fuzz_config.seed)
            max_int_str = f", max_int={_fuzz_config.max_int}" if _fuzz_config.max_int else ""
            print(f"🎲 Fuzzing enabled: seed={_fuzz_config.seed}, count={_fuzz_config.count}{max_int_str}")
    return _fuzz_config


def _cap_int(value: int, max_val: Optional[int] = None) -> int:
    """Cap an integer value to the configured maximum."""
    config = get_fuzz_config()
    cap = max_val if max_val is not None else config.max_int
    if cap is not None and value > cap:
        return value % (cap + 1)  # Wrap to range [0, cap]
    return value


def _cap_int_signed(value: int, max_val: Optional[int] = None) -> int:
    """Cap a signed integer value to the configured maximum (symmetric around 0)."""
    config = get_fuzz_config()
    cap = max_val if max_val is not None else config.max_int
    if cap is not None:
        if value > cap:
            return value % (cap + 1)
        elif value < -cap:
            return -(abs(value) % (cap + 1))
    return value


# =============================================================================
# Integer Generators (uint256, int256, etc.)
# =============================================================================


def random_uint256(count: int) -> List[int]:
    """Generate fully random uint256 values (capped by FUZZ_MAX_INT if set)."""
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 2**256 - 1
    return [random.randint(0, max_val) for _ in range(count)]


def random_uint256_biased(count: int) -> List[int]:
    """
    Generate random uint256 values with bias toward interesting values.
    Capped by FUZZ_MAX_INT if set.

    Distribution:
    - 20% small values (0-1000)
    - 20% values near powers of 2
    - 20% large values (near max)
    - 20% specific bit patterns (0x55, 0xAA, 0xFF)
    - 20% fully random
    """
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 2**256 - 1

    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.2:
            # Small values (0-1000 or max_val if smaller)
            result.append(random.randint(0, min(1000, max_val)))
        elif choice < 0.4:
            # Values near powers of 2
            max_power = max_val.bit_length() if max_val > 0 else 1
            power = random.randint(1, min(255, max_power))
            offset = random.randint(-10, 10)
            value = max(0, min(max_val, (2**power) + offset))
            result.append(value)
        elif choice < 0.6:
            # Large values (near max)
            result.append(max(0, max_val - random.randint(0, min(1000, max_val))))
        elif choice < 0.8:
            # Values with specific bit patterns (scaled to max_val)
            if max_val >= 255:
                pattern = random.choice([0x55, 0xAA, 0xFF, 0x00])
                num_bytes = min(32, (max_val.bit_length() + 7) // 8)
                value = int.from_bytes(bytes([pattern] * num_bytes), "big")
                result.append(min(value, max_val))
            else:
                result.append(random.randint(0, max_val))
        else:
            # Fully random
            result.append(random.randint(0, max_val))
    return result


def random_int256(count: int) -> List[int]:
    """Generate random signed int256 values (two's complement). Capped by FUZZ_MAX_INT if set."""
    config = get_fuzz_config()
    if config.max_int is not None:
        max_val = config.max_int
        return [random.randint(-max_val, max_val) for _ in range(count)]

    result = []
    for _ in range(count):
        val = random.randint(0, 2**256 - 1)
        # Convert to signed
        if val >= 2**255:
            val -= 2**256
        result.append(val)
    return result


def random_uint8(count: int) -> List[int]:
    """Generate random uint8 values (0-255). Capped by FUZZ_MAX_INT if set."""
    config = get_fuzz_config()
    max_val = min(255, config.max_int) if config.max_int is not None else 255
    return [random.randint(0, max_val) for _ in range(count)]


def random_uint64(count: int) -> List[int]:
    """Generate random uint64 values. Capped by FUZZ_MAX_INT if set."""
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 2**64 - 1
    return [random.randint(0, max_val) for _ in range(count)]


def random_uint128(count: int) -> List[int]:
    """Generate random uint128 values. Capped by FUZZ_MAX_INT if set."""
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 2**128 - 1
    return [random.randint(0, max_val) for _ in range(count)]


def random_small_int(count: int, max_val: int = 1000) -> List[int]:
    """Generate small random integers (useful for loop counters, indices)."""
    config = get_fuzz_config()
    if config.max_int is not None:
        max_val = min(max_val, config.max_int)
    return [random.randint(0, max_val) for _ in range(count)]


def random_shift_amount(count: int) -> List[int]:
    """Generate random shift amounts (0-256, biased toward edge cases). Capped by FUZZ_MAX_INT if set."""
    config = get_fuzz_config()
    max_shift = 256
    if config.max_int is not None:
        max_shift = min(256, config.max_int)

    edge_cases = [x for x in [0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256] if x <= max_shift]
    result = edge_cases[:min(count, len(edge_cases))]
    remaining = count - len(result)
    if remaining > 0:
        result.extend([random.randint(0, max_shift) for _ in range(remaining)])
    return result


# =============================================================================
# Address Generators
# =============================================================================


def random_address(count: int) -> List[int]:
    """Generate random Ethereum addresses (20 bytes / 160 bits). Capped by FUZZ_MAX_INT if set."""
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 2**160 - 1
    return [random.randint(0, max_val) for _ in range(count)]


def random_address_with_special(count: int) -> List[int]:
    """
    Generate addresses including special/precompile addresses.
    Capped by FUZZ_MAX_INT if set.

    Includes precompile range (0x01-0x0a) and system contracts.
    """
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 2**160 - 1

    special = [
        0x0,  # Zero address
        0x1,  # ecrecover
        0x2,  # SHA256
        0x3,  # RIPEMD160
        0x4,  # identity
        0x5,  # modexp
        0x6,  # ecAdd
        0x7,  # ecMul
        0x8,  # ecPairing
        0x9,  # blake2f
        0x0A,  # point evaluation (EIP-4844)
    ]
    # Only include special addresses that fit within max_val
    special = [a for a in special if a <= max_val]
    # Add max address if it fits
    if max_val >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:
        special.append(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

    result = special[:min(count, len(special))]
    remaining = count - len(result)
    if remaining > 0:
        result.extend(random_address(remaining))
    return result


# =============================================================================
# Bytes Generators
# =============================================================================


def random_bytes(count: int, max_len: int = 32) -> List[bytes]:
    """Generate random byte sequences of varying lengths."""
    return [random.randbytes(random.randint(0, max_len)) for _ in range(count)]


def random_bytes32(count: int) -> List[bytes]:
    """Generate random 32-byte values."""
    return [random.randbytes(32) for _ in range(count)]


def random_bytes_fixed(count: int, length: int) -> List[bytes]:
    """Generate random byte sequences of fixed length."""
    return [random.randbytes(length) for _ in range(count)]


def random_calldata(count: int, max_len: int = 1024) -> List[bytes]:
    """
    Generate random calldata with varying lengths.

    Always includes empty calldata as first element.
    """
    result = [b""]  # Empty calldata
    for _ in range(count - 1):
        length = random.randint(0, max_len)
        result.append(random.randbytes(length))
    return result


def random_calldata_with_selector(count: int, max_data_len: int = 256) -> List[bytes]:
    """
    Generate random calldata with 4-byte function selectors.

    Format: selector (4 bytes) + data (variable)
    """
    result = [b""]  # Empty calldata
    for _ in range(count - 1):
        selector = random.randbytes(4)
        data_len = random.randint(0, max_data_len)
        # Align to 32 bytes (ABI encoding)
        data_len = (data_len // 32) * 32
        data = random.randbytes(data_len) if data_len > 0 else b""
        result.append(selector + data)
    return result


def random_bytecode(count: int, max_len: int = 256) -> List[bytes]:
    """
    Generate random bytecode-like sequences.

    Includes valid opcode patterns and random bytes.
    """
    # Common opcodes
    opcodes = [
        0x00,  # STOP
        0x01,  # ADD
        0x02,  # MUL
        0x03,  # SUB
        0x04,  # DIV
        0x10,  # LT
        0x11,  # GT
        0x14,  # EQ
        0x15,  # ISZERO
        0x16,  # AND
        0x17,  # OR
        0x18,  # XOR
        0x19,  # NOT
        0x20,  # KECCAK256
        0x30,  # ADDRESS
        0x31,  # BALANCE
        0x32,  # ORIGIN
        0x33,  # CALLER
        0x34,  # CALLVALUE
        0x35,  # CALLDATALOAD
        0x36,  # CALLDATASIZE
        0x37,  # CALLDATACOPY
        0x50,  # POP
        0x51,  # MLOAD
        0x52,  # MSTORE
        0x54,  # SLOAD
        0x55,  # SSTORE
        0x56,  # JUMP
        0x57,  # JUMPI
        0x5B,  # JUMPDEST
        0x60,  # PUSH1
        0x80,  # DUP1
        0x90,  # SWAP1
        0xF1,  # CALL
        0xF3,  # RETURN
        0xFD,  # REVERT
        0xFE,  # INVALID
        0xFF,  # SELFDESTRUCT
    ]

    result = []
    for _ in range(count):
        length = random.randint(1, max_len)
        code = bytes([random.choice(opcodes) for _ in range(length)])
        result.append(code)
    return result


# =============================================================================
# Gas and Value Generators
# =============================================================================


def random_gas(count: int) -> List[int]:
    """
    Generate random gas values within typical bounds. Capped by FUZZ_MAX_INT if set.

    Distribution:
    - 20% minimum gas for simple tx (21000 + small)
    - 20% medium gas (50k-500k)
    - 20% high gas (500k-5M)
    - 20% very high gas (5M-30M)
    - 20% edge cases
    """
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 30000000

    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.2:
            result.append(min(21000 + random.randint(0, 1000), max_val))
        elif choice < 0.4:
            result.append(random.randint(0, min(500000, max_val)))
        elif choice < 0.6:
            result.append(random.randint(0, min(5000000, max_val)))
        elif choice < 0.8:
            result.append(random.randint(0, min(30000000, max_val)))
        else:
            edge = [0, 1, 21000, 21001]
            if max_val >= 2**32 - 1:
                edge.append(2**32 - 1)
            result.append(random.choice(edge))
    return result


def random_gas_price(count: int) -> List[int]:
    """Generate random gas prices (in wei). Capped by FUZZ_MAX_INT if set."""
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 2**64 - 1

    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.3:
            # Low gas price (1-10 gwei or max)
            result.append(random.randint(0, min(10**10, max_val)))
        elif choice < 0.6:
            # Medium gas price (10-100 gwei or max)
            result.append(random.randint(0, min(10**11, max_val)))
        elif choice < 0.9:
            # High gas price (100-1000 gwei or max)
            result.append(random.randint(0, min(10**12, max_val)))
        else:
            # Edge cases
            edge = [0, 1]
            if max_val >= 10**9:
                edge.append(10**9)
            result.append(random.choice(edge))
    return result


def random_value(count: int) -> List[int]:
    """
    Generate random wei values for transactions. Capped by FUZZ_MAX_INT if set.

    Distribution across different magnitude ranges.
    """
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 2**128 - 1

    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.3:
            # Zero or small (0-1 gwei or max)
            result.append(random.randint(0, min(10**9, max_val)))
        elif choice < 0.6:
            # Typical amounts (gwei to ether range or max)
            result.append(random.randint(0, min(10**18, max_val)))
        elif choice < 0.8:
            # Large amounts (1-1000 ether or max)
            result.append(random.randint(0, min(10**21, max_val)))
        else:
            # Edge cases
            edge = [0, 1]
            if max_val >= 10**18:
                edge.append(10**18)
            result.append(random.choice(edge))
    return result


def random_balance(count: int) -> List[int]:
    """Generate random account balances. Capped by FUZZ_MAX_INT if set."""
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 10**24

    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.2:
            # Zero or dust
            result.append(random.randint(0, min(10**15, max_val)))
        elif choice < 0.5:
            # Small balance (< 1 ETH)
            result.append(random.randint(0, min(10**18, max_val)))
        elif choice < 0.8:
            # Medium balance (1-1000 ETH)
            result.append(random.randint(0, min(10**21, max_val)))
        else:
            # Large balance (1000+ ETH)
            result.append(random.randint(0, min(10**24, max_val)))
    return result


# =============================================================================
# Storage Generators
# =============================================================================


def random_storage_key(count: int) -> List[int]:
    """Generate random storage keys (uint256). Capped by FUZZ_MAX_INT if set."""
    # Include slot 0 which is commonly used
    result = [0]
    result.extend(random_uint256_biased(count - 1))
    return result


def random_storage_value(count: int) -> List[int]:
    """Generate random storage values (uint256). Capped by FUZZ_MAX_INT if set."""
    return random_uint256_biased(count)


def random_storage_pairs(count: int) -> List[Tuple[int, int]]:
    """Generate random (key, value) pairs for storage. Capped by FUZZ_MAX_INT if set."""
    keys = random_storage_key(count)
    values = random_storage_value(count)
    return list(zip(keys, values))


# =============================================================================
# Nonce and Block Generators
# =============================================================================


def random_nonce(count: int) -> List[int]:
    """Generate random nonce values. Capped by FUZZ_MAX_INT if set."""
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 2**64 - 1

    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.4:
            # Common low nonces
            result.append(random.randint(0, min(100, max_val)))
        elif choice < 0.7:
            # Medium nonces
            result.append(random.randint(0, min(10000, max_val)))
        elif choice < 0.9:
            # High nonces
            result.append(random.randint(0, min(2**32, max_val)))
        else:
            # Edge cases
            edge = [0, 1]
            if max_val >= 2**64 - 1:
                edge.extend([2**64 - 2, 2**64 - 1])
            result.append(random.choice(edge))
    return result


def random_block_number(count: int) -> List[int]:
    """Generate random block numbers. Capped by FUZZ_MAX_INT if set."""
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 2**64 - 1

    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.3:
            # Early blocks
            result.append(random.randint(0, min(1000, max_val)))
        elif choice < 0.6:
            # Medium blocks (around mainnet current)
            result.append(random.randint(0, min(20000000, max_val)))
        elif choice < 0.9:
            # Future blocks
            result.append(random.randint(0, min(100000000, max_val)))
        else:
            # Edge cases
            edge = [0, 1]
            if max_val >= 2**32 - 1:
                edge.append(2**32 - 1)
            result.append(random.choice(edge))
    return result


def random_timestamp(count: int) -> List[int]:
    """Generate random timestamps. Capped by FUZZ_MAX_INT if set."""
    config = get_fuzz_config()
    max_val = config.max_int if config.max_int is not None else 2**32 - 1

    # Base: roughly current time (2024)
    base_time = min(1700000000, max_val)
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.7:
            # Near current time (or within max_val)
            offset_range = min(10000000, max_val)
            result.append(random.randint(0, min(base_time + offset_range, max_val)))
        elif choice < 0.9:
            # Future (or within max_val)
            result.append(random.randint(0, max_val))
        else:
            # Edge cases
            edge = [0, 1]
            if max_val >= base_time:
                edge.append(base_time)
            result.append(random.choice(edge))
    return result


# =============================================================================
# Boolean and Enum Generators
# =============================================================================


def random_bool(count: int) -> List[bool]:
    """Generate random boolean values."""
    return [random.choice([True, False]) for _ in range(count)]


def random_bool_biased(count: int, true_probability: float = 0.5) -> List[bool]:
    """Generate random boolean values with configurable bias."""
    return [random.random() < true_probability for _ in range(count)]


# =============================================================================
# Hash Generators
# =============================================================================


def random_hash(count: int) -> List[bytes]:
    """Generate random 32-byte hash values."""
    return [random.randbytes(32) for _ in range(count)]


def random_hash_with_special(count: int) -> List[bytes]:
    """
    Generate hash values including special cases.

    Includes zero hash, max hash, and random hashes.
    """
    special = [
        b"\x00" * 32,  # Zero hash
        b"\xff" * 32,  # Max hash
        b"\x01" + b"\x00" * 31,  # Versioned hash (KZG)
    ]
    result = special[:min(count, len(special))]
    remaining = count - len(result)
    if remaining > 0:
        result.extend(random_hash(remaining))
    return result


def random_blob_hash(count: int) -> List[bytes]:
    """
    Generate random blob hashes with KZG version byte (0x01).

    Used for EIP-4844 blob transactions.
    """
    result = []
    for _ in range(count):
        # Version byte (0x01) + 31 random bytes
        result.append(b"\x01" + random.randbytes(31))
    return result


# =============================================================================
# Transaction Type Generators
# =============================================================================


def random_tx_type(count: int) -> List[int]:
    """Generate random transaction types."""
    # Valid transaction types: 0 (legacy), 1 (access list), 2 (EIP-1559), 3 (blob)
    tx_types = [0, 1, 2, 3]
    return [random.choice(tx_types) for _ in range(count)]


def random_access_list_entry(count: int) -> List[Tuple[int, List[int]]]:
    """
    Generate random access list entries.

    Each entry is (address, [storage_keys]).
    """
    result = []
    for _ in range(count):
        address = random.randint(0, 2**160 - 1)
        num_keys = random.randint(0, 10)
        storage_keys = [random.randint(0, 2**256 - 1) for _ in range(num_keys)]
        result.append((address, storage_keys))
    return result


def random_access_list(count: int, max_entries: int = 5) -> List[List[Tuple[int, List[int]]]]:
    """
    Generate random access lists (list of access list entries).

    Each access list contains 0 to max_entries entries.
    """
    result = [[]]  # Always include empty access list
    for _ in range(count - 1):
        num_entries = random.randint(0, max_entries)
        entries = random_access_list_entry(num_entries)
        result.append(entries)
    return result


# =============================================================================
# Withdrawal Generators (EIP-4895)
# =============================================================================


def random_withdrawal_amount(count: int) -> List[int]:
    """
    Generate random withdrawal amounts in Gwei.

    Validators can withdraw up to 32 ETH max effective balance.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.3:
            # Small withdrawals (dust to 1 ETH in Gwei)
            result.append(random.randint(0, 10**9))
        elif choice < 0.6:
            # Medium withdrawals (1-10 ETH in Gwei)
            result.append(random.randint(10**9, 10**10))
        elif choice < 0.9:
            # Large withdrawals (10-32 ETH in Gwei)
            result.append(random.randint(10**10, 32 * 10**9))
        else:
            # Edge cases
            result.append(random.choice([0, 1, 32 * 10**9, 2**64 - 1]))
    return result


def random_validator_index(count: int) -> List[int]:
    """Generate random validator indices."""
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.5:
            # Common range (first million validators)
            result.append(random.randint(0, 1000000))
        elif choice < 0.8:
            # Extended range
            result.append(random.randint(1000000, 10000000))
        else:
            # Edge cases
            result.append(random.choice([0, 1, 2**32 - 1, 2**64 - 1]))
    return result


# =============================================================================
# Code/Initcode Generators
# =============================================================================


def random_initcode(count: int, max_len: int = 512) -> List[bytes]:
    """
    Generate random initcode (contract creation code).

    Initcode typically ends with RETURN or has specific patterns.
    """
    result = []
    for _ in range(count):
        length = random.randint(1, max_len)
        # Generate random bytecode
        code = bytearray(random.randbytes(length))
        # Optionally make it valid by ending with RETURN (0xF3) or STOP (0x00)
        if random.random() < 0.5:
            code[-1] = random.choice([0x00, 0xF3, 0xFD])  # STOP, RETURN, or REVERT
        result.append(bytes(code))
    return result


def random_deployed_code(count: int, max_len: int = 256) -> List[bytes]:
    """
    Generate random deployed contract code.

    More likely to be valid executable bytecode.
    """
    valid_opcodes = [
        0x00,  # STOP
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  # Arithmetic
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15,  # Comparison
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,  # Bitwise
        0x20,  # KECCAK256
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,  # Environment
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,  # Block info
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,  # Stack/Memory/Storage
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65,  # PUSH1-PUSH6
        0x80, 0x81, 0x82, 0x83,  # DUP1-DUP4
        0x90, 0x91, 0x92, 0x93,  # SWAP1-SWAP4
        0xF1, 0xF2, 0xF3, 0xF4, 0xFA, 0xFD, 0xFE, 0xFF,  # Call/Return opcodes
    ]
    result = []
    for _ in range(count):
        length = random.randint(1, max_len)
        code = bytes([random.choice(valid_opcodes) for _ in range(length)])
        result.append(code)
    return result


# =============================================================================
# Memory/Offset Generators
# =============================================================================


def random_memory_offset(count: int) -> List[int]:
    """
    Generate random memory offsets.

    Biased toward common ranges and edge cases.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.3:
            # Small offsets (0-256)
            result.append(random.randint(0, 256))
        elif choice < 0.6:
            # Medium offsets (256-4096)
            result.append(random.randint(256, 4096))
        elif choice < 0.8:
            # Large offsets (4096-65536)
            result.append(random.randint(4096, 65536))
        else:
            # Edge cases (32-byte aligned)
            result.append(random.choice([0, 32, 64, 128, 256, 512, 1024, 2**16, 2**24]))
    return result


def random_memory_size(count: int) -> List[int]:
    """
    Generate random memory sizes.

    Used for operations like CALLDATACOPY, CODECOPY, etc.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.2:
            # Zero or small (0-32)
            result.append(random.randint(0, 32))
        elif choice < 0.5:
            # Common sizes (32-256)
            result.append(random.randint(32, 256))
        elif choice < 0.8:
            # Medium sizes (256-4096)
            result.append(random.randint(256, 4096))
        else:
            # Edge cases
            result.append(random.choice([0, 1, 31, 32, 33, 64, 128, 256, 1024]))
    return result


def random_stack_height(count: int) -> List[int]:
    """
    Generate random stack heights (0-1024 valid, can include invalid).

    EVM stack limit is 1024 items.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.3:
            # Low stack (0-16, common for operations)
            result.append(random.randint(0, 16))
        elif choice < 0.6:
            # Medium stack (16-256)
            result.append(random.randint(16, 256))
        elif choice < 0.8:
            # High stack (256-1024)
            result.append(random.randint(256, 1024))
        else:
            # Edge cases (near/at/over limit)
            result.append(random.choice([0, 1, 15, 16, 1023, 1024, 1025]))
    return result


# =============================================================================
# Log/Event Generators
# =============================================================================


def random_log_topic(count: int) -> List[bytes]:
    """Generate random log topics (32 bytes each)."""
    return random_bytes32(count)


def random_log_data(count: int, max_len: int = 256) -> List[bytes]:
    """Generate random log data."""
    return random_bytes(count, max_len)


def random_num_topics(count: int) -> List[int]:
    """
    Generate random number of topics (0-4 for LOG0-LOG4).
    """
    return [random.randint(0, 4) for _ in range(count)]


# =============================================================================
# CREATE/CREATE2 Generators
# =============================================================================


def random_salt(count: int) -> List[int]:
    """Generate random salt values for CREATE2."""
    # Include common salt values
    result = [0, 1]
    result.extend(random_uint256_biased(count - 2))
    return result[:count]


def random_create2_address(
    deployer: int,
    salt: int,
    init_code_hash: bytes
) -> int:
    """
    Compute CREATE2 address from components.

    This is a helper, not a generator.
    """
    import hashlib
    prefix = b"\xff"
    deployer_bytes = deployer.to_bytes(20, "big")
    salt_bytes = salt.to_bytes(32, "big")
    data = prefix + deployer_bytes + salt_bytes + init_code_hash
    return int.from_bytes(hashlib.sha3_256(data).digest()[12:], "big")


# =============================================================================
# Precompile-specific Generators
# =============================================================================


def random_ecrecover_input(count: int) -> List[bytes]:
    """
    Generate random inputs for ecrecover precompile (0x01).

    Format: hash (32) + v (32) + r (32) + s (32) = 128 bytes
    """
    result = []
    for _ in range(count):
        msg_hash = random.randbytes(32)
        v = (27 + random.randint(0, 1)).to_bytes(32, "big")  # 27 or 28
        r = random.randbytes(32)
        s = random.randbytes(32)
        result.append(msg_hash + v + r + s)
    return result


def random_bn256_point(count: int) -> List[bytes]:
    """
    Generate random bn256 curve points for ecAdd/ecMul precompiles.

    Format: x (32) + y (32) = 64 bytes per point
    Note: These are random bytes, not necessarily valid curve points.
    """
    result = []
    for _ in range(count):
        x = random.randbytes(32)
        y = random.randbytes(32)
        result.append(x + y)
    return result


def random_modexp_input(count: int) -> List[bytes]:
    """
    Generate random inputs for modexp precompile (0x05).

    Format: Bsize (32) + Esize (32) + Msize (32) + B + E + M
    """
    result = []
    for _ in range(count):
        b_size = random.randint(1, 64)
        e_size = random.randint(1, 64)
        m_size = random.randint(1, 64)

        header = (
            b_size.to_bytes(32, "big") +
            e_size.to_bytes(32, "big") +
            m_size.to_bytes(32, "big")
        )
        b = random.randbytes(b_size)
        e = random.randbytes(e_size)
        m = random.randbytes(m_size)

        result.append(header + b + e + m)
    return result


def random_blake2f_input(count: int) -> List[bytes]:
    """
    Generate random inputs for blake2f precompile (0x09).

    Format: rounds (4) + h (64) + m (128) + t (16) + f (1) = 213 bytes
    """
    result = []
    for _ in range(count):
        rounds = random.randint(0, 12).to_bytes(4, "big")
        h = random.randbytes(64)  # State
        m = random.randbytes(128)  # Message block
        t = random.randbytes(16)  # Offset counter
        f = bytes([random.randint(0, 1)])  # Final block flag
        result.append(rounds + h + m + t + f)
    return result


# =============================================================================
# EIP-4844 Blob Generators
# =============================================================================


def random_blob_data(count: int) -> List[bytes]:
    """
    Generate random blob data (128 KB each, but truncated for testing).

    Full blob is 4096 * 32 = 131072 bytes.
    For testing, we generate smaller random data.
    """
    result = []
    for _ in range(count):
        # Generate smaller blobs for testing (1-4 KB)
        size = random.randint(1024, 4096)
        result.append(random.randbytes(size))
    return result


def random_blob_versioned_hash(count: int) -> List[bytes]:
    """
    Generate random versioned blob hashes.

    Version byte (0x01 for KZG) + 31 bytes of hash.
    """
    return random_blob_hash(count)


# =============================================================================
# Fork-specific Value Generators
# =============================================================================


def random_base_fee(count: int) -> List[int]:
    """
    Generate random base fee values (EIP-1559).

    Base fee is in wei, typically 1-1000 gwei.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.3:
            # Low base fee (1-10 gwei)
            result.append(random.randint(10**9, 10**10))
        elif choice < 0.6:
            # Medium base fee (10-100 gwei)
            result.append(random.randint(10**10, 10**11))
        elif choice < 0.9:
            # High base fee (100-500 gwei)
            result.append(random.randint(10**11, 5 * 10**11))
        else:
            # Edge cases
            result.append(random.choice([0, 1, 7, 10**9, 10**12]))
    return result


def random_max_fee_per_gas(count: int) -> List[int]:
    """Generate random max fee per gas values (EIP-1559)."""
    return random_gas_price(count)


def random_max_priority_fee(count: int) -> List[int]:
    """
    Generate random max priority fee values (EIP-1559).

    Typically lower than max fee per gas.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.4:
            # Low priority (1-5 gwei)
            result.append(random.randint(10**9, 5 * 10**9))
        elif choice < 0.7:
            # Medium priority (5-20 gwei)
            result.append(random.randint(5 * 10**9, 20 * 10**9))
        elif choice < 0.9:
            # High priority (20-100 gwei)
            result.append(random.randint(20 * 10**9, 10**11))
        else:
            # Edge cases
            result.append(random.choice([0, 1, 10**9, 10**10]))
    return result


def random_max_fee_per_blob_gas(count: int) -> List[int]:
    """
    Generate random max fee per blob gas values (EIP-4844).

    Blob gas prices are typically lower than regular gas.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.5:
            # Low blob fee (1-100 wei)
            result.append(random.randint(1, 100))
        elif choice < 0.8:
            # Medium blob fee (100 wei - 1 gwei)
            result.append(random.randint(100, 10**9))
        else:
            # Edge cases
            result.append(random.choice([0, 1, 10**9, 10**12]))
    return result


# =============================================================================
# Code Size/Limit Generators
# =============================================================================


def random_code_size(count: int) -> List[int]:
    """
    Generate random code sizes.

    Biased toward important limits like MAX_CODE_SIZE (24576).
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.3:
            # Small code (0-1024)
            result.append(random.randint(0, 1024))
        elif choice < 0.6:
            # Medium code (1024-10000)
            result.append(random.randint(1024, 10000))
        elif choice < 0.8:
            # Near max code size (20000-24576)
            result.append(random.randint(20000, 24576))
        else:
            # Edge cases around MAX_CODE_SIZE
            result.append(random.choice([0, 1, 24575, 24576, 24577, 49152]))
    return result


def random_initcode_size(count: int) -> List[int]:
    """
    Generate random initcode sizes.

    MAX_INITCODE_SIZE is 49152 (2 * MAX_CODE_SIZE) as of Shanghai.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.3:
            # Small initcode
            result.append(random.randint(0, 1024))
        elif choice < 0.6:
            # Medium initcode
            result.append(random.randint(1024, 24576))
        elif choice < 0.8:
            # Large initcode (near limit)
            result.append(random.randint(24576, 49152))
        else:
            # Edge cases
            result.append(random.choice([0, 1, 49151, 49152, 49153]))
    return result


# =============================================================================
# Call Depth Generator
# =============================================================================


def random_call_depth(count: int) -> List[int]:
    """
    Generate random call depths.

    EVM call depth limit is 1024.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.4:
            # Low depth (0-10)
            result.append(random.randint(0, 10))
        elif choice < 0.7:
            # Medium depth (10-100)
            result.append(random.randint(10, 100))
        elif choice < 0.9:
            # High depth (100-1024)
            result.append(random.randint(100, 1024))
        else:
            # Edge cases
            result.append(random.choice([0, 1, 1023, 1024, 1025]))
    return result


# =============================================================================
# Return Data Generators
# =============================================================================


def random_return_data(count: int, max_len: int = 256) -> List[bytes]:
    """Generate random return data."""
    result = [b""]  # Include empty return
    for _ in range(count - 1):
        length = random.randint(0, max_len)
        # Prefer 32-byte aligned lengths
        if random.random() < 0.5:
            length = (length // 32) * 32
        result.append(random.randbytes(length) if length > 0 else b"")
    return result


def random_revert_data(count: int) -> List[bytes]:
    """
    Generate random revert data.

    Includes empty, standard Error(string), and Panic(uint256) formats.
    """
    # Error(string) selector: 0x08c379a0
    # Panic(uint256) selector: 0x4e487b71
    result = [b""]  # Empty revert

    for _ in range(count - 1):
        choice = random.random()
        if choice < 0.3:
            # Empty or short revert
            result.append(random.randbytes(random.randint(0, 4)))
        elif choice < 0.6:
            # Error(string) format
            selector = bytes.fromhex("08c379a0")
            # Simplified: just random data after selector
            data = random.randbytes(random.randint(0, 128))
            result.append(selector + data)
        elif choice < 0.8:
            # Panic(uint256) format
            selector = bytes.fromhex("4e487b71")
            panic_code = random.randint(0, 0x51).to_bytes(32, "big")
            result.append(selector + panic_code)
        else:
            # Random revert data
            result.append(random.randbytes(random.randint(0, 256)))
    return result


# =============================================================================
# Chain ID Generator
# =============================================================================


def random_chain_id(count: int) -> List[int]:
    """
    Generate random chain IDs.

    Includes common chain IDs and random values.
    """
    common_chain_ids = [
        1,      # Ethereum Mainnet
        5,      # Goerli
        11155111,  # Sepolia
        137,    # Polygon
        42161,  # Arbitrum One
        10,     # Optimism
        8453,   # Base
    ]
    result = common_chain_ids[:min(count, len(common_chain_ids))]
    remaining = count - len(result)
    if remaining > 0:
        for _ in range(remaining):
            result.append(random.randint(1, 2**64 - 1))
    return result


# =============================================================================
# Difficulty/Prevrandao Generator
# =============================================================================


def random_difficulty(count: int) -> List[int]:
    """
    Generate random difficulty values (pre-merge).
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.5:
            # Typical difficulty range
            result.append(random.randint(10**12, 10**15))
        elif choice < 0.8:
            # High difficulty
            result.append(random.randint(10**15, 10**18))
        else:
            # Edge cases
            result.append(random.choice([0, 1, 2**64 - 1, 2**256 - 1]))
    return result


def random_prevrandao(count: int) -> List[int]:
    """
    Generate random prevrandao values (post-merge).

    Prevrandao is a 32-byte random value from the beacon chain.
    """
    return [random.randint(0, 2**256 - 1) for _ in range(count)]


# =============================================================================
# EIP-7702 Authorization Generators
# =============================================================================


def random_authorization_chain_id(count: int) -> List[int]:
    """Generate random chain IDs for EIP-7702 authorization tuples."""
    return random_chain_id(count)


def random_authorization_nonce(count: int) -> List[int]:
    """Generate random nonces for EIP-7702 authorization tuples."""
    return random_nonce(count)


# =============================================================================
# EOF (EVM Object Format) Generators
# =============================================================================


def random_eof_version(count: int) -> List[int]:
    """Generate EOF version numbers."""
    # Currently only version 1 is valid
    return [1] * count


def random_eof_code_section_count(count: int) -> List[int]:
    """
    Generate random number of code sections for EOF containers.

    Valid range is 1-1024.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.5:
            # Small number of sections (1-10)
            result.append(random.randint(1, 10))
        elif choice < 0.8:
            # Medium (10-100)
            result.append(random.randint(10, 100))
        else:
            # Edge cases
            result.append(random.choice([1, 2, 1023, 1024]))
    return result


def random_eof_max_stack_height(count: int) -> List[int]:
    """
    Generate random max stack heights for EOF code sections.

    Valid range is 0-1023.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.4:
            # Low stack (0-16)
            result.append(random.randint(0, 16))
        elif choice < 0.7:
            # Medium stack (16-256)
            result.append(random.randint(16, 256))
        elif choice < 0.9:
            # High stack (256-1023)
            result.append(random.randint(256, 1023))
        else:
            # Edge cases
            result.append(random.choice([0, 1, 1022, 1023]))
    return result


# =============================================================================
# BLS12-381 Precompile Generators (EIP-2537)
# =============================================================================


def random_bls12_g1_point(count: int) -> List[bytes]:
    """
    Generate random BLS12-381 G1 points.

    Format: x (64 bytes) + y (64 bytes) = 128 bytes
    Note: These are random bytes, not necessarily valid curve points.
    """
    result = []
    for _ in range(count):
        x = random.randbytes(64)
        y = random.randbytes(64)
        result.append(x + y)
    return result


def random_bls12_g2_point(count: int) -> List[bytes]:
    """
    Generate random BLS12-381 G2 points.

    Format: x (128 bytes) + y (128 bytes) = 256 bytes
    Note: These are random bytes, not necessarily valid curve points.
    """
    result = []
    for _ in range(count):
        x = random.randbytes(128)
        y = random.randbytes(128)
        result.append(x + y)
    return result


def random_bls12_scalar(count: int) -> List[bytes]:
    """
    Generate random BLS12-381 scalar values.

    Format: 32 bytes (256 bits)
    """
    return [random.randbytes(32) for _ in range(count)]


def random_bls12_fp(count: int) -> List[bytes]:
    """
    Generate random BLS12-381 field element (Fp).

    Format: 64 bytes (padded 381-bit field element)
    """
    return [random.randbytes(64) for _ in range(count)]


def random_bls12_fp2(count: int) -> List[bytes]:
    """
    Generate random BLS12-381 extension field element (Fp2).

    Format: 128 bytes (two Fp elements)
    """
    return [random.randbytes(128) for _ in range(count)]


# =============================================================================
# P256 (secp256r1) Precompile Generators (EIP-7212)
# =============================================================================


def random_p256_signature(count: int) -> List[bytes]:
    """
    Generate random P256 signature inputs.

    Format: message_hash (32) + r (32) + s (32) + x (32) + y (32) = 160 bytes
    """
    result = []
    for _ in range(count):
        msg_hash = random.randbytes(32)
        r = random.randbytes(32)
        s = random.randbytes(32)
        x = random.randbytes(32)
        y = random.randbytes(32)
        result.append(msg_hash + r + s + x + y)
    return result


# =============================================================================
# Jump Offset Generators (EOF)
# =============================================================================


def random_rjump_offset(count: int) -> List[int]:
    """
    Generate random relative jump offsets for EOF RJUMP/RJUMPI.

    Offsets are signed 16-bit integers (-32768 to 32767).
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.3:
            # Small positive offsets (common case)
            result.append(random.randint(0, 100))
        elif choice < 0.5:
            # Small negative offsets (backward jumps)
            result.append(random.randint(-100, -1))
        elif choice < 0.7:
            # Medium offsets
            result.append(random.randint(-1000, 1000))
        else:
            # Edge cases
            result.append(random.choice([0, 1, -1, 32767, -32768, 127, -128]))
    return result


def random_rjumpv_table_size(count: int) -> List[int]:
    """
    Generate random RJUMPV table sizes.

    Valid range is 1-256 entries.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.5:
            # Small tables (1-10)
            result.append(random.randint(1, 10))
        elif choice < 0.8:
            # Medium tables (10-100)
            result.append(random.randint(10, 100))
        else:
            # Edge cases
            result.append(random.choice([1, 2, 255, 256]))
    return result


# =============================================================================
# Function Section Generators (EOF)
# =============================================================================


def random_eof_inputs_outputs(count: int) -> List[Tuple[int, int]]:
    """
    Generate random (inputs, outputs) pairs for EOF function sections.

    Valid range: 0-127 for both inputs and outputs.
    """
    result = []
    for _ in range(count):
        choice = random.random()
        if choice < 0.4:
            # Common small values
            inputs = random.randint(0, 4)
            outputs = random.randint(0, 4)
        elif choice < 0.7:
            # Medium values
            inputs = random.randint(0, 16)
            outputs = random.randint(0, 16)
        else:
            # Edge cases
            inputs = random.choice([0, 1, 126, 127])
            outputs = random.choice([0, 1, 126, 127])
        result.append((inputs, outputs))
    return result


# =============================================================================
# Selector/Choice Generators
# =============================================================================


def random_opcode_from_list(opcodes: List[int], count: int) -> List[int]:
    """Select random opcodes from a provided list."""
    return [random.choice(opcodes) for _ in range(count)]


def random_choice(items: List[T], count: int) -> List[T]:
    """Select random items from a provided list."""
    return [random.choice(items) for _ in range(count)]


def random_subset(items: List[T], count: int, min_size: int = 0, max_size: Optional[int] = None) -> List[List[T]]:
    """
    Generate random subsets of a list.

    Args:
        items: List to select from
        count: Number of subsets to generate
        min_size: Minimum subset size
        max_size: Maximum subset size (defaults to len(items))
    """
    if max_size is None:
        max_size = len(items)
    result = []
    for _ in range(count):
        size = random.randint(min_size, max_size)
        subset = random.sample(items, min(size, len(items)))
        result.append(subset)
    return result


# =============================================================================
# Main Helper Functions
# =============================================================================


def get_fuzz_params(
    hardcoded: List[T],
    generator: Callable[[int], List[T]],
    count: Optional[int] = None,
) -> List[T]:
    """
    Get test parameters, combining hardcoded values with random values if fuzzing is enabled.

    Args:
        hardcoded: List of hardcoded edge-case values (filtered by FUZZ_MAX_INT if set)
        generator: Function that generates random values, takes count as argument
        count: Number of random values to generate (overrides FUZZ_COUNT if set)

    Returns:
        List of test parameter values

    Example:
        list_of_args = get_fuzz_params(
            hardcoded=[0, 1, 2, 0xFF, 0x100, 2**256-1],
            generator=random_uint256_biased,
        )
    """
    config = get_fuzz_config()

    if not config.enabled:
        return hardcoded

    actual_count = count if count is not None else config.count
    random_values = generator(actual_count)

    # Combine and deduplicate while preserving order
    seen = set()
    result = []

    # Filter hardcoded values by FUZZ_MAX_INT if set (only applies to integers)
    for v in hardcoded:
        # Skip integer values that exceed max_int cap
        if config.max_int is not None and isinstance(v, int):
            if v > config.max_int:
                continue
        key = v if isinstance(v, (int, str, bytes, bool)) else id(v)
        if key not in seen:
            seen.add(key)
            result.append(v)

    for v in random_values:
        key = v if isinstance(v, (int, str, bytes, bool)) else id(v)
        if key not in seen:
            seen.add(key)
            result.append(v)

    return result


def get_fuzz_combinations(
    hardcoded: List[T],
    generator: Callable[[int], List[T]],
    repeat: int = 2,
    count: Optional[int] = None,
) -> List[Tuple[T, ...]]:
    """
    Get combinations of test parameters for multi-argument tests.

    Args:
        hardcoded: List of hardcoded edge-case values
        generator: Function that generates random values
        repeat: Number of times to repeat for combinations (default: 2 for pairs)
        count: Number of random values to generate

    Returns:
        List of tuples representing all combinations

    Example:
        combinations = get_fuzz_combinations(
            hardcoded=[0, 1, 0xFF],
            generator=random_uint256_biased,
            repeat=2,
        )
        # Returns: [(0,0), (0,1), (0,0xFF), ..., (random1, random2), ...]
    """
    params = get_fuzz_params(hardcoded, generator, count)
    return list(itertools.product(params, repeat=repeat))


def get_fuzz_pairs(
    hardcoded_a: List[T],
    hardcoded_b: List[T],
    generator_a: Callable[[int], List[T]],
    generator_b: Callable[[int], List[T]],
    count: Optional[int] = None,
) -> List[Tuple[T, T]]:
    """
    Get pairs of test parameters from two different generators.

    Useful when testing two different types of parameters together.

    Example:
        pairs = get_fuzz_pairs(
            hardcoded_a=[0, 1],
            hardcoded_b=[21000, 100000],
            generator_a=random_uint256,
            generator_b=random_gas,
        )
    """
    params_a = get_fuzz_params(hardcoded_a, generator_a, count)
    params_b = get_fuzz_params(hardcoded_b, generator_b, count)
    return list(itertools.product(params_a, params_b))
