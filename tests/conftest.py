"""
Root conftest.py for execution-spec-tests with randomization support.

This module provides pytest hooks and fixtures to enable randomized test
parameter generation for fuzzing purposes. All random value generators
are in tests/fuzzing_utils.py.

See RAND.md for full documentation.
"""

import os
import random
from typing import List

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add randomization command-line options to pytest."""
    random_group = parser.getgroup("Randomization", "Options for randomized test generation")
    random_group.addoption(
        "--random-seed",
        action="store",
        dest="random_seed",
        default=None,
        help=(
            "Seed for random number generation. "
            "Use 'random' for a random seed, or specify an integer for reproducibility. "
            "Default: None (no randomization, use hardcoded values)."
        ),
    )
    random_group.addoption(
        "--random-count",
        action="store",
        dest="random_count",
        default=10,
        type=int,
        help="Number of random values to generate per parameter. Default: 10.",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Configure randomization based on command-line options."""
    seed_option = config.getoption("random_seed")

    if seed_option is None:
        # Check environment variable as fallback
        env_seed = os.environ.get("FUZZ_SEED")
        if env_seed is not None:
            config._random_seed = int(env_seed)
            config._random_enabled = True
        else:
            config._random_seed = None
            config._random_enabled = False
    elif seed_option.lower() == "random":
        # Generate a random seed
        config._random_seed = random.randint(0, 2**32 - 1)
        config._random_enabled = True
    else:
        # Use the provided seed
        config._random_seed = int(seed_option)
        config._random_enabled = True

    if config._random_enabled:
        random.seed(config._random_seed)
        print(f"\n🎲 Randomization enabled with seed: {config._random_seed}")
        print(f"   To reproduce: --random-seed={config._random_seed}")
        print(f"   Or set: FUZZ_SEED={config._random_seed}\n")


def pytest_report_header(config: pytest.Config) -> List[str]:
    """Add randomization info to the pytest header."""
    if hasattr(config, "_random_enabled") and config._random_enabled:
        return [f"random seed: {config._random_seed}"]
    return []


# =============================================================================
# Pytest Fixtures for Randomization
# =============================================================================


@pytest.fixture
def random_seed(request: pytest.FixtureRequest) -> int | None:
    """Get the random seed for this test session."""
    config = request.config
    if hasattr(config, "_random_seed"):
        return config._random_seed
    return None


@pytest.fixture
def random_count(request: pytest.FixtureRequest) -> int:
    """Get the random count for this test session."""
    return request.config.getoption("random_count")
