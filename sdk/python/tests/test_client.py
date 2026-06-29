"""End-to-end tests for the agentkernel client against a mock kernel.

Runnable with either:
    python3 -m unittest discover sdk/python
    python3 -m pytest sdk/python
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from agentkernel import (  # noqa: E402
    ConnectorOp,
    DenialError,
    EffectContract,
    Kernel,
    KernelError,
    Shell,
)
from mock_kernel import make_server  # noqa: E402
