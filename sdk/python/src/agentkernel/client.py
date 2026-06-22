"""HTTP client for the AgentKernel Execution Protocol (JSON binding).

Zero runtime dependencies: transport is stdlib ``urllib``. An alternative
transport (e.g. httpx) can be injected via the ``transport`` argument —
any callable ``(method, url, body_json_or_none, headers) -> (status, body_bytes)``.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .errors import DenialError, KernelError, TransportError
from .types import (
    ActionKind,
    Branch,
    BranchComparison,
    BranchDiff,
    CapabilityLease,
    Denial,
    EffectContract,
    EffectPreview,
    Episode,
    Json,
    PendingEffect,
    Receipt,
    ResourceBudget,
    StepResult,
)
