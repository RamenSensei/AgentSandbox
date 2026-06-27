"""A minimal in-process mock kernel: stdlib http.server implementing enough
of the AgentKernel HTTP API to exercise the client end to end."""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple


class MockKernelState:
    def __init__(self) -> None:
        self.counter = 0
        self.episodes: Dict[str, Dict[str, Any]] = {}
        self.branches: Dict[str, Dict[str, Any]] = {}
        self.effects: Dict[str, Dict[str, Any]] = {}
        self.receipts: Dict[str, Dict[str, Any]] = {}
        self.leases: Dict[str, Dict[str, Any]] = {}
        self.flaky_remaining = 0  # respond 503 this many times

    def next_id(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}-{self.counter}"
