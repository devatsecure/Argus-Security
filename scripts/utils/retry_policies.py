"""
Shared tenacity retry policies for LLM, HTTP, and subprocess calls.
Use these instead of defining retry logic inline for consistency and maintainability.
"""

import json
import subprocess
from tenacity import (
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# ---------------------------------------------------------------------------
# LLM / API (Connection, Timeout)
# ---------------------------------------------------------------------------

LLM_RETRY_EXCEPTIONS = (ConnectionError, TimeoutError)
LLM_STOP = stop_after_attempt(3)
LLM_WAIT = wait_exponential(multiplier=1, min=4, max=10)
LLM_RETRY = retry_if_exception_type(LLM_RETRY_EXCEPTIONS)

# ---------------------------------------------------------------------------
# HTTP / URL (URLError, HTTPError, ConnectionError, TimeoutError)
# ---------------------------------------------------------------------------

def get_http_retry_exceptions():
    import urllib.error
    return (urllib.error.URLError, urllib.error.HTTPError, ConnectionError, TimeoutError)

HTTP_STOP = stop_after_attempt(3)
HTTP_WAIT = wait_exponential(multiplier=1, min=2, max=60)

def http_retry_if():
    return retry_if_exception_type(get_http_retry_exceptions())

# ---------------------------------------------------------------------------
# Subprocess (SubprocessError, OSError, RuntimeError)
# ---------------------------------------------------------------------------

SUBPROCESS_RETRY_EXCEPTIONS = (subprocess.SubprocessError, OSError, RuntimeError)
SUBPROCESS_STOP = stop_after_attempt(3)
SUBPROCESS_WAIT = wait_exponential(multiplier=1, min=2, max=60)
SUBPROCESS_RETRY = retry_if_exception_type(SUBPROCESS_RETRY_EXCEPTIONS)

# Subprocess + JSON decode (e.g. supply chain scorecard)
SUBPROCESS_JSON_RETRY = retry_if_exception_type(
    (subprocess.SubprocessError, OSError, RuntimeError, json.JSONDecodeError)
)
