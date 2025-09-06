# cli_setup/finlyt_common.py
import os
import json
import shutil
import subprocess
import random
import time
from datetime import datetime, timezone
from typing import Optional, Any, Dict, Iterable

UTC = timezone.utc
RETRYABLE = {429, 500, 502, 503, 504}

def run_cmd(cmd: Iterable[str], *, check: bool = True, capture: bool = False, env: dict | None = None):
    """
    Run a shell command with nice logging.
    - If capture=True: returns stdout (str) and prints it.
    - If capture=False: prints output to the terminal and returns "".
    Raises CalledProcessError when check=True and the command fails.
    """
    cmd = list(cmd)
    print(f"\n$ {' '.join(cmd)}")
    proc = subprocess.run(
        cmd,
        check=check,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        text=True,
        env=env or os.environ.copy(),
    )
    if capture:
        print(proc.stdout or "")
        return proc.stdout
    return ""

def az_exists() -> bool:
    """Return True if Azure CLI is on PATH."""
    return shutil.which("az") is not None

def compile_bicep_to_json(bicep_path: str, out_json_path: Optional[str] = None) -> str:
    """
    Compile a Bicep file to JSON template.
    Tries: (1) `az bicep build` then (2) `bicep build`.
    Returns the absolute path to the compiled JSON template.
    """
    import os
    bicep_path = os.path.abspath(bicep_path)
    if not out_json_path:
        root, _ = os.path.splitext(bicep_path)
        out_json_path = root + ".json"
    out_json_path = os.path.abspath(out_json_path)

    try:
        run_cmd(["az", "bicep", "build", "--file", bicep_path, "--outfile", out_json_path], check=True)
        if os.path.exists(out_json_path):
            print(f"[bicep] Compiled via Azure CLI -> {out_json_path}")
            return out_json_path
    except Exception as ex:
        print(f"[bicep] az bicep failed; will try 'bicep build': {ex}")

    run_cmd(["bicep", "build", bicep_path, "--outfile", out_json_path], check=True)
    if not os.path.exists(out_json_path):
        raise RuntimeError("Bicep compile failed; outfile missing.")
    print(f"[bicep] Compiled via bicep CLI -> {out_json_path}")
    return out_json_path

def http_with_backoff(func, url, *, headers=None, params=None, json_body=None, data=None,
                      timeout: float = 60.0, max_retries: int = 5,
                      base_delay: float = 0.5, max_delay: float = 8.0, verbose: bool = False):
    """
    Generic HTTP wrapper with exponential backoff on retryable codes.
    Accepts requests.<method> `func` and returns the final Response or None.
    """
    attempt = 0
    while True:
        try:
            r = func(url, headers=headers, params=params, json=json_body, data=data, timeout=timeout)
        except Exception:
            r = None

        # Return on success or non-retryable status
        code = getattr(r, "status_code", 599)
        if r is not None and code not in RETRYABLE:
            return r
        if attempt >= max_retries:
            return r

        # Honor Retry-After or retry-after-ms when present
        delay = None
        if r is not None:
            ra = r.headers.get("Retry-After") or r.headers.get("retry-after-ms")
            if ra:
                try:
                    if isinstance(ra, str) and ("ms" in ra.lower()):
                        digits = "".join(ch for ch in ra if (ch.isdigit() or ch == "."))
                        delay = float(digits) / 1000.0
                    else:
                        delay = float(ra)
                except Exception:
                    delay = None

        if delay is None:
            delay = min(max_delay, base_delay * (2 ** attempt)) + random.uniform(0, 0.25)
        if verbose:
            print(f"[retry] {code} -> sleep {delay:.2f}s (attempt {attempt+1}/{max_retries})")
        time.sleep(delay)
        attempt += 1

def get_token(cred) -> str:
    """Obtain an ARM audience bearer token using the provided Azure Identity credential."""
    return cred.get_token("https://management.azure.com/.default").token


def sanitize_storage_account_name(name: str) -> str:
    """
    Produce a valid Azure storage account name from an input string.
    Rules enforced: lowercase letters and numbers only, 3-24 chars.
    If resulting name is shorter than 3 chars, pad with 'st0'. If empty, return 'st' + 6 hex digits.
    """
    import re, hashlib
    if not isinstance(name, str):
        name = str(name or "")
    n = name.lower()
    # keep only a-z0-9
    n = re.sub(r'[^a-z0-9]', '', n)
    if not n:
        # deterministic fallback using hash of original name
        digest = hashlib.sha1(name.encode() if isinstance(name, str) else str(name).encode()).hexdigest()[:6]
        n = f"st{digest}"
    # ensure within 3..24
    if len(n) < 3:
        n = (n + 'st0st0')[:3]
    if len(n) > 24:
        n = n[:24]
    return n