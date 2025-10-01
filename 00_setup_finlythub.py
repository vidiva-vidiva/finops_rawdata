#!/usr/bin/env python3
"""00_setup_finlythub.py

Lightweight orchestrator that wires together the detection phase (01) and the
deployment / export creation phase (02).

High-level flow (default / --auto):
 1. Ensure detection has been run (invoke 01_detect_finlythub.py if settings missing
    or --force-detect supplied).
 2. Load settings.json and evaluate readiness signals under
       settings.finlyt.cost_mgmt.can_setup_exports
    plus any existing exports listed under settings.finlyt.cm_exports.running.
 3. If FinlytHub infra (storage account) is missing OR no FOCUS export exists
    and environment is eligible, invoke deploy (02_deploy_finlythub.py) to:
       - (Optionally) deploy FinlytHub infra via Bicep (--use-bicep) when hub missing
       - Create a default FOCUS (Daily) export named 'finlyt_focus_daily'.
 4. Skip deployment when exports already present unless --force-deploy provided.

You can also:
  * --deploy-interactive : drop directly into 02's interactive flow after (optional) detection
  * --skip-detect        : assume settings.json already reflects current state
  * --dry-run            : print the action plan but do not execute deploy

Exit codes:
  0 success (or no-op)
  1 generic failure
  2 detection failed
  3 deploy preconditions not met

"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, Optional, List, Tuple
import json, os
from datetime import datetime, date, timedelta
import re
import requests

SETTINGS_FILE = os.getenv("SETTINGS_FILE", os.path.join(os.path.dirname(__file__), "settings.json"))  # legacy read-only
from settings_io import load_aggregated, update_recommended_scope, update_destination

# ----------------------- Virtual Environment Bootstrap -----------------------
def _in_venv() -> bool:
    return getattr(sys, 'real_prefix', None) is not None or sys.prefix != getattr(sys, 'base_prefix', sys.prefix)

def _venv_python_path(venv_dir: str) -> str:
    if os.name == 'nt':
        return os.path.join(venv_dir, 'Scripts', 'python.exe')
    return os.path.join(venv_dir, 'bin', 'python')

def maybe_bootstrap_venv(disable: bool = False):
    """Ensure a local .venv exists and re-exec inside it if not already.

    Behavior:
      * Skips if disable=True, already inside a venv, FINLYT_DISABLE_VENV=1, or FINLYT_VENV_BOOTSTRAPPED set.
      * Creates .venv using current interpreter.
      * Installs requirements.txt if present.
      * Re-execs the script using the venv's Python with FINLYT_VENV_BOOTSTRAPPED=1 to prevent loops.
    """
    if disable or os.getenv('FINLYT_DISABLE_VENV') == '1' or os.getenv('FINLYT_VENV_BOOTSTRAPPED') == '1':
        return
    base_dir = os.path.dirname(os.path.abspath(__file__))
    req_path = os.path.join(base_dir, 'requirements.txt')
    if _in_venv():
        # Already in a virtual environment; ensure deps if missing.
        if os.path.isfile(req_path):
            try:
                import importlib
                needed = False
                for test_mod in ("azure.identity","azure.mgmt.resource","azure.mgmt.storage","azure.storage.blob"):
                    try:
                        importlib.import_module(test_mod)
                    except Exception:
                        needed = True
                        break
                if needed:
                    _log("Detected missing Azure SDK modules; installing requirements into current venv...")
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', req_path])
            except Exception as ex:
                _log(f"Dependency installation skipped (non-fatal): {ex}")
        return
    venv_dir = os.path.join(base_dir, '.venv')
    py_in_venv = _venv_python_path(venv_dir)
    try:
        if not os.path.exists(venv_dir):
            _log("Creating virtual environment (.venv) ...")
            subprocess.check_call([sys.executable, '-m', 'venv', venv_dir])
        # Install requirements if available (fresh outer environment)
        if os.path.isfile(req_path):
            _log("Installing dependencies into .venv (requirements.txt)...")
            subprocess.check_call([py_in_venv, '-m', 'pip', 'install', '--upgrade', 'pip'])
            subprocess.check_call([py_in_venv, '-m', 'pip', 'install', '-r', req_path])
        else:
            _log("requirements.txt not found; skipping dependency install.")
        # Re-exec in venv
        env = os.environ.copy()
        env['FINLYT_VENV_BOOTSTRAPPED'] = '1'
        _log("Re-launching inside .venv ...")
        os.execvpe(py_in_venv, [py_in_venv] + sys.argv, env)
    except Exception as ex:
        _log(f"Virtual environment bootstrap skipped (non-fatal): {ex}")
        # Continue without venv


# ----------------------- Helpers -----------------------
def _log(msg: str):
    print(f"[Finlyt] {msg}")


def load_combined_settings() -> Dict[str, Any]:
    return load_aggregated()


def run_detection(python_exe: str = sys.executable, force: bool = False) -> bool:
    """Run 01_detect_finlythub.py if settings absent or force=True.
    Returns True on success / unchanged, False on failure."""
    need = force or (not os.path.exists(SETTINGS_FILE))
    if not need:
        _log("Detection skipped (settings already present; use --force-detect to re-run).")
        return True
    _log("Running detection (01_detect_finlythub.py)...")
    proc = subprocess.run([python_exe, "01_detect_finlythub.py"], capture_output=True, text=True)
    if proc.returncode != 0:
        # Testing fallback when azure SDK not present and FINLYT_TEST_MODE=1
        if os.getenv("FINLYT_TEST_MODE") == "1" and "ModuleNotFoundError" in (proc.stderr + proc.stdout):
            _log("Azure SDK missing; creating minimal split settings fallback (legacy write suppressed).")
            # Construct minimal split settings shapes
            from datetime import datetime
            now_iso = datetime.utcnow().isoformat() + 'Z'
            user_settings = {"observed": now_iso, "permissions": {}}
            finlyt_settings = {
                "observed": now_iso,
                "subscription": {"id": None, "location": "eastus"},
                "resource_group": {"name": None},
                "storage_account": {"id": None},
                "managed_identities": {},
                "exports_running": []
            }
            cm_export_settings = {
                "observed": now_iso,
                "finlyt": {
                    "can_setup_exports": {"eligible_for_export": True},
                    "recommended_export_scope": {"id": "/subscriptions/00000000-0000-0000-0000-000000000000"},
                    "recommended_destination": {"resource_id": None, "container": "cost", "root_path": "exports/focus"}
                },
                "nonfinlyt": {},
                "exports": {"finlyt": []}
            }
            # Local atomic writer
            def _aw(path, obj):
                try:
                    tmp = path + '.tmp'
                    with open(tmp,'w') as f:
                        json.dump(obj,f,indent=2)
                    os.replace(tmp,path)
                except Exception as ex:
                    _log(f"Failed to write {path}: {ex}")
            try:
                base_dir = os.path.dirname(__file__)
                _aw(os.getenv("USER_SETTINGS_FILE", os.path.join(base_dir, "user_settings.json")), user_settings)
                _aw(os.getenv("FINLYT_SETTINGS_FILE", os.path.join(base_dir, "finlyt_settings.json")), finlyt_settings)
                _aw(os.getenv("CM_EXPORT_SETTINGS_FILE", os.path.join(base_dir, "cm_export_settings.json")), cm_export_settings)
                _log("Wrote minimal split settings (test mode).")
                return True
            except Exception as e:
                _log(f"Failed to write minimal split settings: {e}")
                return False
        _log("Detection failed:")
        sys.stderr.write(proc.stdout + proc.stderr)
        return False
    _log("Detection complete.")
    return True


def _safe_get(d: Dict[str, Any], path: str, default=None):
    cur: Any = d
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def analyze_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    """Extract readiness signals and existing export state."""
    can_setup = _safe_get(settings, 'finlyt.cost_mgmt.can_setup_exports', {}) or {}
    exports_running = _safe_get(settings, 'finlyt.cm_exports.running', []) or []
    hub_sa_id = _safe_get(settings, 'finlyt.Storage_account.id')
    rec_scope_id = _safe_get(settings, 'finlyt.cost_mgmt.recommended_export_scope.id')
    dest_res_id = _safe_get(settings, 'finlyt.cost_mgmt.recommended_destination.resource_id') or hub_sa_id
    dest_container = _safe_get(settings, 'finlyt.cost_mgmt.recommended_destination.container') or 'cost'
    focus_export_exists = any((e.get('name') or '').startswith('finlyt_focus_') for e in exports_running if isinstance(e, dict))
    eligible = bool(can_setup.get('eligible_for_export'))
    return {
        'hub_present': bool(hub_sa_id),
        'focus_export_exists': focus_export_exists,
        'eligible_for_export': eligible,
        'recommended_scope_id': rec_scope_id,
        'dest_resource_id': dest_res_id,
        'dest_container': dest_container,
        'settings_subscription_id': _safe_get(settings, 'finlyt.subscription.id'),
        'settings_rg_name': _safe_get(settings, 'finlyt.resource_group.name'),
        'settings_location': _safe_get(settings, 'finlyt.subscription.location') or 'eastus',
    }


# build_deploy_command removed: non-interactive automation pruned


# ----------------------- Interactive Enhancements -----------------------
EXIT_TOKENS = {"q","quit","exit","x"}

def _prompt(msg: str, default: Optional[str] = None, allow_empty: bool = True) -> str:
    while True:
        raw = input(f"{msg}{' ['+default+']' if default else ''}: ").strip()
        if raw.lower() in EXIT_TOKENS:
            return "__EXIT__"
        if not raw and default is not None:
            raw = default
        if raw or allow_empty:
            return raw
        print(" Value required.")


def _menu(title: str, options: List[str]) -> int:
    print(f"\n{title} (type q to exit)")
    for i,o in enumerate(options,1):
        print(f" {i}. {o}")
    while True:
        sel = input("Enter choice #: ").strip()
        if sel.lower() in EXIT_TOKENS:
            return -1
        if sel.isdigit():
            idx = int(sel)
            if 1 <= idx <= len(options):
                return idx-1
        print(" Invalid selection.")


def _save_settings(path: str, settings: Dict[str, Any]):
    # Deprecated: legacy writes removed. Function retained for compatibility if invoked.
    _log("[deprecated] Ignored legacy settings write (split settings only).")


def _ensure_settings_struct(settings: Dict[str, Any]):
    settings.setdefault('finlyt', {})
    fin = settings['finlyt']
    fin.setdefault('cost_mgmt', {})
    fin['cost_mgmt'].setdefault('recommended_export_scope', {})
    fin['cost_mgmt'].setdefault('recommended_destination', {})
    fin.setdefault('cm_exports', {})
    fin['cm_exports'].setdefault('running', [])
    fin.setdefault('Storage_account', {})
    return settings


# interactive_first_time removed: always use interactive deploy script directly


def interactive_change_scope(settings: Dict[str,Any], path: str):
    settings = _ensure_settings_struct(settings)
    cur = _safe_get(settings,'finlyt.cost_mgmt.recommended_export_scope.id')
    print(f"Current recommended scope: {cur}")
    print("Enter a full ARM scope ID (subscription, resourceGroup, managementGroup or billing scopes). Examples:\n  /subscriptions/<sub>\n  /subscriptions/<sub>/resourceGroups/<rg>\n  /providers/Microsoft.Management/managementGroups/<mg>\n  /providers/Microsoft.Billing/billingAccounts/<ba>/billingProfiles/<bp>")
    new_scope = _prompt("New scope id", cur or "")
    if not new_scope:
        print("No change.")
        return
    settings['finlyt']['cost_mgmt']['recommended_export_scope']['id'] = new_scope
    try:
        update_recommended_scope(new_scope)
        _log("Updated recommended scope in split settings.")
    except Exception as ex:
        _log(f"Failed to update split scope: {ex}")


def interactive_change_destination(settings: Dict[str,Any], path: str):
    settings = _ensure_settings_struct(settings)
    dest = settings['finlyt']['cost_mgmt']['recommended_destination']
    cur_id = dest.get('resource_id') or _safe_get(settings,'finlyt.Storage_account.id')
    cur_cont = dest.get('container') or 'cost'
    cur_root = dest.get('root_path') or 'exports/focus'
    print(f"Current destination resourceId: {cur_id}")
    rid = _prompt("Storage account resourceId", cur_id or "")
    container = _prompt("Container name", cur_cont)
    root = _prompt("Root path (folder prefix)", cur_root)
    dest.update({'resource_id': rid, 'container': container, 'root_path': root})
    try:
        update_destination(rid, container, root)
        _log("Updated destination in split settings.")
    except Exception as ex:
        _log(f"Failed to update destination: {ex}")


def _month_iter(start: date, end: date):
    cur = date(start.year, start.month, 1)
    terminal = date(end.year, end.month, 1)
    while cur <= terminal:
        if cur.month == 12:
            nxt = date(cur.year+1,1,1)
        else:
            nxt = date(cur.year,cur.month+1,1)
        yield cur, (nxt - timedelta(days=1))
        cur = nxt


def _parse_month(s: str) -> date:
    s = s.strip()
    fmts = ["%Y-%m","%Y-%m-%d"]
    for f in fmts:
        try:
            d = datetime.strptime(s,f).date()
            return date(d.year,d.month,1)
        except Exception:
            continue
    raise ValueError("Invalid date; expected YYYY-MM or YYYY-MM-DD")


def _http_token(cred) -> str:
    # reuse existing detection of token through finlyt_common if available
    try:
        from finlyt_common import get_token
        return get_token(cred)
    except Exception:
        return ''


def _export_body(dataset_type: str, storage_rid: str, container: str, root: str, from_dt: str, to_dt: str, fmt: str, compression: Optional[str]) -> Dict[str,Any]:
    body = {
        "properties": {
            "definition": {
                "type": dataset_type,
                "timeframe": "Custom",
                "timePeriod": {"from": from_dt, "to": to_dt}
            },
            "deliveryInfo": {"destination": {"resourceId": storage_rid, "container": container, "rootFolderPath": root}},
            "format": fmt,
            "schedule": {"recurrence": "Monthly", "status": "Inactive", "recurrencePeriod": {"from": "2020-01-01T00:00:00Z","to": "2035-12-31T00:00:00Z"}}
        }
    }
    if compression:
        body['properties']['compressionMode'] = compression
    return body


def interactive_seed_historical(settings_path: str, settings: Dict[str,Any]):
    settings = _ensure_settings_struct(settings)
    scope_id = _safe_get(settings,'finlyt.cost_mgmt.recommended_export_scope.id')
    storage_rid = _safe_get(settings,'finlyt.cost_mgmt.recommended_destination.resource_id') or _safe_get(settings,'finlyt.Storage_account.id')
    if not scope_id or not storage_rid:
        _log("Scope or destination missing. Set them first.")
        return
    container_default = _safe_get(settings,'finlyt.cost_mgmt.recommended_destination.container') or 'cost'

    # Discover existing exports to infer preferred container/root per dataset & detect collisions
    existing_exports: Dict[str, Dict[str, Any]] = {}
    try:
        token = _http_token(None)
        if not token:
            from azure.identity import DefaultAzureCredential
            cred = DefaultAzureCredential()
            token = cred.get_token("https://management.azure.com/.default").token
        headers = {"Authorization": f"Bearer {token}"}
        list_url = f"https://management.azure.com/{scope_id}/providers/Microsoft.CostManagement/exports?api-version=2025-03-01"
        lr = requests.get(list_url, headers=headers, timeout=60)
        if lr.status_code == 200:
            for exp in (lr.json() or {}).get('value', []):
                name = exp.get('name') or ''
                props = exp.get('properties') or {}
                dest = (props.get('deliveryInfo') or {}).get('destination') or {}
                existing_exports[name] = { 'container': dest.get('container'), 'root': dest.get('rootFolderPath'), 'type': ((props.get('definition') or {}).get('type')) }
    except Exception:
        pass

    # Map dataset -> existing container/root if we find a standard export for it
    def infer_dataset_destination(ds: str) -> Tuple[str,str]:
        patterns = [f"finlyt_{ds.lower()}_daily", f"finlyt_{ds.lower()}_monthly", f"finlyt_{ds.lower()}_focus", f"finlyt_{ds.lower()}"]
        for p in patterns:
            if p in existing_exports:
                info = existing_exports[p]
                c = info.get('container') or container_default
                r = info.get('root') or ''
                return c, r
        # historical ones
        for name, info in existing_exports.items():
            if name.startswith(f"finlyt_hist_{ds.lower()}"):
                return info.get('container') or container_default, (info.get('root') or '')
        return container_default, ''

    datasets = ["FOCUS","ActualCost","AmortizedCost","Usage"]
    selected = []
    print("Select datasets (comma separated indices):")
    for i,d in enumerate(datasets,1):
        print(f" {i}. {d}")
    raw = _prompt("Choices", "1,2")
    for part in raw.split(','):
        part = part.strip()
        if part.isdigit():
            idx = int(part)-1
            if 0 <= idx < len(datasets):
                selected.append(datasets[idx])
    if not selected:
        _log("No datasets selected.")
        return
    start_m = _prompt("Start month (YYYY-MM)")
    end_m = _prompt("End month (YYYY-MM)")
    try:
        start = _parse_month(start_m)
        end = _parse_month(end_m)
    except ValueError as ex:
        _log(str(ex))
        return
    if end < start:
        _log("End month before start month.")
        return
    fmt = _prompt("Format (Csv|Parquet)", "Parquet")
    fmt = fmt.strip().lower().capitalize() if fmt else 'Parquet'
    if fmt not in ('Csv','Parquet'):
        _log("Invalid format; defaulting to Parquet")
        fmt = 'Parquet'
    compression = _prompt("Compression (None|Gzip|Snappy)", "Snappy" if fmt=='Parquet' else 'Gzip')
    compression = (compression or '').strip().capitalize()
    if compression.lower() == 'none':
        compression = None
    # Build initial inference map
    ds_dest_map: Dict[str, Tuple[str,str]] = {}
    for ds in selected:
        inf_c, inf_root = infer_dataset_destination(ds)
        base_root = inf_root or {
            'FOCUS':'exports/focus', 'ActualCost':'exports/actual', 'AmortizedCost':'exports/amortized', 'Usage':'exports/usage'
        }[ds]
        hist_root = f"{base_root.rstrip('/')}/historical"
        ds_dest_map[ds] = (inf_c, hist_root)

    # Per-dataset confirmation / override
    print("\nHistorical destination selection (per dataset). Press Enter to accept shown values.")
    for ds in selected:
        cur_c, cur_hist = ds_dest_map[ds]
        print(f"\n{ds} current suggestion:\n  container = {cur_c}\n  baseHistoricalRoot = {cur_hist}")
        if not _prompt("Accept suggestion? (Y/n)", "Y").lower().startswith('y'):
            new_c = _prompt("  Container", cur_c) or cur_c
            new_root = _prompt("  Base historical root (without year/month)", cur_hist) or cur_hist
            ds_dest_map[ds] = (new_c.strip() or cur_c, new_root.rstrip('/') or cur_hist)

    print("\nFinal historical destinations:")
    for ds,(c,hr) in ds_dest_map.items():
        print(f"  {ds}: container={c} baseHistoricalRoot={hr}")
    if not _prompt("Proceed with these destinations? (Y/n)", "Y").lower().startswith('y'):
        _log("Historical seeding cancelled.")
        return

    # Overlap detection: existing historical export names
    months = []
    cur = start
    while cur <= end:
        months.append(cur.strftime('%Y%m'))
        if cur.month == 12:
            cur = date(cur.year+1,1,1)
        else:
            cur = date(cur.year,cur.month+1,1)
    overlaps: Dict[str,List[str]] = {ds:[] for ds in selected}
    for name in existing_exports.keys():
        for ds in selected:
            for mm in months:
                if name == f"finlyt_hist_{ds.lower()}_{mm}":
                    overlaps[ds].append(mm)

    # Historical month presence now provided by detection (settings.finlyt.hub.historical.months)
    # Use detection-provided historical months from settings (if available) instead of live blob scan
    detected_hist = _safe_get(settings, 'finlyt.hub.historical.months', {}) or {}
    blob_overlaps: Dict[str,List[str]] = {ds:[] for ds in selected}
    for ds in selected:
        ds_key = ds.lower()
        existing_months = detected_hist.get(ds_key) or []
        for mm in months:
            if mm in existing_months:
                blob_overlaps[ds].append(mm)

    any_overlap = any(overlaps[ds] or blob_overlaps[ds] for ds in selected)
    skip_existing = True
    if any_overlap:
        print("\nExisting historical data detected:")
        for ds in selected:
            coll = set(overlaps[ds]) | set(blob_overlaps[ds])
            if coll:
                print(f"  {ds}: {', '.join(sorted(coll))}")
        while True:
            action = _prompt("Action? [S]kip existing / [O]verwrite / [N]ew base root / [C]ancel", "S").strip().lower() or 's'
            if action in ('s','o','n','c'):
                break
        if action == 'c':
            _log("Historical seeding cancelled.")
            return
        if action == 'o':
            skip_existing = False
        elif action == 'n':
            # Allow user to adjust base root per dataset then recompute overlaps once
            for ds in selected:
                c, hr = ds_dest_map[ds]
                new_hr = _prompt(f"New base root for {ds} (blank to keep {hr})", hr) or hr
                ds_dest_map[ds] = (c, new_hr.rstrip('/'))
            # (We do not re-check overlaps after changing root to keep logic simple.)
            skip_existing = True
            print("Using new base roots; existing months (previous roots) will not block seeding.")

    # Acquire token (reuse earlier if fetched)
    try:
        token = token if 'token' in locals() and token else _http_token(None)
    except Exception:
        token = None
    if not token:
        try:
            from azure.identity import DefaultAzureCredential
            cred = DefaultAzureCredential()
            token = cred.get_token("https://management.azure.com/.default").token
        except Exception:
            _log("Failed to get token.")
            return
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    dataset_api = { 'FOCUS':'FocusCost','ActualCost':'ActualCost','AmortizedCost':'AmortizedCost','Usage':'Usage' }
    for ds in selected:
        api_type = dataset_api[ds]
        ds_fmt = 'Csv' if api_type.startswith('Reservation') else fmt
        if ds_fmt == 'Csv' and compression == 'Snappy':
            eff_comp = 'Gzip'
        elif ds_fmt == 'Parquet' and compression == 'Gzip':
            eff_comp = 'Snappy'
        else:
            eff_comp = compression
        container, base_hist_root = ds_dest_map[ds]
        for m_start, m_end in _month_iter(start, end):
            yyyymm = m_start.strftime('%Y%m')
            export_name = f"finlyt_hist_{ds.lower()}_{yyyymm}"
            if skip_existing and export_name in existing_exports:
                _log(f" Skipping {export_name} (exists).")
                continue
            # Skip if blob-level exists under chosen root when skipping
            if skip_existing and yyyymm in blob_overlaps.get(ds, []):
                _log(f" Skipping {export_name} (detected blob data exists).")
                continue
            root = f"{base_hist_root.rstrip('/')}/{m_start.year}/{m_start.strftime('%m')}"
            body = _export_body(api_type, storage_rid, container, root,
                                f"{m_start.isoformat()}T00:00:00Z", f"{m_end.isoformat()}T23:59:59Z",
                                ds_fmt, eff_comp)
            put_url = f"https://management.azure.com/{scope_id}/providers/Microsoft.CostManagement/exports/{export_name}?api-version=2025-03-01"
            run_url = f"https://management.azure.com/{scope_id}/providers/Microsoft.CostManagement/exports/{export_name}/run?api-version=2025-03-01"
            try:
                r1 = requests.put(put_url, headers=headers, data=json.dumps(body), timeout=60)
                if r1.status_code not in (200,201):
                    _log(f" {export_name} create failed {r1.status_code}: {r1.text[:120]}")
                    continue
                r2 = requests.post(run_url, headers=headers, timeout=60)
                if r2.status_code not in (200,202):
                    _log(f" {export_name} run failed {r2.status_code}: {r2.text[:120]}")
                    continue
                _log(f" Seeded {ds} {yyyymm} -> container={container} root={root}")
            except Exception as ex:
                _log(f" {export_name} error: {ex}")
    _log("Historical seeding requests submitted.")


def interactive_add_exports(python_exe: str, settings_path: str):
    # Always materialize a fresh combined settings snapshot for the deploy script.
    try:
        combined = load_aggregated()
        combined_path = os.path.join(os.path.dirname(settings_path), '.finlyt_combined_settings.json')
        with open(combined_path, 'w', encoding='utf-8') as fh:
            json.dump(combined, fh, indent=2)
        use_settings_path = combined_path
    except Exception:
        # Fallback to original path (may be legacy or missing). Deploy script will attempt its own aggregation.
        use_settings_path = settings_path
    cmd = [python_exe, '02_deploy_finlythub.py']
    _log('Launching export creation (interactive)...')
    # Preflight dependency check so we can give a friendly message BEFORE entering wizard
    missing = []
    for mod in [
        'azure.identity', 'azure.mgmt.resource', 'azure.mgmt.storage', 'azure.storage.blob'
    ]:
        try:
            __import__(mod)
        except Exception:
            missing.append(mod)
    if missing:
        _log("Missing modules detected: " + ', '.join(missing))
        _log("Install with: pip install azure-identity azure-mgmt-resource azure-mgmt-storage azure-storage-blob")
        if not _prompt("Continue anyway? (y/N)", "N").lower().startswith('y'):
            _log("Aborting interactive export wizard due to missing dependencies.")
            return
    try:
        # Use subprocess.call so the child inherits the TTY allowing user interaction.
        rc = subprocess.call(cmd)
        if rc != 0:
            _log(f"Interactive deploy script exited with code {rc}.")
            _log("If it exited immediately, ensure Azure credentials are available and required SDK packages are installed.")
    except Exception as ex:
        _log(f"Failed to start interactive deploy: {ex}")


def interactive_cleanup(python_exe: str):
    _log('Launching cleanup (03_cleanup_finlythub.py)...')
    subprocess.run([python_exe, '03_cleanup_finlythub.py'])


def manage_menu(args):
    """Management actions for an existing installation."""
    while True:
        try:
            settings = load_combined_settings()
        except Exception:
            settings = {}
        choice = _menu("Select a repair/management action", [
            "Add or modify exports",
            "Change recommended scope",
            "Change export destination",
            "Seed historical datasets",
            "Cleanup (remove exports/resources)",
            "Exit"
        ])
        if choice == -1 or choice == 5:
            _log("Leaving repair menu.")
            break
        if choice == 0:
            interactive_add_exports(sys.executable, SETTINGS_FILE)
        elif choice == 1:
            interactive_change_scope(settings, SETTINGS_FILE)
        elif choice == 2:
            interactive_change_destination(settings, SETTINGS_FILE)
        elif choice == 3:
            interactive_seed_historical(SETTINGS_FILE, settings)
        elif choice == 4:
            interactive_cleanup(sys.executable)


def _extract_sa_name(resource_id: Optional[str]) -> Optional[str]:
    if not resource_id or not isinstance(resource_id,str):
        return None
    m = re.search(r"/storageAccounts/([^/]+)", resource_id, re.IGNORECASE)
    return m.group(1) if m else None

def _summarize_environment(analysis: Dict[str,Any]):
    print("\n----- Finlyt Hub Detected -----")
    print(f"Scope: {analysis.get('recommended_scope_id') or '-'}")
    print(f"Subscription Id: {analysis.get('settings_subscription_id') or '-'}")
    print(f"Resource Group: {analysis.get('settings_rg_name') or '-'}")
    print(f"Location: {analysis.get('settings_location') or '-'}")
    sa_name = _extract_sa_name(analysis.get('dest_resource_id')) if analysis.get('dest_resource_id') else '-'  # may be None
    print(f"Storage Account: {sa_name or '-'}")
    # Permissions / scope readiness summary
    eligible = analysis.get('eligible_for_export')
    if eligible:
        print("CM Export Permission: User appears ELIGIBLE for scheduling exports")
    else:
        print("CM Export Permission: User NOT eligible (can_setup_exports.eligible_for_export=false)")

def root_menu(args):
    """Top-level menu (Install or Repair). Always uses interactive deploy for Install."""
    while True:
        if sys.stdout.isatty():
            hdr = "Finlyt Setup"
            line = '=' * len(hdr)
            print(f"\n\033[36m{line}\n{hdr}\n{line}\033[0m")
        choice = _menu("Finlyt Setup", [
            "Install Finlyt (interactive)",
            "Repair / Manage Finlyt",
            "Exit"
        ])
        if choice == -1 or choice == 2:
            _log("Exit.")
            return
        # Force detection every loop to ensure fresh state
        if not run_detection(force=True):
            _log("Detection failed; cannot continue.")
            return
        try:
            settings = load_combined_settings()
        except Exception:
            settings = {}
        analysis = analyze_settings(settings) if settings else {
            'hub_present': False,'focus_export_exists': False,'eligible_for_export': True,
            'recommended_scope_id': None,'dest_resource_id': None,'dest_container': 'cost',
            'settings_subscription_id': None,'settings_rg_name': None,'settings_location': 'eastus'
        }
        _summarize_environment(analysis)
        if choice == 0:  # Always interactive deploy
            cmd = [sys.executable, '02_deploy_finlythub.py']
            _log('Launching interactive deploy: ' + ' '.join(cmd))
            rc = subprocess.call(cmd)
            if rc != 0:
                _log(f'Interactive deploy failed (exit {rc}).')
            else:
                _log('Interactive deploy completed.')
        elif choice == 1:  # Repair / Manage
            _log('Entering repair / management menu. (Press Ctrl+C to exit at any time)')
            manage_menu(args)



def main():
    global SETTINGS_FILE
    ap = argparse.ArgumentParser(description="FinlytHub interactive setup / management.")
    ap.add_argument('--settings', default=SETTINGS_FILE, help='Path to settings.json (default: repo root).')
    ap.add_argument('--cleanup', action='store_true', help='Launch cleanup directly and exit.')
    ap.add_argument('--no-venv', action='store_true', help='Disable automatic .venv creation / re-exec.')
    args = ap.parse_args()
    SETTINGS_FILE = args.settings

    # Auto-bootstrap virtual environment early (may re-exec and never return here in first pass)
    maybe_bootstrap_venv(disable=args.no_venv)

    if args.cleanup:
        _log('Launching interactive cleanup (03_cleanup_finlythub.py)...')
        rc = subprocess.call([sys.executable, '03_cleanup_finlythub.py'])
        return rc

    # Pure interactive menu flow
    root_menu(args)
    return 0


if __name__ == '__main__':
    try:
        rc = main()
        sys.exit(rc)
    except KeyboardInterrupt:
        _log('Interrupted.')
        sys.exit(1)
