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
from datetime import datetime, date, timedelta
import re
import requests

SETTINGS_FILE = os.getenv("SETTINGS_FILE", os.path.join(os.path.dirname(__file__), "settings.json"))


# ----------------------- Helpers -----------------------
def _log(msg: str):
    print(f"[orchestrator] {msg}")


def load_settings(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return json.load(f)


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
            _log("Azure SDK missing; creating minimal test settings.json fallback.")
            minimal = {
                "finlyt": {
                    "subscription": {"id": None, "location": "eastus"},
                    "resource_group": {"name": None},
                    "Storage_account": {"id": None},
                    "cost_mgmt": {
                        "can_setup_exports": {"eligible_for_export": True},
                        "recommended_export_scope": {"id": "/subscriptions/00000000-0000-0000-0000-000000000000"},
                        "recommended_destination": {"resource_id": None, "container": "cost", "root_path": "exports/focus"}
                    },
                    "cm_exports": {"running": []}
                }
            }
            try:
                with open(SETTINGS_FILE, 'w') as f:
                    json.dump(minimal, f, indent=2)
                _log("Wrote minimal test settings.")
                return True
            except Exception as e:
                _log(f"Failed to write minimal settings: {e}")
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


def build_deploy_command(analysis: Dict[str, Any], args) -> Optional[list[str]]:
    """Return the command list to invoke deploy (02) or None if no-op."""
    # If interactive requested, ignore auto logic
    if args.deploy_interactive:
        return [sys.executable, '02_deploy_finlythub.py', '--interactive', '--settings', SETTINGS_FILE]

    # Auto logic
    need_infra = not analysis['hub_present']
    need_focus_export = (not analysis['focus_export_exists']) or args.force_deploy

    if not need_infra and not need_focus_export:
        return None  # no action

    export_name = args.export_name or 'finlyt_focus_daily'
    scope_id = args.scope_id or analysis['recommended_scope_id']
    if not scope_id:
        # If we lack a recommended scope but have a subscription id, fallback to subscription scope
        sub_id = analysis['settings_subscription_id']
        if sub_id:
            scope_id = f"/subscriptions/{sub_id}"
    if not scope_id:
        raise RuntimeError('Unable to determine export scope id (supply --scope-id).')

    cmd = [sys.executable, '02_deploy_finlythub.py', '--settings', SETTINGS_FILE,
           '--export-name', export_name, '--dataset', 'FOCUS', '--recurrence', 'Daily', '--timeframe', 'MTD', '--format', 'Parquet']

    if need_infra:
        # Need to deploy hub infra via Bicep.
        sub_id = args.dest_subscription_id or analysis['settings_subscription_id']
        if not sub_id:
            raise RuntimeError('No subscription id available for infra deployment (pass --dest-subscription-id).')
        rg_name = args.dest_rg or analysis['settings_rg_name']
        if not rg_name:
            # Derive deterministic RG if missing
            rg_name = f"rg-finlythub-{sub_id[:8]}"
        location = args.dest_location or analysis['settings_location']
        cmd.extend(['--use-bicep', '--dest-subscription-id', sub_id, '--dest-rg', rg_name, '--dest-location', location])
    else:
        # Existing hub; pass destination pieces only if user overrides; else rely on settings inference inside deploy script.
        if args.dest_subscription_id:  # user explicit override
            cmd.extend(['--dest-subscription-id', args.dest_subscription_id])
        if args.dest_rg:
            cmd.extend(['--dest-rg', args.dest_rg])
        if args.dest_sa:
            cmd.extend(['--dest-sa', args.dest_sa])
        if args.dest_container:
            cmd.extend(['--dest-container', args.dest_container])
        if args.dest_root:
            cmd.extend(['--dest-root', args.dest_root])

    # Scope args (explicit scope-id wins)
    cmd.extend(['--scope-id', scope_id])

    if args.extra_deploy_args:
        # naive split; users can quote if needed
        cmd.extend(args.extra_deploy_args.split())
    return cmd


# ----------------------- Interactive Enhancements -----------------------
def _prompt(msg: str, default: Optional[str] = None, allow_empty: bool = True) -> str:
    while True:
        raw = input(f"{msg}{' ['+default+']' if default else ''}: ").strip()
        if not raw and default is not None:
            raw = default
        if raw or allow_empty:
            return raw
        print(" Value required.")


def _menu(title: str, options: List[str]) -> int:
    print(f"\n{title}")
    for i,o in enumerate(options,1):
        print(f" {i}. {o}")
    while True:
        sel = input("Enter choice #: ").strip()
        if sel.isdigit():
            idx = int(sel)
            if 1 <= idx <= len(options):
                return idx-1
        print(" Invalid selection.")


def _save_settings(path: str, settings: Dict[str, Any]):
    try:
        with open(path,'w') as f:
            json.dump(settings,f,indent=2)
        _log(f"Settings updated -> {path}")
    except Exception as ex:
        _log(f"Failed to save settings: {ex}")


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


def interactive_first_time(set_path: str, python_exe: str, analysis: Dict[str,Any], args) -> None:
    _log("First-time setup selected.")
    # Run detection (force) if hub not present or settings minimal
    if not analysis['hub_present'] or not os.path.exists(set_path):
        if not run_detection(force=True):
            _log("Detection failed; aborting first-time setup.")
            return
        try:
            settings = load_settings(set_path)
            analysis.update(analyze_settings(settings))
        except Exception:
            pass
    # Build and run deploy command (focus daily) irrespective of eligibility when user confirms
    confirm = _prompt("Proceed with deploying FinlytHub infra/FOCUS export now? (y/N)", "N").lower().startswith('y')
    if not confirm:
        _log("First-time setup aborted by user.")
        return
    class Dummy: pass
    dummy = Dummy()
    # mimic argparse Namespace for needed attributes
    for k in ['deploy_interactive','force_deploy','dest_subscription_id','dest_rg','dest_location','dest_sa','dest_container','dest_root','export_name','scope_id','extra_deploy_args']:
        setattr(dummy,k,getattr(args,k,None))
    dummy.force_deploy = True  # ensure creation even if eligibility false
    cmd = build_deploy_command(analysis, dummy)
    if not cmd:
        _log("Nothing to deploy (already present).")
        return
    _log('Executing: ' + ' '.join(cmd))
    subprocess.run(cmd)
    _log("First-time setup complete.")


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
    _save_settings(path, settings)


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
    _save_settings(path, settings)


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
    cmd = [python_exe, '02_deploy_finlythub.py', '--interactive', '--settings', settings_path]
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
            settings = load_settings(SETTINGS_FILE)
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
        else:
            _log("Leaving repair menu.")
            break


def root_menu(args):
    """Top-level menu presented when no flags supplied.
    Options: Install Finlyt (first-time) or Repair Finlyt (manage existing).
    Both paths force detection to refresh settings.json first."""
    while True:
        choice = _menu("Finlyt Setup", [
            "Install Finlyt (first-time setup)",
            "Repair / Manage Finlyt",
            "Exit"
        ])
        if choice == 2:
            _log("Exit.")
            return
        # Always refresh settings (force detection) before action
        if not run_detection(force=True):
            _log("Detection failed; cannot continue.")
            return
        try:
            settings = load_settings(SETTINGS_FILE)
        except Exception:
            settings = {}
        analysis = analyze_settings(settings) if settings else {
            'hub_present': False,'focus_export_exists': False,'eligible_for_export': True,
            'recommended_scope_id': None,'dest_resource_id': None,'dest_container': 'cost',
            'settings_subscription_id': None,'settings_rg_name': None,'settings_location': 'eastus'
        }
        if choice == 0:  # Install
            _log('Current state (post-detection): ' + json.dumps({k:v for k,v in analysis.items() if k not in ('dest_resource_id',)}, indent=2))
            # Allow user to choose interactive wizard vs quick (auto) install
            if _prompt("Use interactive deployment wizard? (Y/n)", "Y").lower().startswith('y'):
                # Delegate fully to deploy script interactive mode (handles infra + exports + historical prompt)
                cmd = [sys.executable, '02_deploy_finlythub.py', '--interactive', '--settings', SETTINGS_FILE]
                _log('Launching interactive deploy: ' + ' '.join(cmd))
                rc = subprocess.call(cmd)
                if rc != 0:
                    _log(f'Interactive deploy failed (exit {rc}).')
                else:
                    _log('Interactive deploy completed.')
            else:
                _log('Proceeding with quick install (non-interactive).')
                class Dummy: pass
                dummy = Dummy()
                for k in ['deploy_interactive','force_deploy','dest_subscription_id','dest_rg','dest_location','dest_sa','dest_container','dest_root','export_name','scope_id','extra_deploy_args']:
                    setattr(dummy,k,getattr(args,k,None))
                dummy.force_deploy = True
                cmd = build_deploy_command(analysis, dummy)
                if not cmd:
                    _log('Finlyt appears already installed (hub + focus export).')
                else:
                    _log('Executing install: ' + ' '.join(cmd))
                    rc = subprocess.call(cmd)
                    if rc != 0:
                        _log(f'Install deploy failed (exit {rc}).')
                    else:
                        _log('Install completed.')
        elif choice == 1:  # Repair / Manage
            _log('Entering repair / management menu.')
            manage_menu(args)
        # Loop again after action to allow multiple operations



def main():
    global SETTINGS_FILE  # declare early so default usage below is valid
    ap = argparse.ArgumentParser(description="Orchestrate FinlytHub detect + deploy/export flow.")
    ap.add_argument('--settings', default=SETTINGS_FILE, help='Path to settings.json (default: repo root).')
    ap.add_argument('--auto', action='store_true', help='Run detection (if needed) then auto deploy missing infra/export.')
    ap.add_argument('--force-detect', action='store_true', help='Force re-run detection even if settings exists.')
    ap.add_argument('--skip-detect', action='store_true', help='Skip detection phase (assume settings current).')
    ap.add_argument('--force-deploy', action='store_true', help='Force deploy even if focus export already exists.')
    ap.add_argument('--deploy-interactive', action='store_true', help='Enter deploy script interactive mode after detection.')
    ap.add_argument('--cleanup', action='store_true', help='Run interactive cleanup (exports + tagged resources) after detection and skip deploy logic.')
    ap.add_argument('--dry-run', action='store_true', help='Show actions without executing deploy.')
    ap.add_argument('--export-name', help='Override export name (default finlyt_focus_daily)')
    ap.add_argument('--scope-id', help='Override scope id (else use recommended or subscription).')
    ap.add_argument('--extra-deploy-args', help='Additional raw args appended to deploy command.')
    # Infra override options (useful when hub missing)
    ap.add_argument('--dest-subscription-id')
    ap.add_argument('--dest-rg')
    ap.add_argument('--dest-location')
    ap.add_argument('--dest-sa')
    ap.add_argument('--dest-container')
    ap.add_argument('--dest-root')
    args = ap.parse_args()

    # Rebind module-level SETTINGS_FILE to user-specified path (allowed)
    SETTINGS_FILE = args.settings

    if args.auto or args.deploy_interactive or args.cleanup:
        pass  # proceed with legacy flow
    else:
        # Root interactive menu (Install / Repair)
        root_menu(args)
        return 0

    # 1. Detection (unless skipped)
    if not args.skip_detect:
        if not run_detection(force=args.force_detect):
            return 2
    else:
        _log('Detection skipped by --skip-detect.')

    if not os.path.exists(SETTINGS_FILE):
        _log(f'Settings file not found after detection step: {SETTINGS_FILE}')
        return 2

    # 2. Analyze settings
    try:
        settings = load_settings(SETTINGS_FILE)
    except Exception as e:
        _log(f'Failed to read settings: {e}')
        return 2
    analysis = analyze_settings(settings)
    _log('Analysis: ' + json.dumps({k: v for k, v in analysis.items() if k not in ('dest_resource_id',)}, indent=2))

    # If not eligible and no hub present, abort unless user forces
    if not analysis['eligible_for_export'] and not args.force_deploy and not args.deploy_interactive and not args.cleanup:
        _log('Environment not eligible for export setup (can_setup_exports.eligible_for_export = false). Use --force-deploy to override.')
        return 3

    # Cleanup mode shortcut
    if args.cleanup:
        _log('Launching interactive cleanup (03_cleanup_finlythub.py)...')
        import subprocess as _sp
        rc2 = _sp.call([sys.executable, '03_cleanup_finlythub.py'])
        return rc2

    # 3. Build deploy command
    try:
        deploy_cmd = build_deploy_command(analysis, args)
    except Exception as e:
        _log(f'Cannot build deploy command: {e}')
        return 3

    if not deploy_cmd:
        _log('No deployment action required (infra + export already in place).')
        return 0

    _log('Planned deploy command: \n  ' + ' '.join(deploy_cmd))

    if args.dry_run:
        _log('--dry-run specified; exiting without execution.')
        return 0

    # 4. Execute deploy
    _log('Executing deploy (02_deploy_finlythub.py)...')
    proc = subprocess.run(deploy_cmd, text=True)
    if proc.returncode != 0:
        _log(f'Deploy command failed with exit code {proc.returncode}.')
        return proc.returncode or 1
    _log('Deploy/export phase complete.')
    return 0


if __name__ == '__main__':
    try:
        rc = main()
        sys.exit(rc)
    except KeyboardInterrupt:
        _log('Interrupted.')
        sys.exit(1)
