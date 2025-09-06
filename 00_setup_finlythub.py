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
from typing import Any, Dict, Optional

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


def main():
    global SETTINGS_FILE  # declare early so default usage below is valid
    ap = argparse.ArgumentParser(description="Orchestrate FinlytHub detect + deploy/export flow.")
    ap.add_argument('--settings', default=SETTINGS_FILE, help='Path to settings.json (default: repo root).')
    ap.add_argument('--auto', action='store_true', help='Run detection (if needed) then auto deploy missing infra/export.')
    ap.add_argument('--force-detect', action='store_true', help='Force re-run detection even if settings exists.')
    ap.add_argument('--skip-detect', action='store_true', help='Skip detection phase (assume settings current).')
    ap.add_argument('--force-deploy', action='store_true', help='Force deploy even if focus export already exists.')
    ap.add_argument('--deploy-interactive', action='store_true', help='Enter deploy script interactive mode after detection.')
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

    if not args.auto and not args.deploy_interactive:
        _log('Nothing to do (specify --auto or --deploy-interactive).')
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
    if not analysis['eligible_for_export'] and not args.force_deploy and not args.deploy_interactive:
        _log('Environment not eligible for export setup (can_setup_exports.eligible_for_export = false). Use --force-deploy to override.')
        return 3

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
