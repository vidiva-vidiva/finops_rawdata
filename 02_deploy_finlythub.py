#!/usr/bin/env python3
# 02_deploy_finlythub.py
# Deploys FinlytHub (storage + containers + UAMI) by compiling Bicep in-script,
# computing unique names per subscription, running an incremental deployment,
# gating on preflight checks, reading outputs, and assigning RBAC to the UAMI.
"""
deploy.py - Settings-aware deploy that can (optionally) Bicep-deploy FinlytHub
and then create/update a Cost Management export at any supported scope.

Scopes supported by Exports API (2025-03-01):
  /subscriptions/{subId}
  /subscriptions/{subId}/resourceGroups/{rg}
  /providers/Microsoft.Management/managementGroups/{mgId}
  /providers/Microsoft.Billing/billingAccounts/{baId}
  /providers/Microsoft.Billing/billingAccounts/{baId}/billingProfiles/{bpId}
  /providers/Microsoft.Billing/billingAccounts/{baId}/billingProfiles/{bpId}/invoiceSections/{isId}
(Partners: customers/{customerId})
Docs: https://learn.microsoft.com/rest/api/cost-management/exports/create-or-update?view=rest-cost-management-2025-03-01
"""

import os
import sys
import json
import uuid
import argparse
import hashlib
from datetime import datetime, timezone, timedelta, date
from typing import Dict, Any, Optional
from finlyt_common import run_cmd, compile_bicep_to_json, http_with_backoff, get_token

import requests
import subprocess
import time
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient

# ---------- Constants ----------
SETTINGS_FILE = os.getenv("SETTINGS_FILE", "settings.json")
USER_SETTINGS_FILE = os.getenv("USER_SETTINGS_FILE", "user_settings.json")
FINLYT_SETTINGS_FILE = os.getenv("FINLYT_SETTINGS_FILE", "finlyt_settings.json")
CM_EXPORT_SETTINGS_FILE = os.getenv("CM_EXPORT_SETTINGS_FILE", "cm_export_settings.json")
UTC = timezone.utc
EXPORTS_API = "2025-03-01"   # Exports API version
RETRYABLE = {429, 500, 502, 503, 504}

from settings_io import update_exports  # shared settings writer (no legacy writes)

# ---------- Infra (SDK) ----------
def ensure_rg(cred, subscription_id: str, rg_name: str, location: str, tags: dict | None = None):
    """Ensure resource group exists and is tagged.
    Merges existing tags with supplied tags (supplied wins on key conflict)."""
    rm = ResourceManagementClient(cred, subscription_id)
    existing_tags = {}
    try:
        rg = rm.resource_groups.get(rg_name)
        existing_tags = getattr(rg, 'tags', {}) or {}
    except Exception:
        existing_tags = {}
    merged = existing_tags.copy()
    if tags:
        merged.update(tags)
    body = {"location": location}
    if merged:
        body["tags"] = merged
    rm.resource_groups.create_or_update(rg_name, body)

def ensure_sa(cred, subscription_id: str, rg_name: str, sa_name: str, location: str, sku: str = "Standard_LRS"):
    sm = StorageManagementClient(cred, subscription_id)
    try:
        sm.storage_accounts.get_properties(rg_name, sa_name)
        return
    except Exception:
        pass
    poller = sm.storage_accounts.begin_create(
        rg_name, sa_name,
        {"sku": {"name": sku}, "kind": "StorageV2", "location": location, "enable_https_traffic_only": True}
    )
    poller.result()

def is_storage_account_name_available(cred, subscription_id: str, name: str) -> tuple[bool, str | None]:
    """Check global availability of a storage account name. Returns (available, reason)."""
    try:
        sm = StorageManagementClient(cred, subscription_id)
        resp = sm.storage_accounts.check_name_availability({"name": name, "type": "Microsoft.Storage/storageAccounts"})
        return (bool(getattr(resp, 'name_available', False)), getattr(resp, 'message', None))
    except Exception as ex:
        return (True, f"check_name_availability_failed: {ex}")

def ensure_container(cred, sa_name: str, container: str):
    blob = BlobServiceClient(f"https://{sa_name}.blob.core.windows.net", credential=cred)
    cc = blob.get_container_client(container)
    try:
        cc.get_container_properties()
    except Exception:
        cc.create_container()

def deploy_finlythub_via_bicep(cred, subscription_id: str, rg_name: str, bicep_path: str,
                               hub_name: str, mi_name: str, location: str, tags: Dict[str, str]) -> Dict[str, Any]:
    """
    Uses 'az deployment group create' for simplicity to deploy the compiled template.
    You can replace with SDK-based ARM deployment if you prefer.
    """
    # Ensure RG exists first
    ensure_rg(cred, subscription_id, rg_name, location, tags)

    # Always (re)compile Bicep AFTER RG confirmation to avoid stale template or path issues
    def _recompile_bicep(src: str) -> str:
        base, _ = os.path.splitext(src)
        out_path = base + ".deploy.json"
        try:
            # Prefer direct az bicep build to guarantee fresh output
            cmd = ["az","bicep","build","--file", src, "--outfile", out_path]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise RuntimeError(f"bicep build failed: {proc.stderr or proc.stdout}")
            print(f"[bicep] Recompiled {src} -> {out_path}")
            return out_path
        except Exception as ex:
            # Fallback to existing helper if direct build fails
            from finlyt_common import compile_bicep_to_json
            print(f"[bicep] Direct build failed ({ex}); falling back to compile_bicep_to_json helper.")
            return compile_bicep_to_json(src)

    template_json = _recompile_bicep(bicep_path)

    # CLI group deployment (keeps parity with your current approach)
    cmd = [
        "az", "deployment", "group", "create",
        "--subscription", subscription_id,
        "--resource-group", rg_name,
        "--template-file", template_json,
        "--parameters",
            f"hubName={hub_name}",
            f"miName={mi_name}",
            f"location={location}",
            f"deploymentTimestamp={datetime.now(UTC).isoformat()}",
            f"tags={json.dumps(tags)}"
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=os.environ.copy())
    log_path = f"./deploy_{hub_name}_{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}.log"
    # Always persist logs (even on success) if AZURE_FINLYT_DEBUG env var is set
    if proc.returncode != 0 or os.getenv('AZURE_FINLYT_DEBUG'):
        try:
            with open(log_path, 'w') as lf:
                lf.write('COMMAND: ' + ' '.join(cmd) + '\n')
                lf.write('\nSTDOUT:\n' + (proc.stdout or ''))
                lf.write('\n\nSTDERR:\n' + (proc.stderr or ''))
        except Exception:
            pass
    if proc.returncode != 0:
        combined = (proc.stderr or '')
        if proc.stdout:
            combined += "\n[stdout]\n" + proc.stdout
        lower = combined.lower()
        hint = ''
        if 'authorizationfailed' in lower:
            hint = '\nHint: Ensure you have at least Contributor on the resource group and subscription.'
        elif 'invalidparameter' in lower:
            hint = '\nHint: Validate parameter values (hubName uniqueness, location spelling).'
        elif 'storageaccountalreadytaken' in lower or 'anotherobjectwiththesamename' in lower:
            hint = '\nHint: Storage account name already in use globally. Pick a different hub name.'
        elif 'not found' in lower and 'resource group' in lower:
            hint = '\nHint: Resource group creation may have failed; check permissions.'
        # Fallback to SDK if specific consumption error appears
        if 'the content for this response was already consumed' in lower or 'already consumed' in lower:
            try:
                from azure.mgmt.resource import ResourceManagementClient
                with open(template_json,'r') as tf:
                    template_doc = json.load(tf)
                rm = ResourceManagementClient(cred, subscription_id)
                params = {
                    'hubName': {'value': hub_name},
                    'miName': {'value': mi_name},
                    'location': {'value': location},
                    'deploymentTimestamp': {'value': datetime.now(UTC).isoformat()},
                    'tags': {'value': tags}
                }
                print("[fallback] Retrying deployment via SDK (ARM) due to CLI response consumption error.")
                poller = rm.deployments.begin_create_or_update(
                    rg_name,
                    f"finlythub-{hub_name}",
                    {"properties": {"mode": "Incremental", "template": template_doc, "parameters": params}}
                )
                dep_result = poller.result()
                try:
                    outputs = getattr(dep_result.properties, 'outputs', {}) or {}
                except Exception:
                    outputs = {}
                return {
                    "resource_id": outputs.get("storageAccountId", {}).get("value") or
                                   f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Storage/storageAccounts/{hub_name}",
                    "storage_account_name": outputs.get("storageAccountName", {}).get("value") or hub_name,
                    "uami": {
                        "id": outputs.get("uamiId", {}).get("value"),
                        "principal_id": outputs.get("uamiPrincipalId", {}).get("value"),
                        "client_id": outputs.get("uamiClientId", {}).get("value")
                    },
                    "containers": {
                        "daily": outputs.get("dailyContainerName", {}).get("value") or "daily",
                        "monthly": outputs.get("monthlyContainerName", {}).get("value") or "monthly",
                        "reservation": outputs.get("reservationContainerName", {}).get("value") or "reservation"
                    }
                }
            except Exception as sdk_ex:
                raise RuntimeError(f"Bicep deployment failed (exit {proc.returncode}) and SDK fallback failed: {sdk_ex}\nSee {log_path}\n{combined}{hint}")
        raise RuntimeError(f"Bicep deployment failed (exit {proc.returncode})\nLog: {log_path}\n{combined}{hint}")

    try:
        body = json.loads(proc.stdout)
    except Exception:
        body = {}

    # Parse outputs
    outputs = (body.get("properties", {}) or {}).get("outputs", {}) or {}
    return {
        "resource_id": outputs.get("storageAccountId", {}).get("value") or
                       f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Storage/storageAccounts/{hub_name}",
        "storage_account_name": outputs.get("storageAccountName", {}).get("value") or hub_name,
        "uami": {
            "id": outputs.get("uamiId", {}).get("value"),
            "principal_id": outputs.get("uamiPrincipalId", {}).get("value"),
            "client_id": outputs.get("uamiClientId", {}).get("value")
        },
        "containers": {
            "daily": outputs.get("dailyContainerName", {}).get("value") or "daily",
            "monthly": outputs.get("monthlyContainerName", {}).get("value") or "monthly",
            "reservation": outputs.get("reservationContainerName", {}).get("value") or "reservation"
        }
    }

# ---------- Exports ----------
def create_or_update_export(cred, scope_id: str, export_name: str, export_body: Dict[str, Any]) -> Dict[str, Any]:
    from finlyt_common import get_token
    token = get_token(cred)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = (f"https://management.azure.com/{scope_id}"
           f"/providers/Microsoft.CostManagement/exports/{export_name}?api-version={EXPORTS_API}")
    r = http_with_backoff(requests.put, url, headers=headers, json_body=export_body, timeout=120)
    if r is None or r.status_code not in (200, 201):
        raise RuntimeError(f"CreateOrUpdate failed: HTTP {getattr(r,'status_code',None)} {getattr(r,'text','')[:400]}")
    return r.json() or {}

def build_export_body(dataset: str, recurrence: str, dest_resource_id: str,
                      container: str, root: str, fmt: str,
                      timeframe: str = "Custom",
                      from_date: Optional[str] = None, to_date: Optional[str] = None,
                      compression: Optional[str] = None, overwrite: bool = False,
                      schedule_status: str = "Active") -> Dict[str, Any]:
    """
    Builds request body for Exports Create/Update (2025-03-01).
    Supports all documented timeframe enums. Only includes timePeriod when timeframe=='Custom'.
    """
    dtype = "FocusCost" if dataset.lower() == "focus" else dataset

    # Accept both shorthand and full enum
    tf_map = {
        "MTD": "MonthToDate",
        "Custom": "Custom",
        "MonthToDate": "MonthToDate",
        "BillingMonthToDate": "BillingMonthToDate",
        "TheLastMonth": "TheLastMonth",
        "TheLastBillingMonth": "TheLastBillingMonth",
        "WeekToDate": "WeekToDate",
        "TheCurrentMonth": "TheCurrentMonth",
    }
    timeframe_value = tf_map.get(timeframe, timeframe or "Custom")

    # API requires timeframe=Custom only when schedule.status == Inactive (per 2025-03-01 validation observed).
    # Allow caller to explicitly set schedule_status to 'Inactive' for one-off historical month runs.
    if timeframe_value == 'Custom' and schedule_status != 'Inactive':
        # Defensive adjustment to avoid 400 validation error when caller forgets.
        schedule_status = 'Inactive'

    props: Dict[str, Any] = {
        "definition": {
            "type": dtype,
            "timeframe": timeframe_value
        },
        "deliveryInfo": {
            "destination": {
                "resourceId": dest_resource_id,
                "container": container,
                "rootFolderPath": root or ""
            }
        },
        "schedule": {
            "recurrence": recurrence,
            "status": schedule_status,
            "recurrencePeriod": {
                "from": "2020-01-01T00:00:00Z",
                "to": "2035-12-31T00:00:00Z"
            }
        }
    }
    # Only include timePeriod when using Custom
    if timeframe_value == "Custom":
        tp_from = from_date or datetime.now(UTC).strftime("%Y-%m-%d")
        tp_to = to_date or datetime.now(UTC).strftime("%Y-%m-%d")
        props["definition"]["timePeriod"] = {"from": tp_from, "to": tp_to}

    # Always include format when provided (FOCUS needs it too)
    if fmt:
        props["format"] = fmt
    if compression:
        props["compressionMode"] = compression  # Gzip | Snappy
    if overwrite:
        props["dataOverwriteBehavior"] = "OverwritePreviousReport"
    return {"properties": props}


def run_export(cred, scope_id: str, export_name: str) -> None:
    """Trigger an on-demand run of an existing export definition."""
    token = get_token(cred)
    headers = {"Authorization": f"Bearer {token}"}
    url = (f"https://management.azure.com/{scope_id}"
           f"/providers/Microsoft.CostManagement/exports/{export_name}/run?api-version={EXPORTS_API}")
    r = http_with_backoff(requests.post, url, headers=headers, timeout=60)
    if r is None or r.status_code not in (200, 202):
        raise RuntimeError(f"Run export failed: HTTP {getattr(r,'status_code',None)} {getattr(r,'text','')[:300]}")


def _month_iter(start: date, end: date):
    """Yield (month_start_date, month_end_date) inclusive for each calendar month in range."""
    cur = date(start.year, start.month, 1)
    terminal = date(end.year, end.month, 1)
    while cur <= terminal:
        if cur.month == 12:
            nxt = date(cur.year + 1, 1, 1)
        else:
            nxt = date(cur.year, cur.month + 1, 1)
        last = nxt - timedelta(days=1)
        yield cur, last
        cur = nxt


def _parse_ym(s: str) -> date:
    """Accept YYYY-MM or YYYY-MM-DD; return normalized first-of-month date."""
    s = (s or '').strip()
    fmts = ["%Y-%m", "%Y-%m-%d"]
    for f in fmts:
        try:
            d = datetime.strptime(s, f).date()
            return date(d.year, d.month, 1)
        except Exception:
            continue
    raise ValueError(f"Invalid date format: {s} (expected YYYY-MM or YYYY-MM-DD)")


def seed_historical_cost_datasets(cred, scope_id: str, datasets: list[str], *,
                                  export_dest_resource_id: str,
                                  storage_account_name: str,
                                  containers: dict,
                                  dataset_api_type: dict,
                                  default_roots: dict,
                                  start_month: str, end_month: str,
                                  fmt_choice: str, compression_choice: str) -> None:
    """Seed historical cost data by creating + running month-sliced Custom exports.

    Folder structure: <root>/historical/<YYYY>/<MM>
    Export name pattern: finlyt_hist_<dataset>_<yyyymm>
    Creates/updates export definitions (idempotent) then immediately triggers a run.
    """
    try:
        start = _parse_ym(start_month)
        end = _parse_ym(end_month)
    except ValueError as ex:
        print(f" Historical seeding skipped: {ex}")
        return
    if end < start:
        print(" Historical seeding skipped: end before start.")
        return

    monthly_container = containers.get('monthly') or 'monthly'
    # Derive effective compression (reuse logic from interactive flow)
    def _effective(fmt: str, comp: str | None):
        if not comp or comp == 'None':
            return None
        if fmt == 'Csv' and comp == 'Snappy':
            return 'Gzip'
        if fmt == 'Parquet' and comp == 'Gzip':
            return 'Snappy'
        return comp
    base_comp = _effective(fmt_choice, compression_choice)

    print("\n[historical] Seeding months from", start.strftime('%Y-%m'), "to", end.strftime('%Y-%m'))

    # Overlap detection (blob-based) to prompt user
    try:
        blob_client = BlobServiceClient(f"https://{storage_account_name}.blob.core.windows.net", credential=cred)
    except Exception:
        blob_client = None

    def _month_code(d: date) -> str:
        return d.strftime('%Y%m')

    requested_months = []
    cur_chk = start
    while cur_chk <= end:
        requested_months.append(_month_code(cur_chk))
        if cur_chk.month == 12:
            cur_chk = date(cur_chk.year+1,1,1)
        else:
            cur_chk = date(cur_chk.year,cur_chk.month+1,1)

    existing_by_ds: dict[str,set[str]] = {ds:set() for ds in datasets}
    if blob_client:
        monthly_container = containers.get('monthly') or 'monthly'
        for ds in datasets:
            root_base = default_roots.get(ds, 'exports')
            for code in requested_months:
                y = code[:4]; m = code[4:]
                prefix = f"{root_base.rstrip('/')}/historical/{y}/{m}/"
                try:
                    cont = blob_client.get_container_client(monthly_container)
                    gen = cont.list_blobs(name_starts_with=prefix)
                    if any(True for _ in gen):
                        existing_by_ds[ds].add(code)
                except Exception:
                    pass

    overlaps_exist = any(existing_by_ds[ds] for ds in datasets)
    action = 's'
    if overlaps_exist:
        print("[historical] Existing data detected:")
        for ds in datasets:
            if existing_by_ds[ds]:
                print(f"  {ds}: {', '.join(sorted(existing_by_ds[ds]))}")
        while True:
            action = input("Action for existing months? [S]kip / [O]verwrite / [C]ancel (default S): ").strip().lower() or 's'
            if action in ('s','o','c'):
                break
        if action == 'c':
            print("[historical] Cancelled.")
            return

    hist_overwrite = (action == 'o')

    manifest_entries: list[dict] = []
    manifest_start = datetime.utcnow().isoformat()
    for ds in datasets:
        api_type = dataset_api_type.get(ds, ds)
        ds_fmt = 'Csv' if api_type.startswith('Reservation') else fmt_choice
        ds_comp = None if ds_fmt == 'Csv' and api_type.startswith('Reservation') else base_comp
        root_base = default_roots.get(ds, 'exports')
        for m_start, m_end in _month_iter(start, end):
            yyyymm = m_start.strftime('%Y%m')
            export_name = f"finlyt_hist_{ds.lower()}_{yyyymm}"
            root_path = f"{root_base.rstrip('/')}/historical/{m_start.year}/{m_start.strftime('%m')}"
            body = build_export_body(
                dataset=api_type,
                recurrence="Monthly",  # schedule metadata required but not meaningful for custom slice
                dest_resource_id=export_dest_resource_id,
                container=monthly_container,
                root=root_path,
                fmt=ds_fmt,
                timeframe="Custom",
                from_date=f"{m_start.isoformat()}T00:00:00Z",
                to_date=f"{m_end.isoformat()}T23:59:59Z",
                compression=ds_comp,
                overwrite=False
            )
            try:
                create_or_update_export(cred, scope_id, export_name, body)
                run_export(cred, scope_id, export_name)
                print(f"  {ds} {yyyymm}: submitted -> container={monthly_container} path={root_path}")
            except Exception as ex:
                print(f"  WARN {ds} {yyyymm}: {ex}")
            time.sleep(1.0)  # light pacing to reduce throttling risk
    print("[historical] Historical export runs queued. Files appear as runs complete.")


# ---------- Settings helpers ----------
def load_settings(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return json.load(f)

def suggest_defaults_from_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    rec_scope = ((settings.get("finlyt", {}) or {}).get("cost_mgmt", {}) or {}).get("recommended_export_scope", {})
    rec_dest  = ((settings.get("finlyt", {}) or {}).get("cost_mgmt", {}) or {}).get("recommended_destination", {})
    sa = (settings.get("finlyt", {}) or {}).get("Storage_account", {}) or {}
    return {
        "scope_id": rec_scope.get("id"),
        "dest_resource_id": rec_dest.get("resource_id") or sa.get("id"),
        "dest_container": rec_dest.get("container") or "cost",
        "dest_root": rec_dest.get("root_path") or "exports/focus"
    }

 # ---------- Interactive Flow ----------
def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1].strip()
    return s

EXIT_TOKENS = {"q","quit","exit","x"}

def _prompt(msg: str, default: str | None = None) -> str:
    try:
        raw = input(f"{msg}{' ['+default+']' if default else ''}: ").strip()
    except EOFError:
        return _strip_quotes(default or '')
    if raw.lower() in EXIT_TOKENS:
        return "__EXIT__"
    val = raw or (default or '')
    return _strip_quotes(val)

def _choose(msg: str, options: list[str], default_index: int | None = None) -> str:
    print(msg)
    for i, o in enumerate(options, 1):
        print(f" {i}. {o}")
    while True:
        raw = _prompt("Enter choice", str(default_index+1) if default_index is not None else None)
        if raw == "__EXIT__":
            print("Exit requested.")
            sys.exit(0)
        try:
            idx = int(raw)
            if 1 <= idx <= len(options):
                return options[idx-1]
        except Exception:
            pass
        print("Invalid choice. Try again.")


def _multiselect(msg: str, options: list[str], default_indices: list[int] | None = None) -> list[str]:
    """
    Console multiselect: prints numbered options and accepts comma-separated indices.
    Returns the list of chosen option strings. Re-prompts on invalid input.
    """
    print(msg)
    for i, o in enumerate(options, 1):
        print(f" {i}. {o}")
    default_indices = default_indices or []
    default_str = ",".join(str(i+1) for i in default_indices) if default_indices else None
    while True:
        raw = _prompt("Select one or more (comma-separated)", default_str)
        if raw == "__EXIT__":
            print("Exit requested.")
            sys.exit(0)
        parts = [p.strip() for p in (raw or "").split(",") if p.strip()]
        try:
            idxs = sorted({int(p)-1 for p in parts}) if parts else (default_indices or [])
            if not idxs:
                raise ValueError
            if any(i < 0 or i >= len(options) for i in idxs):
                raise ValueError
            return [options[i] for i in idxs]
        except Exception:
            print("Invalid selection. Use numbers like 1,2,3 from the list above.")

def _parse_scope_id(scope_id: str) -> dict:
     """Return {'type': <...>, pieces...} from an ARM scope id."""
     s = (scope_id or "").strip()
     out = {"type": None}
     if not s:
         return out
     # Normalize double slashes etc.
     parts = [p for p in s.split('/') if p]
     try:
         if parts[0] == 'subscriptions':
             out["type"] = "subscription"
             out["subscription"] = parts[1]
             # resourceGroup path
             if len(parts) >= 4 and parts[2] == 'resourceGroups':
                 out["type"] = "resourceGroup"
                 out["resourceGroup"] = parts[3]
         elif parts[0] == 'providers' and parts[1] == 'Microsoft.Management' and parts[2] == 'managementGroups':
             out["type"] = "managementGroup"
             out["managementGroup"] = parts[3]
         elif parts[0] == 'providers' and parts[1] == 'Microsoft.Billing' and parts[2] == 'billingAccounts':
             out["billingAccount"] = parts[3]
             if len(parts) >= 6 and parts[4] == 'billingProfiles':
                 out["type"] = "billingProfile"
                 out["billingProfile"] = parts[5]
                 if len(parts) >= 8 and parts[6] == 'invoiceSections':
                     out["type"] = "invoiceSection"
                     out["invoiceSection"] = parts[7]
             else:
                 out["type"] = "billingAccount"
     except Exception:
         pass
     return out

def get_timeframes_for_scope(scope_id: str) -> dict:
    """
    Returns a dict of {Daily: <timeframe>, Monthly: <timeframe>}
    that matches the allowed values for the given scope type.
    """
    parsed = _parse_scope_id(scope_id)
    stype = parsed.get("type")

    if stype in ("billingAccount", "billingProfile", "invoiceSection"):
        return {"Daily": "MonthToDate", "Monthly": "TheLastMonth"}
    else:
        return {"Daily": "MonthToDate", "Monthly": "TheLastMonth"}

def _parse_storage_account_id(resource_id: str) -> dict:
     """
     Parse a Storage Account ARM ID into {subscription, resourceGroup, name}.
     /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}
     """
     out = {}
     if not resource_id:
         return out
     parts = [p for p in resource_id.split('/') if p]
     try:
         if parts[0] == 'subscriptions' and parts[2] == 'resourceGroups' and parts[4] == 'providers' and parts[5] == 'Microsoft.Storage' and parts[6] == 'storageAccounts':
             out["subscription"] = parts[1]
             out["resourceGroup"] = parts[3]
             out["name"] = parts[7]
     except Exception:
         pass
     return out

def interactive_flow(cred, settings):
    """
    Minimal interactive: user selects SCOPE and DATASETS only.
    Destination (RG/SA/container/export names) comes entirely from Bicep/settings.
    """
    # --- UI helpers ---
    class UI:
        ENABLE = sys.stdout.isatty()
        @staticmethod
        def c(code: str) -> str:
            if not UI.ENABLE:
                return ''
            return f"\033[{code}m"
        BOLD = lambda: UI.c('1')
        DIM = lambda: UI.c('2')
        GREEN = lambda: UI.c('32')
        CYAN = lambda: UI.c('36')
        YELLOW = lambda: UI.c('33')
        RED = lambda: UI.c('31')
        RESET = lambda: UI.c('0')
        @staticmethod
        def banner(text: str):
            line = '=' * len(text)
            print(f"{UI.CYAN()}{line}\n{text}\n{line}{UI.RESET()}")
        @staticmethod
        def step(n: int, msg: str):
            print(f"{UI.BOLD()}{UI.CYAN()}[Step {n}]{UI.RESET()} {msg}")

    UI.banner('Finlyt Export Interactive Wizard (type q to exit)')
    print(f"{UI.DIM()}Press Ctrl+C or type 'q' anytime to abort. Values in [] show defaults. Enter to accept.{UI.RESET()}")
    # 1) Determine scope (prefer recommendation)
    seeded = suggest_defaults_from_settings(settings)
    rec_scope_id = (seeded or {}).get("scope_id")
    def _scope_exists(cred, scope_id: str) -> bool:
        token = get_token(cred)
        headers = {"Authorization": f"Bearer {token}"}
        url = f"https://management.azure.com/{scope_id}/providers/Microsoft.CostManagement/exports?api-version={EXPORTS_API}"
        r = http_with_backoff(requests.get, url, headers=headers, timeout=30)
        return r is not None and r.status_code in (200,204,401,403)

    UI.step(1, 'Select export scope')
    if rec_scope_id and _scope_exists(cred, rec_scope_id):
        print(f"Detected recommended export scope: {UI.BOLD()}{rec_scope_id}{UI.RESET()}")
        ans_use = _prompt("Use recommended scope? (Y/n)", "Y")
        if ans_use == "__EXIT__":
            print("Exit requested.")
            return
        if ans_use.lower().startswith('y'):
            scope_id = rec_scope_id
        else:
            scope_id = None
    else:
        scope_id = None

    if not scope_id:
        # guided builder for scope id with validation & recommendations
        options = ["subscription","resourceGroup","managementGroup","billingAccount","billingProfile","invoiceSection"]
        scope_type = _choose("\nSelect a scope to create/update cost management exports:", options, 0)

        # Parse recommended scope into components for suggestion
        rec_parsed = _parse_scope_id(rec_scope_id) if rec_scope_id else {}

        import re

        # Gather fallback IDs from settings
        fallback_sub_ids = []
        fallback_mg_ids: list[str] = []
        fallback_ba_ids: list[str] = []
        fallback_bp_ids: list[str] = []  # format ba/profile
        fallback_inv_ids: list[str] = [] # format ba/profile/invoice
        try:
            fin_sub = (settings.get('finlyt', {}) or {}).get('subscription', {}) or {}
            if fin_sub.get('id'):
                fallback_sub_ids.append(fin_sub.get('id'))
            hub = (settings.get('finlyt', {}) or {}).get('hub', {}) or {}
            if hub.get('subscription_id') and hub.get('subscription_id') not in fallback_sub_ids:
                fallback_sub_ids.append(hub.get('subscription_id'))
            # Management groups (assignment summary list) if present
            assignments = (settings.get('finlyt', {}) or {}).get('cost_mgmt', {}) or {}
            # Pull from any structure if available later (placeholder)
            # Billing accounts / profiles / invoice sections from settings['billing'] assignments summary
            billing = settings.get('billing', {}) or {}
            # For detailed fallback we inspect 'accounts' only; profiles & invoice sections aren't stored there
            # but we have recommended scope id which may embed them.
            if billing.get('accounts'):
                for a in billing.get('accounts') or []:
                    if a and a.get('id') and a.get('id') not in fallback_ba_ids:
                        fallback_ba_ids.append(a.get('id'))
            # Derive bp/invoice from recommended scope if present (split path segments)
            if rec_scope_id and 'billingAccounts' in rec_scope_id:
                parts = [p for p in rec_scope_id.split('/') if p]
                try:
                    ba_idx = parts.index('billingAccounts')+1 if 'billingAccounts' in parts else None
                    if ba_idx and ba_idx < len(parts):
                        ba_name = parts[ba_idx]
                        if ba_name and ba_name not in fallback_ba_ids:
                            fallback_ba_ids.append(ba_name)
                    if 'billingProfiles' in parts:
                        bp_idx = parts.index('billingProfiles')+1
                        if bp_idx < len(parts):
                            bp_name = parts[bp_idx]
                            ba_name = fallback_ba_ids[0] if fallback_ba_ids else None
                            if ba_name and bp_name:
                                combo = f"{ba_name}/{bp_name}"
                                if combo not in fallback_bp_ids:
                                    fallback_bp_ids.append(combo)
                    if 'invoiceSections' in parts:
                        inv_idx = parts.index('invoiceSections')+1
                        if inv_idx < len(parts):
                            inv_name = parts[inv_idx]
                            # Need ba/profile
                            if fallback_bp_ids:
                                prefix = fallback_bp_ids[0]
                                full = f"{prefix}/{inv_name}"
                                if full not in fallback_inv_ids:
                                    fallback_inv_ids.append(full)
                except Exception:
                    pass
        except Exception:
            pass

        def _validate_component(label: str, value: str, recommended: str | None) -> str:
            """Validate a scope component. If invalid offer recommended or fallback list; allow one retry then abort."""
            def _is_valid(lbl: str, val: str) -> bool:
                if lbl.startswith('Subscription'):
                    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", val))
                if lbl.startswith('Resource group'):
                    return bool(re.fullmatch(r"[-\w\._()]{1,90}", val)) and not val.endswith('.')
                return bool(val)
            attempt = 0
            current = value
            while True:
                if _is_valid(label, current):
                    if recommended and current != recommended:
                        print(f"Note: using {label.lower()} '{current}' (differs from settings '{recommended}').")
                    return current
                attempt += 1
                if attempt == 1:
                    if recommended:
                        print(f"Invalid {label.lower()} '{current}'. Recommended from settings: {recommended}")
                        if _prompt(f"Use recommended {label.lower()}? (Y/n)", "Y").lower().startswith('y'):
                            current = recommended
                            continue
                    def _select_from_list(title: str, items: list[str]) -> str | None:
                        if not items:
                            return None
                        print(title)
                        for i, v in enumerate(items, 1):
                            print(f"  {i}. {v}")
                        choose_local = _prompt("Select number to use or press Enter to type manually")
                        if choose_local.isdigit():
                            idx2 = int(choose_local)-1
                            if 0 <= idx2 < len(items):
                                return items[idx2]
                        return None
                    if label.startswith('Subscription'):
                        sel = _select_from_list("Available subscription IDs from settings:", fallback_sub_ids)
                        if sel:
                            current = sel
                            continue
                    elif label.startswith('Management group'):
                        sel = _select_from_list("Available management group IDs from settings:", fallback_mg_ids)
                        if sel:
                            current = sel
                            continue
                    elif label.startswith('Billing account'):
                        sel = _select_from_list("Available billing account IDs from settings:", fallback_ba_ids)
                        if sel:
                            current = sel
                            continue
                    elif label.startswith('Billing profile'):
                        sel = _select_from_list("Available billing profile IDs from settings (ba/profile):", fallback_bp_ids)
                        if sel and '/' in sel:
                            current = sel.split('/',1)[1]
                            continue
                    elif label.startswith('Invoice section'):
                        sel = _select_from_list("Available invoice section IDs from settings (ba/profile/invoice):", fallback_inv_ids)
                        if sel and sel.count('/') == 2:
                            current = sel.rsplit('/',1)[1]
                            continue
                    current = _prompt(f"Re-enter {label}")
                    continue
                print(f"Aborting: invalid {label.lower()} entered twice.")
                sys.exit(1)

        # Build scope id based on selected type
        if scope_type == 'subscription':
            sub_in = _prompt('Subscription ID')
            sub = _validate_component('Subscription ID', sub_in, rec_parsed.get('subscription'))
            scope_id = f"/subscriptions/{sub}"
        elif scope_type == 'resourceGroup':
            sub_in = _prompt('Subscription ID')
            sub = _validate_component('Subscription ID', sub_in, rec_parsed.get('subscription'))
            rg_in = _prompt('Resource group name')
            rg = _validate_component('Resource group name', rg_in, rec_parsed.get('resourceGroup'))
            scope_id = f"/subscriptions/{sub}/resourceGroups/{rg}"
        elif scope_type == 'managementGroup':
            mg_in = _prompt('Management group ID')
            mg = _validate_component('Management group ID', mg_in, rec_parsed.get('managementGroup'))
            scope_id = f"/providers/Microsoft.Management/managementGroups/{mg}"
        elif scope_type == 'billingAccount':
            ba_in = _prompt('Billing account ID')
            ba = _validate_component('Billing account ID', ba_in, rec_parsed.get('billingAccount'))
            scope_id = f"/providers/Microsoft.Billing/billingAccounts/{ba}"
        elif scope_type == 'billingProfile':
            ba_in = _prompt('Billing account ID')
            ba = _validate_component('Billing account ID', ba_in, rec_parsed.get('billingAccount'))
            bp_in = _prompt('Billing profile ID')
            bp = _validate_component('Billing profile ID', bp_in, rec_parsed.get('billingProfile'))
            scope_id = f"/providers/Microsoft.Billing/billingAccounts/{ba}/billingProfiles/{bp}"
        else:  # invoiceSection
            ba_in = _prompt('Billing account ID')
            ba = _validate_component('Billing account ID', ba_in, rec_parsed.get('billingAccount'))
            bp_in = _prompt('Billing profile ID')
            bp = _validate_component('Billing profile ID', bp_in, rec_parsed.get('billingProfile'))
            inv_in= _prompt('Invoice section ID')
            inv = _validate_component('Invoice section ID', inv_in, rec_parsed.get('invoiceSection'))
            scope_id = f"/providers/Microsoft.Billing/billingAccounts/{ba}/billingProfiles/{bp}/invoiceSections/{inv}"

    # Offer destination storage recommendation before proceeding; allow override
    seeded_defaults = suggest_defaults_from_settings(settings)
    rec_dest_id = (seeded_defaults or {}).get('dest_resource_id')
    override_meta: dict | None = None
    # For deferred deployment when user chooses an override path
    # override_meta will include a key 'pending' with values: 'bicep' | 'sdk'
    if rec_dest_id:
        print(f"\nSelect destination Storage for {scope_id}:")
        print(f"  Recommended: {rec_dest_id}")
        use_dest = _prompt("Use recommended destination? (Y/n)", "Y").lower().startswith('y')
        if not use_dest:
            # Override flow
            print("\nDestination override selected.")
            mode = _choose("Choose destination mode:", ["Existing storage account","Deploy new FinlytHub (Bicep)"] ,0)
            if mode == "Existing storage account":
                # Collect subscription + RG + SA name; defer creation until confirmation
                import re
                while True:
                    o_sub = _prompt("Destination subscription ID")
                    if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", o_sub):
                        print(" Invalid subscription GUID format.")
                        continue
                    break
                o_rg = _prompt("Destination resource group name")
                o_sa = _prompt("Existing or new storage account name")
                o_loc = _prompt("Location (for RG/SA creation if needed)", "eastus") or "eastus"
                override_meta = {
                    "pending": "sdk",
                    "subscription_id": o_sub,
                    "resource_group": o_rg,
                    "location": o_loc,
                    "storage_account_name": o_sa,
                    "resource_id": f"/subscriptions/{o_sub}/resourceGroups/{o_rg}/providers/Microsoft.Storage/storageAccounts/{o_sa}",
                    "uami": {},
                    "containers": {"daily":"daily","monthly":"monthly","reservation":"reservation"},
                    # Ensure tags captured for later ensure_rg() call at commit stage
                    "tags": {"Application":"FinlytHub","Mode":"Override"}
                }
            else:
                # Bicep override path: collect (optionally different) sub / RG / location / hub name
                import re
                print(" Will deploy a NEW FinlytHub via Bicep (override). Leave blank to accept defaults shown in [] where offered.")
                # Derive a default subscription from scope or settings
                def _extract_sub_from_scope(sid: str) -> str | None:
                    m = re.search(r"/subscriptions/([0-9a-fA-F-]{36})", sid or "")
                    return m.group(1) if m else None
                default_sub = _extract_sub_from_scope(scope_id) or _extract_sub_from_scope(rec_scope_id) or ''
                while True:
                    o_sub = _prompt(f"Destination subscription ID", default_sub) or default_sub
                    if not o_sub:
                        print(" Subscription ID is required.")
                        continue
                    if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", o_sub):
                        print(" Invalid subscription GUID format.")
                        continue
                    break
                # Resource group default derives from first 8 chars of sub
                rg_default = f"rg-finlythub-{o_sub[:8]}"
                o_rg = _prompt("Destination resource group name", rg_default) or rg_default
                loc_default = "eastus"
                o_loc = _prompt("Location", loc_default) or loc_default
                # Hub name default is deterministic (sha1)
                suffix = hashlib.sha1(o_sub.encode()).hexdigest()[:8]
                hub_default = f"finlythub{suffix}"
                o_hub = _prompt("FinlytHub storage account name", hub_default) or hub_default
                mi_default = f"{o_hub}-mi"
                o_mi = _prompt("User-assigned identity name", mi_default) or mi_default
                # Name availability check loop
                while True:
                    avail, reason = is_storage_account_name_available(cred, o_sub, o_hub)
                    if avail:
                        break
                    print(f"  Storage account name '{o_hub}' not available. {reason or ''}".strip())
                    o_hub = _prompt("Enter a different storage account name")
                    if not o_hub:
                        continue
                # Also basic format validation
                import re as _re
                if not _re.fullmatch(r"[a-z0-9]{3,24}", o_hub):
                    print("  Name violates format rules (lowercase letters/digits 3-24). Auto-adjusting.")
                    cleaned = ''.join(ch for ch in o_hub.lower() if ch.isalnum())[:24]
                    if len(cleaned) < 3:
                        cleaned = (cleaned + 'fin')[:3]
                    o_hub = cleaned
                # If this exactly matches the recommended destination, warn & allow retry
                rec_id_norm = rec_dest_id.lower() if rec_dest_id else None
                attempt_warned = False
                while True:
                    candidate_id = (f"/subscriptions/{o_sub}/resourceGroups/{o_rg}/providers/"
                                    f"Microsoft.Storage/storageAccounts/{o_hub}")
                    if rec_id_norm and candidate_id.lower() == rec_id_norm and not attempt_warned:
                        print(" WARNING: Chosen override values produce the SAME destination as the recommended one.")
                        cont = _prompt("Proceed anyway? (y/N)", "N").lower().startswith('y')
                        if cont:
                            break
                        # allow user to change hub or RG
                        o_rg = _prompt("Destination resource group name (re-enter)", o_rg) or o_rg
                        o_hub = _prompt("FinlytHub storage account name (re-enter)", o_hub) or o_hub
                        attempt_warned = True
                        continue
                    break
                print(f" Deploying override FinlytHub: {candidate_id}")
                # Defer actual Bicep deployment until after user confirms plan
                override_meta = {
                    "pending": "bicep",
                    "subscription_id": o_sub,
                    "resource_group": o_rg,
                    "location": o_loc,
                    "hub_name": o_hub,
                    "mi_name": o_mi,
                    "resource_id": f"/subscriptions/{o_sub}/resourceGroups/{o_rg}/providers/Microsoft.Storage/storageAccounts/{o_hub}",
                    "uami": {},
                    "containers": {"daily":"daily","monthly":"monthly","reservation":"reservation"},
                    "tags": {"Application":"FinlytHub","Mode":"Override"}
                }

    # 2) Destination ensure/deploy
    UI.step(2, 'Resolve / deploy destination storage')
    if override_meta is not None:
        meta = override_meta
    else:
        finlyt = settings.get('finlyt', {}) if isinstance(settings, dict) else {}
        dest_sub = (finlyt.get('subscription', {}) or {}).get('id')
        dest_rg  = (finlyt.get('resource_group', {}) or {}).get('name')
        dest_loc = (finlyt.get('subscription', {}) or {}).get('location') or 'eastus'
        if not dest_sub:
            import re
            # Try to derive from scope if it's a subscription or RG scope
            m_sub = re.search(r"/subscriptions/([^/]+)", scope_id or "", flags=re.IGNORECASE)
            if m_sub:
                dest_sub = m_sub.group(1)
        if not dest_rg:
            m_rg = re.search(r"/resourcegroups/([^/]+)", scope_id or "", flags=re.IGNORECASE)
            if m_rg:
                dest_rg = m_rg.group(1)
        # If still missing (billing scopes etc.), prompt user interactively
        if (not dest_sub or not dest_rg) and sys.stdin.isatty():
            print("\nNo existing Finlyt Hub subscription/RG context found for this scope.")
            print("Provide a subscription + resource group to host (or reuse) the Finlyt Hub storage.")
            while not dest_sub:
                dest_sub = input(" Destination subscription id: ").strip() or None
                if not dest_sub:
                    print("  Subscription id required.")
            if not dest_rg:
                suggested_rg = f"rg-finlythub-{dest_sub[:8]}"
                dest_rg = input(f" Destination resource group name [{suggested_rg}]: ").strip() or suggested_rg
        if not dest_sub or not dest_rg:
            raise RuntimeError('Unable to determine destination subscription/resource group for Finlyt Hub storage.')
        if not dest_rg:
            dest_rg = f"rg-finlythub-{dest_sub[:8]}"
        suffix   = hashlib.sha1(dest_sub.encode()).hexdigest()[:8]
        hub_name = f"finlythub{suffix}"
        mi_name  = f"{hub_name}-mi"
        existing_sa_id = (finlyt.get('Storage_account') or {}).get('id') if isinstance(finlyt, dict) else None
        meta = None
        # Always ensure/tag RG early (idempotent) so that reuse of existing storage also has tags
        try:
            ensure_rg(cred, dest_sub, dest_rg, dest_loc, tags={"Application":"FinlytHub"})
        except Exception as _rg_ex:
            print(f"  WARN: Failed to tag/ensure resource group {dest_rg}: {_rg_ex}")
        if existing_sa_id:
            parsed = _parse_storage_account_id(existing_sa_id)
            if parsed.get('subscription') == dest_sub and parsed.get('resourceGroup') == dest_rg:
                meta = {
                    'resource_id': existing_sa_id,
                    'storage_account_name': parsed.get('name'),
                    'uami': {},
                    'containers': {}
                }
                # Ensure containers and (re)tag RG even when reusing existing SA
                try:
                    ensure_rg(cred, dest_sub, dest_rg, dest_loc, tags={"Application":"FinlytHub"})
                except Exception:
                    pass
                for c in ['daily','monthly','reservation']:
                    try:
                        ensure_container(cred, parsed.get('name'), c)
                    except Exception:
                        pass
        if meta is None:
            meta = deploy_finlythub_via_bicep(
                cred=cred,
                subscription_id=dest_sub,
                rg_name=dest_rg,
                bicep_path="./02_finlythub_deploy.bicep",
                hub_name=hub_name,
                mi_name=mi_name,
                location=dest_loc,
                tags={"Application":"FinlytHub"}
            )

    export_dest_resource_id = (meta or override_meta or {}).get("resource_id")
    containers = (meta or override_meta or {}).get('containers', {})

    # 3) Dataset selection only (multi-select)
    # Determine scope type to decide Reservation dataset availability
    parsed_scope = _parse_scope_id(scope_id)
    scope_type = parsed_scope.get('type')
    reservation_supported = scope_type in ("billingAccount","billingProfile","invoiceSection")
    UI.step(3, 'Choose datasets & options')
    print("Dataset availability:")
    print("  FOCUS, ActualCost, AmortizedCost, Usage: supported for all selected scopes")
    if reservation_supported:
        print("  Reservation: supported for billingAccount / billingProfile / invoiceSection scopes")
    else:
        print("  Reservation: NOT supported for scope type '" + str(scope_type) + "' and will be skipped if selected")
    datasets = _multiselect(
        "Select datasets to export:",
        ["FOCUS","ActualCost","AmortizedCost","Usage","Reservation"],
        default_indices=[0,1]
    )
    if not reservation_supported and "Reservation" in datasets:
        datasets = [d for d in datasets if d != "Reservation"]
        print("  -> Skipping Reservation dataset (unsupported at this scope type).")

    # Ask for simple path mode (flatten: rootFolderPath="")
    spm_ans = _prompt("Simplify paths (store directly under container/<exportName>/...)? (y/N)", "N")
    if spm_ans == "__EXIT__":
        print("Exit requested.")
        return
    simple_path_mode = spm_ans.lower().startswith('y')

    ds_recurrences = {
        "FOCUS": ["Daily","Monthly"],
        "ActualCost": ["Daily","Monthly"],
        "AmortizedCost": ["Daily","Monthly"],
        "Usage": ["Daily","Monthly"],
        "Reservation": ["Daily","Monthly"]
    }

    fmt_choice = _choose("Format (affects all datasets, some may override):", ["Parquet","Csv"], 0)
    comp_default = 'Snappy' if fmt_choice=='Parquet' else 'Gzip'
    compression = _choose("Compression:", ["None","Gzip","Snappy"], ["None","Gzip","Snappy"].index(comp_default))
    ow_ans = _prompt("Overwrite existing files for same period? (y/N)", "N")
    if ow_ans == "__EXIT__":
        print("Exit requested.")
        return
    overwrite = ow_ans.lower().startswith('y')

    ds_to_container_key = {
        'FOCUS':'daily','ActualCost':'daily','AmortizedCost':'daily','Usage':'daily','Reservation':'reservation'}
    default_roots = {
        'FOCUS':'exports/focus','ActualCost':'exports/actual','AmortizedCost':'exports/amortized','Usage':'exports/usage','Reservation':'exports/reservation'}
    if simple_path_mode:
        # Flatten: scheduled + historical share the same (empty) root.
        default_roots = {k: '' for k in default_roots}

    # Scope-aware timeframe mapping
    tf_map = get_timeframes_for_scope(scope_id)

    dataset_api_type = {
        'FOCUS': 'FocusCost',
        'ActualCost': 'ActualCost',
        'AmortizedCost': 'AmortizedCost',
        'Usage': 'Usage',
        # Reservation only used if reservation_supported and selected
        'Reservation': 'ReservationDetails',
    }

    UI.step(4, 'Review planned exports')
    print("Export deployment plan:")
    print(f" Scope: {scope_id}")
    print(f" Destination (planned): {export_dest_resource_id}")
    for ds in datasets:
        recs = ds_recurrences.get(ds, ['Daily'])
        print(f"  - {ds}: {', '.join([r + ' (' + tf_map[r] + ')' for r in recs])}")
    proceed = _prompt('Proceed with deployment and export creation? (Y/n)', 'Y')
    if proceed == "__EXIT__":
        print("Exit requested.")
        return
    if not proceed.lower().startswith('y'):
        print("Aborted. No new resources deployed. No exports created.")
        return

    # Commit deferred deployment if any
    if override_meta and override_meta.get('pending') == 'bicep':
        plan = override_meta
        try:
            clean_tags = {k: v for k, v in (plan.get('tags') or {}).items() if k.lower() != 'mode'}
            if 'Application' not in clean_tags:
                clean_tags['Application'] = 'FinlytHub'
            deployed = deploy_finlythub_via_bicep(
                cred=cred,
                subscription_id=plan['subscription_id'],
                rg_name=plan['resource_group'],
                bicep_path="./02_finlythub_deploy.bicep",
                hub_name=plan['hub_name'],
                mi_name=plan['mi_name'],
                location=plan['location'],
                tags=clean_tags
            )
            override_meta.update(deployed)
        except Exception as ex:
            print(f" Deployment failed: {ex}")
            return
    elif override_meta and override_meta.get('pending') == 'sdk':
        plan = override_meta
        try:
            base_tags = {k:v for k,v in (plan.get('tags') or {}).items() if k.lower() != 'mode'}
            if 'Application' not in base_tags:
                base_tags['Application'] = 'FinlytHub'
            ensure_rg(cred, plan['subscription_id'], plan['resource_group'], plan['location'], tags=base_tags or {"Application":"FinlytHub"})
            ensure_sa(cred, plan['subscription_id'], plan['resource_group'], plan['storage_account_name'], plan['location'])
            for c in ['daily','monthly','reservation']:
                try:
                    ensure_container(cred, plan['storage_account_name'], c)
                except Exception:
                    pass
        except Exception as ex:
            print(f" Ensure failed: {ex}")
            return
    # Resolve meta after potential deployment
    if override_meta:
        meta = override_meta
    export_dest_resource_id = meta["resource_id"]
    containers = meta.get('containers', {})

    created_summary = []
    total_exports_planned = sum(len(ds_recurrences.get(ds, ['Daily'])) for ds in datasets)
    processed = 0
    for ds in datasets:
        for recurrence in ds_recurrences.get(ds, ['Daily']):
            # Choose container per dataset+recurrence
            if ds == 'Reservation':
                container_key = 'reservation'
            else:
                container_key = 'monthly' if recurrence.lower() == 'monthly' else 'daily'
            container_name = containers.get(container_key, container_key)
            try:
                ensure_container(cred, meta['storage_account_name'], container_name)
            except Exception:
                pass
            export_type = dataset_api_type.get(ds, ds)
            fmt = fmt_choice
            if export_type in ("ReservationDetails","ReservationRecommendations","ReservationTransactions"):
                fmt = "Csv"
                effective_compression = None
            else:
                if fmt == "Csv" and compression == "Snappy":
                    effective_compression = "Gzip"
                elif fmt == "Parquet" and compression == "Gzip":
                    effective_compression = "Snappy"
                else:
                    effective_compression = (None if compression == "None" else compression)
            timeframe = tf_map[recurrence]
            if simple_path_mode:
                # Deterministic shorter export names (unique per dataset+recurrence)
                short_map = {'ActualCost':'actual','AmortizedCost':'amort','Usage':'usage','FOCUS':'focus','Reservation':'reservation'}
                name = f"{recurrence.lower()}_{short_map.get(ds, ds.lower())}" if len(datasets) > 1 else recurrence.lower()
            else:
                name = f"finlyt_{ds.lower()}_{recurrence.lower()}"
            # In simple path mode the API rejects an empty rootFolderPath. Use the export
            # name itself as the root so files land under container/<exportName>/...
            root_path = default_roots.get(ds,'exports')
            if simple_path_mode:
                root_path = name
            body = build_export_body(
                dataset=export_type, recurrence=recurrence,
                dest_resource_id=export_dest_resource_id,
                container=container_name, root=root_path,
                fmt=fmt, timeframe=timeframe,
                compression=effective_compression,
                overwrite=overwrite,
                schedule_status='Active'
            )
            try:
                create_or_update_export(cred, scope_id, name, body)
                processed += 1
                created_summary.append({"export": name, "dataset": ds, "recurrence": recurrence, "container": container_name, "timeframe": timeframe})
                print(f" {UI.GREEN()}✔{UI.RESET()} {name} ({ds} | {recurrence} | {timeframe}) -> container: {container_name}  [{processed}/{total_exports_planned}]")
            except RuntimeError as ex:
                processed += 1
                print(f" {UI.YELLOW()}!{UI.RESET()} Failed to create {name} ({ds} | {recurrence}): {ex}  [{processed}/{total_exports_planned}]")
                continue

    # Offer optional historical seeding
    if _prompt("\nSeed historical cost data for selected datasets? (y/N)", "N").lower().startswith('y'):
        elig = [d for d in datasets if d in ("FOCUS","ActualCost","AmortizedCost","Usage")]
        if not elig:
            print(" No eligible datasets selected for historical seeding.")
        else:
            print(" Historical seeding creates one export per month in the range provided.")
            start_m = _prompt(" Start month (YYYY-MM)")
            end_m = _prompt(" End month (YYYY-MM)")
            try:
                if simple_path_mode:
                    # Reuse existing monthly export definitions (or create if missing) and run with Custom timeframe per month.
                    for ds in elig:
                        export_type = dataset_api_type.get(ds, ds)
                        container_name = containers.get('monthly','monthly')
                        ensure_container(cred, meta['storage_account_name'], container_name)
                        # Determine export name used for scheduled monthly export for this dataset
                        if simple_path_mode:
                            short_map = {'ActualCost':'actual','AmortizedCost':'amort','Usage':'usage','FOCUS':'focus'}
                            sched_name = f"monthly_{short_map.get(ds, ds.lower())}" if len(datasets) > 1 else 'monthly'
                        else:
                            sched_name = f"finlyt_{ds.lower()}_monthly"
                        start = _parse_ym(start_m)
                        end = _parse_ym(end_m)
                        if end < start:
                            print("  Skipped (end before start).")
                            continue
                        cur = start
                        print(f"  Seeding {ds} via export '{sched_name}' -> container={container_name}")
                        # Determine original timeframe for scheduled monthly export (should be TheLastMonth or mapping)
                        original_timeframe = get_timeframes_for_scope(scope_id).get('Monthly','TheLastMonth')
                        # Build a base definition to ensure the export exists (Active schedule for ongoing)
                        # We create/update once here before month loop if it doesn't exist
                        try:
                            # Create/update scheduled form first (active)
                            ensure_sched_body = build_export_body(
                                dataset=export_type, recurrence='Monthly',
                                dest_resource_id=export_dest_resource_id,
                                container=container_name, root=(sched_name if simple_path_mode else default_roots.get(ds,'')),
                                fmt=('Csv' if export_type.startswith('Reservation') else fmt_choice),
                                timeframe=original_timeframe,
                                compression=None if export_type.startswith('Reservation') else (None if compression=='None' else compression),
                                overwrite=False,
                                schedule_status='Active'
                            )
                            create_or_update_export(cred, scope_id, sched_name, ensure_sched_body)
                        except Exception:
                            pass

                        # Overlap detection (blob) for existing months under this export root
                        existing_months: set[str] = set()
                        try:
                            blob_client = BlobServiceClient(f"https://{meta['storage_account_name']}.blob.core.windows.net", credential=cred)
                            cont = blob_client.get_container_client(container_name)
                            # For simple path mode root == sched_name
                            root_prefix = f"{sched_name}/" if simple_path_mode else f"{default_roots.get(ds,'')}/historical/"
                            scan_cur = start
                            while scan_cur <= end:
                                code = scan_cur.strftime('%Y%m')
                                if simple_path_mode:
                                    # Files for custom monthly run will land under sched_name/<files>
                                    # Can't easily isolate per-month folders; rely on export re-run detection minimalism
                                    pass
                                else:
                                    y = scan_cur.strftime('%Y'); m = scan_cur.strftime('%m')
                                    pre = f"{root_prefix}{y}/{m}/"
                                    try:
                                        if any(True for _ in cont.list_blobs(name_starts_with=pre)):
                                            existing_months.add(code)
                                    except Exception:
                                        pass
                                if scan_cur.month == 12:
                                    scan_cur = date(scan_cur.year+1,1,1)
                                else:
                                    scan_cur = date(scan_cur.year,scan_cur.month+1,1)
                        except Exception:
                            pass

                        # For simple path mode we cannot precisely detect per-month existing data without schema; treat all as new.
                        action = 's'
                        if existing_months:
                            print(f"    Existing data detected for {ds}: {', '.join(sorted(existing_months))}")
                            while True:
                                action = _prompt("    Action? [S]kip existing / [O]verwrite / [C]ancel", 'S').lower() or 's'
                                if action in ('s','o','c'):
                                    break
                            if action == 'c':
                                print("    Cancelled dataset seeding.")
                                continue
                        overwrite_months = (action == 'o')

                        manifest_entries = []
                        manifest_start = datetime.now(UTC).isoformat()
                        while cur <= end:
                            # Month boundaries
                            if cur.month == 12:
                                nxt = date(cur.year+1,1,1)
                            else:
                                nxt = date(cur.year,cur.month+1,1)
                            last = nxt - timedelta(days=1)
                            dr_from = f"{cur.isoformat()}T00:00:00Z"
                            dr_to = f"{last.isoformat()}T23:59:59Z"
                            fmt_eff = 'Csv' if export_type.startswith('Reservation') else fmt_choice
                            # Build custom body (root remains flattened or standard per simple_path_mode already)
                            body = build_export_body(
                                dataset=export_type, recurrence='Monthly',
                                dest_resource_id=export_dest_resource_id,
                                # Use export name as root in simple path mode to satisfy API (no empty root allowed)
                                container=container_name, root=(sched_name if simple_path_mode else default_roots.get(ds,'')),
                                fmt=fmt_eff, timeframe='Custom',
                                from_date=dr_from, to_date=dr_to,
                                compression=None if fmt_eff=='Csv' else (compression if compression not in ('None','none') else None),
                                overwrite=overwrite_months,
                                schedule_status='Inactive'
                            )
                            try:
                                create_or_update_export(cred, scope_id, sched_name, body)
                                run_export(cred, scope_id, sched_name)
                                print(f"    {UI.GREEN()}•{UI.RESET()} {ds} {cur.strftime('%Y%m')} submitted")
                                manifest_entries.append({"dataset":ds,"month":cur.strftime('%Y%m'),"action":"submitted","export":sched_name,"overwrite":overwrite_months})
                            except Exception as ex:
                                print(f"    WARN {ds} {cur.strftime('%Y%m')}: {ex}")
                                manifest_entries.append({"dataset":ds,"month":cur.strftime('%Y%m'),"action":"error","error":str(ex)})
                            time.sleep(0.5)
                            cur = nxt
                        # Restore original scheduled monthly definition (Active timeframe)
                        try:
                            restore_body = build_export_body(
                                dataset=export_type, recurrence='Monthly',
                                dest_resource_id=export_dest_resource_id,
                                container=container_name, root=(sched_name if simple_path_mode else default_roots.get(ds,'')),
                                fmt=('Csv' if export_type.startswith('Reservation') else fmt_choice),
                                timeframe=original_timeframe,
                                compression=None if export_type.startswith('Reservation') else (None if compression=='None' else compression),
                                overwrite=False,
                                schedule_status='Active'
                            )
                            create_or_update_export(cred, scope_id, sched_name, restore_body)
                        except Exception as ex:
                            print(f"    WARN: Failed to restore schedule for {sched_name}: {ex}")
                        # Write manifest per dataset
                        try:
                            # Manifest file writing removed per new requirement (no historical_seed_manifest_*.json files)
                            # Could log summary inline instead of file persistence.
                            print(f"    Historical seeding summary: {len(manifest_entries)} month actions for {ds} (manifest persistence disabled)")
                        except Exception as mex:
                            print(f"    WARN: Failed to write manifest: {mex}")
                else:
                    seed_historical_cost_datasets(
                        cred,
                        scope_id,
                        elig,
                        export_dest_resource_id=export_dest_resource_id,
                        storage_account_name=meta['storage_account_name'],
                        containers=containers,
                        dataset_api_type=dataset_api_type,
                        default_roots=default_roots,
                        start_month=start_m,
                        end_month=end_m,
                        fmt_choice=fmt_choice,
                        compression_choice=compression
                    )
            except Exception as ex:
                print(f" Historical seeding failed: {ex}")

    UI.step(5, 'Summary')
    if created_summary:
        print(f"{UI.BOLD()}Created/Updated Exports:{UI.RESET()}")
        for e in created_summary:
            print(f"  - {e['export']} ({e['dataset']} {e['recurrence']}) -> {e['container']} :: {e['timeframe']}")
        # Convert created_summary to export-like structures for settings update
        export_records = []
        for e in created_summary:
            export_records.append({
                "name": e.get('export'),
                "dataset": e.get('dataset'),
                "recurrence": e.get('recurrence'),
                "container": e.get('container'),
                "timeframe": e.get('timeframe'),
                "updated": datetime.utcnow().isoformat() + 'Z'
            })
        try:
            # Overwrite exports_running list with newly created/updated exports
            update_exports(export_records)
            print("Updated split settings with new/updated exports.")
        except Exception as ex:
            print(f"WARN: Failed to update split settings: {ex}")
    else:
        print("No exports were created or updated.")
    print(f"{UI.GREEN()}All done.{UI.RESET()}")


# ---------- CLI ----------
def build_scope_id(args) -> str:
    if args.scope_id:
        return args.scope_id.strip()
    if args.scope_type == "subscription":
        return f"/subscriptions/{args.subscription_id}"
    if args.scope_type == "resourceGroup":
        return f"/subscriptions/{args.subscription_id}/resourceGroups/{args.resource_group}"
    if args.scope_type == "managementGroup":
        return f"/providers/Microsoft.Management/managementGroups/{args.management_group_id}"
    if args.scope_type == "billingAccount":
        return f"/providers/Microsoft.Billing/billingAccounts/{args.billing_account_id}"
    if args.scope_type == "billingProfile":
        return (f"/providers/Microsoft.Billing/billingAccounts/{args.billing_account_id}"
                f"/billingProfiles/{args.billing_profile_id}")
    if args.scope_type == "invoiceSection":
        return (f"/providers/Microsoft.Billing/billingAccounts/{args.billing_account_id}"
                f"/billingProfiles/{args.billing_profile_id}/invoiceSections/{args.invoice_section_id}")
    raise ValueError(f"Unsupported or incomplete scope args: {args.scope_type}")

def main():
    ap = argparse.ArgumentParser(description="Deploy FinlytHub infra (optional) and create Cost Management export.")
    ap.add_argument("--interactive", action="store_true", help="Run in guided interactive mode")
    ap.add_argument("--settings", default=SETTINGS_FILE)
    # Scope selection
    ap.add_argument("--scope-id", help="Full scope ARM ID for export (overrides scope-type args)")
    ap.add_argument("--scope-type", choices=["subscription","resourceGroup","managementGroup","billingAccount","billingProfile","invoiceSection"])
    ap.add_argument("--subscription-id")
    ap.add_argument("--resource-group")
    ap.add_argument("--management-group-id")
    ap.add_argument("--billing-account-id")
    ap.add_argument("--billing-profile-id")
    ap.add_argument("--invoice-section-id")

    # Export config
    ap.add_argument("--export-name", required=False)
    ap.add_argument("--dataset", choices=["ActualCost","AmortizedCost","Usage","FOCUS"], default="FOCUS")
    ap.add_argument("--format", choices=["Csv","Parquet"], default="Parquet")
    ap.add_argument("--recurrence", choices=["Daily","Weekly","Monthly"], default="Daily")
    ap.add_argument("--timeframe", choices=["Custom","MTD"], default="Custom")
    ap.add_argument("--from-date", dest="from_date", help="Start date for Custom timeframe (YYYY-MM-DD)")
    ap.add_argument("--to-date", dest="to_date", help="End date for Custom timeframe (YYYY-MM-DD)")
    ap.add_argument("--compression", choices=["None","Gzip","Snappy"])
    ap.add_argument("--overwrite", action="store_true")

    # Destination
    ap.add_argument("--dest-subscription-id", help="Subscription hosting the storage account (if creating/ensuring)")
    ap.add_argument("--dest-location", default="eastus")
    ap.add_argument("--dest-rg")
    ap.add_argument("--dest-sa")
    ap.add_argument("--dest-container")
    ap.add_argument("--dest-root")

    # Infra mode
    ap.add_argument("--use-bicep", action="store_true", help="Deploy/ensure destination via Bicep template")
    ap.add_argument("--bicep-template", default="./02_finlythub_deploy.bicep")
    ap.add_argument("--hub-name", help="Storage account name when using Bicep")
    ap.add_argument("--mi-name", help="UAMI name when using Bicep")
    ap.add_argument("--storage-sku", default="Standard_LRS")
    ap.add_argument("--tags", default='{"Application":"FinlytHub"}', help="JSON object for tags")

    args = ap.parse_args()
    cred = DefaultAzureCredential()

    # Load settings and seed defaults
    settings = load_settings(args.settings) if os.path.exists(args.settings) else {}
    seeded = suggest_defaults_from_settings(settings)

    if args.interactive:
        interactive_flow(cred, settings)
        return
    
    if not args.interactive and not args.export_name:
        raise RuntimeError("Missing required --export-name in non-interactive mode.")

    # Determine scope id
    scope_id = args.scope_id or (build_scope_id(args) if args.scope_type else seeded.get("scope_id"))
    if not scope_id:
        raise RuntimeError("No scope specified. Use --scope-id or --scope-type ... to define export scope.")

    # Determine destination (prefer CLI, then settings)
    dest_container = args.dest_container or seeded.get("dest_container") or "cost"
    dest_root      = args.dest_root      or seeded.get("dest_root") or ""
    tags = {}
    try:
        tags = json.loads(args.tags) if isinstance(args.tags, str) else (args.tags or {})
    except Exception:
        tags = {"Application": "FinlytHub"}

    # If using Bicep: deploy/ensure destination SA + containers + UAMI
    export_dest_resource_id = None
    if args.use_bicep:
        # Need: dest subscription + RG + hub_name + mi_name + location
        if not (args.dest_subscription_id and args.dest_rg):
            raise RuntimeError("--use-bicep requires --dest-subscription-id and --dest-rg")
        hub_name = args.hub_name or f"finlythub{uuid.uuid4().hex[:8]}"
        mi_name  = args.mi_name  or f"{hub_name}-mi"

        # Derive location from --dest-location (or leave as default)
        meta = deploy_finlythub_via_bicep(
            cred=cred,
            subscription_id=args.dest_subscription_id,
            rg_name=args.dest_rg,
            bicep_path=args.bicep_template,
            hub_name=hub_name,
            mi_name=mi_name,
            location=args.dest_location,
            tags=tags
        )
        # Ensure a target container (prefer 'daily' if dataset is FOCUS; else use provided)
        chosen_container = dest_container or meta["containers"].get("daily") or "daily"
        # Make sure it exists (bicep already created the standard containers; this is a no-op if present)
        ensure_container(cred, meta["storage_account_name"], chosen_container)

        export_dest_resource_id = meta["resource_id"]
        dest_container = chosen_container

    else:
        # SDK ensure path (no UAMI by default)
        # Require destination subscription + RG + SA + container
        if not (args.dest_subscription_id and args.dest_rg and args.dest_sa):
            # Fallback to settings if present
            sa_id = seeded.get("dest_resource_id")
            if not sa_id:
                raise RuntimeError("Destination not fully specified. Provide --dest-subscription-id --dest-rg --dest-sa (and --dest-container).")
            export_dest_resource_id = sa_id
        else:
            ensure_rg(cred, args.dest_subscription_id, args.dest_rg, args.dest_location, tags=tags or {"Application":"FinlytHub"})
            ensure_sa(cred, args.dest_subscription_id, args.dest_rg, args.dest_sa, args.dest_location, args.storage_sku)
            ensure_container(cred, args.dest_sa, dest_container)
            export_dest_resource_id = (f"/subscriptions/{args.dest_subscription_id}/resourceGroups/{args.dest_rg}"
                                       f"/providers/Microsoft.Storage/storageAccounts/{args.dest_sa}")

    # Build export body and create/update (non-interactive single export path)
    export_body = build_export_body(
        dataset=args.dataset, recurrence=args.recurrence,
        dest_resource_id=export_dest_resource_id, container=dest_container, root=dest_root,
        fmt=args.format, timeframe=args.timeframe,
        from_date=args.from_date, to_date=args.to_date,
        compression=(None if (args.compression in (None, "None")) else args.compression),
        overwrite=args.overwrite,
        schedule_status='Active'
    )
    result = create_or_update_export(cred, scope_id, args.export_name, export_body)

    print(json.dumps({
        "scope_id": scope_id,
        "export_name": args.export_name,
        "destination": {
            "resource_id": export_dest_resource_id,
            "container": dest_container,
            "root_path": dest_root
        },
        "result": result
    }, indent=2))
    return 0

if __name__ == '__main__':
    try:
        rc = main()
        sys.exit(rc if isinstance(rc, int) else 0)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(1)
