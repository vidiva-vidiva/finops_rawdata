#!/usr/bin/env python3
# 03_cleanup_finlythub.py
# Interactive cleanup tool for FinlytHub exports and tagged resources.
# Lists Cost Management exports and Azure resources tagged with Application=FinlytHub
# allowing the user to selectively delete them.

import os
import sys
import json
import re
import shutil
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timezone

import requests
from azure.identity import DefaultAzureCredential

from finlyt_common import get_token, http_with_backoff

EXPORTS_API = "2025-03-01"
RESOURCE_API = "2022-09-01"
MI_API = "2023-01-31"
# Legacy settings file path retained only for read fallback (no further writes)
SETTINGS_FILE = os.getenv("SETTINGS_FILE", "settings.json")

from settings_io import load_aggregated as load_settings_aggregated, update_exports

# Diagnostic / safety flags (override via env)
SHOW_DEST_ID = os.getenv("FINLYT_SHOW_DEST", "0") == "1"  # include destination resourceId column
VALIDATE_SA  = os.getenv("FINLYT_VALIDATE_SA", "1") == "1"  # GET each storage account to confirm existence
PER_ITEM_CONFIRM = os.getenv("FINLYT_PER_ITEM_CONFIRM", "1") == "1"  # ask per item before deletion
DEBUG_EXPORT = os.getenv("FINLYT_DEBUG", "0") == "1"  # verbose schedule debug


# ------------- Helpers -------------
def update_split_after_deletions(remaining_exports: List[Dict[str, Any]]):
    # Reuse shared update_exports helper (overwrites running list)
    update_exports(remaining_exports)

EXIT_TOKENS = {"q","quit","exit","x"}

def _prompt(msg: str, default: str | None = None) -> str:
    """Prompt user; if they enter an exit token return a sentinel '__EXIT__'."""
    try:
        raw = input(f"{msg}{' ['+default+']' if default else ''}: ").strip()
    except EOFError:
        return default or ''
    if raw.lower() in EXIT_TOKENS:
        return "__EXIT__"
    return raw or (default or '')

def _yesno(msg: str, default: bool = False) -> bool:
    d = 'Y' if default else 'N'
    val = _prompt(f"{msg} (y/N)" if not default else f"{msg} (Y/n)", d)
    if val == "__EXIT__":
        raise KeyboardInterrupt()
    return val.lower().startswith('y')


def _multiselect_indices(count: int, prompt: str, allow_empty: bool = True) -> List[int]:
    while True:
        raw = _prompt(prompt)
        if raw == "__EXIT__":
            raise KeyboardInterrupt()
        raw = raw.strip()
        if not raw and allow_empty:
            return []
        parts = [p.strip() for p in raw.split(',') if p.strip()]
        try:
            idxs = sorted({int(p) for p in parts})
            if any(i < 1 or i > count for i in idxs):
                raise ValueError
            return [i-1 for i in idxs]
        except Exception:
            print(" Invalid selection. Use comma-separated numbers from the table.")


def _pad(s: Any, width: int) -> str:
    s = '' if s is None else str(s)
    return s[:width].ljust(width)


def _terminal_width(default: int = 120) -> int:
    try:
        return shutil.get_terminal_size((default, 20)).columns
    except Exception:
        return default

def _truncate(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    if max_len <= 3:
        return value[:max_len]
    return value[:max_len-1] + '…'

def _print_table(rows: List[Dict[str, Any]], columns: List[tuple[str, str]], title: str):
    """Width-aware table printer with adaptive truncation to avoid ugly wrapping.
    Strategy:
      1. Compute natural width for each column.
      2. If total exceeds terminal width, iteratively shrink widest flexible columns
         (excluding first two) down to a floor (min 8 chars) until it fits.
      3. Truncate cell values to final column widths.
    """
    if not rows:
        print(f"\n{title}: (none found)")
        return
    print(f"\n{title}:")
    term_w = _terminal_width()
    # Compute desired widths
    widths: Dict[str,int] = {}
    for key, header in columns:
        cell_max = max(len(str(r.get(key,''))) for r in rows) if rows else 0
        widths[key] = max(len(header), cell_max, 3)
    num_w = len(str(len(rows)))
    gap = 2
    def total_width() -> int:
        return num_w + 2 + sum(widths[k] for k,_ in columns) + gap*(len(columns)-1)
    if total_width() > term_w:
        # Flexible keys exclude very short columns and the row number
        flex = [k for k,_ in columns]
        floor = 8
        # Repeatedly shrink the currently widest column until fits or all at floor
        while total_width() > term_w and any(widths[k] > floor for k in flex):
            # pick widest
            k_widest = max(flex, key=lambda k: widths[k])
            if widths[k_widest] <= floor:
                # all at floor
                break
            widths[k_widest] -= 1
    # Build header
    header_line = _pad('#', num_w) + '  ' + '  '.join(_pad(h if len(h)<=widths[k] else _truncate(h,widths[k]), widths[k]) for k,h in columns)
    if len(header_line) > term_w:  # Avoid wrapping header itself
        header_line = header_line[:term_w-1] + '…'
    print(header_line)
    print('-'*min(len(header_line), term_w))
    for i, r in enumerate(rows, 1):
        cells = []
        for k,_ in columns:
            raw = '' if r.get(k) is None else str(r.get(k))
            cells.append(_pad(_truncate(raw, widths[k]), widths[k]))
        line = _pad(i, num_w) + '  ' + '  '.join(cells)
        if len(line) > term_w:
            line = line[:term_w-1] + '…'
        print(line)


def _extract_storage_from_dest(resource_id: str) -> str:
    if not resource_id:
        return ''
    m = re.search(r"/storageAccounts/([^/]+)", resource_id, re.IGNORECASE)
    return m.group(1) if m else ''

def _parse_sa_id(resource_id: str):
    if not resource_id:
        return None, None, None
    m = re.match(r"/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Storage/storageAccounts/([^/]+)", resource_id, re.IGNORECASE)
    if not m:
        return None, None, None
    return m.group(1), m.group(2), m.group(3)

def _sa_exists(cred, resource_id: str) -> bool:
    sub, rg, name = _parse_sa_id(resource_id)
    if not sub:
        return False
    token = get_token(cred)
    headers = {"Authorization": f"Bearer {token}"}
    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/"
           f"Microsoft.Storage/storageAccounts/{name}?api-version={RESOURCE_API}")
    r = http_with_backoff(requests.get, url, headers=headers, timeout=30)
    return bool(r and r.status_code == 200)


def fetch_exports(cred, scope_id: str) -> List[Dict[str, Any]]:
    token = get_token(cred)
    headers = {"Authorization": f"Bearer {token}"}
    url = f"https://management.azure.com/{scope_id}/providers/Microsoft.CostManagement/exports?api-version={EXPORTS_API}"
    r = http_with_backoff(requests.get, url, headers=headers, timeout=60)
    if r is None or r.status_code not in (200, 204):
        print(f"  WARN: Failed to list exports for scope {scope_id} -> HTTP {getattr(r,'status_code',None)}")
        return []
    data = r.json() or {}
    return data.get('value', [])


def delete_export(cred, scope_id: str, name: str) -> bool:
    token = get_token(cred)
    headers = {"Authorization": f"Bearer {token}"}
    url = f"https://management.azure.com/{scope_id}/providers/Microsoft.CostManagement/exports/{name}?api-version={EXPORTS_API}"
    r = http_with_backoff(requests.delete, url, headers=headers, timeout=60)
    if r is None:
        return False
    return r.status_code in (200, 202, 204)


def list_tagged_resources(cred, subscription_id: str, tag_name: str = 'Application', tag_value: str = 'FinlytHub') -> List[Dict[str, Any]]:
    token = get_token(cred)
    headers = {"Authorization": f"Bearer {token}"}
    # Filter only supports eq comparisons on single tag name/value
    filter_q = f"tagName eq '{tag_name}' and tagValue eq '{tag_value}'"
    url = ("https://management.azure.com/subscriptions/" + subscription_id +
           f"/resources?$filter={filter_q}&api-version=2021-04-01")
    r = http_with_backoff(requests.get, url, headers=headers, timeout=60)
    if r is None or r.status_code not in (200, 204):
        print(f"  WARN: Failed to list tagged resources -> HTTP {getattr(r,'status_code',None)}")
        return []
    data = r.json() or {}
    return data.get('value', [])


def list_tagged_resource_groups(cred, subscription_id: str, tag_name: str = 'Application', tag_value: str = 'FinlytHub') -> List[Dict[str, Any]]:
    """List resource groups with the given tag (resource groups are not returned by the generic resources list)."""
    token = get_token(cred)
    headers = {"Authorization": f"Bearer {token}"}
    filter_q = f"tagName eq '{tag_name}' and tagValue eq '{tag_value}'"
    url = ("https://management.azure.com/subscriptions/" + subscription_id +
           f"/resourcegroups?$filter={filter_q}&api-version=2022-09-01")
    r = http_with_backoff(requests.get, url, headers=headers, timeout=60)
    if r is None or r.status_code not in (200, 204):
        return []
    data = r.json() or {}
    return data.get('value', [])


def delete_resource(cred, resource_id: str, api_version: Optional[str] = None) -> bool:
    token = get_token(cred)
    headers = {"Authorization": f"Bearer {token}"}
    if not api_version:
        # Heuristic based on type
        if '/storageAccounts/' in resource_id:
            api_version = RESOURCE_API
        elif '/userAssignedIdentities/' in resource_id:
            api_version = MI_API
        else:
            api_version = '2021-04-01'
    url = f"https://management.azure.com{resource_id}?api-version={api_version}"
    r = http_with_backoff(requests.delete, url, headers=headers, timeout=120)
    if r is None:
        return False
    return r.status_code in (200, 202, 204)


def determine_default_scope(settings: Dict[str, Any]) -> Optional[str]:
    return (((settings.get('finlyt', {}) or {}).get('cost_mgmt', {}) or {}).get('recommended_export_scope', {}) or {}).get('id')


def _parse_dt(val: str) -> Optional[datetime]:
    if not val or not isinstance(val, str):
        return None
    # Normalize Z
    v = val.replace('Z', '+00:00')
    try:
        return datetime.fromisoformat(v)
    except Exception:
        return None


def get_resource_creation_time(cred, resource_id: str) -> Optional[str]:
    """Attempt to retrieve creation time for a resource (best-effort)."""
    token = get_token(cred)
    headers = {"Authorization": f"Bearer {token}"}
    # Infer api version
    if '/storageAccounts/' in resource_id:
        api_version = RESOURCE_API
    elif '/userAssignedIdentities/' in resource_id:
        api_version = MI_API
    else:
        api_version = '2021-04-01'
    url = f"https://management.azure.com{resource_id}?api-version={api_version}"
    r = http_with_backoff(requests.get, url, headers=headers, timeout=60)
    if r is None or r.status_code not in (200, 201):
        return None
    try:
        data = r.json() or {}
        props = data.get('properties', {}) or {}
        for key in ('creationTime','createdTime','provisioningStateTransitionTime'):
            if props.get(key):
                # Return ISO trimmed to seconds
                iso = props.get(key)
                dt = _parse_dt(iso)
                if dt:
                    return dt.astimezone(timezone.utc).isoformat(timespec='seconds')
                return iso
    except Exception:
        return None
    return None


def get_export_creation_time(cred, scope_id: str, export_name: str) -> Optional[str]:
    """GET individual export (may surface timeCreated in future API)."""
    token = get_token(cred)
    headers = {"Authorization": f"Bearer {token}"}
    url = (f"https://management.azure.com/{scope_id}/providers/Microsoft.CostManagement/exports/"
           f"{export_name}?api-version={EXPORTS_API}")
    r = http_with_backoff(requests.get, url, headers=headers, timeout=60)
    if r is None or r.status_code not in (200, 201):
        return None
    try:
        data = r.json() or {}
        props = data.get('properties', {}) or {}
        for key in ('createdDateTime','timeCreated','creationTime'):
            if props.get(key):
                dt = _parse_dt(props.get(key))
                if dt:
                    return dt.astimezone(timezone.utc).isoformat(timespec='seconds')
                return props.get(key)
    except Exception:
        return None
    return None


def get_export_schedule_times(cred, scope_id: str, export_name: str) -> dict:
    """Fetch schedule for a given export to obtain nextRun/lastRun times.
    Returns dict with keys nextRun, lastRun (or empty if not found)."""
    token = get_token(cred)
    headers = {"Authorization": f"Bearer {token}"}
    url = (f"https://management.azure.com/{scope_id}/providers/Microsoft.CostManagement/exports/"
           f"{export_name}?api-version={EXPORTS_API}")
    try:
        r = http_with_backoff(requests.get, url, headers=headers, timeout=60)
        if r is None or r.status_code not in (200, 201):
            return {}
        data = r.json() or {}
        props = data.get('properties', {}) or {}
        schedule = props.get('schedule', {}) or {}
        nxt = (schedule.get('nextRunTime') or schedule.get('nextRunDateTime'))
        lst = (schedule.get('lastRunTime') or schedule.get('lastRunDateTime'))
        return {k: v for k, v in (('nextRun', nxt), ('lastRun', lst)) if v}
    except Exception:
        return {}


def interactive_cleanup(settings: Optional[Dict[str, Any]] = None):
    print("FinlytHub Cleanup Utility  (type 'q' or 'exit' anytime to abort)")
    print("This tool lists Cost Management exports and Azure resources tagged with Application=FinlytHub.")
    cred = DefaultAzureCredential()
    settings = settings or load_settings_aggregated()
    # ------- Scope discovery & selection (multi) -------
    default_scope = determine_default_scope(settings)
    candidates: List[str] = []
    if default_scope:
        candidates.append(default_scope)
    # Subscription scope & RG scope from settings
    sub_id = ((settings.get('finlyt', {}) or {}).get('subscription', {}) or {}).get('id')
    rg_name = ((settings.get('finlyt', {}) or {}).get('resource_group', {}) or {}).get('name')
    if sub_id:
        candidates.append(f"/subscriptions/{sub_id}")
        if rg_name:
            candidates.append(f"/subscriptions/{sub_id}/resourceGroups/{rg_name}")
    # Existing exports (if settings captured them) might carry a scope id
    exports_running = (((settings.get('finlyt', {}) or {}).get('cm_exports', {}) or {}).get('running')) or []
    if isinstance(exports_running, list):
        for e in exports_running:
            if isinstance(e, dict):
                sid = e.get('scope_id') or e.get('scope')
                if sid:
                    candidates.append(sid)
    # Deduplicate preserving order
    seen = set()
    deduped: List[str] = []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            deduped.append(c)
    if not deduped:
        print("No candidate scopes discovered from settings. You may enter scopes manually.")
        manual = _prompt("Enter one or more scope IDs (comma separated) or leave blank to skip", '')
        scopes = [s.strip() for s in manual.split(',') if s.strip()] if manual else []
    else:
        print("\nDiscovered candidate scopes:")
        for i, sc in enumerate(deduped, 1):
            print(f"  {i}. {sc}")
        print("  *  (all)")
        sel_raw = _prompt("Select scopes to scan (e.g. 1,3 or * for all)", '*')
        if sel_raw == "__EXIT__":
            print("Exit requested.")
            return
        if sel_raw.strip() == '*':
            scopes = deduped[:]
        else:
            idx_parts = [p.strip() for p in sel_raw.split(',') if p.strip()]
            chosen: List[str] = []
            for p in idx_parts:
                if p.isdigit():
                    idx = int(p)
                    if 1 <= idx <= len(deduped):
                        chosen.append(deduped[idx-1])
            scopes = chosen
        # Allow adding extra scopes
        extra = _prompt("Enter additional scope IDs (comma separated) or blank to continue", '')
        if extra == "__EXIT__":
            print("Exit requested.")
            return
        if extra:
            for s in [x.strip() for x in extra.split(',') if x.strip()]:
                if s not in scopes:
                    scopes.append(s)
    if not scopes:
        print("No scopes selected. You can still clean tagged resources only.")

    all_export_rows: List[Dict[str, Any]] = []  # holds export rows (will be sorted)
    # export_index_map will be (re)built AFTER sorting to maintain alignment with displayed order
    export_index_map: List[tuple[str,str]] = []
    for sc in scopes:
        exports = fetch_exports(cred, sc)
        for ex in exports:
            props = ex.get('properties', {}) or {}
            schedule = props.get('schedule', {}) or {}
            delivery = (props.get('deliveryInfo', {}) or {}).get('destination', {}) or {}
            definition = props.get('definition', {}) or {}
            name = ex.get('name')
            recurrence = schedule.get('recurrence')
            status = schedule.get('status')
            # Add fallback for nextRunTimeEstimate
            next_run = (schedule.get('nextRunTime') or schedule.get('nextRunDateTime') or schedule.get('nextRunTimeEstimate') or '-')
            last_run = (schedule.get('lastRunTime') or schedule.get('lastRunDateTime') or '-')
            container = delivery.get('container') or ''
            root = delivery.get('rootFolderPath') or ''
            dest_res_id = delivery.get('resourceId') or ''
            sa = _extract_storage_from_dest(dest_res_id)
            fmt = props.get('format') or definition.get('format') or ''
            comp = props.get('compressionMode') or props.get('compression') or ''
            # Flatten definition & schedule metadata
            timeframe = definition.get('timeframe')
            def_type = definition.get('type')
            time_period = (definition.get('timePeriod') or {}) or {}
            date_from = time_period.get('from')
            date_to = time_period.get('to')
            dataset = (definition.get('dataSet') or {}) or {}
            dataset_type = dataset.get('dataSetType')
            granularity = dataset.get('granularity')
            dataset_cfg = (dataset.get('configuration') or {}) or {}
            partition = dataset_cfg.get('partitionData')
            file_pattern = dataset_cfg.get('filePattern')
            overwrite = delivery.get('overwrite') or delivery.get('overwriteExisting')
            # Normalize data overwrite behavior (prefer explicit property, else derive)
            data_overwrite_behavior = (
                props.get('dataOverwriteBehavior')
                or delivery.get('dataOverwriteBehavior')
                or (('Overwrite' if overwrite is True else 'Append') if overwrite in (True, False) else None)
            )
            rec_period = (schedule.get('recurrencePeriod') or {}) or {}
            rec_from = rec_period.get('from')
            rec_to = rec_period.get('to')
            # Per request: surface from properties, not schedule
            next_run_est = props.get('nextRunTimeEstimate')
            created = get_export_creation_time(cred, sc, name) or '-'
            # If next/last run missing, attempt per-export GET to populate schedule times
            if next_run == '-' or last_run == '-':
                sched_times = get_export_schedule_times(cred, sc, name)
                if next_run == '-' and sched_times.get('nextRun'):
                    next_run = sched_times['nextRun']
                if last_run == '-' and sched_times.get('lastRun'):
                    last_run = sched_times['lastRun']
            if DEBUG_EXPORT:
                print(f"[debug] export={name} scheduleKeys={list(schedule.keys())} next={next_run} last={last_run} dest={dest_res_id} timeframe={timeframe} recPeriod=({rec_from},{rec_to}) datasetType={dataset_type} granularity={granularity}")
            row = {
                'scope': sc,
                'location': '-',
                'created': created,
                'name': name,
                'type': def_type,
                'recurrence': recurrence,
                'status': status,
                'nextRun': next_run,
                'lastRun': last_run,
                'nextRunTimeEstimate': next_run_est or '-',
                'container': container,
                'root': root,
                'storage': sa,
                'storageaccount': sa,
                'destId': dest_res_id,
                'saState': 'UNKNOWN',
                'format': fmt,
                'compression': comp,
                'compressionMode': comp,
                'timeframe': timeframe,
                'dateFrom': date_from,
                'dateTo': date_to,
                'datasetType': dataset_type,
                'granularity': granularity,
                'partition': partition,
                'filePattern': file_pattern,
                'overwrite': overwrite,
                'DataOverwriteBehavior': props.get('dataOverwriteBehavior') or '-',
                'recFrom': rec_from,
                'recTo': rec_to,
                'orphan': 'UNKNOWN',
            }
            all_export_rows.append(row)

    # Sort exports by created desc (unknown at bottom)
    def _exp_sort_key(r: Dict[str, Any]):
        dt = _parse_dt(r.get('created'))
        return (0 if dt else 1, -(dt.timestamp()) if dt else 0)
    all_export_rows.sort(key=_exp_sort_key)

    # (Removed unused export_index_map; direct indexing of all_export_rows is used below.)

    export_columns = [
        ('name','Export Name'),
        ('type','Type'),
        ('recurrence','Recurrence'),
        ('recFrom','RecFrom'),
        ('recTo','RecTo'),
        ('status','Status'),
        ('nextRunTimeEstimate','nextRunTimeEstimate'),
        ('timeframe','Timeframe'),
        ('granularity','Granularity'),
        ('DataOverwriteBehavior','DataOverwriteBehavior'),
        ('format','format'),
        ('compressionMode','compressionMode'),
        ('container','Container'),
        ('root','root'),
        ('storageaccount','storageaccount')
    ]
    _print_table(all_export_rows, export_columns, 'Exports')

    # Tagged resources
    sub_id = ((settings.get('finlyt', {}) or {}).get('subscription', {}) or {}).get('id')
    tagged_rows: List[Dict[str, Any]] = []  # will be sorted
    tagged_storage_names: set[str] = set()
    if sub_id:
        # Generic resources (excludes resource groups)
        tag_resources = list_tagged_resources(cred, sub_id)
        for r in tag_resources:
            rid = r.get('id')
            created = get_resource_creation_time(cred, rid) or '-'
            tagged_rows.append({
                'created': created,
                'location': r.get('location',''),
                'type': r.get('type',''),
                'name': r.get('name',''),
                'id': rid,
            })
            if isinstance(r.get('type',''), str) and r.get('type','').lower().endswith('storageaccounts'):
                tagged_storage_names.add(r.get('name',''))
        # Resource groups with tag
        rg_list = list_tagged_resource_groups(cred, sub_id)
        for rg in rg_list:
            rid = rg.get('id')
            # Resource group API does not expose creation time; leave '-'
            tagged_rows.append({
                'created': '-',
                'location': rg.get('location',''),
                'type': 'Microsoft.Resources/resourceGroups',
                'name': rg.get('name',''),
                'id': rid,
            })
    else:
        print("No subscription id in settings.finlyt.subscription.id; skipping tagged resource scan.")

    # Sort tagged resources by creation desc
    def _res_sort_key(r: Dict[str, Any]):
        dt = _parse_dt(r.get('created'))
        return (0 if dt else 1, -(dt.timestamp()) if dt else 0)
    tagged_rows.sort(key=_res_sort_key)
    # (Removed unused tagged_index_map.)

    # Validate storage accounts referenced by exports (existence + tag presence)
    if VALIDATE_SA:
        for r in all_export_rows:
            dest_id = r.get('destId')
            if not r.get('storage'):
                r['saState'] = 'NONE'
                r['orphan'] = 'NO'
                continue
            exists = _sa_exists(cred, dest_id) if dest_id else False
            if not exists:
                r['saState'] = 'MISSING'
                r['orphan'] = 'YES'
            else:
                r['saState'] = 'OK' if r.get('storage') in tagged_storage_names else 'UNTAGGED'
                r['orphan'] = 'NO'
    else:
        for r in all_export_rows:
            if r.get('destId') and r.get('storage'):
                r['orphan'] = 'NO'

    tagged_columns = [
        ('created','Created'),
        ('location','Location'),
        ('type','Type'),
        ('name','Name'),
        ('id','ResourceId')
    ]
    _print_table(tagged_rows, tagged_columns, 'Tagged Resources (Application=FinlytHub)')

    # Selection for exports
    if all_export_rows and _yesno("Delete any exports?", False):
        print("Enter comma-separated numbers from the Exports table to delete. Leave blank to cancel export deletion.")
        idxs = _multiselect_indices(len(all_export_rows), "Export numbers to delete")
        if idxs:
            to_delete = [all_export_rows[i] for i in idxs]
            print(" Selected exports:")
            for r in to_delete:
                print(f"  - {r['name']} (scope {r['scope']}) SA={r.get('storage')} state={r.get('saState')} nextRun={r.get('nextRun')} lastRun={r.get('lastRun')}")
            force = os.getenv('FINLYT_FORCE_DELETE') == '1'
            if not force:
                confirm = _yesno(f"Confirm deletion of {len(to_delete)} selected exports?", False)
                if not confirm:
                    print(" Export deletion aborted.")
                    to_delete = []
            if to_delete:
                if not force:
                    final = _prompt("Type DELETE to permanently remove these exports", "")
                    if final != "DELETE":
                        print(" Export deletion aborted at final confirmation.")
                        to_delete = []
                if to_delete:
                    for r in to_delete:
                        if PER_ITEM_CONFIRM and not force:
                            if not _yesno(f" Delete export {r['name']}?", False):
                                print(f" Skipped export {r['name']}")
                                continue
                        sc, ename = r['scope'], r['name']
                        ok = delete_export(cred, sc, ename)
                        print(f" - {'Deleted' if ok else 'FAILED'} export {ename} (scope {sc})")
                    # Recompute remaining exports list for settings update
                    remaining = []
                    for r in all_export_rows:
                        if r['name'] not in [d['name'] for d in to_delete]:
                            # minimal export shape
                            remaining.append({
                                'name': r.get('name'),
                                'scope': r.get('scope'),
                                'container': r.get('container'),
                                'storage': r.get('storage'),
                                'lastRun': r.get('lastRun'),
                            })
                    try:
                        update_split_after_deletions(remaining)
                        print(" Updated split settings to reflect export deletions.")
                    except Exception as ex:
                        print(f" WARN: Failed to update split settings after deletions: {ex}")
    else:
        if all_export_rows:
            print(" No export deletions selected.")

    # Selection for tagged resources
    if tagged_rows and _yesno("Delete any tagged resources (infra)?", False):
        print("Enter comma-separated numbers from the Tagged Resources table to delete. Leave blank to cancel.")
        idxs = _multiselect_indices(len(tagged_rows), "Resource numbers to delete")
        if idxs:
            to_delete_res = [tagged_rows[i] for i in idxs]
            print(" Selected resources:")
            for r in to_delete_res:
                print(f"  - {r['type']} {r['name']} :: {r['id']}")
            force = os.getenv('FINLYT_FORCE_DELETE') == '1'
            if not force:
                confirm = _yesno(f"Confirm deletion of {len(to_delete_res)} selected resources?", False)
                if not confirm:
                    print(" Resource deletion aborted.")
                    to_delete_res = []
            if to_delete_res:
                if not force:
                    final = _prompt("Type DELETE to permanently remove these resources", "")
                    if final != "DELETE":
                        print(" Resource deletion aborted at final confirmation.")
                        to_delete_res = []
                if to_delete_res:
                    for r in to_delete_res:
                        if PER_ITEM_CONFIRM and not force:
                            if not _yesno(f" Delete resource {r['type']} {r['name']}?", False):
                                print(f" Skipped {r['id']}")
                                continue
                        rid = r['id']
                        ok = delete_resource(cred, rid)
                        print(f" - {'Deleted' if ok else 'FAILED'} {rid}")
    else:
        if tagged_rows:
            print(" No resource deletions selected.")

    print("\nCleanup complete.")


def main():
    interactive_cleanup()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(1)
