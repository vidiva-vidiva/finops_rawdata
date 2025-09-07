#!/usr/bin/env python3
# 03_cleanup_finlythub.py
# Interactive cleanup tool for FinlytHub exports and tagged resources.
# Lists Cost Management exports and Azure resources tagged with Application=FinlytHub
# allowing the user to selectively delete them.

import os
import sys
import json
import re
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timezone

import requests
from azure.identity import DefaultAzureCredential

from finlyt_common import get_token, http_with_backoff

EXPORTS_API = "2025-03-01"
RESOURCE_API = "2022-09-01"
MI_API = "2023-01-31"
SETTINGS_FILE = os.getenv("SETTINGS_FILE", "settings.json")


# ------------- Helpers -------------
def load_settings(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path, 'r') as f:
        try:
            return json.load(f)
        except Exception:
            return {}


def _prompt(msg: str, default: str | None = None) -> str:
    try:
        raw = input(f"{msg}{' ['+default+']' if default else ''}: ").strip()
        return raw or (default or '')
    except EOFError:
        return default or ''


def _yesno(msg: str, default: bool = False) -> bool:
    d = 'Y' if default else 'N'
    val = _prompt(f"{msg} (y/N)" if not default else f"{msg} (Y/n)", d)
    return val.lower().startswith('y')


def _multiselect_indices(count: int, prompt: str, allow_empty: bool = True) -> List[int]:
    while True:
        raw = _prompt(prompt).strip()
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


def _print_table(rows: List[Dict[str, Any]], columns: List[tuple[str, str]], title: str):
    if not rows:
        print(f"\n{title}: (none found)")
        return
    print(f"\n{title}:")
    # Compute widths
    widths: Dict[str,int] = {}
    for key, header in columns:
        widths[key] = max(len(header), *(len(str(r.get(key,''))) for r in rows))
    # Row number column
    num_w = len(str(len(rows)))
    header_line = _pad('#', num_w) + '  ' + '  '.join(_pad(h, widths[k]) for k,h in columns)
    print(header_line)
    print('-'*len(header_line))
    for i, r in enumerate(rows, 1):
        line = _pad(i, num_w) + '  ' + '  '.join(_pad(r.get(k,''), widths[k]) for k,_ in columns)
        print(line)


def _extract_storage_from_dest(resource_id: str) -> str:
    if not resource_id:
        return ''
    m = re.search(r"/storageAccounts/([^/]+)", resource_id, re.IGNORECASE)
    return m.group(1) if m else ''


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


def interactive_cleanup(settings: Optional[Dict[str, Any]] = None):
    print("FinlytHub Cleanup Utility")
    print("This tool lists Cost Management exports and Azure resources tagged with Application=FinlytHub.")
    cred = DefaultAzureCredential()
    settings = settings or load_settings(SETTINGS_FILE)
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
        if extra:
            for s in [x.strip() for x in extra.split(',') if x.strip()]:
                if s not in scopes:
                    scopes.append(s)
    if not scopes:
        print("No scopes selected. You can still clean tagged resources only.")

    all_export_rows: List[Dict[str, Any]] = []
    export_index_map: List[tuple[str,str]] = []  # (scope_id, export_name)
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
            next_run = schedule.get('nextRunTime') or '-'
            container = delivery.get('container') or ''
            root = delivery.get('rootFolderPath') or ''
            dest_res_id = delivery.get('resourceId') or ''
            sa = _extract_storage_from_dest(dest_res_id)
            fmt = props.get('format') or definition.get('format') or ''
            comp = props.get('compressionMode') or props.get('compression') or ''
            created = get_export_creation_time(cred, sc, name) or '-'
            row = {
                'scope': sc,
                'location': '-',
                'created': created,
                'name': name,
                'recurrence': recurrence,
                'status': status,
                'nextRun': next_run,
                'container': container,
                'root': root,
                'storage': sa,
                'format': fmt,
                'compression': comp,
            }
            all_export_rows.append(row)
            export_index_map.append((sc, name))

    # Sort exports by created desc (unknown at bottom)
    def _exp_sort_key(r: Dict[str, Any]):
        dt = _parse_dt(r.get('created'))
        return (0 if dt else 1, -(dt.timestamp()) if dt else 0)
    all_export_rows.sort(key=_exp_sort_key)

    export_columns = [
        ('created','Created'),
        ('location','Location'),
        ('name','Export'),
        ('recurrence','Recurrence'),
        ('status','Status'),
        ('nextRun','NextRun'),
        ('container','Container'),
        ('root','Root'),
        ('storage','StorageAccount'),
        ('format','Format'),
        ('compression','Compression')
    ]
    _print_table(all_export_rows, export_columns, 'Exports')

    # Tagged resources
    sub_id = ((settings.get('finlyt', {}) or {}).get('subscription', {}) or {}).get('id')
    tagged_rows: List[Dict[str, Any]] = []
    tagged_index_map: List[str] = []
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
            tagged_index_map.append(rid)
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
            tagged_index_map.append(rid)
    else:
        print("No subscription id in settings.finlyt.subscription.id; skipping tagged resource scan.")

    # Sort tagged resources by creation desc
    def _res_sort_key(r: Dict[str, Any]):
        dt = _parse_dt(r.get('created'))
        return (0 if dt else 1, -(dt.timestamp()) if dt else 0)
    tagged_rows.sort(key=_res_sort_key)

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
            confirm = _yesno(f"Confirm deletion of {len(idxs)} exports", False)
            if confirm:
                for i in idxs:
                    sc, ename = export_index_map[i]
                    ok = delete_export(cred, sc, ename)
                    print(f" - {'Deleted' if ok else 'FAILED'} export {ename} (scope {sc})")
            else:
                print(" Export deletion aborted.")
    else:
        if all_export_rows:
            print(" No export deletions selected.")

    # Selection for tagged resources
    if tagged_rows and _yesno("Delete any tagged resources (infra)?", False):
        print("Enter comma-separated numbers from the Tagged Resources table to delete. Leave blank to cancel.")
        idxs = _multiselect_indices(len(tagged_rows), "Resource numbers to delete")
        if idxs:
            confirm = _yesno(f"Confirm deletion of {len(idxs)} resources", False)
            if confirm:
                for i in idxs:
                    rid = tagged_index_map[i]
                    ok = delete_resource(cred, rid)
                    print(f" - {'Deleted' if ok else 'FAILED'} {rid}")
            else:
                print(" Resource deletion aborted.")
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
