# 01_detect_FinlytHub.py 
""" 
01_detect_finlythub.py — Detect + Preflight (refactored)

This refactor:
 - Breaks the monolith into small, testable functions
 - Adds atomic write for SETTINGS_FILE
 - Preserves original checks and enrichment (providers, RBAC, policies,
   cost management checks, storage/container checks, exports summary)
 - Keeps bounded concurrency for per-sub preflight

Behavior and outputs are equivalent to the previous script: writes a single
settings.json at config.SETTINGS_FILE with the derived schema.
"""
from __future__ import annotations

import os
import re
import json
import time
import random
import urllib.parse
import tempfile
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import OrderedDict
from datetime import datetime, timezone
from finlyt_common import http_with_backoff, get_token
import requests
from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient

import config
SETTINGS_FILE = os.getenv("SETTINGS_FILE") or config.SETTINGS_FILE
# New split settings file paths (env overrides handled in config)
USER_SETTINGS_FILE = config.USER_SETTINGS_FILE
FINLYT_SETTINGS_FILE = config.FINLYT_SETTINGS_FILE
CM_EXPORT_SETTINGS_FILE = config.CM_EXPORT_SETTINGS_FILE

# provide a UTC tzinfo instance for existing code that uses 'UTC'
UTC = timezone.utc

# ---------- Config / constants ----------
TAG_APPLICATION = "Application"
APPLICATION_VALUE = "FinlytHub"
MGMT_RESOURCE = "https://management.azure.com/.default"

PROVIDERS_API = "2020-01-01"
RBAC_API = "2022-04-01"
MG_API = "2021-04-01"
POLICY_API = "2021-06-01"
COST_QUERY_API = "2025-03-01"
COST_EXPORTS_API = "2025-03-01"
DIAG_API = "2017-05-01-preview"
BILLING_API = "2024-04-01"

MAX_WORKERS = int(os.getenv("FINLYT_MAX_WORKERS", "8"))
COST_QUERY_TYPES = [x.strip() for x in os.getenv("FINLYT_COST_QUERY_TYPES", "Usage").split(",") if x.strip()]
SKIP_PRICE_SHEET = os.getenv("FINLYT_SKIP_PRICE_SHEET", "true").lower() in ("1", "true", "yes", "y")

RETRYABLE = {429, 500, 502, 503, 504}

def mgmt_get(cred, url: str, params: Dict[str, str] = None) -> requests.Response:
    headers = {"Authorization": f"Bearer {get_token(cred)}"}
    return http_with_backoff(requests.get, url, headers=headers, params=params, timeout=30)


def mgmt_post_json(cred, url: str, body: Dict[str, Any]) -> requests.Response:
    headers = {"Authorization": f"Bearer {get_token(cred)}", "Content-Type": "application/json"}
    return http_with_backoff(requests.post, url, headers=headers, json_body=body, timeout=60)


# ----------------------------------------------------------------
# Billing helpers (accounts, profiles, invoice sections, role defs)
# ----------------------------------------------------------------
def list_billing_accounts(cred) -> List[Dict[str, Any]]:
    """
    Lists billing accounts the caller can access.
    GET /providers/Microsoft.Billing/billingAccounts?api-version=2024-04-01
    """
    url = f"https://management.azure.com/providers/Microsoft.Billing/billingAccounts?api-version={BILLING_API}"
    r = mgmt_get(cred, url)
    if r is None or r.status_code != 200:
        return []
    return r.json().get("value", []) or []

def list_billing_profiles_by_account(cred, billing_account_name: str) -> List[Dict[str, Any]]:
    """
    Lists billing profiles under a billing account.
    GET /providers/Microsoft.Billing/billingAccounts/{ba}/billingProfiles?api-version=2024-04-01
    """
    base = f"https://management.azure.com/providers/Microsoft.Billing/billingAccounts/{billing_account_name}"
    url = f"{base}/billingProfiles?api-version={BILLING_API}"
    r = mgmt_get(cred, url)
    if r is None or r.status_code != 200:
        return []
    return r.json().get("value", []) or []

def list_invoice_sections_by_profile(cred, billing_account_name: str, billing_profile_name: str) -> List[Dict[str, Any]]:
    """
    Lists invoice sections under a billing profile (MCA).
    GET /providers/Microsoft.Billing/billingAccounts/{ba}/billingProfiles/{bp}/invoiceSections?api-version=2024-04-01
    """
    base = f"https://management.azure.com/providers/Microsoft.Billing/billingAccounts/{billing_account_name}/billingProfiles/{billing_profile_name}"
    url = f"{base}/invoiceSections?api-version={BILLING_API}"
    r = mgmt_get(cred, url)
    if r is None or r.status_code != 200:
        return []
    return r.json().get("value", []) or []

def list_ba_role_assignments_for_caller(cred, billing_account_name: str) -> List[Dict[str, Any]]:
    url = f"https://management.azure.com/providers/Microsoft.Billing/billingAccounts/{billing_account_name}/billingRoleAssignments?api-version={BILLING_API}"
    r = mgmt_get(cred, url)
    if r is None or r.status_code != 200:
        return []
    return r.json().get("value", []) or []

def list_bp_role_assignments_for_caller(cred, billing_account_name: str, billing_profile_name: str) -> List[Dict[str, Any]]:
    base = f"https://management.azure.com/providers/Microsoft.Billing/billingAccounts/{billing_account_name}/billingProfiles/{billing_profile_name}"
    url = f"{base}/billingRoleAssignments?api-version={BILLING_API}"
    r = mgmt_get(cred, url)
    if r is None or r.status_code != 200:
        return []
    return r.json().get("value", []) or []

def list_is_role_assignments_for_caller(cred, billing_account_name: str, billing_profile_name: str, invoice_section_name: str) -> List[Dict[str, Any]]:
    base = f"https://management.azure.com/providers/Microsoft.Billing/billingAccounts/{billing_account_name}/billingProfiles/{billing_profile_name}/invoiceSections/{invoice_section_name}"
    url = f"{base}/billingRoleAssignments?api-version={BILLING_API}"
    r = mgmt_get(cred, url)
    if r is None or r.status_code != 200:
        return []
    return r.json().get("value", []) or []

def get_billing_role_definition_name(cred, role_definition_id: str) -> Optional[str]:
    """
    Resolve a billing roleDefinitionId to a display role name.
    GET {roleDefinitionId}?api-version=2024-04-01
    """
    if not role_definition_id:
        return None
    url = f"https://management.azure.com{role_definition_id}?api-version={BILLING_API}"
    r = mgmt_get(cred, url)
    if r is None or r.status_code != 200:
        return None
    props = (r.json() or {}).get("properties", {}) or {}
    return props.get("roleName") or props.get("name") or None


# ---------- Small utilities ----------
def _to_null_if_empty(v):
    if v is None:
        return None
    if isinstance(v, (list, tuple, set)) and len(v) == 0:
        return None
    if isinstance(v, dict) and len(v) == 0:
        return None
    if isinstance(v, str) and v.strip() == "":
        return None
    return v


def _normalize_tags(tags: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]: return tags or None

def _latest_run_from_history(props: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    rh = props.get("runHistory") or {}
    runs = rh.get("value") or rh.get("runs") or []
    if not isinstance(runs, list) or not runs:
        return None, None

    def _ts(x):
        t = x.get("submittedTime") or x.get("runStartTime") or x.get("processingStartTime")
        try:
            return datetime.fromisoformat(t.replace("Z", "+00:00")) if isinstance(t, str) else datetime.min
        except Exception:
            return datetime.min

    runs.sort(key=_ts, reverse=True)
    lr = runs[0]
    last_run = lr.get("submittedTime") or lr.get("runStartTime")
    status = lr.get("status") or lr.get("provisioningState")
    return last_run, status


def summarize_export(exp: Dict[str, Any]) -> Dict[str, Any]:
    props = exp.get("properties", {}) or {}
    delivery = (props.get("deliveryInfo", {}) or {}).get("destination", {}) or {}
    schedule = props.get("schedule", {}) or {}
    fmt = props.get("format")
    last_run, status = _latest_run_from_history(props)
    return {
        "name": exp.get("name"),
        "format": fmt,
        "destination_container": delivery.get("container") or delivery.get("storageContainer"),
        "destination_resource_id": delivery.get("resourceId") or delivery.get("storageAccount"),
        "root_path": delivery.get("rootFolderPath"),
        "schedule": schedule.get("recurrence") or schedule.get("status") or "",
        "last_run": last_run,
        "status": status,
    }


# ---------- Detection / discovery ----------
def detect_finlythub_resources(cred) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []
    sub_client = SubscriptionClient(cred)
    for sub in sub_client.subscriptions.list():
        sub_id = sub.subscription_id
        try:
            rm = ResourceManagementClient(cred, sub_id)
            for rg in rm.resource_groups.list():
                # Include tagged resource group itself
                rg_tags = getattr(rg, 'tags', {}) or {}
                if rg_tags.get(TAG_APPLICATION) == APPLICATION_VALUE:
                    detections.append({
                        "name": rg.name,
                        "type": "Microsoft.Resources/resourceGroups",
                        "id": rg.id,
                        "location": getattr(rg, 'location', None),
                        "resource_group": rg.name,
                        "subscription_id": sub_id,
                        "tags": rg_tags
                    })
                for res in rm.resources.list_by_resource_group(rg.name):
                    tags = res.tags or {}
                    if tags.get(TAG_APPLICATION) == APPLICATION_VALUE:
                        detections.append({
                            "name": res.name,
                            "type": res.type,
                            "id": res.id,
                            "location": res.location,
                            "resource_group": rg.name,
                            "subscription_id": sub_id,
                            "tags": tags
                        })
        except Exception:
            # best-effort: skip subscription if SDK call fails
            continue
    return detections


# ---------- Providers / MGs / RBAC helpers ----------
def check_providers(cred, sub_id: str) -> Dict[str, Any]:
    required = ["Microsoft.CostManagement", "Microsoft.CostManagementExports", "Microsoft.Storage", "Microsoft.Authorization"]
    details = {}
    for rp in required:
        url = f"https://management.azure.com/subscriptions/{sub_id}/providers/{rp}?api-version={PROVIDERS_API}"
        r = mgmt_get(cred, url)
        if r is None:
            details[rp] = {"http": None, "text": "request_failed"}
            continue
        status = r.status_code
        if status == 200:
            body = r.json()
            details[rp] = {"http": status, "registrationState": body.get("registrationState")}
        else:
            details[rp] = {"http": status, "text": r.text[:400]}
    return details


def list_management_groups(cred) -> List[Dict[str, Any]]:
    url = f"https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version={MG_API}"
    r = mgmt_get(cred, url)
    if r is None or r.status_code != 200:
        return []
    return r.json().get("value", []) or []


def mg_descendants(cred, mg_id: str) -> List[Dict[str, Any]]:
    url = f"https://management.azure.com/providers/Microsoft.Management/managementGroups/{mg_id}/descendants?api-version={MG_API}"
    r = mgmt_post_json(cred, url, {})
    if r is None or r.status_code != 200:
        return []
    return r.json().get("value", []) or []


def role_assignments_for_principal(cred, scope: str, principal_oid: str) -> List[Dict[str, Any]]:
    if not principal_oid:
        return []
    flt = urllib.parse.quote(f"assignedTo('{principal_oid}')")
    url = (f"https://management.azure.com{scope}"
           f"/providers/Microsoft.Authorization/roleAssignments"
           f"?api-version={RBAC_API}&$filter={flt}")
    r = mgmt_get(cred, url)
    if r is None or r.status_code != 200:
        return []
    return r.json().get("value", []) or []


def fetch_role_definition(cred, role_definition_id: str) -> Dict[str, Any]:
    url = f"https://management.azure.com{role_definition_id}?api-version={RBAC_API}"
    r = mgmt_get(cred, url)
    return r.json() if (r is not None and r.status_code == 200) else {}


def merge_actions_from_role_defs(cred, role_assignments: List[Dict[str, Any]]) -> Tuple[Set[str], List[str]]:
    role_def_ids = {ra["properties"]["roleDefinitionId"] for ra in role_assignments if "properties" in ra}
    actions: Set[str] = set()
    role_names: List[str] = []
    for rd_id in role_def_ids:
        rd = fetch_role_definition(cred, rd_id)
        props = rd.get("properties", {})
        rn = props.get("roleName")
        if rn:
            role_names.append(rn)
        for perm in props.get("permissions", []) or []:
            for a in perm.get("actions", []) or []:
                actions.add(a)
            for da in perm.get("dataActions", []) or []:
                actions.add(da)
    return actions, role_names


def wildcard_allows(pattern: str, needed: str) -> bool:
    regex = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
    return re.match(regex, needed, flags=re.IGNORECASE) is not None


def check_permissions_effective(cred, sub_id: str, principal_oid: str,
                                mg_to_subs: Dict[str, Set[str]],
                                mg_assignments_cache: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    required_actions = [
        "Microsoft.Storage/storageAccounts/write",
        "Microsoft.Storage/storageAccounts/listKeys/action",
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.CostManagement/exports/write",
    ]
    sub_scope = f"/subscriptions/{sub_id}"
    sub_ras = role_assignments_for_principal(cred, sub_scope, principal_oid)
    mg_ras = []
    for mg_id, desc_subs in mg_to_subs.items():
        if sub_id in desc_subs:
            mg_ras.extend(mg_assignments_cache.get(mg_id, []))
    actions_sub, roles_sub = merge_actions_from_role_defs(cred, sub_ras)
    actions_mg, roles_mg = merge_actions_from_role_defs(cred, mg_ras)
    actions_all = actions_sub.union(actions_mg)
    roles_all = sorted(set(roles_sub + roles_mg))
    req_eval = {req: any(wildcard_allows(a, req) for a in actions_all) for req in required_actions}
    ok = all(req_eval.values()) if req_eval else False
    return {
        "ok": ok,
        "required_actions": req_eval,
        "roles_seen": roles_all,
        "assignments": {
            "subscription_scope_count": len(sub_ras),
            "mg_scope_count": len(mg_ras)
        }
    }


# ---------- Policies / cost mgmt / storage checks ----------
def check_policy_denies(cred, sub_id: str) -> Dict[str, Any]:
    base = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Authorization"
    r = mgmt_get(cred, f"{base}/policyAssignments?api-version={POLICY_API}")
    if r is None or r.status_code != 200:
        return {"ok": False, "http": getattr(r, "status_code", None), "text": getattr(r, "text", "")[:400]}
    items = r.json().get("value", []) or []
    findings = []
    for a in items:
        pid = a.get("properties", {}).get("policyDefinitionId")
        if not pid:
            continue
        r2 = mgmt_get(cred, f"https://management.azure.com{pid}?api-version={POLICY_API}")
        if r2 is None or r2.status_code != 200:
            continue
        js = r2.json()
        txt = json.dumps(js)
        if '"effect":"Deny"' in txt or '"effect": "Deny"' in txt:
            if ("Microsoft.Storage" in txt) or ("Microsoft.CostManagement" in txt) or ("CostManagement" in txt):
                findings.append({"assignment": a.get("name"), "definition": pid})
    return {"ok": True, "findings": findings, "assignments_count": len(items)}

# ---------- Cost Management checks ----------
def check_cost_mgmt(cred, sub_id: str) -> Dict[str, Any]:
    """
    Check if the subscription allows the user to configure key Cost Management exports.
    Returns a list of export types with human-readable status and reason.
    """
    COST_EXPORTS = [
        "PriceSheet",
        "ReservationDetails",
        "ReservationRecommendations",
        "ReservationTransactions",
        "Usage",
        "ActualCost",
        "AmortizedCost",
        "FocusCost",
    ]

    results = []

    # Check if Exports API is accessible
    base = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.CostManagement"
    try:
        r = mgmt_get(cred, f"{base}/exports?api-version={COST_EXPORTS_API}")
    except Exception:
        r = None

    exports_accessible = False
    if r is None:
        exports_status = "error"
        exports_reason = "Request failed or timed out when checking exports API."
    elif r.status_code == 200:
        exports_status = "accessible"
        exports_reason = "Exports API responded successfully."
        exports_accessible = True
    elif r.status_code == 403:
        exports_status = "forbidden"
        exports_reason = "Caller does not have permission to list Cost Management exports."
    else:
        exports_status = "error"
        exports_reason = f"Unexpected response: {r.text[:200]}"

    # For each export type, attempt to "test" access by calling the query endpoint (best-effort)
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    for export_type in COST_EXPORTS:
        if export_type == "PriceSheet":
            # PriceSheet is separate API
            ps_url = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Billing/pricesheets?api-version=2019-10-01-preview"
            try:
                rps = mgmt_get(cred, ps_url)
                if rps is None:
                    status = "error"
                    reason = "Request failed or timed out for PriceSheet."
                elif rps.status_code in (200, 204):
                    status = "accessible"
                    reason = "User can configure PriceSheet."
                elif rps.status_code == 403:
                    status = "forbidden"
                    reason = "Caller does not have permission for PriceSheet."
                else:
                    status = "error"
                    reason = f"Unexpected response: {rps.text[:200]}"
            except Exception:
                status = "error"
                reason = "Exception occurred while checking PriceSheet."
        else:
            # Other Cost Management queries
            if export_type not in COST_QUERY_TYPES:
                status = "skipped"
                reason = f"Test skipped for {export_type} by configuration."
            else:
                url = f"{base}/query?api-version={COST_QUERY_API}"
                payload = {
                    "type": export_type,
                    "timeframe": "Custom",
                    "timePeriod": {"from": today, "to": today},
                    "dataset": {"granularity": "Daily", "aggregation": {"cost": {"name": "PreTaxCost", "function": "Sum"}}}
                }
                headers = {"Authorization": f"Bearer {get_token(cred)}", "Content-Type": "application/json"}
                try:
                    rr = http_with_backoff(requests.post, url, headers=headers, json_body=payload,
                                           timeout=30, max_retries=3)
                    if rr is None:
                        status = "error"
                        reason = f"Request failed for {export_type}."
                    elif rr.status_code == 200:
                        status = "accessible"
                        reason = f"User can configure '{export_type}' export."
                    elif rr.status_code == 403:
                        status = "forbidden"
                        reason = f"Caller does not have permission for '{export_type}' export."
                    else:
                        status = "error"
                        reason = f"Unexpected response ({rr.status_code}) for '{export_type}': {getattr(rr, 'text', '')[:200]}"
                except Exception:
                    status = "error"
                    reason = f"Exception occurred while checking '{export_type}'."

        results.append({
            "type": export_type,
            "status": status,
            "reason": reason
        })

    return {"results": results, "exports_accessible": exports_accessible}


def check_storage(cred, sub_id: str, rg: Optional[str] = None, account: Optional[str] = None, container: Optional[str] = None) -> Dict[str, Any]:
    info = {"executed": False}
    if not (rg and account and container):
        return info
    info["executed"] = True
    try:
        sm = StorageManagementClient(cred, sub_id)
        sm.storage_accounts.get_properties(rg, account)
        info["storage_found"] = True
    except Exception as e:
        info["storage_found"] = False
        info["error"] = f"storage_missing: {e}"
        return info
    try:
        blob = BlobServiceClient(f"https://{account}.blob.core.windows.net", credential=cred)
        blob.get_container_client(container).get_container_properties()
        info["container_accessible"] = True
    except Exception as e:
        info["container_accessible"] = False
        info["error"] = f"container_inaccessible: {e}"
    return info


def check_diagnostics(cred, sub_id: str) -> Dict[str, Any]:
    url = f"https://management.azure.com/subscriptions/{sub_id}/providers/microsoft.insights/diagnosticSettings?api-version={DIAG_API}"
    r = mgmt_get(cred, url)
    if r is None or r.status_code != 200:
        return {"ok": False, "http": getattr(r, "status_code", None), "text": getattr(r, "text", "")[:300]}
    val = r.json().get("value", []) or []
    return {"ok": True, "count": len(val), "names": [v.get("name") for v in val]}


# ---------- Exports helpers ----------
def list_cost_exports(cred, scope_sub: str) -> List[Dict[str, Any]]:
    url = (f"https://management.azure.com/{scope_sub}"
           f"/providers/Microsoft.CostManagement/exports?api-version={COST_EXPORTS_API}")
    r = mgmt_get(cred, url)
    if r is None or r.status_code != 200:
        return []
    return r.json().get("value", []) or []


def get_export_with_history(cred, scope_sub: str, export_name: str) -> Optional[Dict[str, Any]]:
    url = (f"https://management.azure.com/{scope_sub}"
           f"/providers/Microsoft.CostManagement/exports/{export_name}"
           f"?api-version={COST_EXPORTS_API}&$expand=runHistory")
    r = mgmt_get(cred, url)
    return r.json() if (r is not None and r.status_code == 200) else None


# ---------- Queries shaping ----------
def build_queries_by_job(cost_queries: Dict[str, Any], subscription_id: Optional[str]) -> Dict[str, Any]:
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    scope = f"/subscriptions/{subscription_id}" if subscription_id else None

    def shape_one(qtype: str):
        q = (cost_queries or {}).get(qtype, {}) or {}
        ok = q.get("ok")
        http = q.get("http")
        text = q.get("text")
        if ok is True:
            status = "Accessible"
            reason = f"HTTP {http} for {qtype}." if http else f"{qtype} query succeeded."
        elif ok is None:
            status = "Skipped"
            reason = "Test skipped by configuration."
        else:
            status = "PermissionUnknown"
            reason = f"HTTP {http} for {qtype}: {text}" if http else "Check inconclusive or missing permission."
        dataset = {
            "Usage": "Daily aggregation: Sum PreTaxCost",
            "ActualCost": "Daily aggregation: Sum ActualCost",
            "AmortizedCost": "Daily aggregation",
        }.get(qtype, "Daily aggregation")
        return {
            "type": qtype,
            "scope": scope,
            "timeframe": "Custom",
            "timePeriod": {"from": today, "to": today},
            "dataset": dataset,
            "status": status,
            "reason": reason,
            "observed": datetime.now(UTC).isoformat() + "Z",
        }

    return {
        "usage_check": shape_one("Usage"),
        "actual_cost_check": shape_one("ActualCost"),
        "amortized_cost_check": shape_one("AmortizedCost"),
    }


# ---------- Orchestration pieces ----------
def gather_subscriptions(cred) -> List[Any]:
    client = SubscriptionClient(cred)
    return [s for s in client.subscriptions.list()]


def build_mg_to_subs_map(cred) -> Dict[str, Set[str]]:
    mg_list = list_management_groups(cred)
    mg_to_subs: Dict[str, Set[str]] = {}
    for mg in mg_list:
        mg_id = mg.get("name") or mg.get("id")
        if not mg_id:
            continue
        desc = mg_descendants(cred, mg_id)
        subs = set()
        for d in desc:
            if d.get("type", "").lower().endswith("/subscriptions"):
                sid = d.get("name") or (d.get("properties", {}) or {}).get("id")
                if sid:
                    subs.add(sid)
        mg_to_subs[mg_id] = {s for s in subs if isinstance(s, str)}
    return mg_to_subs


def cache_mg_assignments(cred, mg_to_subs: Dict[str, Set[str]], principal_oid: str) -> Dict[str, List[Dict[str, Any]]]:
    cache: Dict[str, List[Dict[str, Any]]] = {}
    for mg_id in mg_to_subs.keys():
        mg_scope = f"/providers/Microsoft.Management/managementGroups/{mg_id}"
        cache[mg_id] = role_assignments_for_principal(cred, mg_scope, principal_oid) if principal_oid else []
    return cache



def preflight_for_subscription(cred, sub, oid: str, mg_to_subs, mg_assign_cache) -> Dict[str, Any]:
    sub_id = sub.subscription_id
    sub_name = getattr(sub, "display_name", None) or getattr(sub, "subscription_name", None) or ""

    providers = check_providers(cred, sub_id)
    permissions = check_permissions_effective(cred, sub_id, oid, mg_to_subs, mg_assign_cache)
    policies = check_policy_denies(cred, sub_id)

    # Return the new cost mgmt structure: {"results": [...], "exports_accessible": bool}
    cost_mgmt_resp = check_cost_mgmt(cred, sub_id)
    cost_mgmt = cost_mgmt_resp.get("results", [])
    exports_api_accessible = bool(cost_mgmt_resp.get("exports_accessible"))

    # attempt a storage check if SETTINGS envs are set (best-effort)
    storage = check_storage(
        cred,
        sub_id,
        os.getenv("FINLYT_RESOURCE_GROUP"),
        os.getenv("FINLYT_STORAGE_ACCOUNT"),
        os.getenv("FINLYT_CONTAINER_NAME"),
    )
    diagnostics = check_diagnostics(cred, sub_id)

    providers_ok = all(v.get("registrationState") == "Registered" for v in providers.values())
    missing_actions = [a for a, ok in permissions.get("required_actions", {}).items() if not ok]
    policies_blocking = bool(policies.get("findings"))
    storage_ready = (
        storage.get("executed", False)
        and storage.get("storage_found", False)
        and storage.get("container_accessible", False)
    )
    eligible_for_export = providers_ok and permissions.get("ok") and not policies_blocking and storage_ready

    summary = {
        "id": sub_id,
        "name": sub_name,
        "tenant_id": getattr(sub, "tenant_id", None),
        "permissions_ok": permissions.get("ok"),
        "roles_seen": permissions.get("roles_seen", []),
        "missing_actions": missing_actions,
        "policies_blocking": policies_blocking,
        "storage_ready": storage_ready,
        "exports_existing": [],  # filled later when enrichment runs against hub or subscription
        "eligible_for_export": eligible_for_export,
    }
    details = {
        "providers": providers,
        "permissions": {**permissions, "missing_actions": missing_actions},
        "policies": policies,
        "storage": storage,
        "cost_mgmt": cost_mgmt,  # list of per-type checks
        "cost_mgmt_meta": {"exports_api_accessible": exports_api_accessible},
        "diagnostics": diagnostics,
        "identity": {"object_id": oid},
    }
    return {"summary": summary, "details": details}



def enrich_hub_and_exports(cred, detected: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not detected:
        return None
    hub_sa = next((d for d in detected if (d.get("type", "").lower() == "microsoft.storage/storageaccounts")), None)
    base = hub_sa or detected[0]
    hub = {
        "subscription_id": base.get("subscription_id"),
        "resource_group": base.get("resource_group"),
        "account_name": base.get("name"),
        "location": base.get("location"),
        "resource_id": base.get("id"),
    }
    try:
        sm = StorageManagementClient(cred, hub["subscription_id"])
        acct = sm.storage_accounts.get_properties(hub["resource_group"], hub["account_name"])
        nr = getattr(acct, "network_rule_set", None)
        network_rules = None
        if nr and getattr(nr, "default_action", None):
            network_rules = "public" if str(nr.default_action).lower() == "allow" else "private"
        # best-effort container accessibility check if FINLYT_CONTAINER_NAME provided
        container_accessible = None
        container_env = os.getenv("FINLYT_CONTAINER_NAME")
        if container_env:
            try:
                blob = BlobServiceClient(f"https://{hub['account_name']}.blob.core.windows.net", credential=cred)
                blob.get_container_client(container_env).get_container_properties()
                container_accessible = True
            except Exception:
                container_accessible = False
        hub["storage"] = {
            "kind": getattr(acct, "kind", None),
            "sku": getattr(getattr(acct, "sku", None), "name", None),
            "container_name": container_env or None,
            "container_accessible": container_accessible,
            "network_rules": network_rules,
        }
    except Exception:
        pass

    # exports
    scope_sub = f"subscriptions/{hub['subscription_id']}"
    exports = []
    try:
        ex_list = list_cost_exports(cred, scope_sub)
    except Exception:
        ex_list = []
    for e in ex_list:
        ename = e.get("name")
        full = get_export_with_history(cred, scope_sub, ename) if ename else None
        exports.append(summarize_export(full or e))
    hub["exports"] = exports

    # Historical month presence scan (best-effort) for standard datasets under inferred roots
    # Only attempt if we have blob access; results inform setup script to skip duplicates.
    dataset_roots = {
        'focus': 'exports/focus/historical',
        'actualcost': 'exports/actual/historical',
        'amortizedcost': 'exports/amortized/historical',
        'usage': 'exports/usage/historical'
    }
    hist_summary: Dict[str, Any] = {}
    try:
        bsc = BlobServiceClient(f"https://{hub['account_name']}.blob.core.windows.net", credential=cred)
        # Collect distinct containers from existing exports to refine search
        exp_containers = {e.get('destination_container') for e in exports if e.get('destination_container')}
        if not exp_containers:
            # Fallback to common container names
            exp_containers = {'cost','daily','monthly'}
        for ds_key, base_root in dataset_roots.items():
            months_found: Set[str] = set()
            for cont in exp_containers:
                try:
                    cc = bsc.get_container_client(cont)
                    # List blobs with delimiter to fetch pseudo-folders: base_root/YYYY/MM/
                    # We'll list up to a cap per dataset to avoid excessive traversal.
                    max_list = 500
                    blob_iter = cc.list_blobs(name_starts_with=base_root + '/', results_per_page=200)
                    count = 0
                    for b in blob_iter:
                        count += 1
                        if count > max_list:
                            break
                        name = getattr(b, 'name', '')
                        # Expect pattern base_root/YYYY/MM/...
                        parts = name.split('/')
                        # parts: [exports, focus, historical, YYYY, MM, ...]
                        if len(parts) >= 5 and parts[-1]:
                            try:
                                idx = parts.index('historical')
                            except ValueError:
                                continue
                            if idx+2 < len(parts):
                                yyyy = parts[idx+1]
                                mm = parts[idx+2]
                                if len(yyyy) == 4 and len(mm) == 2 and yyyy.isdigit() and mm.isdigit():
                                    months_found.add(yyyy+mm)
                    if months_found:
                        hist_summary[ds_key] = sorted(months_found)
                except Exception:
                    continue
        if hist_summary:
            hub['historical'] = {'months': hist_summary}
    except Exception:
        pass
    hub["status"] = {"healthy": bool(exports), "issues": [] if exports else ["No Cost Management exports found at subscription scope"]}
    return hub


def atomic_write_settings(path: str, obj: Any):
    expanded = os.path.expanduser(path)
    d = os.path.dirname(expanded) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-settings-", text=True)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, expanded)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


# ---------- Main orchestrator ----------
def main():
    # Support a fast test mode which writes a minimal settings file and exits
    if os.getenv("FINLYT_TEST_MODE") == "1":
        minimal = {
            "finlyt": {"subscription": {"id": None}, "cost_mgmt": {}},
            "user": {"permissions": {"roles_seen": None}}
        }
        atomic_write_settings(SETTINGS_FILE, minimal)
        print(f"[test-mode] wrote minimal settings to {SETTINGS_FILE}")
        return

    cred = DefaultAzureCredential()
    # signed-in object id best-effort via az CLI; keep same heuristic as before
    def signed_in_object_id() -> str:
        env_oid = os.getenv("FINLYT_IDENTITY_OBJECT_ID")
        if env_oid:
            return env_oid.strip()
        try:
            import subprocess
            cmd = ["az", "ad", "signed-in-user", "show", "--query", "id", "-o", "tsv"]
            oid = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode().strip()
            return oid
        except Exception:
            return ""

    oid = signed_in_object_id()

    if os.getenv('FINLYT_QUIET','0') != '1':
        print("Detecting FinlytHub resources...")
    detected = detect_finlythub_resources(cred)

    if os.getenv('FINLYT_QUIET','0') != '1':
        print("Enumerating subscriptions for preflight...")
    all_subs = gather_subscriptions(cred)
    all_sub_ids = [s.subscription_id for s in all_subs]

    if os.getenv('FINLYT_QUIET','0') != '1':
        print("Building management group -> subscriptions map...")
    mg_to_subs = build_mg_to_subs_map(cred)
    mg_assign_cache = cache_mg_assignments(cred, mg_to_subs, oid)

    if os.getenv('FINLYT_QUIET','0') != '1':
        print(f"Running preflight checks across {len(all_subs)} subscription(s) (max workers={MAX_WORKERS})...")
    from concurrent.futures import ThreadPoolExecutor, as_completed
    subscriptions_results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(preflight_for_subscription, cred, s, oid, mg_to_subs, mg_assign_cache) for s in all_subs]
        for fut in as_completed(futures):
            try:
                subscriptions_results.append(fut.result())
            except Exception as e:
                if os.getenv('FINLYT_QUIET','0') != '1':
                    print(f"[warn] preflight failed for one subscription: {e}")

    if os.getenv('FINLYT_QUIET','0') != '1':
        print("Enriching hub and exports metadata (if detected)...")
    hub = enrich_hub_and_exports(cred, detected)

    # Build comprehensive tagged resource inventories (multi-hub / multi-sub) for finlyt_settings extension
    def _strip_mode(tags: Dict[str, Any] | None) -> Dict[str, Any] | None:
        if not tags:
            return tags
        if 'Mode' in tags:
            tags = {k: v for k, v in tags.items() if k != 'Mode'}
        return tags

    tagged_storage = []
    tagged_mi = []
    tagged_rgs = []
    subs_with_tag: Dict[str, Dict[str, Any]] = {}
    for item in detected:
        itype = (item.get('type') or '').lower()
        sub_id = item.get('subscription_id')
        subs_with_tag.setdefault(sub_id, {"id": sub_id})
        base = {
            'id': item.get('id'),
            'name': item.get('name'),
            'location': item.get('location'),
            'subscription_id': sub_id,
            'resource_group': item.get('resource_group'),
            'tags': _strip_mode(item.get('tags'))
        }
        if itype == 'microsoft.storage/storageaccounts':
            tagged_storage.append(base)
        elif 'userassignedidentities' in itype:
            tagged_mi.append(base)
        elif itype == 'microsoft.resources/resourcegroups':
            tagged_rgs.append(base)

    # Augment subscription entries with name from subscriptions_results
    for sres in subscriptions_results:
        sid = sres.get('summary', {}).get('id')
        if sid in subs_with_tag:
            subs_with_tag[sid]['name'] = sres.get('summary', {}).get('name')
            subs_with_tag[sid]['roles_seen'] = sres.get('summary', {}).get('roles_seen')
            subs_with_tag[sid]['eligible_for_export'] = sres.get('summary', {}).get('eligible_for_export')

    # construct settings payload matching previous schema
    sub_for_user_summary = None
    if hub and hub.get("subscription_id"):
        sub_for_user_summary = next((s for s in subscriptions_results if s["summary"]["id"] == hub["subscription_id"]), None)
    else:
        sub_for_user_summary = subscriptions_results[0] if subscriptions_results else None

    roles_seen = (sub_for_user_summary or {}).get("summary", {}).get("roles_seen") or []
    
    # ---- Build user assignments and summaries (Billing Account, Billing Profiles / Invoice Sections, Management Groups, subscription)
    assignments_list: List[Dict[str, Any]] = []

    # Subscription scope (direct role assignments for caller)
    if sub_for_user_summary:
        sid = sub_for_user_summary["summary"].get("id")
        sname = sub_for_user_summary["summary"].get("name") or ""
        sub_scope = f"/subscriptions/{sid}" if sid else None
        sub_roles_seen = None
        sub_assign_count = None
        if sid:
            try:
                sub_ras = role_assignments_for_principal(cred, sub_scope, oid)
                _, sub_role_names = merge_actions_from_role_defs(cred, sub_ras)
                sub_roles_seen = sorted(set(sub_role_names)) or None
                sub_assign_count = len(sub_ras)
            except Exception:
                pass
        assignments_list.append({
            "scope": "subscription",
            "id": sid,
            "name": sname,
            "assignments_count": sub_assign_count,
            "roles_seen": sub_roles_seen
        })

    sa_tags = {}
    try:
        if hub and hub.get("subscription_id") and hub.get("resource_group") and hub.get("account_name"):
            sm = StorageManagementClient(cred, hub["subscription_id"])
            acct = sm.storage_accounts.get_properties(hub["resource_group"], hub["account_name"])
            sa_tags = getattr(acct, "tags", None) or {}
    except Exception:
        pass

    finlyt_tags = _normalize_tags(sa_tags)

    sa_kind = None
    sa_sku = None
    sa_network = None
    sa_access_tier = None
    try:
        if hub:
            sm = StorageManagementClient(cred, hub["subscription_id"])
            acct = sm.storage_accounts.get_properties(hub["resource_group"], hub["account_name"])
            sa_kind = getattr(acct, "kind", None)
            sa_sku = getattr(getattr(acct, "sku", None), "name", None)
            nr = getattr(acct, "network_rule_set", None)
            if nr and getattr(nr, "default_action", None):
                sa_network = "public" if str(nr.default_action).lower() == "allow" else "private"
            sa_access_tier = getattr(acct, "access_tier", None)
    except Exception:
        pass

    containers_list = []
    if hub and hub.get("account_name"):
        try:
            blob = BlobServiceClient(f"https://{hub['account_name']}.blob.core.windows.net", credential=cred)
            for c in blob.list_containers(name_starts_with=None):
                if hasattr(c, "name"):
                    containers_list.append(c.name)
        except Exception:
            pass

    exports_all = []
    try:
        scope_sub = f"subscriptions/{hub['subscription_id']}" if hub and hub.get("subscription_id") else None
        if scope_sub:
            ex_list = list_cost_exports(cred, scope_sub)
            enriched = []
            for e in ex_list:
                ename = e.get("name")
                full = get_export_with_history(cred, scope_sub, ename) if ename else None
                enriched.append(summarize_export(full or e))
            exports_all = enriched
    except Exception:
        exports_all = []

    finlyt_exports = []
    nonfinlyt_exports = []
    hub_res_id = (hub or {}).get("resource_id") or ""
    for e in exports_all:
        dest =( e.get("destination_resource_id") or "").lower()
        if (hub_res_id or "").lower() and dest.startswith((hub_res_id or "").lower()):
            finlyt_exports.append(e)
        else:
            nonfinlyt_exports.append(e)

    finlyt_exp1 = finlyt_exports[0] if len(finlyt_exports) > 0 else None
    finlyt_exp2 = finlyt_exports[1] if len(finlyt_exports) > 1 else None
    nonfinlyt_exp1 = nonfinlyt_exports[0] if len(nonfinlyt_exports) > 0 else None
    nonfinlyt_exp2 = nonfinlyt_exports[1] if len(nonfinlyt_exports) > 1 else None

    mi_finlyt = {"id": None, "principal_id": None, "client_id": None, "name": None, "tags": None}
    try:
        if hub:
            for d in (detected or []):
                if str(d.get("type", "")).lower().endswith("userassignedidentities"):
                    mi_finlyt["id"] = d.get("id")
                    mi_finlyt["name"] = d.get("name")
                    mi_finlyt["tags"] = _normalize_tags(d.get("tags") or {})
                    break
    except Exception:
        pass

    # build final settings
    settings = OrderedDict({
        "user": {
            "permissions": {
                "roles_seen": _to_null_if_empty(roles_seen),
                "assignments": _to_null_if_empty(assignments_list),
            }
        },
        "finlyt": {
            "subscription": {
                "id": _to_null_if_empty((hub or {}).get("subscription_id")),
                "name": _to_null_if_empty((sub_for_user_summary or {}).get("summary", {}).get("name")),
                "location": _to_null_if_empty((hub or {}).get("location")),
                "providers_registered": _to_null_if_empty([
                    k for k, v in ((sub_for_user_summary or {}).get("details", {}).get("providers", {}) or {}).items()
                    if (v or {}).get("registrationState") == "Registered"
                ]),
                "tags": _to_null_if_empty(finlyt_tags)
            },
            "resource_group": {
                "id": _to_null_if_empty((f"/subscriptions/{(hub or {}).get('subscription_id')}/resourceGroups/{(hub or {}).get('resource_group')}"
                                         if (hub or {}).get("subscription_id") and (hub or {}).get("resource_group") else None)),
              "name": _to_null_if_empty((hub or {}).get("resource_group")),
                "location": _to_null_if_empty((hub or {}).get("location")),
                "tags": _to_null_if_empty(finlyt_tags),
            },
            "Storage_account": {
                "id": _to_null_if_empty((hub or {}).get("resource_id")),
                "name": _to_null_if_empty((hub or {}).get("account_name")),
                "location": _to_null_if_empty((hub or {}).get("location")),
                "kind": _to_null_if_empty(sa_kind),
                "sku": _to_null_if_empty(sa_sku),
                "network_access": _to_null_if_empty(sa_network),
                "access_tier": _to_null_if_empty(sa_access_tier),
                "containers": _to_null_if_empty(containers_list),
                "tags": _to_null_if_empty(finlyt_tags),
            },
            "managed_identities": mi_finlyt,
            "cost_mgmt": {},
            "cm_exports": {
                "running": finlyt_exports or []
            }
        },
        "nonfinlyt": {
            "subscription": {
                "id": _to_null_if_empty((sub_for_user_summary or {}).get("summary", {}).get("id")),
                "name": _to_null_if_empty((sub_for_user_summary or {}).get("summary", {}).get("name")),
                "location": _to_null_if_empty((sub_for_user_summary or {}).get("summary", {}).get("location")),
                "providers_registered": _to_null_if_empty([
                    k for k, v in ((sub_for_user_summary or {}).get("details", {}).get("providers", {}) or {}).items()
                    if (v or {}).get("registrationState") == "Registered"
                ]),
            },
            "resource_group": {"id": None, "name": None, "location": None},
            "Storage_account": {"id": None, "name": None, "location": None, "kind": None, "sku": None, "network_access": None, "access_tier": None, "containers": None},
            "managed_identities": {"id": None, "principal_id": None, "client_id": None, "name": None},
            "cost_mgmt": {},
            "cm_exports": {
                "running": nonfinlyt_exports or []
            }
        }
    })

    # ---------- Management Group assignments (caller -> each MG) ----------
    mg_display = {
        (mg.get("name") or mg.get("id")):
            ((mg.get("properties", {}) or {}).get("displayName") or mg.get("displayName") or (mg.get("name") or mg.get("id")))
        for mg in list_management_groups(cred)
    }
    for mg_id, ras in (mg_assign_cache or {}).items():
        if not ras:
            continue
        try:
            _, role_names_mg = merge_actions_from_role_defs(cred, ras)
        except Exception:
            role_names_mg = []
        assignments_list.append({
            "scope": "managementGroup",
            "id": mg_id,
            "name": mg_display.get(mg_id, mg_id),
            "assignments_count": len(ras),
            "roles_seen": sorted(set(role_names_mg)) or None
        })

    # ---------- Billing plane: Accounts → Profiles → Invoice Sections (caller) ----------
    billing_accounts = list_billing_accounts(cred)
    billing_accounts_out: List[Dict[str, Any]] = []
    for ba in billing_accounts:
        ba_name = ba.get("name")
        ba_props = ba.get("properties", {}) or {}
        # Billing Account roles for caller
        roles_ba: List[str] = []
        ras_ba = list_ba_role_assignments_for_caller(cred, ba_name) if ba_name else []
        for ra in ras_ba:
            rd_id = (ra.get("properties", {}) or {}).get("roleDefinitionId")
            rn = get_billing_role_definition_name(cred, rd_id)
            if rn:
                roles_ba.append(rn)
        assignments_list.append({
            "scope": "billingAccount",
            "id": ba_name,
            "name": ba_props.get("displayName") or ba_name,
            "assignments_count": len(ras_ba),
            "roles_seen": sorted(set(roles_ba)) or None
        })
        # Billing Profiles
        for bp in list_billing_profiles_by_account(cred, ba_name):
            bp_name = bp.get("name")
            bp_props = bp.get("properties", {}) or {}
            roles_bp: List[str] = []
            ras_bp = list_bp_role_assignments_for_caller(cred, ba_name, bp_name)
            for ra in ras_bp:
                rd_id = (ra.get("properties", {}) or {}).get("roleDefinitionId")
                rn = get_billing_role_definition_name(cred, rd_id)
                if rn:
                    roles_bp.append(rn)
            assignments_list.append({
                "scope": "billingProfile",
                "id": f"{ba_name}/{bp_name}",
                "name": bp_props.get("displayName") or bp_name,
                "assignments_count": len(ras_bp),
                "roles_seen": sorted(set(roles_bp)) or None
            })
            # Invoice Sections (MCA)
            for inv in list_invoice_sections_by_profile(cred, ba_name, bp_name):
                inv_name = inv.get("name")
                inv_props = inv.get("properties", {}) or {}
                roles_is: List[str] = []
                ras_is = list_is_role_assignments_for_caller(cred, ba_name, bp_name, inv_name)
                for ra in ras_is:
                    rd_id = (ra.get("properties", {}) or {}).get("roleDefinitionId")
                    rn = get_billing_role_definition_name(cred, rd_id)
                    if rn:
                        roles_is.append(rn)
                assignments_list.append({
                    "scope": "invoiceSection",
                    "id": f"{ba_name}/{bp_name}/{inv_name}",
                    "name": inv_props.get("displayName") or inv_name,
                    "assignments_count": len(ras_is),
                    "roles_seen": sorted(set(roles_is)) or None
                })

    # Persist consolidated billing summary (optional but helpful)
    settings["billing"] = {
        "accounts": _to_null_if_empty([
            {
                "id": ba.get("name"),
                "display_name": (ba.get("properties") or {}).get("displayName"),
                "agreement_type": (ba.get("properties") or {}).get("agreementType"),
                "account_type": (ba.get("properties") or {}).get("accountType"),
                "has_read_access": (ba.get("properties") or {}).get("hasReadAccess"),
            }
            for ba in billing_accounts
        ]),
        "observed": datetime.now(UTC).isoformat() + "Z"
    }

    # Recommend a billing profile scope and destination for deploy step (best-effort)
    try:
        bp_scope = None
        for ba in billing_accounts:
            ba_name = ba.get("name")
            for bp in list_billing_profiles_by_account(cred, ba_name):
                bp_name = bp.get("name")
                if ba_name and bp_name:
                    bp_scope = f"/providers/Microsoft.Billing/billingAccounts/{ba_name}/billingProfiles/{bp_name}"
                    break
            if bp_scope:
                break
        settings["finlyt"]["cost_mgmt"]["recommended_export_scope"] = {
            "type": "billingProfile" if bp_scope else "subscription",
            "id": bp_scope or (f"/subscriptions/{(hub or {}).get('subscription_id')}" if (hub or {}).get("subscription_id") else None)
        }
        settings["finlyt"]["cost_mgmt"]["recommended_destination"] = {
            "resource_id": (hub or {}).get("resource_id"),
            "container": os.getenv("FINLYT_CONTAINER_NAME") or "cost",
            "root_path": "exports/billing-profile/focus"
        }
    except Exception:
        pass

    # additional query enrichment (run in main, after `settings` is created)

    # Use the hub subscription if present; else fall back to the first preflight result
    sub_ctx = sub_for_user_summary or (subscriptions_results[0] if subscriptions_results else None)

    # Pick the subscription ID to embed in the query scopes
    sub_id_for_queries = (hub or {}).get("subscription_id") or (sub_ctx or {}).get("summary", {}).get("id")

    # Build the quick "queries_by_job" projection off the preflight list
    cost_mgmt_list = ((sub_ctx or {}).get("details", {}) or {}).get("cost_mgmt", []) or []
    queries_src = {
        q.get("type"): {
            "ok": q.get("status") == "accessible",
            "http": None,
            "text": q.get("reason"),
        }
        for q in cost_mgmt_list
        if q.get("type")
    }

    settings["finlyt"]["cost_mgmt"]["queries_by_job"] = build_queries_by_job(queries_src, sub_id_for_queries)
    settings["nonfinlyt"]["cost_mgmt"]["queries_by_job"] = build_queries_by_job(
        queries_src,
        (sub_ctx or {}).get("summary", {}).get("id"),
    )

    # Compute booleans for can_setup_exports using the sub_ctx signals
    providers = (sub_ctx or {}).get("details", {}).get("providers", {}) or {}
    providers_ok = all((v or {}).get("registrationState") == "Registered" for v in providers.values())

    permissions = (sub_ctx or {}).get("details", {}).get("permissions", {}) or {}
    policies = (sub_ctx or {}).get("details", {}).get("policies", {}) or {}
    storage = (sub_ctx or {}).get("details", {}).get("storage", {}) or {}

    has_exports_write = permissions.get("required_actions", {}).get("Microsoft.CostManagement/exports/write") is True
    policies_blocking = bool(policies.get("findings"))
    storage_ready = storage.get("executed", False) and storage.get("storage_found", False) and storage.get("container_accessible", False)
    eligible_for_export = providers_ok and permissions.get("ok") and not policies_blocking and storage_ready

    exports_api_accessible = bool(((sub_ctx or {}).get("details", {}).get("cost_mgmt_meta") or {}).get("exports_api_accessible"))

    settings["finlyt"]["cost_mgmt"]["can_setup_exports"] = {
        "exports_api_accessible": exports_api_accessible,
        "has_exports_write_permission": has_exports_write,
        "providers_ok": providers_ok,
        "policies_blocking": policies_blocking,
        "storage_ready": storage_ready,
        "eligible_for_export": eligible_for_export,
    }

    # ---------------- Split settings construction ----------------
    try:
        user_settings = {
            "observed": datetime.now(UTC).isoformat() + "Z",
            "identity": {"object_id": oid or None},
            "permissions": settings.get("user", {}).get("permissions"),
            "assignments": settings.get("user", {}).get("permissions", {}).get("assignments"),
            "roles_seen": settings.get("user", {}).get("permissions", {}).get("roles_seen"),
            "billing": settings.get("billing")
        }

        # Sanitize existing single-resource tags
        sub_single = settings.get("finlyt", {}).get("subscription") or {}
        if isinstance(sub_single.get('tags'), dict):
            sub_single['tags'] = _strip_mode(sub_single.get('tags'))
        rg_single = settings.get("finlyt", {}).get("resource_group") or {}
        if isinstance(rg_single.get('tags'), dict):
            rg_single['tags'] = _strip_mode(rg_single.get('tags'))
        sa_single = settings.get("finlyt", {}).get("Storage_account") or {}
        if isinstance(sa_single.get('tags'), dict):
            sa_single['tags'] = _strip_mode(sa_single.get('tags'))
        mi_single = settings.get("finlyt", {}).get("managed_identities") or {}
        if isinstance(mi_single.get('tags'), dict):
            mi_single['tags'] = _strip_mode(mi_single.get('tags'))

        finlyt_settings = {
            "observed": datetime.now(UTC).isoformat() + "Z",
            "subscription": sub_single,
            "resource_group": rg_single,
            "storage_account": sa_single,
            "managed_identities": mi_single,
            "exports_running": settings.get("finlyt", {}).get("cm_exports", {}).get("running"),
            "historical": ((settings.get("finlyt", {}) or {}).get("historical")) or None,
            "tagged": {
                "subscriptions": list(subs_with_tag.values()),
                "resource_groups": tagged_rgs,
                "storage_accounts": tagged_storage,
                "managed_identities": tagged_mi
            }
        }

        cm_export_settings = {
            "observed": datetime.now(UTC).isoformat() + "Z",
            "finlyt": settings.get("finlyt", {}).get("cost_mgmt"),
            "nonfinlyt": settings.get("nonfinlyt", {}).get("cost_mgmt"),
            "exports": {
                "finlyt": settings.get("finlyt", {}).get("cm_exports", {}).get("running"),
                "nonfinlyt": settings.get("nonfinlyt", {}).get("cm_exports", {}).get("running"),
            }
        }

        # Defensive stripping of empty values (optional, keep structure minimal)
        def _strip_empty(d):
            if not isinstance(d, dict):
                return d
            return {k: v for k, v in d.items() if v not in (None, [], {}, "")}

        user_settings = _strip_empty(user_settings)
        finlyt_settings = _strip_empty(finlyt_settings)
        cm_export_settings = _strip_empty(cm_export_settings)

        atomic_write_settings(USER_SETTINGS_FILE, user_settings)
        atomic_write_settings(FINLYT_SETTINGS_FILE, finlyt_settings)
        atomic_write_settings(CM_EXPORT_SETTINGS_FILE, cm_export_settings)
        if os.getenv('FINLYT_QUIET','0') != '1':
            print(f"[Finlyt][detect] user_settings -> {USER_SETTINGS_FILE}")
            print(f"[Finlyt][detect] finlyt_settings -> {FINLYT_SETTINGS_FILE}")
            print(f"[Finlyt][detect] cm_export_settings -> {CM_EXPORT_SETTINGS_FILE}")
    except Exception as e:
        if os.getenv('FINLYT_QUIET','0') != '1':
            print(f"[Finlyt][warn] Failed to write split settings files: {e}")

    # Legacy consolidated write removed (split settings only moving forward)
    if os.getenv('FINLYT_QUIET','0') != '1':
        print(f"Detected {len(detected)} FinlytHub resource(s). Preflight across {len(all_subs)} subscription(s).")


if __name__ == "__main__":
    main()
