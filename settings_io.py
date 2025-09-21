"""Shared settings IO utilities for FinlytHub.

This module consolidates logic for reading and writing the new split settings
files (user_settings.json, finlyt_settings.json, cm_export_settings.json) and
exposes helpers to load a synthesized legacy-style aggregated structure for
in-memory consumption without persisting a legacy settings.json file.

All write helpers intentionally NO LONGER write the legacy settings.json file.
Legacy support (reading) remains for backward compatibility during transition.
"""
from __future__ import annotations

import os
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import config

USER_SETTINGS_FILE = config.USER_SETTINGS_FILE
FINLYT_SETTINGS_FILE = config.FINLYT_SETTINGS_FILE
CM_EXPORT_SETTINGS_FILE = config.CM_EXPORT_SETTINGS_FILE
LEGACY_SETTINGS_FILE = config.SETTINGS_FILE  # read-only fallback

ISO = lambda: datetime.utcnow().isoformat() + 'Z'

# ---------------- Low-level helpers ----------------

def _load_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

def _write_json_atomic(path: str, obj: Any):
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)

# ---------------- Aggregated loader ----------------

def load_aggregated() -> Dict[str, Any]:
    """Load split settings and synthesize a legacy-shaped dict.
    Falls back to legacy settings.json if split files are absent.
    """
    user = _load_json(USER_SETTINGS_FILE)
    finlyt = _load_json(FINLYT_SETTINGS_FILE)
    cmexp = _load_json(CM_EXPORT_SETTINGS_FILE)
    if not (user or finlyt or cmexp):
        # Fallback legacy (no write-back)
        return _load_json(LEGACY_SETTINGS_FILE)
    synthesized: Dict[str, Any] = {
        "user": {"permissions": {}},
        "finlyt": {"cost_mgmt": {}, "cm_exports": {}},
        "nonfinlyt": {"cost_mgmt": {}}
    }
    perms = user.get('permissions') or {}
    synthesized['user']['permissions']['roles_seen'] = perms.get('roles_seen') or user.get('roles_seen')
    synthesized['user']['permissions']['assignments'] = perms.get('assignments') or user.get('assignments')
    synthesized['finlyt']['subscription'] = finlyt.get('subscription') or {}
    synthesized['finlyt']['resource_group'] = finlyt.get('resource_group') or {}
    synthesized['finlyt']['Storage_account'] = finlyt.get('storage_account') or {}
    synthesized['finlyt']['cost_mgmt'] = cmexp.get('finlyt') or {}
    synthesized['nonfinlyt']['cost_mgmt'] = cmexp.get('nonfinlyt') or {}
    synthesized['finlyt']['cm_exports']['running'] = (cmexp.get('exports') or {}).get('finlyt') or finlyt.get('exports_running') or []
    return synthesized

# ---------------- Update helpers ----------------

def update_exports(export_records: List[Dict[str, Any]]):
    """Replace the list of running exports in split files.
    Does NOT write legacy settings.json.
    """
    finlyt = _load_json(FINLYT_SETTINGS_FILE)
    cmexp = _load_json(CM_EXPORT_SETTINGS_FILE)
    finlyt['exports_running'] = export_records
    cmexp_exports = cmexp.get('exports') or {}
    cmexp_exports['finlyt'] = export_records
    cmexp['exports'] = cmexp_exports
    now = ISO()
    finlyt['observed'] = now
    cmexp['observed'] = now
    _write_json_atomic(FINLYT_SETTINGS_FILE, finlyt)
    _write_json_atomic(CM_EXPORT_SETTINGS_FILE, cmexp)


def update_recommended_scope(scope_id: str):
    cmexp = _load_json(CM_EXPORT_SETTINGS_FILE)
    finlyt = _load_json(FINLYT_SETTINGS_FILE)
    fin = cmexp.get('finlyt') or {}
    fin.setdefault('recommended_export_scope', {})['id'] = scope_id
    cmexp['finlyt'] = fin
    _write_json_atomic(CM_EXPORT_SETTINGS_FILE, cmexp)
    # Mirror minimal in finlyt file only if needed (optional)
    finlyt.setdefault('cost_mgmt', {}).setdefault('recommended_export_scope', {})['id'] = scope_id
    _write_json_atomic(FINLYT_SETTINGS_FILE, finlyt)


def update_destination(resource_id: Optional[str], container: Optional[str], root_path: Optional[str]):
    cmexp = _load_json(CM_EXPORT_SETTINGS_FILE)
    finlyt = _load_json(FINLYT_SETTINGS_FILE)
    fin = cmexp.get('finlyt') or {}
    dest = fin.setdefault('recommended_destination', {})
    if resource_id is not None:
        dest['resource_id'] = resource_id
    if container is not None:
        dest['container'] = container
    if root_path is not None:
        dest['root_path'] = root_path
    cmexp['finlyt'] = fin
    _write_json_atomic(CM_EXPORT_SETTINGS_FILE, cmexp)
    # Mirror minimal copy (optional)
    finlyt.setdefault('cost_mgmt', {}).setdefault('recommended_destination', {}).update({k:v for k,v in dest.items() if v is not None})
    _write_json_atomic(FINLYT_SETTINGS_FILE, finlyt)

__all__ = [
    'load_aggregated',
    'update_exports',
    'update_recommended_scope',
    'update_destination',
]
