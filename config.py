"""Minimal configuration module.

Currently only exposes SETTINGS_FILE used by detection and orchestrator scripts.
All previous constants (storage mode, variants, compression defaults, etc.) were
removed as they were not referenced anywhere else in the codebase. Retrieve the
older version from version control if reintroducing centralized/per-scope
export abstractions later.
"""

import os

# Primary consolidated settings file (legacy / backward compatibility)
SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "settings.json")

# New split settings files (can be overridden via environment variables)
USER_SETTINGS_FILE = os.getenv("USER_SETTINGS_FILE") or os.path.join(os.path.dirname(__file__), "user_settings.json")
FINLYT_SETTINGS_FILE = os.getenv("FINLYT_SETTINGS_FILE") or os.path.join(os.path.dirname(__file__), "finlyt_settings.json")
CM_EXPORT_SETTINGS_FILE = os.getenv("CM_EXPORT_SETTINGS_FILE") or os.path.join(os.path.dirname(__file__), "cm_export_settings.json")

__all__ = [
	"SETTINGS_FILE",
	"USER_SETTINGS_FILE",
	"FINLYT_SETTINGS_FILE",
	"CM_EXPORT_SETTINGS_FILE",
]
