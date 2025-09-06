# config.py

# Centralized settings and defaults for Finlyt exports.

import os
import hashlib

# -------------------------------------------------------------------
# Where to store selected scopes (runtime state file)
SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "settings.json")

# -------------------------------------------------------------------
# Storage mode: "per-scope" (default) or "centralized"
EXPORT_STORAGE_MODE = os.environ.get("EXPORT_STORAGE_MODE", "per-scope").lower()

# -------------------------------------------------------------------
# Per-scope storage defaults (used when EXPORT_STORAGE_MODE == "per-scope")
PER_SCOPE_STORAGE_RG_PREFIX = "rg-finlyt-export-"
PER_SCOPE_STORAGE_ACCOUNT_PREFIX = "stfinlytexport"  # subId hash appended at runtime
PER_SCOPE_STORAGE_CONTAINER = "cost-exports"
PER_SCOPE_STORAGE_SKU = "Standard_LRS"
PER_SCOPE_STORAGE_KIND = "StorageV2"  # GPv2 recommended

# Per-scope runtime defaults
PER_SCOPE_SUBSCRIPTION_ID = os.environ.get("PER_SCOPE_SUBSCRIPTION_ID")
PER_SCOPE_RESOURCE_GROUP = os.environ.get(
    "PER_SCOPE_RESOURCE_GROUP", PER_SCOPE_STORAGE_RG_PREFIX + "default"
)
PER_SCOPE_LOCATION = os.environ.get("PER_SCOPE_LOCATION", "eastus")

# Helper: generate a globally unique storage account name from subscription id
def per_scope_storage_account_name(subscription_id: str) -> str:
    short_hash = hashlib.sha1(subscription_id.encode()).hexdigest()[:6]
    return (PER_SCOPE_STORAGE_ACCOUNT_PREFIX + short_hash)[:24]  # Azure limit

# -------------------------------------------------------------------
# --- FinlytHub centralized storage (always deployed once) ---
HUB_RG_DEFAULT = "FinlytHubRG"
HUB_NAME_DEFAULT = "finlythubstore"

# Populated either by detection or deployment
HUB_STORAGE_RESOURCE_ID = None  
HUB_ACCOUNT_NAME = None
HUB_RESOURCE_GROUP = None
HUB_SUBSCRIPTION_ID = None
HUB_LOCATION = None

# -------------------------------------------------------------------
# Default export base name (each variant appends a suffix)
EXPORT_NAME = "finlyt-export"

# Preferred deployment locations in order
PREFERRED_LOCATIONS = ["eastus", "westus2", "centralus"]

# -------------------------------------------------------------------
# Cost Management export configuration
COST_EXPORT_CONTAINER = os.environ.get("COST_EXPORT_CONTAINER", "cost-exports")
COST_EXPORT_ROOT = os.environ.get("COST_EXPORT_ROOT", "finops")

COST_EXPORT_FORMAT = os.environ.get("COST_EXPORT_FORMAT", "Parquet")  # Parquet or Csv
COST_EXPORT_COMPRESSION = os.environ.get("COST_EXPORT_COMPRESSION", "None")  # None|Gzip (CSV), Snappy (Parquet)
COST_EXPORT_OVERWRITE = os.environ.get("COST_EXPORT_OVERWRITE", "CreateNewReport")  # or OverwritePreviousReport
COST_EXPORT_PARTITION = os.environ.get("COST_EXPORT_PARTITION", "true").lower() in ("1", "true", "yes")

# -------------------------------------------------------------------
# Define export variants (per-scope or centralized)
EXPORT_VARIANTS = [
    {"key": "daily-actual",    "type": "ActualCost",    "schedule": "Daily",   "timeframe": "MonthToDate", "granularity": "Daily", "format": "Parquet"},
    {"key": "daily-amortized", "type": "AmortizedCost", "schedule": "Daily",   "timeframe": "MonthToDate", "granularity": "Daily", "format": "Parquet"},
    {"key": "monthly-actual",    "type": "ActualCost",    "schedule": "Monthly", "timeframe": "Custom", "granularity": "Daily", "format": "Csv"},
    {"key": "monthly-amortized", "type": "AmortizedCost", "schedule": "Monthly", "timeframe": "Custom", "granularity": "Daily", "format": "Csv"},
    # Optional: weekly exports
    # {"key": "weekly-actual", "type": "ActualCost", "schedule": "Weekly", "timeframe": "WeekToDate", "granularity": "Daily", "format": "Parquet"},
]

# -------------------------------------------------------------------
# Validation
if EXPORT_STORAGE_MODE not in ("per-scope", "centralized"):
    raise ValueError("EXPORT_STORAGE_MODE must be 'per-scope' or 'centralized'")

if EXPORT_STORAGE_MODE == "centralized" and not HUB_STORAGE_RESOURCE_ID:
    raise ValueError("In centralized mode, COST_EXPORT_STORAGE_RESOURCE_ID must be set")

if COST_EXPORT_FORMAT == "Parquet" and COST_EXPORT_COMPRESSION not in ("None", "Snappy"):
    raise ValueError("Parquet exports support only None or Snappy compression")

if COST_EXPORT_FORMAT == "Csv" and COST_EXPORT_COMPRESSION not in ("None", "Gzip"):
    raise ValueError("CSV exports support only None or Gzip compression")
