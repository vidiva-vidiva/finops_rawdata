# Finlyt Hub – Cost Management Exports Toolkit

Interactive utilities to detect your environment, deploy a lightweight Finlyt Hub (storage + containers + optional UAMI), and manage Azure Cost Management exports at subscription / RG / management group and billing scopes.

This project now uses split settings files for clarity and reliability:
- `user_settings.json` – identity and permission summary
- `finlyt_settings.json` – Finlyt Hub infra details and exports summary
- `cm_export_settings.json` – Cost Management export readiness + recommendations + exports map

The legacy `settings.json` is no longer written. It may still be read as a fallback if split files don’t exist yet.

## Prerequisites

- Python 3.10+
- Azure SDKs (install in your active environment):
	- azure-identity
	- azure-mgmt-resource
	- azure-mgmt-storage
	- azure-mgmt-subscription
	- azure-storage-blob

Optional: Azure CLI for best detection fidelity (signed-in user OID, bicep build fallback).

## Get Started

Use one of the quick-start paths below (local shell or Azure Cloud Shell). Azure CLI login improves detection fidelity.

### Quick Start (recommended)
```bash
az login                                # authenticate (skip if already logged in)
az account set --subscription <subId>   # optional: pick subscription context
git clone https://github.com/vidiva-vidiva/finops_rawdata.git finlyt-hub
cd finlyt-hub
python 00_setup_finlythub.py            # auto: creates .venv, installs deps, runs detection, launches menu
```

### One‑liner (curl bootstrap)
```bash
curl -O https://raw.githubusercontent.com/vidiva-vidiva/finops_rawdata/main/bootstrap_finlyt.sh \
  && bash bootstrap_finlyt.sh
```

### What happens on first run
- A local `.venv/` is created (unless you pass `--no-venv` or set `FINLYT_DISABLE_VENV=1`).
- `requirements.txt` dependencies are installed if missing.
- Detection runs to generate: `user_settings.json`, `finlyt_settings.json`, `cm_export_settings.json`.
- The interactive menu lets you Install (deploy hub + exports) or Manage / Cleanup.

### Optional manual virtual environment (if you prefer explicit steps)
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python 00_setup_finlythub.py
```

### Common flags / env vars
- `--no-venv` : skip auto virtual environment creation
- `--cleanup` : jump directly into cleanup module
- `FINLYT_DISABLE_VENV=1` : environment variable alternative to `--no-venv`
- `FINLYT_TEST_MODE=1` : write minimal split settings without full Azure SDKs (for offline testing)

### Shortcuts & notes
- Quit any prompt with: `q`, `quit`, `exit`, or `x`.
- No legacy `settings.json` is written; only the three split files are authoritative.
- Re-run detection from the menu whenever environment changes (new permissions/resources).
- Limited permissions? You still get a partial state captured in the split settings.

Advanced direct invocation of other scripts (`01_detect_*`, `02_deploy_*`, `03_cleanup_*`) is supported but not the documented path; prefer the single entry point.

### Bootstrap script (optional single entry path)

You can automate cloning, environment setup, and launching the single entry point with the helper script:

```bash
curl -O https://raw.githubusercontent.com/vidiva-vidiva/finops_rawdata/main/bootstrap_finlyt.sh
bash bootstrap_finlyt.sh
```

What it does (idempotent):
- Clones (or updates) the repo into `finlyt-hub/`
- Creates/uses `.venv` virtual environment
- Installs Python dependencies
- Runs detection if split settings are missing
- Launches the interactive orchestrator

Flags (still end at the orchestrator unless suppressed):
```bash
bash bootstrap_finlyt.sh --just-detect        # Only run detection then exit
bash bootstrap_finlyt.sh --no-orchestrator    # Skip launching 00_setup after detection
bash bootstrap_finlyt.sh --force-detect       # Re-run detection even if files exist
```

Environment overrides:
```bash
REPO_URL=... TARGET_DIR=... PYTHON_BIN=python3.12 bash bootstrap_finlyt.sh
```


## Scripts

The orchestrator internally invokes these components (single supported entry point):

1) Detection phase
   - Gathers subscriptions, permissions, tagged resources, existing exports
   - Writes/refreshes the split settings files (atomic)

2) Deployment & export creation
   - Wizard to pick scope, datasets, cadence, format
   - Ensures or deploys Finlyt Hub destination (Bicep optional)
   - Updates split settings (no legacy writes)

3) Cleanup
   - Lists exports with width-aware table
   - Deletes selected exports and updates settings
   - Optional deletion of tagged infra resources (Application=FinlytHub)

## Settings model (split files)

- `user_settings.json`
	- `observed` – ISO timestamp
	- `identity` – signed-in object id (best effort)
	- `permissions` – roles seen, assignment counts

- `finlyt_settings.json`
	- `observed`
	- `subscription`, `resource_group`, `storage_account`, `managed_identities`
	- `exports_running` – simplified list of exports
	- `historical` – optional historical summary
	- `tagged` – inventories of all tagged subscriptions, RGs, storage accounts, and managed identities

- `cm_export_settings.json`
	- `observed`
	- `finlyt` – Cost Management readiness and recommended `recommended_export_scope` and `recommended_destination`
	- `nonfinlyt` – same structure for non-hub scenarios
	- `exports` – `{ "finlyt": [...], "nonfinlyt": [...] }`

All writes are atomic. Legacy `settings.json` is not written anymore.

## Programmatic use

Use the shared IO helpers to read or update settings:

```python
from settings_io import load_aggregated, update_exports, update_recommended_scope, update_destination

settings = load_aggregated()  # synthesized legacy-shaped dict for convenience
update_recommended_scope("/subscriptions/<sub>/resourceGroups/<rg>")
update_destination(resource_id="/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<sa>",
									 container="cost",
									 root_path="exports/focus")
update_exports([{"name":"finlyt_focus_daily","dataset":"FOCUS","recurrence":"Daily","container":"daily"}])
```

## Tips

- Exit shortcuts: `q`, `quit`, `exit`, `x` work in all interactive prompts.
- If you run detection without Azure SDKs, set `FINLYT_TEST_MODE=1` for a minimal split settings stub.
- To scan more scopes in cleanup, add them when prompted (comma separated).

## Troubleshooting

- Missing Azure SDK imports: install the prerequisite packages in your active environment.
- Permission issues creating exports: ensure your account has required actions (e.g., `CostManagement/exports/write`).
- Bicep compilation issues: the deploy script attempts `az bicep build`, then falls back to an internal compiler helper.

## License

MIT (unless stated otherwise in repository).
