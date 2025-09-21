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

## Scripts

1) Detect – environment summary and recommendations
- File: `01_detect_finlythub.py`
- Output: writes split settings files (atomically)
- Run:
	```bash
	python 01_detect_finlythub.py
	```
- What it does:
	- Enumerates subscriptions you can access, checks provider registrations, policies, and permissions.
	- Discovers tagged Finlyt Hub resources (RGs, Storage Accounts, Managed Identities).
	- Lists existing Cost Management exports where permitted.
	- Writes split settings; also adds a `tagged` inventory to `finlyt_settings.json`.

2) Orchestrate – Install / Repair menu (interactive)
- File: `00_setup_finlythub.py`
- Run:
	```bash
	python 00_setup_finlythub.py
	```
- Menu actions:
	- Install Finlyt (interactive): launches the deploy wizard (02) and creates exports.
	- Repair / Manage: change recommended scope/destination, seed historical, run cleanup.
	- Cleanup: invokes `03_cleanup_finlythub.py` to remove exports/resources.

3) Deploy – Interactive export creation (+ optional hub deploy)
- File: `02_deploy_finlythub.py`
- Run:
	```bash
	python 02_deploy_finlythub.py --interactive
	```
- Highlights:
	- Choose export scope (subscription/RG/MG/billing) and datasets (FOCUS, ActualCost, AmortizedCost, Usage, Reservation).
	- Optionally deploy or reuse a storage destination (Finlyt Hub) with Bicep or SDK ensure.
	- Writes new/updated exports back to split settings only (no legacy file).
	- No longer sets or preserves any `Mode: Override` tag; only `Application: FinlytHub` is used when tagging.

4) Cleanup – Interactive export/resource cleanup
- File: `03_cleanup_finlythub.py`
- Run:
	```bash
	python 03_cleanup_finlythub.py
	```
- Features:
	- Lists exports across selected scopes with width-aware tables.
	- Validates referenced storage accounts (optional).
	- Deletes chosen exports and updates split settings accordingly.
	- Optionally deletes tagged resources (Application=FinlytHub).

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
