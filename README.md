# Finops_rawdata

## Orchestrated Flow

Use `00_setup_finlythub.py` to automate detect + deploy.

### Quick start (auto mode)

```bash
python 00_setup_finlythub.py --auto
```

Behavior:
1. Runs detection (01) if `settings.json` missing.
2. Reads readiness flags from `settings.finlyt.cost_mgmt.can_setup_exports`.
3. If FinlytHub storage missing, deploys infra via Bicep and creates a default daily FOCUS export.
4. If storage exists but no `finlyt_focus_daily` export yet, creates it.
5. Skips deploy when already satisfied.

### Common options

```text
--force-detect       Re-run detection even if settings.json exists
--skip-detect        Assume existing settings.json is current
--force-deploy       Recreate export even if already present
--deploy-interactive Run 02_deploy_finlythub.py in interactive mode after detection
--dry-run            Show planned actions only
--scope-id           Override export scope (else use recommended/subscription)
--dest-subscription-id / --dest-rg  Provide infra targets when hub missing
```

### Example forcing infra + export

```bash
python 00_setup_finlythub.py --auto --force-detect --force-deploy
```

### Interactive deployment

```bash
python 00_setup_finlythub.py --deploy-interactive
```

The orchestrator is idempotent for the default export and will no-op when everything is already in place.
