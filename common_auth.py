# common_auth.py
# Copyright (c) Finlyt
# Licensed under MIT License
#
# Provides centralized authentication for all Finlyt setup scripts.

import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient


def get_credentials():
    """
    Returns a credential object usable by Azure SDK clients.
    Uses DefaultAzureCredential which tries (in order):
      - Environment variables (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET)
      - Managed Identity (if running inside Azure)
      - Azure CLI (az login)
      - Visual Studio / PowerShell
    """
    try:
        return DefaultAzureCredential(exclude_interactive_browser_credential=False)
    except Exception as e:
        raise RuntimeError(f"Failed to acquire Azure credentials: {e}")


def list_subscriptions():
    """
    Returns a list of subscriptions the current identity has access to.
    """
    creds = get_credentials()
    client = SubscriptionClient(creds)

    subs = []
    for sub in client.subscriptions.list():
        subs.append({
            "subscription_id": sub.subscription_id,
            "display_name": sub.display_name,
            "state": sub.state
        })
    return subs


if __name__ == "__main__":
    # Quick test: list subscriptions
    print("Testing authentication...")
    try:
        subs = list_subscriptions()
        if not subs:
            print("No subscriptions found. Did you run 'az login'?")
        else:
            print("Accessible subscriptions:")
            for s in subs:
                print(f"  {s['display_name']} ({s['subscription_id']}) - {s['state']}")
    except Exception as e:
        print(f"Authentication failed: {e}")
