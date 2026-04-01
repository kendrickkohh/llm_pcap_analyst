#!/usr/bin/env python3
"""
copy_drive_files.py — Duplicate the SC4063 Drive folder 5 times.

Mirrors the exact structure:
    SC4063_copy_N/
    ├── shards/
    │   ├── 2025-03-01/
    │   │   ├── zeek/ (16 files)
    │   │   └── alerts.ndjson
    │   ├── ... (9 days)
    │   └── manifest.json
    ├── 34936-sensor-*.pcap  (flat at root)
    └── *.json bundles

Server-side copy only — no downloading.
"""

import json
import os
import sys
import time

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# ── Config ────────────────────────────────────────────────────────────────────

N_COPIES = 5
DELAY_PER_FILE = 2  # seconds between API copy calls (Drive rate limit is ~30/min)
SOURCE_FOLDER = "1VQ4pPjiKJGs16KVpJFg2weeoLrVWlkT2"
SCOPES = ["https://www.googleapis.com/auth/drive"]
TOKEN_FILE = "oauth-token.json"

# Skip "Copy of ..." files already in the source folder
SKIP_PREFIX = "Copy of "


def get_drive():
    creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())
    return build("drive", "v3", credentials=creds)


def list_children(drive, folder_id):
    """List all non-trashed children of a folder."""
    items = []
    page_token = None
    while True:
        resp = drive.files().list(
            q=f"'{folder_id}' in parents and trashed=false",
            fields="nextPageToken, files(id, name, mimeType, size)",
            pageSize=1000,
            orderBy="name",
            pageToken=page_token,
        ).execute()
        items.extend(resp.get("files", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return items


def scan_folder(drive, folder_id, path=""):
    """
    Recursively scan a folder. Returns a list of entries:
        [("folder", id, name, rel_path, 0, [children]),
         ("file",   id, name, rel_path, size, None)]
    """
    children = list_children(drive, folder_id)
    entries = []

    for item in children:
        name = item["name"]
        full_path = f"{path}/{name}" if path else name

        # Skip "Copy of ..." duplicates already in source
        if name.startswith(SKIP_PREFIX):
            continue

        if item["mimeType"] == "application/vnd.google-apps.folder":
            sub = scan_folder(drive, item["id"], full_path)
            entries.append(("folder", item["id"], name, full_path, 0, sub))
        else:
            size = int(item.get("size", 0))
            entries.append(("file", item["id"], name, full_path, size, None))

    return entries


def count_entries(entries):
    folders = 0
    files = 0
    total_bytes = 0
    for kind, _, _, _, size, children in entries:
        if kind == "folder":
            folders += 1
            sf, sfi, sb = count_entries(children)
            folders += sf
            files += sfi
            total_bytes += sb
        else:
            files += 1
            total_bytes += size
    return folders, files, total_bytes


def copy_tree(drive, entries, dest_parent_id, copy_num, counters):
    """Recursively copy entries into dest_parent_id."""
    for kind, src_id, name, rel_path, size, children in entries:
        if kind == "folder":
            # Create folder
            new_folder = drive.files().create(
                body={
                    "name": name,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [dest_parent_id],
                },
                fields="id",
            ).execute()
            new_id = new_folder["id"]
            counters["folders"] += 1
            time.sleep(0.1)

            # Recurse into children
            copy_tree(drive, children, new_id, copy_num, counters)
        else:
            # Copy file with retry on rate limit
            max_retries = 5
            for attempt in range(max_retries):
                try:
                    drive.files().copy(
                        fileId=src_id,
                        body={"name": name, "parents": [dest_parent_id]},
                        fields="id",
                    ).execute()
                    counters["files"] += 1
                    total = counters["total_files"]
                    done = counters["files"]
                    if done % 25 == 0 or size > 500_000_000:
                        size_str = f"{size / 1e6:.0f} MB" if size > 1e6 else f"{size / 1e3:.0f} KB"
                        print(f"    [{done}/{total}] {name}  ({size_str})")
                    break
                except HttpError as e:
                    if "userRateLimitExceeded" in str(e) or "rateLimitExceeded" in str(e):
                        wait = 2 ** (attempt + 1)
                        if attempt < max_retries - 1:
                            print(f"    [rate limit] {name} — waiting {wait}s (retry {attempt + 1})")
                            time.sleep(wait)
                            continue
                    counters["failed"] += 1
                    total = counters["total_files"]
                    print(f"    FAIL {name}: {e}")
                    break

            time.sleep(DELAY_PER_FILE)


def main():
    print("=" * 60)
    print(f"  SC4063 Drive Folder Copier — {N_COPIES} copies")
    print("=" * 60)

    drive = get_drive()

    # Check account
    about = drive.about().get(fields="user,storageQuota").execute()
    user = about["user"]["emailAddress"]
    quota = about.get("storageQuota", {})
    used_gb = int(quota.get("usage", 0)) / 1e9
    limit_gb = int(quota.get("limit", 0)) / 1e9
    print(f"  Account: {user}")
    print(f"  Storage: {used_gb:.1f} GB / {limit_gb:.0f} GB")

    # Scan source
    print(f"\nScanning source folder...")
    tree = scan_folder(drive, SOURCE_FOLDER)
    n_folders, n_files, total_bytes = count_entries(tree)
    total_gb = total_bytes / 1e9
    print(f"  {n_folders} folders, {n_files} files, {total_gb:.1f} GB")
    print(f"  {N_COPIES} copies = {total_gb * N_COPIES:.0f} GB needed")
    print(f"  Available: {limit_gb - used_gb:.0f} GB")

    if total_gb * N_COPIES > (limit_gb - used_gb):
        print(f"  WARNING: not enough storage for {N_COPIES} copies!")

    # Create copies
    results = []
    for i in range(1, N_COPIES + 1):
        print(f"\n{'=' * 60}")
        print(f"  Copy {i}/{N_COPIES}")
        print(f"{'=' * 60}")

        root = drive.files().create(
            body={"name": f"SC4063_copy_{i}", "mimeType": "application/vnd.google-apps.folder"},
            fields="id",
        ).execute()
        root_id = root["id"]

        # Share publicly
        drive.permissions().create(
            fileId=root_id,
            body={"type": "anyone", "role": "reader"},
        ).execute()

        url = f"https://drive.google.com/drive/folders/{root_id}"
        print(f"  Folder: {url}")

        counters = {"folders": 0, "files": 0, "failed": 0, "total_files": n_files}
        copy_tree(drive, tree, root_id, i, counters)

        print(f"\n  Done: {counters['files']} files, {counters['folders']} folders, {counters['failed']} failed")
        results.append({
            "copy": i,
            "folder_id": root_id,
            "url": url,
            "files": counters["files"],
            "folders": counters["folders"],
            "failed": counters["failed"],
        })

    # Summary
    print(f"\n{'=' * 60}")
    print(f"  ALL DONE")
    print(f"{'=' * 60}")
    for r in results:
        print(f"  Copy {r['copy']}: {r['files']} files — {r['url']}")

    with open("drive_copies.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Saved to drive_copies.json")


if __name__ == "__main__":
    main()
