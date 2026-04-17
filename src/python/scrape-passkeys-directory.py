#!/usr/bin/env python3
"""Scrape passkeys.directory for passkey support data.

All listing and detail data is fetched from the public Supabase REST API that
backs passkeys.directory in a single request — no browser rendering or
per-entry detail page fetching is required. Logo images are downloaded from
the 1Password icon CDN using the per-entry domain name.

Outputs (in data/passkeys.directory/):
    images/        — downloaded brand logo images ({domain}.png)
    inventory.json — one entry per site with all available metadata
"""

import asyncio
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp

INDEX_URL = "https://passkeys.directory/"

# Hardcoded fallback credentials (public anon key, safe to embed).
# The script attempts to scrape current values from the site's JS bundle first.
_FALLBACK_SUPABASE_URL = "https://apecbgwekadegtkzpwyh.supabase.co"
_FALLBACK_SUPABASE_ANON_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFwZWNiZ3dla2FkZWd0a3pwd3loIiwi"
    "cm9sZSI6ImFub24iLCJpYXQiOjE2Nzk1MjAyNTAsImV4cCI6MTk5NTA5NjI1MH0"
    ".n7Is0JnMPSgYxZz2zHrnCu9BNyDZ3tVKHuHeaOT1_s8"
)

IMAGE_CDN = "https://cache.agilebits.com/richicons/images/login/120/{domain}.png"
OUTPUT_DIR = Path("data/passkeys.directory_")
IMAGES_DIR = OUTPUT_DIR / "images"
INVENTORY_FILE = "inventory.json"

# Max simultaneous image downloads
_DOWNLOAD_CONCURRENCY = 20


def _supported(row: dict[str, Any]) -> list[str]:
    """Return the supported passkey methods for a row."""
    methods = []
    if row.get("passkey_signin"):
        methods.append("Sign In")
    if row.get("passkey_mfa"):
        methods.append("MFA")
    return methods


def _date_added(row: dict[str, Any]) -> str | None:
    """Return the ISO date string (YYYY-MM-DD) from the created_at timestamp."""
    created = row.get("created_at")
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        return dt.date().isoformat()
    except ValueError:
        return created


def row_to_entry(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a Supabase row into an inventory entry.

    Args:
        row: Raw row dict from the Supabase REST API.

    Returns:
        Inventory entry dict.
    """
    domain = row.get("domain") or ""
    return {
        "company": row.get("name"),
        "domain": domain,
        "image": f"{domain}.png" if domain else None,
        "frontpage_url": row.get("domain_full") or None,
        "supported": _supported(row),
        "category": row.get("category"),
        "date_added": _date_added(row),
        "setup_url": row.get("setup_link"),
        "additional_info_url": row.get("documentation_link"),
        "notes": row.get("notes"),
    }


async def scrape_supabase_credentials(
    session: aiohttp.ClientSession,
) -> tuple[str, str]:
    """Scrape the current Supabase URL and anon key from the site's JS bundle.

    Fetches the index page to find the app JS bundle URL, then searches the
    bundle for the supabaseUrl and supabaseKey values. Falls back to the
    hardcoded constants if extraction fails, logging a warning.

    Args:
        session: Active aiohttp client session.

    Returns:
        Tuple of (supabase_url, supabase_anon_key).
    """
    try:
        async with session.get(INDEX_URL) as resp:
            resp.raise_for_status()
            html = await resp.text()

        app_js = re.search(r'src="(/app-[^"]+\.js)"', html)
        if not app_js:
            raise ValueError("Could not find app JS bundle URL in index page")

        bundle_url = f"https://passkeys.directory{app_js.group(1)}"
        async with session.get(bundle_url) as resp:
            resp.raise_for_status()
            js = await resp.text()

        url_match = re.search(r'supabaseUrl:"(https://[^"]+)"', js)
        key_match = re.search(r'supabaseKey:"(eyJ[^"]+)"', js)
        if not url_match or not key_match:
            raise ValueError("Could not find supabaseUrl/supabaseKey in JS bundle")

        url = url_match.group(1)
        key = key_match.group(1)
    except Exception as exc:
        print(f"[WARN] Failed to scrape credentials, using fallback: {exc}", file=sys.stderr)
        return _FALLBACK_SUPABASE_URL, _FALLBACK_SUPABASE_ANON_KEY

    if url != _FALLBACK_SUPABASE_URL:
        print(f"[INFO] Supabase URL changed: {_FALLBACK_SUPABASE_URL!r} → {url!r}", file=sys.stderr)
    if key != _FALLBACK_SUPABASE_ANON_KEY:
        print("[INFO] Supabase anon key has changed from hardcoded fallback", file=sys.stderr)

    print(f"[INFO] Using Supabase URL: {url}", file=sys.stderr)
    return url, key


async def fetch_all_sites(
    session: aiohttp.ClientSession,
    supabase_url: str,
    supabase_key: str,
) -> list[dict[str, Any]]:
    """Fetch all approved passkey-supporting sites from the Supabase REST API.

    Args:
        session: Active aiohttp client session.
        supabase_url: Supabase project URL.
        supabase_key: Supabase anon key.

    Returns:
        List of raw row dicts.

    Raises:
        aiohttp.ClientResponseError: On HTTP errors.
    """
    url = f"{supabase_url}/rest/v1/sites"
    params = {
        "select": "*",
        "hidden": "eq.false",
        "or": "(passkey_signin.eq.true,passkey_mfa.eq.true)",
        "limit": "1000",
        "order": "name.asc",
    }
    headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
    }
    print("[INFO] Fetching site list from Supabase REST API", file=sys.stderr)
    async with session.get(url, params=params, headers=headers) as resp:
        resp.raise_for_status()
        return await resp.json()


async def download_image(
    session: aiohttp.ClientSession,
    domain: str,
    dest: Path,
    sem: asyncio.Semaphore,
) -> bool | None:
    """Download a logo image for a domain to dest.

    Args:
        session: Active aiohttp client session.
        domain: Site domain (used to build the CDN URL).
        dest: Destination file path.
        sem: Concurrency semaphore.

    Returns:
        True if downloaded, False if already exists, None if not available (404).
    """
    if dest.exists():
        return False
    url = IMAGE_CDN.format(domain=domain)
    async with sem:
        try:
            async with session.get(url) as resp:
                if resp.status == 404:
                    print(f"[WARN] No CDN image for {domain}, skipping", file=sys.stderr)
                    return None
                resp.raise_for_status()
                dest.write_bytes(await resp.read())
                return True
        except Exception as exc:
            print(f"[WARN] Failed to download image for {domain}: {exc}", file=sys.stderr)
            return None


def load_inventory(path: Path) -> list[dict[str, Any]]:
    """Load existing inventory JSON, returning an empty list on missing/corrupt file."""
    if not path.exists():
        return []
    try:
        inventory: list[dict[str, Any]] = json.loads(path.read_text())
        print(f"[INFO] Loaded existing inventory with {len(inventory)} entries", file=sys.stderr)
        return inventory
    except Exception as exc:
        print(f"[WARN] Could not read existing inventory: {exc}", file=sys.stderr)
        return []


def save_inventory(path: Path, inventory: list[dict[str, Any]], added: int, updated: int) -> None:
    """Write inventory sorted alphabetically by company name.

    Args:
        path: Destination path.
        inventory: Full list of entries to write.
        added: Count of newly added entries (for logging).
        updated: Count of updated entries (for logging).
    """
    sorted_inv = sorted(inventory, key=lambda e: (e.get("company") or "").lower())
    path.write_text(json.dumps(sorted_inv, indent=2, ensure_ascii=False))
    print(
        f"[INFO] Saved inventory with {len(inventory)} entries "
        f"({added} new, {updated} updated) → {path}",
        file=sys.stderr,
    )


async def main() -> None:
    """Fetch passkeys.directory data and download images."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    IMAGES_DIR.mkdir(exist_ok=True)

    async with aiohttp.ClientSession() as session:
        supabase_url, supabase_key = await scrape_supabase_credentials(session)

        try:
            rows = await fetch_all_sites(session, supabase_url, supabase_key)
        except Exception as exc:
            print(f"[ERROR] Failed to fetch site list: {exc}", file=sys.stderr)
            sys.exit(1)

        print(f"[INFO] Fetched {len(rows)} entries", file=sys.stderr)

        inventory_path = OUTPUT_DIR / INVENTORY_FILE
        inventory = load_inventory(inventory_path)
        inventory_map = {e["domain"]: e for e in inventory}

        added = updated = 0
        sem = asyncio.Semaphore(_DOWNLOAD_CONCURRENCY)
        image_tasks: list[tuple[str, asyncio.Task[bool | None]]] = []

        for row in rows:
            entry = row_to_entry(row)
            domain = entry["domain"]
            if not domain:
                continue

            if domain in inventory_map:
                existing = inventory_map[domain]
                # Preserve frontpage_url if already set; not overwritten on re-scrapes
                if existing.get("frontpage_url") is not None:
                    entry["frontpage_url"] = existing["frontpage_url"]
                prev = dict(existing)
                existing.update(entry)
                if existing != prev:
                    updated += 1
            else:
                inventory.append(entry)
                inventory_map[domain] = entry
                added += 1

            if entry["image"]:
                task = asyncio.ensure_future(
                    download_image(session, domain, IMAGES_DIR / entry["image"], sem)
                )
                image_tasks.append((domain, task))

        # Await all image downloads; null out image field when CDN has no image
        downloaded = skipped = unavailable = 0
        for domain, task in image_tasks:
            result = await task
            if result is True:
                downloaded += 1
            elif result is False:
                skipped += 1
            else:  # None — not available on CDN
                inventory_map[domain]["image"] = None
                unavailable += 1
        print(
            f"[INFO] Images: {downloaded} downloaded, {skipped} skipped, "
            f"{unavailable} unavailable (image set to null)",
            file=sys.stderr,
        )

        save_inventory(inventory_path, inventory, added, updated)


if __name__ == "__main__":
    asyncio.run(main())
