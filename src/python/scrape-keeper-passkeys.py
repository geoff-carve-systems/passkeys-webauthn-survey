#!/usr/bin/env python3
"""Scrape the Keeper Security passkeys directory and download logo images.

Parses the static HTML at keepersecurity.com/passkeys-directory/, extracts
brand entries, downloads their logo images, and writes an inventory JSON.

The page embeds all data directly in the HTML as data-* attributes on .brand
div elements — no JavaScript rendering is required.

Outputs (in data/keepersecurity.com_passkeys-directory/):
    <filename>.png/.svg/...  — downloaded brand logo images
    inventory.json           — metadata for each entry
"""

import asyncio
import html
import json
import re
import sys
from pathlib import Path
from typing import Any

import aiohttp

TARGET_URL = "https://www.keepersecurity.com/passkeys-directory/"
OUTPUT_DIR = Path("data/keepersecurity.com_passkeys-directory")
IMAGES_DIR = OUTPUT_DIR / "images"
INVENTORY_FILE = "inventory.json"

FILTER_LABELS: dict[str, str] = {
    "signIn": "Sign-In Method",
    "mfa": "MFA",
}


def parse_brands(page_html: str) -> list[dict[str, Any]]:
    """Extract brand entries from the page HTML.

    Each .brand div carries data-name, data-cat, data-filter, and an img src.
    Supported methods are derived from the space-separated data-filter value.

    Args:
        page_html: Raw HTML of the passkeys directory page.

    Returns:
        List of dicts with keys: company, image_url, category, supported.
    """
    brand_pattern = re.compile(
        r'<div class="brand"'
        r'[^>]*data-cat="(?P<cat>[^"]*)"'
        r'[^>]*data-filter="(?P<filter>[^"]*)"'
        r'[^>]*data-name="(?P<name>[^"]*)"'
        r'[^>]*>.*?<img[^>]+src="(?P<src>[^"]+)"',
        re.DOTALL,
    )

    brands = []
    for m in brand_pattern.finditer(page_html):
        filter_tokens = m.group("filter").split()
        supported = [FILTER_LABELS[t] for t in filter_tokens if t in FILTER_LABELS]
        brands.append(
            {
                "company": html.unescape(m.group("name")),
                "image_url": m.group("src"),
                "category": html.unescape(m.group("cat")),
                "supported": supported,
            }
        )
    return brands


def filename_from_url(url: str) -> str:
    """Extract the bare filename from an image URL."""
    return Path(url.split("?")[0]).name


def load_inventory(path: Path) -> list[dict[str, Any]]:
    """Load existing inventory JSON, returning an empty list on missing/corrupt file.

    Args:
        path: Path to inventory.json.

    Returns:
        List of existing inventory entries.
    """
    if not path.exists():
        return []
    try:
        inventory: list[dict[str, Any]] = json.loads(path.read_text())
        print(f"[INFO] Loaded existing inventory with {len(inventory)} entries", file=sys.stderr)
        return inventory
    except Exception as exc:
        print(f"[WARN] Could not read existing inventory: {exc}", file=sys.stderr)
        return []


def save_inventory(path: Path, inventory: list[dict[str, Any]], added: int) -> None:
    """Write inventory to JSON, sorted by image filename (case-insensitive).

    Args:
        path: Destination path.
        inventory: Full list of entries to write.
        added: Count of newly added entries (for logging).
    """
    sorted_inv = sorted(inventory, key=lambda e: e["image"].lower())
    path.write_text(json.dumps(sorted_inv, indent=2, ensure_ascii=False))
    print(
        f"[INFO] Saved inventory with {len(inventory)} entries ({added} new) → {path}",
        file=sys.stderr,
    )


async def download_image(
    session: aiohttp.ClientSession, url: str, dest: Path
) -> None:
    """Download a binary image from url to dest.

    Args:
        session: Active aiohttp client session.
        url: Image URL.
        dest: Local destination path.

    Raises:
        aiohttp.ClientResponseError: On HTTP errors.
    """
    async with session.get(url) as resp:
        resp.raise_for_status()
        dest.write_bytes(await resp.read())


async def main() -> None:
    """Scrape the Keeper passkeys directory and download brand logos."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    IMAGES_DIR.mkdir(exist_ok=True)

    async with aiohttp.ClientSession() as session:
        print(f"[INFO] Fetching {TARGET_URL}", file=sys.stderr)
        async with session.get(TARGET_URL) as resp:
            resp.raise_for_status()
            page_html = await resp.text()

        brands = parse_brands(page_html)
        if not brands:
            print("[ERROR] No brand entries found — page structure may have changed", file=sys.stderr)
            sys.exit(1)
        print(f"[INFO] Found {len(brands)} brand entries", file=sys.stderr)

        inventory_path = OUTPUT_DIR / INVENTORY_FILE
        inventory = load_inventory(inventory_path)
        inventory_map = {e["image"]: e for e in inventory}

        downloaded = skipped = added = 0
        total = len(brands)

        for i, brand in enumerate(brands, 1):
            url = brand["image_url"]
            filename = filename_from_url(url)
            dest = IMAGES_DIR / filename

            if dest.exists():
                print(f"[{i}/{total}] Skip (exists): {filename}", file=sys.stderr)
                skipped += 1
            else:
                try:
                    print(f"[{i}/{total}] Downloading: {filename}", file=sys.stderr)
                    await download_image(session, url, dest)
                    downloaded += 1
                except Exception as exc:
                    print(f"[WARN] Failed to download {url}: {exc}", file=sys.stderr)
                    continue

            if filename not in inventory_map:
                entry: dict[str, Any] = {
                    "image": filename,
                    "company": brand["company"],
                    "category": brand["category"],
                    "supported": brand["supported"],
                    "frontpage_url": None,
                }
                inventory.append(entry)
                inventory_map[filename] = entry
                added += 1

        save_inventory(inventory_path, inventory, added)
        print(
            f"[INFO] Done — downloaded {downloaded}, skipped {skipped}, "
            f"{added} new inventory entries",
            file=sys.stderr,
        )


if __name__ == "__main__":
    asyncio.run(main())
