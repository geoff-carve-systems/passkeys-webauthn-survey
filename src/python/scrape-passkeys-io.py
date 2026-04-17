#!/usr/bin/env python3
"""Scrape the passkeys.io "who supports passkeys" directory.

Parses the static HTML at passkeys.io/who-supports-passkeys and extracts
company name and frontpage URL from each card entry. No images are present.

Each card contains:
  - company name  (div.p.bold)
  - frontpage URL (a.style-link href, null when href="#")

Outputs (in data/passkeys.io_who-supports-passkeys/):
    inventory.json  — one entry per company with company and frontpage_url
"""

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any

import aiohttp

TARGET_URL = "https://www.passkeys.io/who-supports-passkeys"
OUTPUT_DIR = Path("data/passkeys.io_who-supports-passkeys")
INVENTORY_FILE = "inventory.json"

# Matches a full card: extracts company name and href (may be "#")
_CARD_RE = re.compile(
    r'class="w-layout-cell card padding".*?'
    r'class="p line-hight bold">(?P<company>[^<]+)</div>'
    r'.*?'
    r'<a href="(?P<href>[^"]*)"[^>]*class="[^"]*style-link[^"]*">',
    re.DOTALL,
)


def parse_entries(page_html: str) -> list[dict[str, Any]]:
    """Extract company entries from the page HTML.

    Args:
        page_html: Raw HTML of the passkeys.io directory page.

    Returns:
        List of dicts with keys: company, frontpage_url.
    """
    entries = []
    for m in _CARD_RE.finditer(page_html):
        href = m.group("href")
        entries.append(
            {
                "company": m.group("company"),
                "frontpage_url": href if href != "#" else None,
            }
        )
    return entries


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
    """Write inventory to JSON, sorted by company name (case-insensitive).

    Args:
        path: Destination path.
        inventory: Full list of entries to write.
        added: Count of newly added entries (for logging).
    """
    sorted_inv = sorted(inventory, key=lambda e: e["company"].lower())
    path.write_text(json.dumps(sorted_inv, indent=2, ensure_ascii=False))
    print(
        f"[INFO] Saved inventory with {len(inventory)} entries ({added} new) → {path}",
        file=sys.stderr,
    )


async def main() -> None:
    """Scrape passkeys.io and save the company directory to inventory.json."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    async with aiohttp.ClientSession() as session:
        print(f"[INFO] Fetching {TARGET_URL}", file=sys.stderr)
        async with session.get(TARGET_URL) as resp:
            resp.raise_for_status()
            page_html = await resp.text()

    entries = parse_entries(page_html)
    if not entries:
        print("[ERROR] No entries found — page structure may have changed", file=sys.stderr)
        sys.exit(1)
    print(f"[INFO] Found {len(entries)} entries", file=sys.stderr)

    inventory_path = OUTPUT_DIR / INVENTORY_FILE
    inventory = load_inventory(inventory_path)
    inventory_map = {e["company"]: e for e in inventory}

    added = 0
    for entry in entries:
        if entry["company"] not in inventory_map:
            inventory.append(entry)
            inventory_map[entry["company"]] = entry
            added += 1

    save_inventory(inventory_path, inventory, added)


if __name__ == "__main__":
    asyncio.run(main())
