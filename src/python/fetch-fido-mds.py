#!/usr/bin/env python3
"""Download FIDO Alliance Metadata Service (MDS) data.

Downloads the raw MDS3 JWT blob and the Metadata Convenience Service (c-MDS) JSON.
Files are only written when their content has changed since the last download.

Outputs (in data/fidoalliance.org_metadata_service/):
    YYYYMMDD_mds3.blob  — raw MDS3 JWT blob
    YYYYMMDD_cmds.json  — Metadata Convenience Service data
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import aiohttp

OUTPUT_DIR = Path("data/fidoalliance.org_metadata_service/journal/")
MDS3_URL = "https://mds3.fidoalliance.org/"
CMDS_URL = "https://c-mds.fidoalliance.org/"


async def download_mds3_blob(session: aiohttp.ClientSession) -> str:
    """Download the raw MDS3 JWT blob.

    Args:
        session: Active aiohttp client session.

    Returns:
        Raw JWT string (three base64url-encoded parts joined by '.').
    """
    async with session.get(MDS3_URL) as resp:
        resp.raise_for_status()
        return await resp.text()


async def download_cmds(session: aiohttp.ClientSession) -> dict[str, Any]:
    """Download the Metadata Convenience Service JSON.

    Args:
        session: Active aiohttp client session.

    Returns:
        Parsed JSON dict mapping AAGUID strings to display metadata.
    """
    async with session.get(CMDS_URL) as resp:
        resp.raise_for_status()
        return await resp.json(content_type=None)


def _load_most_recent(suffix: str) -> str | None:
    """Return the text of the most recently dated file matching *{suffix} in OUTPUT_DIR.

    Files are expected to be named YYYYMMDD{suffix}. The most recent is determined
    by sorting filenames descending (lexicographic order is correct for YYYYMMDD).
    Returns None if no matching file exists.
    """
    matches = sorted(OUTPUT_DIR.glob(f"*{suffix}"), reverse=True)
    if not matches:
        return None
    return matches[0].read_text()


def _save_if_changed(path: Path, text: str, suffix: str, label: str) -> bool:
    """Write text to path only if it differs from the most recent existing file.

    Args:
        path: Destination path (YYYYMMDD-prefixed filename).
        text: Content to write.
        suffix: Filename suffix used to find the most recent previous file.
        label: Human-readable name for log messages.

    Returns:
        True if the file was written, False if data was unchanged.
    """
    existing = _load_most_recent(suffix)
    if existing == text:
        print(f"[INFO] {label} unchanged since last download, skipping save", file=sys.stderr)
        return False
    path.write_text(text)
    return True


async def main() -> None:
    """Download and save FIDO MDS and c-MDS data."""
    datestamp = datetime.now().strftime("%Y%m%d")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    async with aiohttp.ClientSession() as session:
        # MDS3 JWT blob
        print(f"[INFO] Downloading MDS3 JWT blob from {MDS3_URL}", file=sys.stderr)
        try:
            blob = await download_mds3_blob(session)
        except Exception as exc:
            print(f"[ERROR] Failed to download MDS3 blob: {exc}", file=sys.stderr)
            sys.exit(1)

        blob_path = OUTPUT_DIR / f"{datestamp}_mds3.blob"
        if _save_if_changed(blob_path, blob, "_mds3.blob", "MDS3 blob"):
            print(f"[INFO] Saved MDS3 blob → {blob_path}", file=sys.stderr)

        # Metadata Convenience Service
        print(f"[INFO] Downloading Metadata Convenience Service from {CMDS_URL}", file=sys.stderr)
        try:
            cmds_data = await download_cmds(session)
        except Exception as exc:
            print(f"[ERROR] Failed to download c-MDS data: {exc}", file=sys.stderr)
            sys.exit(1)

        cmds_path = OUTPUT_DIR / f"{datestamp}_cmds.json"
        cmds_text = json.dumps(cmds_data, indent=2)
        if _save_if_changed(cmds_path, cmds_text, "_cmds.json", "c-MDS data"):
            print(
                f"[INFO] Saved c-MDS data ({len(cmds_data)} entries) → {cmds_path}",
                file=sys.stderr,
            )


if __name__ == "__main__":
    asyncio.run(main())
