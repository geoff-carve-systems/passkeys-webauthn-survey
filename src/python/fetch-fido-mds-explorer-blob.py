#!/usr/bin/env python3
"""Download mds.blob from opotonniee/fido-mds-explorer on GitHub.

Fetches the file at a specific commit, defaulting to the most recent. Use --commit N
to go back N commits (0 = current, 1 = previous, 2 = two commits ago, etc.).

Output filenames are prefixed with the commit date: YYYYMMDD_mds.blob.

Outputs (in data/github.com_opotonniee_fido-mds-explorer/):
    YYYYMMDD_mds.blob  — FIDO MDS JWT blob
"""

import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

REPO = "opotonniee/fido-mds-explorer"
GITHUB_API = "https://api.github.com"
RAW_BASE = "https://raw.githubusercontent.com"
OUTPUT_DIR = Path("data/github.com_opotonniee_fido-mds-explorer/journal/")
FILES = ["mds.blob"]


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed namespace with a ``commit`` integer attribute.
    """
    parser = argparse.ArgumentParser(
        description="Download FIDO MDS blob from GitHub at a specific commit offset."
    )
    parser.add_argument(
        "--commit",
        "-n",
        type=int,
        default=0,
        metavar="N",
        help="Commit offset: 0=current (default), 1=previous, 2=two commits ago, etc.",
    )
    return parser.parse_args()


async def fetch_commit(session: aiohttp.ClientSession, offset: int) -> tuple[str, datetime]:
    """Fetch the SHA and date of the commit at the given offset from HEAD.

    GitHub's API caps per_page at 100, so large offsets require fetching the
    appropriate page (page = offset // 100 + 1, index = offset % 100).

    Args:
        session: Active aiohttp client session.
        offset: How many commits back from the most recent (0 = latest).

    Returns:
        Tuple of (commit SHA, commit datetime in UTC).

    Raises:
        ValueError: If the requested offset exceeds available commits.
        aiohttp.ClientResponseError: On HTTP errors.
    """
    url = f"{GITHUB_API}/repos/{REPO}/commits"
    page = offset // 100 + 1
    index_in_page = offset % 100
    params = {"per_page": 100, "page": page}
    print(
        f"[INFO] Fetching commit list from {url} (offset={offset}, page={page}, index={index_in_page})",
        file=sys.stderr,
    )

    async with session.get(url, params=params) as resp:
        resp.raise_for_status()
        commits = await resp.json()

    if len(commits) <= index_in_page:
        raise ValueError(
            f"Requested commit offset {offset} (page {page}, index {index_in_page}) "
            f"but page only returned {len(commits)} commit(s). "
            "The repository history may not go back that far."
        )

    entry = commits[index_in_page]
    sha = entry["sha"]
    date_str = entry["commit"]["committer"]["date"]
    commit_dt = datetime.fromisoformat(date_str.replace("Z", "+00:00")).astimezone(timezone.utc)
    print(f"[INFO] Selected commit {sha[:12]} dated {commit_dt.date().isoformat()}", file=sys.stderr)
    return sha, commit_dt


async def download_file(session: aiohttp.ClientSession, sha: str, filename: str) -> str:
    """Download a raw file from the repository at the given commit SHA.

    Args:
        session: Active aiohttp client session.
        sha: Full commit SHA.
        filename: Filename relative to the repo root.

    Returns:
        File contents as a string.

    Raises:
        aiohttp.ClientResponseError: On HTTP errors.
    """
    url = f"{RAW_BASE}/{REPO}/{sha}/{filename}"
    print(f"[INFO] Downloading {url}", file=sys.stderr)
    async with session.get(url) as resp:
        resp.raise_for_status()
        return await resp.text()


def _most_recent_text(suffix: str) -> str | None:
    """Return the text of the most recently dated file matching *{suffix} in OUTPUT_DIR.

    Files are expected to be named YYYYMMDD{suffix}. Returns None if none exist.
    """
    matches = sorted(OUTPUT_DIR.glob(f"*{suffix}"), reverse=True)
    if not matches:
        return None
    return matches[0].read_text()


def save_if_changed(path: Path, text: str, suffix: str, label: str) -> bool:
    """Write text to path only if it differs from the most recent existing file.

    This works correctly as long as you download oldest files first. It will
    be unreliable if you are trying to backfill data when more a recent file exists.

    Args:
        path: Destination path (YYYYMMDD-prefixed filename).
        text: Content to write.
        suffix: Filename suffix used to find the most recent previous file.
        label: Human-readable name for log messages.

    Returns:
        True if the file was written, False if data was unchanged.
    """
    existing = _most_recent_text(suffix)
    if existing == text:
        print(f"[INFO] {label} unchanged since last download, skipping save", file=sys.stderr)
        return False
    path.write_text(text)
    print(f"[INFO] Saved {label} → {path}", file=sys.stderr)
    return True


async def main() -> None:
    """Download FIDO MDS blob from GitHub at the requested commit offset."""
    args = parse_args()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            sha, commit_dt = await fetch_commit(session, args.commit)
        except Exception as exc:
            print(f"[ERROR] Failed to fetch commit info: {exc}", file=sys.stderr)
            sys.exit(1)

        datestamp = commit_dt.strftime("%Y%m%d")

        for filename in FILES:
            try:
                text = await download_file(session, sha, filename)
            except aiohttp.ClientResponseError as exc:
                if exc.status == 404:
                    print(
                        f"[WARN] {filename} not found at commit {sha[:12]} (may not exist yet), skipping",
                        file=sys.stderr,
                    )
                    continue
                print(f"[ERROR] Failed to download {filename}: {exc}", file=sys.stderr)
                sys.exit(1)
            except Exception as exc:
                print(f"[ERROR] Failed to download {filename}: {exc}", file=sys.stderr)
                sys.exit(1)

            out_path = OUTPUT_DIR / f"{datestamp}_{filename}"
            save_if_changed(out_path, text, f"_{filename}", filename)


if __name__ == "__main__":
    asyncio.run(main())
