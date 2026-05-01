#!/usr/bin/env python3
"""Download aaguid.json and aaguid.json.schema from passkeydeveloper/passkey-authenticator-aaguids.

Fetches files at a specific commit, defaulting to the most recent. Use --commit N
to go back N commits (0 = current, 1 = previous, 2 = two commits ago, etc.).

Output filenames are prefixed with the commit date: YYYYMMDD_aaguid.json and
YYYYMMDD_aaguid.json.schema.

Outputs (in data/github.com_passkeydeveloper_passkey-authenticator-aaguids/):
    YYYYMMDD_aaguid.json         — AAGUID-to-authenticator metadata map
    YYYYMMDD_aaguid.json.schema  — JSON Schema for the above
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import aiohttp

REPO = "passkeydeveloper/passkey-authenticator-aaguids"
GITHUB_API = "https://api.github.com"
RAW_BASE = "https://raw.githubusercontent.com"
OUTPUT_DIR = Path("data/github.com_passkeydeveloper_passkey-authenticator-aaguids/journal/")
FILES = ["aaguid.json", "aaguid.json.schema"]


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed namespace with ``commit`` (int) and ``all`` (bool) attributes.
    """
    parser = argparse.ArgumentParser(
        description="Download passkey AAGUID data from GitHub at a specific commit offset."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--commit",
        "-n",
        type=int,
        default=0,
        metavar="N",
        help="Commit offset: 0=current (default), 1=previous, 2=two commits ago, etc.",
    )
    group.add_argument(
        "--all",
        action="store_true",
        help=(
            "Download all commits that touched aaguid.json since the most recently "
            "downloaded file in the output directory."
        ),
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


def most_recent_download_date() -> date | None:
    """Return the most recent YYYYMMDD date prefix from files in OUTPUT_DIR.

    Scans for files matching ``????????_aaguid.json`` and returns the maximum date.
    Returns None if no matching files exist.
    """
    matches = list(OUTPUT_DIR.glob("????????_aaguid.json"))
    if not matches:
        return None
    dates = []
    for p in matches:
        prefix = p.name[:8]
        try:
            dates.append(datetime.strptime(prefix, "%Y%m%d").date())
        except ValueError:
            continue
    return max(dates) if dates else None


async def fetch_blob_commits_since(
    session: aiohttp.ClientSession, since: date
) -> list[tuple[str, datetime]]:
    """Fetch all commits that modified aaguid.json on or after ``since`` (UTC).

    Pages through the GitHub Commits API using the ``path`` filter. Returns
    commits sorted oldest-first.

    Args:
        session: Active aiohttp client session.
        since: Start date (UTC midnight inclusive).

    Returns:
        List of (commit SHA, commit datetime in UTC), oldest first.
    """
    url = f"{GITHUB_API}/repos/{REPO}/commits"
    since_str = f"{since.isoformat()}T00:00:00Z"
    results: list[tuple[str, datetime]] = []
    page = 1
    while True:
        params = {"path": "aaguid.json", "since": since_str, "per_page": 100, "page": page}
        print(
            f"[INFO] Fetching blob commit list page {page} (since={since_str})",
            file=sys.stderr,
        )
        async with session.get(url, params=params) as resp:
            resp.raise_for_status()
            commits = await resp.json()
        if not commits:
            break
        for entry in commits:
            sha = entry["sha"]
            date_str = entry["commit"]["committer"]["date"]
            commit_dt = datetime.fromisoformat(date_str.replace("Z", "+00:00")).astimezone(
                timezone.utc
            )
            results.append((sha, commit_dt))
        if len(commits) < 100:
            break
        page += 1
    # API returns newest-first; reverse to oldest-first
    results.reverse()
    return results


def last_commit_per_day(
    commits: list[tuple[str, datetime]],
) -> list[tuple[str, datetime]]:
    """Keep only the last (latest) commit per UTC day.

    Args:
        commits: List of (sha, commit_dt) sorted oldest-first.

    Returns:
        One entry per day (the latest commit of that day), sorted oldest-first.
    """
    by_day: dict[date, tuple[str, datetime]] = {}
    for sha, commit_dt in commits:
        day = commit_dt.date()
        if day not in by_day or commit_dt > by_day[day][1]:
            by_day[day] = (sha, commit_dt)
    return sorted(by_day.values(), key=lambda x: x[1])


async def download_and_save(
    session: aiohttp.ClientSession, sha: str, commit_dt: datetime
) -> None:
    """Download all FILES at the given commit and save changed ones to OUTPUT_DIR.

    Args:
        session: Active aiohttp client session.
        sha: Full commit SHA.
        commit_dt: Commit datetime (UTC), used to build the YYYYMMDD filename prefix.
    """
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

        # Pretty-print JSON files; leave schema as-is if it's not valid JSON
        if filename.endswith(".json") and not filename.endswith(".schema"):
            try:
                text = json.dumps(json.loads(text), indent=2)
            except json.JSONDecodeError:
                pass

        out_path = OUTPUT_DIR / f"{datestamp}_{filename}"
        save_if_changed(out_path, text, f"_{filename}", filename)


async def main() -> None:
    """Download AAGUID files from GitHub at the requested commit offset."""
    args = parse_args()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with aiohttp.ClientSession(headers=headers) as session:
        if args.all:
            since = most_recent_download_date()
            if since is None:
                print(
                    "[ERROR] No existing downloads found in output directory. "
                    "Use -n to download an initial file before using --all.",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(f"[INFO] Fetching aaguid.json commits since {since.isoformat()} (UTC)", file=sys.stderr)
            try:
                commits = await fetch_blob_commits_since(session, since)
            except Exception as exc:
                print(f"[ERROR] Failed to fetch commit list: {exc}", file=sys.stderr)
                sys.exit(1)
            commits = last_commit_per_day(commits)
            if not commits:
                print("[INFO] Already up to date.", file=sys.stderr)
                return
            print(f"[INFO] {len(commits)} day(s) to process", file=sys.stderr)
            for sha, commit_dt in commits:
                print(
                    f"[INFO] Processing commit {sha[:12]} dated {commit_dt.date().isoformat()}",
                    file=sys.stderr,
                )
                await download_and_save(session, sha, commit_dt)
        else:
            try:
                sha, commit_dt = await fetch_commit(session, args.commit)
            except Exception as exc:
                print(f"[ERROR] Failed to fetch commit info: {exc}", file=sys.stderr)
                sys.exit(1)
            await download_and_save(session, sha, commit_dt)


if __name__ == "__main__":
    asyncio.run(main())
