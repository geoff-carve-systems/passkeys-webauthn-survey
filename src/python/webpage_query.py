#!/usr/bin/env python3
"""
Webpage Query Module

Provides functionality to query webpages and track referenced URLs.
"""

import argparse
import asyncio
import json
import pickle
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, NamedTuple, Set, Tuple
from html import unescape as _html_unescape
from urllib.parse import urljoin

import functools
import random
import string

import aiohttp
from playwright.async_api import Browser, async_playwright, Page
from urllib.parse import urlparse

OUTPUT_DIR = Path("data/analysis")

# Matches fetch('...') calls — captures the URL string literal.
_FETCH_URL_RE = re.compile(r"""fetch\s*\(\s*['"`]([^'"`\s]+)['"`]""")
# Keywords indicating a registration-related URL path.
_REGISTRATION_PATH_RE = re.compile(r"register|registration|attestation", re.I)
# Endpoint function classification — matched against the final path segment.
_OPTIONS_SEGMENT_RE = re.compile(r"options|begin|challenge|start|init", re.I)
_VERIFICATION_SEGMENT_RE = re.compile(r"verif|finish|complete|response|submit|assert|attest", re.I)

# WebAuthn JS patterns searched in every script (inline + external).
_WEBAUTHN_PATTERNS = re.compile(
    r"navigator\.credentials\.get"
    r"|navigator\.credentials\.create"
    r"|PublicKeyCredential"
    r"|navigator\.credentials\.store"
    r"|navigator\.credentials\.preventSilentAccess"
)
# Maximum number of page requests made by webauthn_javascript.
_WEBAUTHN_JS_MAX_REQUESTS = 10
# Maximum number of lazily-loaded webpack chunks webauthn_javascript will fetch.
_WEBAUTHN_JS_MAX_LAZY_CHUNKS = 100
# Maximum number of Vite/Rollup dynamic-import URLs webauthn_javascript will fetch.
_WEBAUTHN_JS_MAX_PENDING_URLS = 100
# Matches lowercase hex strings of typical webpack content hash lengths (8–32 chars).
_WEBPACK_HEX_HASH = re.compile(r"^[0-9a-f]{8,32}$")
# Maximum number of page requests made by http_crawl2.
_HTTP_CRAWL2_MAX_REQUESTS = 20
# Maximum number of page requests made by http_crawl3.
_HTTP_CRAWL3_MAX_REQUESTS = 20
# Timeout in milliseconds for Playwright page navigation and network operations.
_PLAYWRIGHT_TIMEOUT_MS = 10_000
# <link rel> values whose href points to a navigable same-origin page.
_LINK_REL_FOLLOW: frozenset[str] = frozenset({"alternate", "canonical", "next", "prev"})
# Segments matching this pattern are treated as auth-related in UrlTree.__iter__
# and visited before non-matching segments (100x child_count penalty for non-matches).
_ITER_AUTH_SEGMENTS = re.compile(
    r"account|login|signin|sign-in|register|registration|auth|checkout|"
    r"profile|password|credential|passkey|webauthn|fido|mfa|2fa|"
    r"verify|verification|security|identity|session",
    re.I,
)
# First DNS-label values that identify auth/identity subdomains (e.g. id.atlassian.com).
# Used in UrlTree.__iter__ to prioritise DomainNodes for auth subdomains.
_ITER_AUTH_SUBDOMAIN_LABELS: frozenset[str] = frozenset({
    "id", "ids", "identity", "sso", "auth", "login", "account", "accounts",
    "signin", "signup", "register", "secure", "pass",
})


def _netloc_matches_base_domain(netloc: str, base_domain: str) -> bool:
    """Return True if netloc is exactly base_domain or a subdomain of it."""
    host = netloc.split(":")[0]
    return host == base_domain or host.endswith("." + base_domain)


# Button text / aria-label patterns that suggest auth-related actions.
# Used in _extract_links_js_click_nav to find buttons worth clicking.
_AUTH_BUTTON_KEYWORDS = re.compile(
    r"sign[\s\-]?in|sign[\s\-]?up|sign[\s\-]?on|"
    r"log[\s\-]?in|log[\s\-]?on|log[\s\-]?out|"
    r"register|registration|"
    r"create\s+account|new\s+account|open\s+account|"
    r"get\s+started|"
    r"join|"
    r"passkey|webauthn|fido|"
    r"forgot\s+password|reset\s+password|"
    r"two[\s\-]?factor|2fa|mfa|"
    r"verify|verification|"
    r"authenticate|authentication|"
    r"my\s+account|your\s+account|"
    r"password|credential",
    re.I,
)

# Sensible probe defaults for fields commonly required by registration options endpoints.
# Used to enrich a request body after a 400 validation-error response.
_WEBAUTHN_FIELD_DEFAULTS: Dict[str, Any] = {
    # snake_case (Django / Python frameworks)
    "user_verification": "preferred",
    "attestation": "none",
    "attachment": "platform",
    "discoverable_credential": "preferred",
    "algorithms": [-7, -257],
    # camelCase (Node / Go / Java frameworks)
    "userVerification": "preferred",
    "attestationConveyancePreference": "none",
    "authenticatorAttachment": "platform",
    "residentKey": "preferred",
    "requireResidentKey": False,
}


@functools.lru_cache(maxsize=1)
def _test_params() -> Dict[str, Any]:
    """Return common test parameters for WebAuthn probing. Generated once per process."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return {"username": f"gdrobinson_{suffix}"}


def _strip_transient_keys(obj: Any) -> Any:
    """Recursively remove keys starting with '_' from dicts.

    Pipeline steps may attach transient data under underscore-prefixed keys for
    use by downstream steps. This helper strips those keys before JSON serialization.
    """
    if isinstance(obj, dict):
        return {k: _strip_transient_keys(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [_strip_transient_keys(item) for item in obj]
    return obj


async def _fetch_or_load(
    session: aiohttp.ClientSession,
    url: str,
    cache_dir: Path | None,
) -> tuple[str, int] | None:
    """Return (content, status) for url, using cache_dir when available.

    Cache hit: reads from disk, returns (content, 200).
    Cache miss: fetches via HTTP, writes to cache on ok response, returns
    (content, status). Returns None if the request raises an exception.
    """
    if cache_dir is not None:
        cache_file = cache_dir / _url_to_cache_path(url)
        if cache_file.exists():
            print(f"[INFO] http_sitemap: {url} loaded from cache", file=sys.stderr)
            return cache_file.read_text(), 200
    else:
        cache_file = None
    try:
        async with session.get(url) as resp:
            content = await resp.text()
            if resp.ok and cache_file is not None:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(content)
            return content, resp.status
    except Exception as exc:
        print(f"[WARN] http_sitemap: could not fetch {url}: {exc}", file=sys.stderr)
        return None


def _url_to_cache_path(url: str) -> Path:
    """Return a relative Path mirroring the URL's path hierarchy.

    The path segments are used as-is for directories and filename.
    A query string, if present, is appended to the filename with a '_' separator,
    with non-safe characters replaced by underscores.
    """
    parsed = urlparse(url)
    # Strip leading slash and split into segments; fall back to 'index' for root.
    segments = [s for s in parsed.path.split("/") if s]
    if not segments:
        segments = ["index"]
    rel = Path(*segments)
    if parsed.query:
        q_slug = re.sub(r'[^a-zA-Z0-9._-]', '_', parsed.query)
        q_slug = re.sub(r'_+', '_', q_slug).strip('_')
        rel = rel.parent / f"{rel.name}_{q_slug}"
    return rel


async def http_redirect(
    target_url: str,
    prior_results: Dict[str, Any] | None = None,
    cache_dir: Path | None = None,
) -> Dict[str, Any]:
    """Follow redirects from target_url and publish the resolved URL.

    Makes a single GET request with redirect following. The final URL is
    stored as resolved_url for use by downstream pipeline steps.

    If a prior result already exists in prior_results (pre-loaded from cache),
    skips the request and returns the existing result unchanged.

    Args:
        target_url: The URL to resolve.
        prior_results: Accumulated pipeline results. If "http_redirect" is
            already present, this function is a no-op.
        cache_dir: Unused.

    Returns:
        Dict with "http_redirect" key containing:
          url: final resolved URL after all redirects.
          http_status: HTTP status code of the final response.
          redirect_chain: list of intermediate URLs (empty if no redirects).
          resolved_url: alias for url; used by downstream pipeline steps.
    """
    prior = (prior_results or {}).get("http_redirect")
    if prior is not None:
        print(f"[INFO] http_redirect: using cached result ({prior.get('summary', '')})", file=sys.stderr)
        return {"http_redirect": prior}

    print(f"[INFO] http_redirect: resolving {target_url}", file=sys.stderr)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, allow_redirects=True) as resp:
                final_url = str(resp.url)
                http_status = resp.status
                redirect_chain = [str(r.url) for r in resp.history]
    except Exception as exc:
        print(f"[WARN] http_redirect: request failed: {exc}", file=sys.stderr)
        final_url = target_url
        http_status = None
        redirect_chain = []

    if redirect_chain:
        summary = f"{len(redirect_chain)} redirect(s): {final_url}"
    else:
        summary = f"no redirects, resolved to {final_url}"
    print(f"[INFO] http_redirect: {summary}", file=sys.stderr)

    return {
        "http_redirect": {
            "redirect_chain": redirect_chain,
            "resolved_url": final_url,
            "http_status": http_status,
            "summary": summary,
        },
    }


async def http_sitemap(
    target_url: str,
    prior_results: Dict[str, Any] | None = None,
    cache_dir: Path | None = None,
) -> Dict[str, Any]:
    """Fetch robots.txt and XML sitemaps, recording raw content and extracted URLs.

    Fetches /robots.txt and extracts Sitemap: directives. Also tries /sitemap.xml
    and /sitemap_index.xml as defaults. Parses <loc> tags from all XML sitemaps,
    following sitemap index files to their children (full BFS, cycle-safe).

    If a prior result already exists in prior_results (pre-loaded from cache),
    skips all fetching and returns the existing result unchanged.

    Args:
        target_url: The frontpage URL; used to derive the site origin.
        prior_results: Accumulated pipeline results. If "http_sitemap" is
            already present, this function is a no-op.
        cache_dir: Cache directory for HTTP responses.

    Returns:
        Dict with "http_sitemap" key containing:
          robots_txt: {url, status} or null if not found/accessible.
          sitemaps: list of {url, status, is_index} for each sitemap fetched.
                    _page_urls (transient): loc URLs parsed from each sitemap;
                    is_index=True entries list child sitemap URLs instead of page URLs.
          summary: human-readable summary string.
    """
    prior = (prior_results or {}).get("http_sitemap")
    if prior is not None:
        print(f"[INFO] http_sitemap: using cached result ({prior.get('summary', '')})", file=sys.stderr)
        return {"http_sitemap": prior}

    effective_url = (
        (prior_results or {}).get("http_redirect", {}).get("resolved_url")
        or target_url
    )
    parsed = urlparse(effective_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    robots_url = f"{origin}/robots.txt"
    robots_result = None
    sitemap_urls_from_robots: List[str] = []

    async with aiohttp.ClientSession() as session:
        # 1. Fetch robots.txt and extract Sitemap: directives.
        print(f"[INFO] http_sitemap: fetching {robots_url}", file=sys.stderr)
        fetched = await _fetch_or_load(session, robots_url, cache_dir)
        if fetched is not None:
            content, status = fetched
            robots_result = {"url": robots_url, "status": status}
            if status == 200:
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.lower().startswith("sitemap:"):
                        sitemap_url = stripped.split(":", 1)[1].strip()
                        if sitemap_url:
                            sitemap_urls_from_robots.append(sitemap_url)
            print(
                f"[INFO] http_sitemap: robots.txt status={status}, "
                f"{len(sitemap_urls_from_robots)} sitemap directive(s)",
                file=sys.stderr,
            )

        # 2. Build queue: robots.txt sitemaps first, then well-known defaults.
        default_sitemaps = [f"{origin}/sitemap.xml", f"{origin}/sitemap_index.xml"]
        seen_sitemap_urls: Set[str] = set(sitemap_urls_from_robots)
        queue: List[str] = list(sitemap_urls_from_robots)
        for u in default_sitemaps:
            if u not in seen_sitemap_urls:
                seen_sitemap_urls.add(u)
                queue.append(u)

        # 3. BFS over sitemaps; sitemap index entries enqueue their children.
        sitemaps: List[Dict[str, Any]] = []
        while queue:
            url = queue.pop(0)
            print(f"[INFO] http_sitemap: fetching sitemap {url}", file=sys.stderr)
            fetched = await _fetch_or_load(session, url, cache_dir)
            if fetched is None:
                continue
            content, status = fetched
            if status != 200:
                print(f"[INFO] http_sitemap: {url} status={status}, skipping", file=sys.stderr)
                sitemaps.append({"url": url, "status": status, "is_index": False, "_page_urls": []})
                continue

            loc_urls = re.findall(r"<loc>\s*(.*?)\s*</loc>", content, re.I | re.S)
            is_index = bool(re.search(r"<sitemapindex", content, re.I))

            if is_index:
                for child in loc_urls:
                    if child not in seen_sitemap_urls:
                        seen_sitemap_urls.add(child)
                        queue.append(child)
                print(
                    f"[INFO] http_sitemap: {url} is sitemap index ({len(loc_urls)} child sitemap(s))",
                    file=sys.stderr,
                )
            else:
                print(f"[INFO] http_sitemap: {url} status={status}, {len(loc_urls)} URL(s)", file=sys.stderr)
            sitemaps.append({"url": url, "status": status, "is_index": is_index, "_page_urls": loc_urls})

    total_urls = sum(len(s.get("_page_urls", [])) for s in sitemaps if not s.get("is_index"))
    found_sitemaps = [s for s in sitemaps if s.get("status") == 200]
    robots_found = 1 if (robots_result and robots_result.get("status") == 200) else 0
    summary = f"{robots_found} robots.txt, {len(found_sitemaps)} sitemap(s), {total_urls} page URL(s)"
    print(f"[INFO] http_sitemap: {summary}", file=sys.stderr)
    return {"http_sitemap": {"robots_txt": robots_result, "sitemaps": sitemaps, "summary": summary}}


class UrlTree:
    """URL path tree for a single website origin.

    Organizes candidate URLs into a hierarchy mirroring the site's path
    structure. Supports incremental extension via repeated `extend` calls
    without double-counting aggregate counters.

    Args:
        origin: The scheme+netloc to scope to (e.g. "https://www.example.com").

    Attributes:
        origin: The origin this tree is scoped to.
        root: Root Node representing "/".
    """

    class RootNode:
        """Root of the URL tree, representing the registered base domain (e.g. example.com)

        Children are DomainNodes, one per FQDN added to the tree.
        base_url and queries are always None — present for uniform _recompute/validate.
        """

        def __init__(self, base_domain: str) -> None:
            self.depth = 0
            self.base_domain = base_domain
            self.base_url: str | None = None
            self.queries: "List[str | None] | None" = None
            self.child_count: int = 0
            self.child_page_count: int = 0
            self.child_query_count: int = 0
            self.children: "Dict[str, UrlTree.DomainNode]" = {}

    class DomainNode:
        """A node representing a single FQDN (e.g. id.example.com).

        Children are UrlTree.Nodes representing path segments.
        base_url and queries are always None — present for uniform _recompute/validate.

        Args:
            netloc: The FQDN (host[:port]) this node represents.
            depth: Distance from root (always 1).
        """

        def __init__(self, netloc: str) -> None:
            self.netloc = netloc
            self.depth = 1
            self.base_url: str | None = None
            self.queries: "List[str | None] | None" = None
            self.child_count: int = 0
            self.child_page_count: int = 0
            self.child_query_count: int = 0
            self.children: "Dict[str, UrlTree.Node]" = {}

    class Node:
        """A node in the URL path tree.

        Each node represents one path segment.
        Leaf nodes represent individual pages; intermediate nodes represent
        path directories.

        Args:
            segment: The URL path segment this node represents.
            depth: Distance from root (root = 0).
        """

        def __init__(self, segment: str, depth: int) -> None:
            self.segment = segment
            self.depth = depth
            self.child_count: int = 0
            self.child_page_count: int = 0
            self.child_query_count: int = 0
            self.base_url: str | None = None
            self.queries: List[str | None] | None = None
            self.request_index: Dict[str, int] | None = None
            self._query_set: Set[str | None] | None = None
            self.children: Dict[str, "UrlTree.Node"] = {}

        def add_query(self, base_url: str, query: str | None) -> bool:
            """Record a query variant for this node if not already present.

            Sets base_url on the first call. Appends the query string (or None
            for no query) only if it hasn't been seen before.

            Returns:
                True if a new variant was appended, False if it was a duplicate.
            """
            if self.base_url is None:
                self.base_url = base_url
                self.queries = []
                self.request_index = {}
                self._query_set = set()
            if query not in self._query_set:
                self._query_set.add(query)
                self.queries.append(query)
                return True
            return False

    class PendingNode(NamedTuple):
        """A node yielded by iter_pending, bundled with per-function index accessors."""

        node: "UrlTree.Node"
        get_index: Callable[[], int]
        increment: Callable[[], None]

    def __init__(self, target_url: str) -> None:
        parsed = urlparse(target_url)
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self._origin_netloc: str = parsed.netloc
        self._base_domain: str = ".".join(parsed.netloc.split(".")[-2:])
        self.root = UrlTree.RootNode(self._base_domain)
        self.target_url: "UrlTree.Node | None" = None
        self.extend([target_url])
        domain_node = self.root.children[parsed.netloc]
        segments = [s for s in parsed.path.split("/") if s] or ["/"]
        node: UrlTree.Node = domain_node.children[segments[0]]
        for seg in segments[1:]:
            node = node.children[seg]
        self.target_url = node

    @staticmethod
    def _recompute(node: Any) -> None:
        """Overwrite a node's aggregate counters from its direct children."""
        node.child_count = sum(1 + c.child_count for c in node.children.values())
        node.child_page_count = sum(
            (1 if c.base_url is not None else 0) + c.child_page_count
            for c in node.children.values()
        )
        node.child_query_count = sum(
            (len(c.queries) if c.queries is not None else 0) + c.child_query_count
            for c in node.children.values()
        )

    def extend(self, urls: List[str]) -> None:
        """Add URLs to the tree.

        Exploits sort order to avoid re-traversing shared path prefixes.
        Safe to call multiple times — aggregate counters are recomputed from
        children on backtrack rather than accumulated, so repeated calls do
        not double-count.

        Args:
            urls: Candidate page URLs (need not be pre-sorted).
        """
        stack: List[Any] = [self.root]

        for url in sorted(urls):
            parsed = urlparse(url)
            if not _netloc_matches_base_domain(parsed.netloc, self._base_domain):
                continue

            segments = [s for s in parsed.path.split("/") if s] or ["/"]

            # Ensure stack[1] is the correct DomainNode; drain and switch if netloc changed.
            current_netloc = stack[1].netloc if len(stack) > 1 else None
            if current_netloc != parsed.netloc:
                while len(stack) > 1:
                    UrlTree._recompute(stack.pop())
                if parsed.netloc not in self.root.children:
                    self.root.children[parsed.netloc] = UrlTree.DomainNode(parsed.netloc)
                stack.append(self.root.children[parsed.netloc])

            # Find how many leading path segments already match stack[2:].
            common = 0
            for i, seg in enumerate(segments):
                if i + 2 < len(stack) and stack[i + 2].segment == seg:
                    common += 1
                else:
                    break

            # Backtrack to the divergence point, recomputing each popped node.
            while len(stack) > common + 2:
                UrlTree._recompute(stack.pop())

            # Descend, creating new nodes as needed.
            for i in range(common, len(segments)):
                seg = segments[i]
                parent = stack[-1]
                if seg not in parent.children:
                    parent.children[seg] = UrlTree.Node(seg, depth=i + 2)
                stack.append(parent.children[seg])

            # Record query variant on the terminal node.
            actual_origin = f"{parsed.scheme}://{parsed.netloc}"
            stack[-1].add_query(
                f"{actual_origin}/{parsed.path.lstrip('/')}", parsed.query or None
            )

        # Drain remaining stack, then recompute root.
        while len(stack) > 1:
            UrlTree._recompute(stack.pop())
        UrlTree._recompute(self.root)

    def __iter__(self) -> Iterator["UrlTree.Node"]:
        """Yield all page nodes (base_url is not None) in DFS order.

        Each node is visited exactly once. Children are sorted by a penalised
        child_count before being pushed onto the LIFO stack: non-auth segments
        receive a 100x multiplier, so auth-keyword segments (_ITER_AUTH_SEGMENTS)
        are visited first unless an auth subtree is 100x larger than a non-auth
        sibling. Use iter_pending(fn_name) to filter to nodes with remaining work.
        """
        stack: List[Any] = [self.root]
        while stack:
            node = stack.pop()
            if isinstance(node, UrlTree.Node) and node.base_url is not None:
                yield node
            if isinstance(node, UrlTree.RootNode):
                def _sort_key(n: "UrlTree.DomainNode") -> int:
                    first_label = n.netloc.split(".")[0]
                    return n.child_count * (
                        1 if first_label in _ITER_AUTH_SUBDOMAIN_LABELS else 100
                    )
            else:
                def _sort_key(n: "UrlTree.Node") -> int:  # type: ignore[misc]
                    return n.child_count * (
                        1 if _ITER_AUTH_SEGMENTS.search(n.segment) else 100
                    )
            for child in sorted(node.children.values(), key=_sort_key, reverse=True):
                stack.append(child)

    def reset_pending(self, *, fn_name: str | None = None) -> None:
        """Clear the per-function request index for fn_name on every page node.

        After this call, iter_pending(fn_name) will yield all nodes as if the
        function had never run. fn_name defaults to the calling function's name.
        """
        if fn_name is None:
            fn_name = sys._getframe(1).f_code.co_name  # noqa: SLF001
        for node in self:
            if node.request_index:
                node.request_index.pop(fn_name, None)

    def iter_pending(self, *, fn_name: str | None = None) -> Iterator["UrlTree.PendingNode"]:
        """Yield PendingNode for each node with unprocessed queries for fn_name.

        fn_name defaults to the name of the calling function. Pass fn_name
        explicitly to override.

        Wraps __iter__ and skips nodes where the per-function request index
        has already reached the number of queries on the node.
        """
        if fn_name is None:
            fn_name = sys._getframe(1).f_code.co_name  # noqa: SLF001
        for node in self:
            idx = node.request_index.get(fn_name, 0) if node.request_index else 0
            if idx < len(node.queries):
                yield UrlTree.PendingNode(
                    node=node,
                    get_index=lambda n=node: n.request_index.get(fn_name, 0),
                    increment=lambda n=node: n.request_index.update(
                        {fn_name: n.request_index.get(fn_name, 0) + 1}
                    ),
                )

    def validate(self) -> None:
        """Assert that all aggregate counts on every node are correct.

        Raises:
            AssertionError: If any stored count does not match the computed value.
        """
        def _check(node: Any) -> Tuple[int, int, int]:
            """Return (nodes, pages, queries) for the subtree rooted at node."""
            label = getattr(node, "netloc", None) or getattr(node, "segment", "<root>")
            total_nodes = total_pages = total_queries = 0
            for child in node.children.values():
                c_nodes, c_pages, c_queries = _check(child)
                total_nodes += 1 + c_nodes
                total_pages += (1 if child.base_url is not None else 0) + c_pages
                total_queries += (len(child.queries) if child.queries is not None else 0) + c_queries
            assert node.child_count == total_nodes, (
                f"{label}: child_count={node.child_count}, expected={total_nodes}"
            )
            assert node.child_page_count == total_pages, (
                f"{label}: child_page_count={node.child_page_count}, expected={total_pages}"
            )
            assert node.child_query_count == total_queries, (
                f"{label}: child_query_count={node.child_query_count}, expected={total_queries}"
            )
            return total_nodes, total_pages, total_queries

        _check(self.root)


def _http_crawl_stats(
    tree: "UrlTree",
) -> Tuple[List[Dict[str, Any]], Dict[str, Any] | None, str]:
    """Compute domains, target_node, and summary from a UrlTree.

    Returns:
        domains: One entry per DomainNode, each with netloc, aggregate counts,
            and a top_level_nodes list of its direct path-segment children.
        target_node_info: Stats for the seeded target URL node, or None.
        summary: Human-readable count string.
    """
    total_nodes = 1 + tree.root.child_count
    total_pages = tree.root.child_page_count
    total_queries = tree.root.child_query_count
    summary = f"{total_nodes} node(s), {total_pages} page(s), {total_queries} query variant(s)"

    domains = []
    for domain in sorted(tree.root.children.values(), key=lambda n: n.netloc):
        top_level_nodes = []
        for child in sorted(domain.children.values(), key=lambda n: n.segment):
            child_pages = (1 if child.base_url is not None else 0) + child.child_page_count
            child_queries = len(child.queries or []) + child.child_query_count
            top_level_nodes.append({
                "segment": "/" if child.segment == "/" else f"/{child.segment}",
                "nodes": 1 + child.child_count,
                "pages": child_pages,
                "queries": child_queries,
            })
        domains.append({
            "netloc": domain.netloc,
            "nodes": 1 + domain.child_count,
            "pages": domain.child_page_count,
            "queries": domain.child_query_count,
            "top_level_nodes": top_level_nodes,
        })

    target_node_info = None
    if tree.target_url is not None:
        t = tree.target_url
        t_pages = (1 if t.base_url is not None else 0) + t.child_page_count
        t_queries = len(t.queries or []) + t.child_query_count
        target_node_info = {
            "url": t.base_url or tree.origin,
            "nodes": 1 + t.child_count,
            "pages": t_pages,
            "queries": t_queries,
        }

    return domains, target_node_info, summary


async def http_crawl(
    target_url: str,
    prior_results: Dict[str, Any] | None = None,
    cache_dir: Path | None = None,
) -> Dict[str, Any]:
    """Build a URL tree from resolved_url and http_sitemap _page_urls.

    Scopes to the origin of resolved_url (falls back to target_url if
    http_redirect has not run). Seeds the tree with resolved_url first,
    then adds all same-origin _page_urls from http_sitemap sitemaps.

    If a prior result already exists in prior_results (pre-loaded from cache),
    skips all work and returns the existing result unchanged.

    Args:
        target_url: The original target URL (used as fallback origin only).
        prior_results: Accumulated pipeline results. If "http_crawl" is
            already present, this function is a no-op.
        cache_dir: Unused.

    Returns:
        Dict with "http_crawl" key containing:
          _url_tree: UrlTree object (transient).
          summary: human-readable count of candidates and nodes.
    """
    pr = prior_results or {}

    prior = pr.get("http_crawl")
    if prior is not None:
        tree: UrlTree | None = prior.get("_url_tree")
        if tree is None:
            # No tree in cache (shouldn't happen with pickle); return as-is.
            print(f"[INFO] http_crawl: using cached result ({prior.get('summary', '')})", file=sys.stderr)
            return {"http_crawl": prior}

    else:
        resolved_url = pr.get("http_redirect", {}).get("resolved_url") or target_url

        sitemap_data = pr.get("http_sitemap", {})
        candidates: List[str] = [
            url
            for sitemap in sitemap_data.get("sitemaps", [])
            if not sitemap.get("is_index")
            for url in sitemap.get("_page_urls", [])
        ]

        tree = UrlTree(resolved_url)
        print(f"[INFO] http_crawl: building URL tree for {tree.origin}", file=sys.stderr)
        tree.extend(candidates)
        tree.validate()

    # (re)compute stats and log
    domains, target_node_info, summary = _http_crawl_stats(tree)
    print(f"[INFO] http_crawl: {summary}", file=sys.stderr)
    for domain in domains:
        print(
            f"[INFO] http_crawl:   {domain['netloc']}"
            f"  nodes={domain['nodes']}"
            f"  pages={domain['pages']}"
            f"  queries={domain['queries']}",
            file=sys.stderr,
        )
        for node in domain["top_level_nodes"]:
            print(
                f"[INFO] http_crawl:     {node['segment']}"
                f"  nodes={node['nodes']}"
                f"  pages={node['pages']}"
                f"  queries={node['queries']}",
                file=sys.stderr,
            )
    if target_node_info is not None:
        print(
            f"[INFO] http_crawl:   target → {target_node_info['url']}"
            f"  nodes={target_node_info['nodes']}"
            f"  pages={target_node_info['pages']}"
            f"  queries={target_node_info['queries']}",
            file=sys.stderr,
        )

    return {
        "http_crawl": {
            "_url_tree": tree,
            "domains": domains,
            "target_node": target_node_info,
            "summary": summary,
        }
    }


def _extract_links_href(html: str, base_url: str, origin: str) -> List[str]:
    """Extract same-origin absolute URLs from <a href> and <area href> tags.

    Args:
        html: Raw HTML content.
        base_url: Base URL for resolving relative hrefs (caller should resolve
            <base href> first and pass the result here).
        origin: Origin to scope to (e.g. "https://www.example.com").

    Returns:
        Deduplicated list of same-origin absolute URLs.
    """
    origin_netloc = urlparse(origin).netloc
    base_domain = ".".join(origin_netloc.split(".")[-2:])
    seen: Set[str] = set()
    links: List[str] = []
    for m in re.finditer(r"""<(?:a|area)[^>]+href=["']?([^"'\s>#][^"'>\s]*)["']?""", html, re.I):
        href = _html_unescape(m.group(1).strip())
        if not href:
            continue
        url = urljoin(base_url, href)
        parsed = urlparse(url)
        if not _netloc_matches_base_domain(parsed.netloc, base_domain):
            continue
        # Strip fragment; normalise to bare URL + optional query.
        clean = parsed._replace(fragment="").geturl()
        if clean not in seen:
            seen.add(clean)
            links.append(clean)
    return links


def _extract_links_form(html: str, base_url: str, origin: str) -> List[str]:
    """Extract same-origin absolute URLs from <form action> and formaction attributes.

    Covers <form action>, <button formaction>, and <input formaction>. Only
    GET-method forms produce navigable URLs in the traditional sense, but
    action URLs are extracted regardless of method.

    Args:
        html: Raw HTML content.
        base_url: Base URL for resolving relative actions (caller should
            resolve <base href> first and pass the result here).
        origin: Origin to scope to (e.g. "https://www.example.com").

    Returns:
        Deduplicated list of same-origin absolute URLs.
    """
    origin_netloc = urlparse(origin).netloc
    base_domain = ".".join(origin_netloc.split(".")[-2:])
    seen: Set[str] = set()
    links: List[str] = []
    for pattern in (
        r"""<form[^>]+action=["']?([^"'\s>#][^"'>\s]*)["']?""",
        r"""<(?:button|input)[^>]+formaction=["']?([^"'\s>#][^"'>\s]*)["']?""",
    ):
        for m in re.finditer(pattern, html, re.I):
            action = _html_unescape(m.group(1).strip())
            if not action:
                continue
            url = urljoin(base_url, action)
            parsed = urlparse(url)
            if not _netloc_matches_base_domain(parsed.netloc, base_domain):
                continue
            clean = parsed._replace(fragment="").geturl()
            if clean not in seen:
                seen.add(clean)
                links.append(clean)
    return links


def _extract_links_iframe(html: str, base_url: str, origin: str) -> List[str]:
    """Extract same-origin absolute URLs from <iframe src> and <frame src> tags.

    Args:
        html: Raw HTML content.
        base_url: Base URL for resolving relative srcs (caller should resolve
            <base href> first and pass the result here).
        origin: Origin to scope to (e.g. "https://www.example.com").

    Returns:
        Deduplicated list of same-origin absolute URLs.
    """
    origin_netloc = urlparse(origin).netloc
    base_domain = ".".join(origin_netloc.split(".")[-2:])
    seen: Set[str] = set()
    links: List[str] = []
    for m in re.finditer(r"""<(?:i?frame)[^>]+src=["']?([^"'\s>#][^"'>\s]*)["']?""", html, re.I):
        src = _html_unescape(m.group(1).strip())
        if not src:
            continue
        url = urljoin(base_url, src)
        parsed = urlparse(url)
        if not _netloc_matches_base_domain(parsed.netloc, base_domain):
            continue
        clean = parsed._replace(fragment="").geturl()
        if clean not in seen:
            seen.add(clean)
            links.append(clean)
    return links


def _extract_links_meta_refresh(html: str, base_url: str, origin: str) -> List[str]:
    """Extract same-origin absolute URLs from <meta http-equiv="refresh"> tags.

    The content attribute has the form "N; url=..." or just "N" (no URL).
    Handles attributes in any order.

    Args:
        html: Raw HTML content.
        base_url: Base URL for resolving relative URLs (caller should resolve
            <base href> first and pass the result here).
        origin: Origin to scope to (e.g. "https://www.example.com").

    Returns:
        Deduplicated list of same-origin absolute URLs.
    """
    origin_netloc = urlparse(origin).netloc
    base_domain = ".".join(origin_netloc.split(".")[-2:])
    seen: Set[str] = set()
    links: List[str] = []
    for tag_m in re.finditer(r"<meta([^>]+)>", html, re.I):
        attrs = tag_m.group(1)
        # Match http-equiv=refresh with or without quotes; lookahead prevents
        # matching http-equiv=refreshAll etc. when unquoted.
        if not re.search(
            r"""http-equiv=(?:"refresh"|'refresh'|refresh(?=[\s>"'/]))""", attrs, re.I
        ):
            continue
        # content= may be double-quoted (group 1), single-quoted (group 2),
        # or unquoted (group 3; value ends at whitespace or >).
        content_m = re.search(
            r"""content=(?:"([^"]*)"|'([^']*)'|([^\s>"']+))""", attrs, re.I
        )
        if not content_m:
            continue
        content_val = content_m.group(1) or content_m.group(2) or content_m.group(3) or ""
        url_m = re.search(r";\s*url=([^\s'\"]+)", content_val, re.I)
        if not url_m:
            continue
        raw = _html_unescape(url_m.group(1).strip())
        if not raw:
            continue
        url = urljoin(base_url, raw)
        parsed = urlparse(url)
        if not _netloc_matches_base_domain(parsed.netloc, base_domain):
            continue
        clean = parsed._replace(fragment="").geturl()
        if clean not in seen:
            seen.add(clean)
            links.append(clean)
    return links


def _extract_links_link_rel(html: str, base_url: str, origin: str) -> List[str]:
    """Extract same-origin absolute URLs from <link> tags with navigable rel values.

    Covers rel="alternate" (language/region variants and feed URLs),
    rel="canonical" (authoritative URL for the current page),
    rel="next" and rel="prev" (pagination chains).

    rel may be a space-separated list of tokens; any token matching
    _LINK_REL_FOLLOW causes the href to be extracted.

    Args:
        html: Raw HTML content.
        base_url: Base URL for resolving relative hrefs (caller should resolve
            <base href> first and pass the result here).
        origin: Origin to scope to (e.g. "https://www.example.com").

    Returns:
        Deduplicated list of same-origin absolute URLs.
    """
    origin_netloc = urlparse(origin).netloc
    base_domain = ".".join(origin_netloc.split(".")[-2:])
    seen: Set[str] = set()
    links: List[str] = []
    for tag_m in re.finditer(r"<link([^>]+)>", html, re.I):
        attrs = tag_m.group(1)
        rel_m = re.search(r"""rel=(?:"([^"]*)"|'([^']*)'|([^\s>"']+))""", attrs, re.I)
        if not rel_m:
            continue
        rel_val = rel_m.group(1) or rel_m.group(2) or rel_m.group(3) or ""
        if not _LINK_REL_FOLLOW.intersection(rel_val.lower().split()):
            continue
        href_m = re.search(r"""href=["']?([^"'\s>#][^"'>\s]*)["']?""", attrs, re.I)
        if not href_m:
            continue
        href = _html_unescape(href_m.group(1).strip())
        if not href:
            continue
        url = urljoin(base_url, href)
        parsed = urlparse(url)
        if not _netloc_matches_base_domain(parsed.netloc, base_domain):
            continue
        clean = parsed._replace(fragment="").geturl()
        if clean not in seen:
            seen.add(clean)
            links.append(clean)
    return links


def _extract_links_script_urls(html: str, base_url: str, origin: str) -> List[str]:
    """Extract same-origin URLs from static string literals in inline <script> blocks.

    Scans the content of inline <script> elements (external src= scripts are
    skipped) for common JS navigation patterns containing static quoted strings:

      location.href = '/path'
      window.location.assign('/path')
      window.location.replace('/path')
      history.pushState(state, title, '/path')
      history.replaceState(state, title, '/path')

    Template literals and dynamic expressions are not matched (they require
    quotes, not backticks, and cannot contain ${...} interpolation).

    Args:
        html: Raw HTML content.
        base_url: Base URL for resolving relative paths found in scripts.
        origin: Origin to scope results to.

    Returns:
        Deduplicated list of same-origin absolute URLs.
    """
    # Patterns for static quoted URL arguments in JS navigation calls.
    _SCRIPT_URL_PATTERNS = [
        # location.href = '/path'  (with or without window. prefix)
        re.compile(r"""(?:window\.)?location\.href\s*=\s*["']([^"'`]+)["']"""),
        # location.assign('/path') / location.replace('/path')
        re.compile(r"""(?:window\.)?location\.(?:assign|replace)\s*\(\s*["']([^"'`]+)["']"""),
        # history.pushState/replaceState — third argument is the URL
        re.compile(r"""history\.(?:pushState|replaceState)\s*\([^)]*,\s*["']([^"'`]*)["']\s*\)"""),
    ]

    origin_netloc = urlparse(origin).netloc
    base_domain = ".".join(origin_netloc.split(".")[-2:])
    seen: Set[str] = set()
    links: List[str] = []

    for script_m in re.finditer(r"<script([^>]*)>(.*?)</script>", html, re.I | re.S):
        if re.search(r"""\bsrc\s*=["']?[^"'\s>]""", script_m.group(1), re.I):
            continue  # skip external scripts
        content = script_m.group(2)
        for pat in _SCRIPT_URL_PATTERNS:
            for m in pat.finditer(content):
                raw = m.group(1)
                if not raw or "${" in raw:
                    continue  # skip empty or interpolated strings
                url = urljoin(base_url, raw)
                parsed = urlparse(url)
                if not _netloc_matches_base_domain(parsed.netloc, base_domain):
                    continue
                clean = parsed._replace(fragment="").geturl()
                if clean not in seen:
                    seen.add(clean)
                    links.append(clean)

    return links


async def http_crawl2(
    target_url: str,
    prior_results: Dict[str, Any] | None = None,
    cache_dir: Path | None = None,
) -> Dict[str, Any]:
    """Extend the URL tree by fetching pages and extracting <a href> links.

    Reads the UrlTree built by http_crawl, then iterates pending nodes using
    iter_pending(). For each page fetched, discovered same-origin links are
    added to the tree via extend(). A multi-pass loop ensures newly-added
    nodes are also visited within the same run.

    If a prior result already exists in prior_results (pre-loaded from cache),
    skips all work and returns the existing result unchanged.

    Args:
        target_url: The original target URL (fallback if no http_crawl tree).
        prior_results: Accumulated pipeline results.
        cache_dir: Unused; present for pipeline interface consistency.

    Returns:
        Dict with "http_crawl2" key containing requests_made and summary.
    """
    pr = prior_results or {}

    prior = pr.get("http_crawl2")
    tree: UrlTree | None = pr.get("http_crawl", {}).get("_url_tree")
    if tree is None:
        resolved_url = pr.get("http_redirect", {}).get("resolved_url") or target_url
        tree = UrlTree(resolved_url)

    prior_requests: int = (prior or {}).get("requests_made", 0)
    pages_before = tree.root.child_page_count
    requests_made = 0
    visited_urls: List[str] = []

    async def _visit_node(session: aiohttp.ClientSession, pending: "UrlTree.PendingNode") -> None:
        nonlocal requests_made
        node = pending.node
        query = node.queries[pending.get_index()]
        page_url = f"{node.base_url}?{query}" if query else node.base_url
        pending.increment()
        requests_made += 1
        visited_urls.append(page_url)
        print(f"[INFO] http_crawl2:   visit → {page_url}", file=sys.stderr)

        try:
            async with session.get(page_url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if not resp.ok:
                    print(f"[WARN] http_crawl2: HTTP {resp.status} for {page_url}", file=sys.stderr)
                    return
                html = await resp.text()
        except Exception as exc:
            print(f"[WARN] http_crawl2: failed to fetch {page_url}: {exc}", file=sys.stderr)
            return

        base_m = re.search(r"""<base[^>]+href=["']?([^"'\s>]+)["']?""", html, re.I)
        base_url = urljoin(page_url, _html_unescape(base_m.group(1))) if base_m else page_url
        links: List[str] = []
        for extractor in (
            lambda: _extract_links_href(html, base_url, tree.origin),
            lambda: _extract_links_form(html, base_url, tree.origin),
            lambda: _extract_links_iframe(html, base_url, tree.origin),
            lambda: _extract_links_meta_refresh(html, base_url, tree.origin),
            lambda: _extract_links_link_rel(html, base_url, tree.origin),
            lambda: _extract_links_script_urls(html, base_url, tree.origin),
        ):
            try:
                links += extractor()
            except Exception as exc:
                print(
                    f"[WARN] http_crawl2: extractor failed on {page_url}: {exc}",
                    file=sys.stderr,
                )
        if links:
            tree.extend(links)

    async with aiohttp.ClientSession() as session:
        while requests_made < _HTTP_CRAWL2_MAX_REQUESTS:
            made_progress = False
            for pending in tree.iter_pending():
                if requests_made >= _HTTP_CRAWL2_MAX_REQUESTS:
                    break
                await _visit_node(session, pending)
                made_progress = True
            if not made_progress:
                break

    pages_after = tree.root.child_page_count
    pages_added = pages_after - pages_before
    total_requests = prior_requests + requests_made
    summary = (
        f"visited: {requests_made} URL(s), cached: {prior_requests} URL(s),"
        f" {pages_added} new page(s) discovered"
    )
    print(f"[INFO] http_crawl2: {summary}", file=sys.stderr)
    return {
        "http_crawl2": {
            "requests_made": total_requests,
            "visited_urls": visited_urls,
            "summary": summary,
        }
    }


def _setup_js_navigated_interceptor(page: Page) -> List[str]:
    """Register a framenavigated listener; returns the list it will populate.

    Must be called before page.goto(). Captures every main-frame URL change:
    history.pushState/replaceState, window.location.href assignments,
    location.assign(), location.replace(), and redirect hops.
    """
    collected: List[str] = []
    page.on(
        "framenavigated",
        lambda frame: collected.append(frame.url) if frame == page.main_frame else None,
    )
    return collected


async def _extract_links_js_navigated(
    page: Page, origin: str, navigated_urls: List[str], exclude_url: str | None = None
) -> List[str]:
    """Filter URLs collected by _setup_js_navigated_interceptor to same-origin links.

    navigated_urls includes the initial page.goto() destination and any redirect
    hops. exclude_url (defaults to page.url) is excluded from results — callers
    should pass the originally-requested URL so that redirect destinations are
    not filtered out. All intermediate URLs and programmatic navigations are
    included.
    """
    origin_netloc = urlparse(origin).netloc
    base_domain = ".".join(origin_netloc.split(".")[-2:])
    final_url = exclude_url if exclude_url is not None else page.url
    seen: Set[str] = set()
    links: List[str] = []
    for url in navigated_urls:
        if url == final_url:
            continue
        parsed = urlparse(url)
        if not _netloc_matches_base_domain(parsed.netloc, base_domain):
            continue
        clean = parsed._replace(fragment="").geturl()
        if clean not in seen:
            seen.add(clean)
            links.append(clean)
    return links


async def _extract_links_js_dom(page: Page, origin: str) -> List[str]:
    """Extract same-origin hrefs from <a> and <area> elements in the rendered DOM.

    Queries the fully-rendered DOM (after JS execution) for all anchor and area
    elements. The browser resolves each el.href to an absolute URL, so no urljoin
    is needed. Filters to same-origin, strips fragments, and deduplicates.
    """
    origin_netloc = urlparse(origin).netloc
    base_domain = ".".join(origin_netloc.split(".")[-2:])
    raw: List[str] = await page.eval_on_selector_all(
        "a[href], area[href]",
        "elements => elements.map(el => el.href)",
    )
    seen: Set[str] = set()
    links: List[str] = []
    for href in raw:
        parsed = urlparse(href)
        if not _netloc_matches_base_domain(parsed.netloc, base_domain):
            continue
        clean = parsed._replace(fragment="").geturl()
        if clean not in seen:
            seen.add(clean)
            links.append(clean)
    return links


async def _extract_links_js_click_nav(page: Page, origin: str) -> List[str]:
    """Click JS-only nav links to discover SPA routes not visible in the DOM.

    Targets <a> elements in nav/header landmarks that lack a navigable href
    (absent, empty, or "#") — these are most likely to trigger pushState-based
    navigation not already captured by _extract_links_js_dom. Clicks each
    visible candidate, navigates back on URL change, then delegates filtering
    and deduplication to _extract_links_js_navigated. go_back destinations
    (always start_url) are filtered automatically as final_url.
    """
    navigated_urls = _setup_js_navigated_interceptor(page)
    start_url = page.url

    # Target only links without a real href — real hrefs are already captured
    # by _extract_links_js_dom, so this avoids redundancy and full-page reloads.
    no_href = "a:not([href]), a[href=''], a[href='#']"
    handles = await page.query_selector_all(
        f"nav {no_href}, [role='navigation'] {no_href}, header {no_href}"
    )

    for handle in handles:
        pre_url = page.url
        try:
            if not await handle.is_visible():
                continue
        except Exception:
            continue
        try:
            async with page.expect_navigation(wait_until="commit", timeout=2000):
                await handle.click()
        except Exception:
            pass  # no navigation committed within 2s, or click failed

        if page.url == pre_url:
            continue

        try:
            await page.go_back(wait_until="domcontentloaded", timeout=_PLAYWRIGHT_TIMEOUT_MS)
        except Exception:
            try:
                await page.goto(start_url, wait_until="domcontentloaded", timeout=_PLAYWRIGHT_TIMEOUT_MS)
            except Exception:
                break

    # Auth-keyword buttons — full page scope; keyword filter prevents clicking
    # arbitrary buttons. Covers <button>, submit inputs, and [role=button] elements.
    btn_selector = "button, input[type='button'], input[type='submit'], [role='button']"
    btn_texts: List[str] = await page.eval_on_selector_all(
        btn_selector,
        "els => els.map(el => "
        "(el.textContent || el.getAttribute('value') || "
        " el.getAttribute('aria-label') || '').trim())",
    )
    btn_handles = await page.query_selector_all(btn_selector)
    auth_btn_handles = [
        h for h, t in zip(btn_handles, btn_texts)
        if _AUTH_BUTTON_KEYWORDS.search(t)
    ]

    for handle in auth_btn_handles:
        pre_url = page.url
        try:
            if not await handle.is_visible():
                continue
        except Exception:
            continue
        try:
            async with page.expect_navigation(wait_until="commit", timeout=2000):
                await handle.click()
        except Exception:
            pass  # no navigation committed within 2s, or click failed

        if page.url == pre_url:
            continue

        try:
            await page.go_back(wait_until="domcontentloaded", timeout=_PLAYWRIGHT_TIMEOUT_MS)
        except Exception:
            try:
                await page.goto(start_url, wait_until="domcontentloaded", timeout=_PLAYWRIGHT_TIMEOUT_MS)
            except Exception:
                break

    return await _extract_links_js_navigated(page, origin, navigated_urls)


async def http_crawl3(
    target_url: str,
    prior_results: Dict[str, Any] | None = None,
    cache_dir: Path | None = None,
) -> Dict[str, Any]:
    """Extend the URL tree by rendering pages in a headless browser and extracting JS links.

    Complements http_crawl2 by handling JavaScript navigation that static HTML parsing misses:
    React Router / Next.js / Vue Router <Link> components (rendered as <a href> in the DOM),
    history.pushState / replaceState calls, and other JS-driven route discovery.

    Reads the UrlTree built by http_crawl, then iterates pending nodes using iter_pending().
    For each page, a Playwright browser tab renders it, waits for the network to settle, and
    runs the _extract_links_js_* helpers to collect same-origin links. Newly found links are added
    via tree.extend(), enabling multi-pass discovery within the same run.

    If a prior result already exists in prior_results (pre-loaded from cache), skips all work
    and returns the existing result unchanged.

    Args:
        target_url: The original target URL (fallback if no http_crawl tree).
        prior_results: Accumulated pipeline results.
        cache_dir: Unused; present for pipeline interface consistency.

    Returns:
        Dict with "http_crawl3" key containing requests_made, summary, and _url_tree.
    """
    pr = prior_results or {}

    prior = pr.get("http_crawl3")
    tree: UrlTree | None = pr.get("http_crawl", {}).get("_url_tree")
    if tree is None:
        resolved_url = pr.get("http_redirect", {}).get("resolved_url") or target_url
        tree = UrlTree(resolved_url)

    prior_requests: int = (prior or {}).get("requests_made", 0)
    pages_before = tree.root.child_page_count
    requests_made = 0
    visited_urls: List[str] = []

    async def _visit_node(browser: Browser, pending: "UrlTree.PendingNode") -> None:
        nonlocal requests_made
        node = pending.node
        query = node.queries[pending.get_index()]
        page_url = f"{node.base_url}?{query}" if query else node.base_url
        pending.increment()
        requests_made += 1
        visited_urls.append(page_url)
        print(f"[INFO] http_crawl3:   visit → {page_url}", file=sys.stderr)

        page = await browser.new_page()
        try:
            navigated_urls = _setup_js_navigated_interceptor(page)
            await page.goto(page_url, wait_until="domcontentloaded", timeout=_PLAYWRIGHT_TIMEOUT_MS)
            links: List[str] = []
            for extractor in (
                lambda: _extract_links_js_dom(page, tree.origin),
                lambda: _extract_links_js_click_nav(page, tree.origin),
                # Run last: captures async post-domcontentloaded redirects and any
                # navigations that fired during click_nav (including failures).
                lambda: _extract_links_js_navigated(page, tree.origin, navigated_urls, exclude_url=page_url),
            ):
                try:
                    links += await extractor()
                except Exception as exc:
                    print(
                        f"[WARN] http_crawl3: extractor failed on {page_url}: {exc}",
                        file=sys.stderr,
                    )
            if links:
                tree.extend(links)
        except Exception as exc:
            print(f"[WARN] http_crawl3: failed to visit {page_url}: {exc}", file=sys.stderr)
        finally:
            await page.close()

    async with (
        async_playwright() as pw,
        await pw.chromium.launch(headless=True) as browser,
    ):
        while requests_made < _HTTP_CRAWL3_MAX_REQUESTS:
            made_progress = False
            for pending in tree.iter_pending():
                if requests_made >= _HTTP_CRAWL3_MAX_REQUESTS:
                    break
                await _visit_node(browser, pending)
                made_progress = True
            if not made_progress:
                break

    pages_after = tree.root.child_page_count
    pages_added = pages_after - pages_before
    total_requests = prior_requests + requests_made
    summary = (
        f"visited: {requests_made} URL(s), cached: {prior_requests} URL(s),"
        f" {pages_added} new page(s) discovered"
    )
    print(f"[INFO] http_crawl3: {summary}", file=sys.stderr)
    return {
        "http_crawl3": {
            "requests_made": total_requests,
            "visited_urls": visited_urls,
            "summary": summary,
        }
    }




def _extract_webpack_chunk_format(content: str) -> tuple[str, str, str]:
    """Extract (chunk_prefix, sep, suffix) from the webpack o.u function body.

    chunk_prefix: static directory path before the chunk name/id (e.g. "static/chunks/",
                  "static/js/", "_nuxt/", "")
    sep:          separator between chunk name/id and content hash ("." or "-")
    suffix:       file extension string after the hash (".js", ".chunk.js", etc.)

    Covers Next.js ("static/chunks/", ".", ".js"), Create React App ("static/js/",
    ".", ".chunk.js"), plain webpack ("", ".", ".js"), and Gatsby-style ("", "-", ".js").
    Falls back to ("", ".", ".js") if the body cannot be parsed.
    """
    u_match = re.search(r'\.u\s*=\s*(?:e\s*=>|function\s*\(e\)\s*\{\s*return\s*)', content)
    if not u_match:
        return ("", ".", ".js")
    body = content[u_match.end(): u_match.end() + 600]
    strings = re.findall(r'"([^"]*)"', body)

    # Prefix: first string containing "/" that does not itself end in ".js"
    chunk_prefix = ""
    for s in strings:
        if "/" in s and not s.endswith(".js"):
            chunk_prefix = s
            break

    # Suffix: last string that starts with "." and ends with ".js"
    suffix = ".js"
    for s in reversed(strings):
        if s.startswith(".") and s.endswith(".js"):
            suffix = s
            break

    # Separator: scan a larger window of the o.u body for the inter-map separator.
    # The pattern ({name_map}[e]||e)+SEP+{hash_map}[e]+SUFFIX can span thousands
    # of chars when maps are large, so the 600-char body above may not contain it.
    # Directly match the `||e)+"SEP"` or `[e]+"SEP"+` construct instead.
    sep = "."
    sep_m = re.search(r'(?:\|\|e\)\s*|\[e\]\s*)\+\s*"([-._])"\s*\+', content[u_match.start():])
    if sep_m:
        sep = sep_m.group(1)

    return chunk_prefix, sep, suffix


def _parse_webpack_chunk_map(
    content: str,
) -> tuple[str, str, str, str, dict[int, str], dict[int, str]] | None:
    """Parse a webpack runtime for lazy-chunk URL resolution.

    Detects the public path (o.p), chunk URL components from o.u, and chunk
    hash/name maps. Supports Next.js, Create React App, plain webpack, and
    Gatsby-style bundle formats.

    Returns (public_path, chunk_prefix, sep, suffix, hash_map, name_map) or None.
      public_path:  base URL for chunk requests (e.g. "https://cdn.example.com/")
      chunk_prefix: relative path prefix from o.u (e.g. "static/chunks/", "")
      sep:          separator between chunk name/id and hash ("." or "-")
      suffix:       file extension suffix (".js", ".chunk.js", etc.)
      hash_map:     {chunk_id: 16-char-hex content hash}
      name_map:     {chunk_id: human-readable chunk name}
    """
    pp_match = re.search(r'\.p\s*=\s*"([^"]+)"', content)
    if not pp_match:
        return None
    public_path = pp_match.group(1)

    hash_map: dict[int, str] = {}
    name_map: dict[int, str] = {}
    for obj_match in re.finditer(r'\{(\d+:"[^"]*"(?:,\d+:"[^"]*")*)\}', content):
        pairs = re.findall(r'(\d+):"([^"]*)"', obj_match.group(1))
        if len(pairs) < 3:
            continue
        values = [v for _, v in pairs]
        if all(_WEBPACK_HEX_HASH.match(v) for v in values):
            for k, v in pairs:
                hash_map.setdefault(int(k), v)
        else:
            for k, v in pairs:
                if not _WEBPACK_HEX_HASH.match(v):
                    name_map.setdefault(int(k), v)

    if not hash_map:
        return None

    chunk_prefix, sep, suffix = _extract_webpack_chunk_format(content)
    return public_path, chunk_prefix, sep, suffix, hash_map, name_map


def _webpack_lazy_chunk_urls(
    lazy_ids: set[int],
    public_path: str,
    chunk_prefix: str,
    sep: str,
    suffix: str,
    hash_map: dict[int, str],
    name_map: dict[int, str],
    fetched_js: set[str],
) -> list[str]:
    """Resolve webpack lazy chunk IDs to absolute URLs, skipping already-fetched ones."""
    urls = []
    for cid in sorted(lazy_ids):
        chunk_hash = hash_map.get(cid)
        if not chunk_hash:
            continue
        chunk_name = name_map.get(cid, str(cid))
        url = f"{public_path}{chunk_prefix}{chunk_name}{sep}{chunk_hash}{suffix}"
        if url not in fetched_js:
            urls.append(url)
    return urls


def _webauthn_js_matches(
    content: str, js_url: str, visited_url: str
) -> "Dict[str, Any] | None":
    """Return a finding dict if WebAuthn patterns are found in content, else None."""
    matches = list(dict.fromkeys(_WEBAUTHN_PATTERNS.findall(content)))
    if not matches:
        return None
    print(
        f"[INFO] webauthn_javascript:   found {len(matches)} pattern(s) in {js_url}",
        file=sys.stderr,
    )
    return {"js_url": js_url, "visited_url": visited_url, "webauthn_calls": matches}


def _extract_webauthn_js_inline(
    html: str, page_url: str
) -> "List[Dict[str, Any]]":
    """Search inline <script> blocks in page HTML for WebAuthn patterns."""
    findings = []
    for idx, m in enumerate(re.finditer(r"<script([^>]*)>(.*?)</script>", html, re.DOTALL | re.I)):
        if "src" not in m.group(1).lower() and m.group(2).strip():
            finding = _webauthn_js_matches(m.group(2), f"<inline:{page_url}:{idx}>", page_url)
            if finding:
                findings.append(finding)
    return findings


def _extract_parcel_chunk_urls(content: str, base_url: str) -> "set[str]":
    """Extract Parcel v2 lazy chunk URLs from a bundle manifest embedded in content.

    Parcel v2 runtimes embed a manifest like {"<id>": {"url": "chunk.hash.js", "type": "js"}}.
    Guard: only inspects content that references parcelRequire.
    """
    if "parcelRequire" not in content:
        return set()
    urls: "set[str]" = set()
    for m in re.finditer(r'"url"\s*:\s*"([^"]+\.js)"', content):
        urls.add(urljoin(base_url, m.group(1)))
    return urls


def _extract_amd_urls(content: str, base_url: str) -> "set[str]":
    """Extract JS URLs from RequireJS/AMD require.config paths and require/define deps.

    Covers:
      - require.config({baseUrl: "...", paths: {name: "path", ...}})
      - require(["./rel.js", ...], callback) and define(["./rel.js", ...], factory)
    Only follows relative/absolute specifiers in require/define arrays to avoid
    treating bare module names (resolved via paths config) as URLs.
    """
    if not re.search(r'require\.config\s*\(|define\s*\(|require\s*\(\s*\[', content):
        return set()
    urls: "set[str]" = set()
    amd_base = base_url
    burl_m = re.search(r'\bbaseUrl\s*:\s*["\']([^"\']+)["\']', content)
    if burl_m:
        b = burl_m.group(1)
        amd_base = urljoin(base_url, b if b.endswith("/") else b + "/")
    paths_m = re.search(r'\bpaths\s*:\s*\{([^}]+)\}', content)
    if paths_m:
        for pm in re.finditer(r':\s*["\']([^"\']+)["\']', paths_m.group(1)):
            p = pm.group(1)
            if not p.endswith(".js"):
                p += ".js"
            urls.add(urljoin(amd_base, p))
    for req_m in re.finditer(
        r'(?:require|define)\s*\(\s*(?:["\'][^"\']*["\']\s*,\s*)?\[([^\]]+)\]', content
    ):
        for dep_m in re.finditer(r'["\']([^"\']+)["\']', req_m.group(1)):
            dep = dep_m.group(1)
            if dep.startswith((".", "/", "http://", "https://")):
                if not dep.endswith(".js"):
                    dep += ".js"
                urls.add(urljoin(base_url, dep))
    return urls


def _extract_systemjs_urls(content: str, base_url: str) -> "set[str]":
    """Extract JS URLs from SystemJS System.register deps and System.import calls."""
    if "System." not in content:
        return set()
    urls: "set[str]" = set()
    for m in re.finditer(
        r'System\.register\s*\(\s*(?:["\'][^"\']*["\']\s*,\s*)?\[([^\]]*)\]', content
    ):
        for dep_m in re.finditer(r'["\']([^"\']+\.js)["\']', m.group(1)):
            urls.add(urljoin(base_url, dep_m.group(1)))
    for m in re.finditer(r'System\.import\s*\(\s*["\']([^"\']+\.js)["\']', content):
        urls.add(urljoin(base_url, m.group(1)))
    return urls


def _extract_webauthn_js_module_imports(html: str, page_url: str) -> "set[str]":
    """Extract static ES module import URLs from inline <script type="module"> blocks.

    Covers: import ... from "url", import "url", export ... from "url".
    Returns a set of absolute URLs for JS files to fetch in the pending pass.
    """
    urls: "set[str]" = set()
    for script_m in re.finditer(
        r'<script\b([^>]*)>(.*?)</script>', html, re.DOTALL | re.I
    ):
        attrs = script_m.group(1)
        if not re.search(r'\btype\s*=\s*["\']module["\']', attrs, re.I):
            continue
        body = script_m.group(2)
        for imp_m in re.finditer(
            r'(?:import|export)\s+(?:[^"\']*\s+from\s+|)["\']([^"\']+\.js)["\']', body
        ):
            urls.add(urljoin(page_url, imp_m.group(1)))
    return urls


def _extract_webauthn_js_inline_urls(html: str, page_url: str) -> "set[str]":
    """Extract JS URLs from inline <script> blocks using bundler-specific patterns.

    Covers Parcel chunk manifests, RequireJS/AMD require.config paths,
    and SystemJS System.import / System.register dependencies.
    """
    urls: "set[str]" = set()
    for m in re.finditer(r'<script\b[^>]*>(.*?)</script>', html, re.DOTALL | re.I):
        body = m.group(1)
        if not body.strip():
            continue
        urls.update(_extract_parcel_chunk_urls(body, page_url))
        urls.update(_extract_amd_urls(body, page_url))
        urls.update(_extract_systemjs_urls(body, page_url))
    return urls


async def _extract_webauthn_js_static_scripts(
    html: str,
    page_url: str,
    session: "aiohttp.ClientSession",
    fetched_js: "Set[str]",
) -> "tuple[List[Dict[str, Any]], set[int], Any, set[str]]":
    """Fetch <script src> files, search for WebAuthn patterns, collect lazy-load data.

    Returns (findings, lazy_chunk_ids, webpack_runtime, pending_js_urls).
    lazy_chunk_ids:  webpack chunk IDs found in .e(id) calls across all fetched files.
    webpack_runtime: parsed runtime tuple from _parse_webpack_chunk_map, or None.
    pending_js_urls: JS URLs to fetch in a deferred pass: <link rel="modulepreload">,
                     <link rel="preload" as="script">, and import("...") literals.
    """
    findings: "List[Dict[str, Any]]" = []
    lazy_chunk_ids: set[int] = set()
    webpack_runtime = None
    pending_js_urls: set[str] = set()

    # Collect <link rel="modulepreload"> and <link rel="preload" as="script"> hints from HTML.
    for link_m in re.finditer(r'<link\b([^>]+)>', html, re.I):
        attrs = link_m.group(1)
        is_modulepreload = re.search(r'\brel\s*=\s*["\']modulepreload["\']', attrs, re.I)
        is_preload_script = re.search(r'\brel\s*=\s*["\']preload["\']', attrs, re.I) and re.search(
            r'\bas\s*=\s*["\']script["\']', attrs, re.I
        )
        if not (is_modulepreload or is_preload_script):
            continue
        href_m = re.search(r'\bhref\s*=\s*["\']([^"\']+\.js)["\']', attrs, re.I)
        if href_m:
            pending_js_urls.add(urljoin(page_url, href_m.group(1)))

    for src_m in re.finditer(r"""<script[^>]+\bsrc\s*=\s*["']([^"']+)["']""", html, re.I):
        js_url = urljoin(page_url, src_m.group(1))
        if js_url in fetched_js:
            continue
        fetched_js.add(js_url)
        try:
            async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=20)) as js_resp:
                if not js_resp.ok:
                    continue
                js_text = await js_resp.text()
        except Exception as exc:
            print(f"[WARN] webauthn_javascript: failed to fetch {js_url}: {exc}", file=sys.stderr)
            continue

        finding = _webauthn_js_matches(js_text, js_url, page_url)
        if finding:
            findings.append(finding)
        for lm in re.finditer(r'\.e\((\d+)\)', js_text):
            lazy_chunk_ids.add(int(lm.group(1)))
        if webpack_runtime is None:
            parsed = _parse_webpack_chunk_map(js_text)
            if parsed is not None:
                pp, cp, sp, sx, hm, nm = parsed
                # Resolve public_path against the JS URL so root-relative paths
                # like "/" become "https://host/" before chunk URLs are built.
                webpack_runtime = (urljoin(js_url, pp), cp, sp, sx, hm, nm)
                print(
                    f"[INFO] webauthn_javascript: webpack runtime in {js_url.split('/')[-1]}"
                    f" (format: {cp!r}{{name}}{sp!r}{{hash}}{sx!r})",
                    file=sys.stderr,
                )
        # Collect Vite/Rollup dynamic import("./...") literal paths.
        for imp_m in re.finditer(r'import\s*\(\s*["\']([./][^"\']*\.js)["\']', js_text):
            pending_js_urls.add(urljoin(js_url, imp_m.group(1)))
        pending_js_urls.update(_extract_parcel_chunk_urls(js_text, js_url))
        pending_js_urls.update(_extract_amd_urls(js_text, js_url))
        pending_js_urls.update(_extract_systemjs_urls(js_text, js_url))

    return findings, lazy_chunk_ids, webpack_runtime, pending_js_urls


async def _extract_webauthn_js_webpack_lazy(
    lazy_chunk_ids: "set[int]",
    webpack_runtime: tuple,
    session: "aiohttp.ClientSession",
    fetched_js: "Set[str]",
) -> "List[Dict[str, Any]]":
    """Fetch lazily-loaded webpack chunks and search them for WebAuthn patterns."""
    findings: "List[Dict[str, Any]]" = []
    public_path, chunk_prefix, sep, suffix, hash_map, name_map = webpack_runtime
    lazy_urls = _webpack_lazy_chunk_urls(
        lazy_chunk_ids, public_path, chunk_prefix, sep, suffix, hash_map, name_map, fetched_js,
    )
    print(
        f"[INFO] webauthn_javascript: {len(lazy_chunk_ids)} lazy chunk ID(s) →"
        f" {len(lazy_urls)} unresolved URL(s)",
        file=sys.stderr,
    )
    for lazy_url in lazy_urls[:_WEBAUTHN_JS_MAX_LAZY_CHUNKS]:
        fetched_js.add(lazy_url)
        print(f"[INFO] webauthn_javascript:   lazy → {lazy_url.split('/')[-1]}", file=sys.stderr)
        try:
            async with session.get(lazy_url, timeout=aiohttp.ClientTimeout(total=20)) as js_resp:
                if js_resp.ok:
                    finding = _webauthn_js_matches(await js_resp.text(), lazy_url, "<webpack-lazy>")
                    if finding:
                        findings.append(finding)
                elif js_resp.status != 404:
                    print(
                        f"[WARN] webauthn_javascript: lazy chunk HTTP {js_resp.status}: {lazy_url}",
                        file=sys.stderr,
                    )
        except Exception as exc:
            print(
                f"[WARN] webauthn_javascript: lazy chunk failed {lazy_url}: {exc}", file=sys.stderr
            )
    return findings


async def _extract_webauthn_js_pending_urls(
    pending_js_urls: "set[str]",
    session: "aiohttp.ClientSession",
    fetched_js: "Set[str]",
) -> "List[Dict[str, Any]]":
    """Fetch deferred JS URLs and search them for WebAuthn patterns.

    Covers sources collected during per-page extraction:
      - <link rel="modulepreload" href="..."> hints in page HTML
      - <link rel="preload" as="script" href="..."> hints in page HTML
      - import("./path.js") literal strings inside fetched JS files
      - static import ... from "./path.js" inside inline <script type="module"> blocks
    """
    findings: "List[Dict[str, Any]]" = []
    candidates = [u for u in sorted(pending_js_urls) if u not in fetched_js]
    if not candidates:
        return findings
    print(
        f"[INFO] webauthn_javascript: {len(pending_js_urls)} pending JS URL(s) →"
        f" {len(candidates)} unresolved",
        file=sys.stderr,
    )
    for url in candidates[:_WEBAUTHN_JS_MAX_PENDING_URLS]:
        fetched_js.add(url)
        print(f"[INFO] webauthn_javascript:   pending → {url.split('/')[-1]}", file=sys.stderr)
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as js_resp:
                if js_resp.ok:
                    finding = _webauthn_js_matches(await js_resp.text(), url, "<pending-js>")
                    if finding:
                        findings.append(finding)
                elif js_resp.status != 404:
                    print(
                        f"[WARN] webauthn_javascript: pending JS HTTP {js_resp.status}: {url}",
                        file=sys.stderr,
                    )
        except Exception as exc:
            print(
                f"[WARN] webauthn_javascript: pending JS failed {url}: {exc}", file=sys.stderr
            )
    return findings


async def webauthn_javascript(
    target_url: str,
    prior_results: Dict[str, Any] | None = None,
    cache_dir: Path | None = None,
) -> Dict[str, Any]:
    """Search for WebAuthn JavaScript patterns across pages in the URL tree.

    Fetches each page via HTTP and runs a series of extractors against it:
      _extract_webauthn_js_inline         — inline <script> WebAuthn patterns
      _extract_webauthn_js_module_imports — <script type="module"> static imports → pending
      _extract_webauthn_js_inline_urls    — inline Parcel/AMD/SystemJS URLs → pending
      _extract_webauthn_js_static_scripts — <script src> external files (+ URL extraction)
      _extract_webauthn_js_webpack_lazy   — webpack lazily-loaded chunks
      _extract_webauthn_js_pending_urls   — deferred JS (preload hints, dynamic/AMD/SystemJS imports)

    Uses the UrlTree built by http_crawl when available; otherwise builds a
    local tree from resolved_url (or target_url).

    Args:
        target_url: The original target URL.
        prior_results: Accumulated pipeline results.
        cache_dir: Unused; present for pipeline interface consistency.

    Returns:
        Dict with "webauthn_javascript" key containing findings and summary.
    """
    pr = prior_results or {}
    tree: UrlTree | None = pr.get("http_crawl", {}).get("_url_tree")
    if tree is None:
        resolved_url = pr.get("http_redirect", {}).get("resolved_url") or target_url
        tree = UrlTree(resolved_url)

    prior = pr.get("webauthn_javascript", {})
    if not prior:
        tree.reset_pending()
    findings: List[Dict[str, Any]] = list(prior.get("findings", []))
    prior_requests: int = prior.get("requests_made", 0)
    requests_made = 0
    visited_urls: List[str] = []
    fetched_js: Set[str] = set()
    webpack_runtime = None
    lazy_chunk_ids: set[int] = set()
    pending_js_urls: set[str] = set()

    async with aiohttp.ClientSession() as session:
        for pending in tree.iter_pending():
            if requests_made >= _WEBAUTHN_JS_MAX_REQUESTS:
                break
            node = pending.node
            query = node.queries[pending.get_index()]
            page_url = f"{node.base_url}?{query}" if query else node.base_url
            pending.increment()
            requests_made += 1
            visited_urls.append(page_url)
            print(
                f"[INFO] webauthn_javascript:   visit → {page_url}"
                f" ({len(node.queries)} query variant(s))",
                file=sys.stderr,
            )

            try:
                async with session.get(page_url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    if not resp.ok:
                        print(
                            f"[WARN] webauthn_javascript: HTTP {resp.status} for {page_url}",
                            file=sys.stderr,
                        )
                        continue
                    html = await resp.text()
            except Exception as exc:
                print(
                    f"[WARN] webauthn_javascript: failed to fetch {page_url}: {exc}",
                    file=sys.stderr,
                )
                continue

            findings.extend(_extract_webauthn_js_inline(html, page_url))
            pending_js_urls.update(_extract_webauthn_js_module_imports(html, page_url))
            pending_js_urls.update(_extract_webauthn_js_inline_urls(html, page_url))

            page_findings, new_lazy_ids, new_runtime, new_pending = (
                await _extract_webauthn_js_static_scripts(html, page_url, session, fetched_js)
            )
            findings.extend(page_findings)
            lazy_chunk_ids.update(new_lazy_ids)
            if webpack_runtime is None:
                webpack_runtime = new_runtime
            pending_js_urls.update(new_pending)

        if webpack_runtime is not None and lazy_chunk_ids:
            findings.extend(
                await _extract_webauthn_js_webpack_lazy(
                    lazy_chunk_ids, webpack_runtime, session, fetched_js
                )
            )
        if pending_js_urls:
            findings.extend(
                await _extract_webauthn_js_pending_urls(pending_js_urls, session, fetched_js)
            )

    total_requests = prior_requests + requests_made
    summary = (
        f"{requests_made} URL(s) visited, {prior_requests} URL(s) cached,"
        f" patterns found in {len(findings)} source(s)"
    )
    print(f"[INFO] webauthn_javascript: {summary}", file=sys.stderr)
    return {
        "webauthn_javascript": {
            "findings": findings,
            "requests_made": total_requests,
            "visited_urls": visited_urls,
            "summary": summary,
        }
    }


def _js_calls_found(prior_results: Dict[str, Any] | None) -> set[str]:
    """Return the set of WebAuthn JS call names found by webauthn_javascript."""
    findings = (prior_results or {}).get("webauthn_javascript", {}).get("findings", [])
    calls: set[str] = set()
    for finding in findings:
        calls.update(finding.get("webauthn_calls", []))
    return calls


def _classify_endpoint(url: str) -> str:
    """Classify a registration endpoint URL using WebAuthn spec terminology.

    The W3C WebAuthn spec and FIDO Alliance conformance tests name the two
    registration endpoints:
      - attestation_options  — server returns PublicKeyCredentialCreationOptions
      - attestation_result   — client submits AuthenticatorAttestationResponse

    Examines the final path segment first for specificity, then the full path.
    """
    path = url.split("?")[0].lower().rstrip("/")
    last_seg = path.rsplit("/", 1)[-1]
    if _OPTIONS_SEGMENT_RE.search(last_seg):
        return "attestation_options"
    if _VERIFICATION_SEGMENT_RE.search(last_seg):
        return "attestation_result"
    if _OPTIONS_SEGMENT_RE.search(path):
        return "attestation_options"
    if _VERIFICATION_SEGMENT_RE.search(path):
        return "attestation_result"
    return "unknown"


async def webauthn_registration_discovery1(
    target_url: str,
    prior_results: Dict[str, Any] | None = None,
    cache_dir: Path | None = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Discover registration endpoint candidates by scanning inline scripts.

    Searches all inline <script> tags for fetch() calls whose URL contains
    registration-related keywords, classifying each by endpoint function.

    Args:
        page: The Playwright page object.
        referenced_urls: List of URLs referenced by the page (unused).
        json_responses: JSON responses buffered during page load (unused).
        prior_results: Accumulated results from earlier pipeline functions.

    Returns:
        Dict with "webauthn_registration_discovery1" key mapping to a list of
        candidates: [{url, function, method, headers, body, confidence, source}].
    """
    js_calls = _js_calls_found(prior_results)
    if js_calls and "navigator.credentials.create" not in js_calls:
        print("[INFO] webauthn_registration_discovery1: skipping (no credentials.create in JS)", file=sys.stderr)
        return {"webauthn_registration_discovery1": []}

    candidates: List[Dict[str, Any]] = []
    print("[INFO] webauthn_registration_discovery1: scanning inline scripts", file=sys.stderr)
    try:
        scripts = await page.query_selector_all('script:not([src])')
        for script in scripts:
            content = await script.inner_text()
            if not content:
                continue
            for m in _FETCH_URL_RE.finditer(content):
                raw_url = m.group(1)
                if _REGISTRATION_PATH_RE.search(raw_url):
                    full_url = urljoin(page.url, raw_url)
                    candidates.append({
                        "url": full_url,
                        "function": _classify_endpoint(raw_url),
                        "method": "POST",
                        "headers": {"Content-Type": "application/json"},
                        "body": None,
                        "confidence": "medium",
                        "source": "inline_js",
                    })
                    print(f"[INFO] webauthn_registration_discovery1: candidate: {full_url}", file=sys.stderr)
    except Exception as exc:
        print(f"[WARN] webauthn_registration_discovery1: scan failed: {exc}", file=sys.stderr)

    seen: set[str] = set()
    candidates = [c for c in candidates if not (c["url"] in seen or seen.add(c["url"]))]  # type: ignore[func-returns-value]
    print(f"[INFO] webauthn_registration_discovery1: {len(candidates)} candidate(s)", file=sys.stderr)
    return {"webauthn_registration_discovery1": candidates}


async def webauthn_registration_discovery2(
    target_url: str,
    prior_results: Dict[str, Any] | None = None,
    cache_dir: Path | None = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Discover registration endpoint candidates by simulating user interaction.

    Fills the username input and clicks the Register button, then intercepts all
    non-static POST/PUT/PATCH requests that fire. Each intercepted request is
    returned as a candidate with its actual method, headers, and body.

    Args:
        page: The Playwright page object (must still be open and interactive).
        referenced_urls: List of URLs referenced by the page (unused).
        json_responses: JSON responses buffered during page load (unused).
        prior_results: Accumulated results from earlier pipeline functions.

    Returns:
        Dict with "webauthn_registration_discovery2" key mapping to a list of
        candidates: [{url, function, method, headers, body, confidence, source}].
    """
    js_calls = _js_calls_found(prior_results)
    if js_calls and "navigator.credentials.create" not in js_calls:
        print("[INFO] webauthn_registration_discovery2: skipping (no credentials.create in JS)", file=sys.stderr)
        return {"webauthn_registration_discovery2": []}

    print("[INFO] webauthn_registration_discovery2: simulating registration interaction", file=sys.stderr)

    username_input = await page.query_selector(
        'input[type="text"], input[type="email"], '
        'input[name*="user" i], input[placeholder*="user" i], input[id*="user" i]'
    )
    if not username_input:
        print("[INFO] webauthn_registration_discovery2: no username input found", file=sys.stderr)
        return {"webauthn_registration_discovery2": []}

    register_btn = None
    for sel in [
        'button:has-text("Register")',
        'button:has-text("Sign Up")',
        'button:has-text("Create")',
        'input[type="submit"][value*="Register" i]',
    ]:
        register_btn = await page.query_selector(sel)
        if register_btn:
            break
    if not register_btn:
        print("[INFO] webauthn_registration_discovery2: no register button found", file=sys.stderr)
        return {"webauthn_registration_discovery2": []}

    captured: List[Dict[str, Any]] = []

    def on_request(request) -> None:
        if request.method not in ("GET", "HEAD"):
            url = request.url
            if not any(skip in url for skip in (".js", ".css", ".png", ".svg", "/static/")):
                captured.append({
                    "url": url,
                    "method": request.method,
                    "headers": dict(request.headers),
                    "body": request.post_data,
                })

    page.on("request", on_request)
    try:
        await username_input.fill(_test_params()["username"])
        await register_btn.click()
        await page.wait_for_timeout(3000)
    except Exception as exc:
        print(f"[WARN] webauthn_registration_discovery2: interaction error: {exc}", file=sys.stderr)
    finally:
        page.remove_listener("request", on_request)

    candidates = []
    for req in captured:
        confidence = "high" if _REGISTRATION_PATH_RE.search(req["url"]) else "medium"
        # Simulation fires the attestation_options request (before credentials.create); classify accordingly.
        fn = _classify_endpoint(req["url"]) if _REGISTRATION_PATH_RE.search(req["url"]) else "attestation_options"
        candidates.append({**req, "function": fn, "confidence": confidence, "source": "playwright_simulation"})
        print(f"[INFO] webauthn_registration_discovery2: captured {req['method']} {req['url']}", file=sys.stderr)

    print(f"[INFO] webauthn_registration_discovery2: {len(candidates)} candidate(s)", file=sys.stderr)
    return {"webauthn_registration_discovery2": candidates}


async def webauthn_registration_options(
    target_url: str,
    prior_results: Dict[str, Any] | None = None,
    cache_dir: Path | None = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Confirm registration options endpoints and capture their full request/response.

    Combines candidates from webauthn_registration_discovery1 and
    webauthn_registration_discovery2, deduplicates by URL, and probes all unique
    candidates classified as 'options'. For each, if the server returns a 400
    validation error (field: [message] format), enriches the body with known WebAuthn
    field defaults and retries once.

    Args:
        page: The Playwright page object (used for page.context.request).
        referenced_urls: List of URLs referenced by the page (unused).
        json_responses: JSON responses buffered during page load (unused).
        prior_results: Accumulated results from earlier pipeline functions.

    Returns:
        Dict with "webauthn_registration_options" key mapping to list of findings.
    """
    js_calls = _js_calls_found(prior_results)
    if js_calls and "navigator.credentials.create" not in js_calls:
        print("[INFO] webauthn_registration_options: skipping (no credentials.create in JS)", file=sys.stderr)
        return {"webauthn_registration_options": []}

    pr = prior_results or {}
    all_candidates = (
        pr.get("webauthn_registration_discovery1", [])
        + pr.get("webauthn_registration_discovery2", [])
    )
    # Only probe candidates classified as the options endpoint; deduplicate by resolved URL.
    # When two candidates point to the same URL, prefer the one with a real captured body
    # (from simulation), then fall back to confidence ranking.
    _conf_rank = {"high": 0, "medium": 1, "low": 2}
    url_to_candidate: Dict[str, Dict[str, Any]] = {}
    for c in all_candidates:
        if c.get("function") not in ("attestation_options", "unknown"):
            continue
        url = c["url"]
        if url not in url_to_candidate:
            url_to_candidate[url] = c
        else:
            existing = url_to_candidate[url]
            has_body, existing_has_body = bool(c.get("body")), bool(existing.get("body"))
            if has_body and not existing_has_body:
                url_to_candidate[url] = c
            elif has_body == existing_has_body:
                if _conf_rank.get(c.get("confidence"), 3) < _conf_rank.get(existing.get("confidence"), 3):
                    url_to_candidate[url] = c
    options_candidates = list(url_to_candidate.values())

    if not options_candidates:
        print("[INFO] webauthn_registration_options: no options candidates, skipping", file=sys.stderr)
        return {"webauthn_registration_options": []}

    required = {"rp", "user", "pubKeyCredParams"}
    findings: List[Dict[str, Any]] = []

    for candidate in options_candidates:
        url = candidate["url"]
        method = (candidate.get("method") or "POST").upper()

        # Build initial request body.
        raw_body = candidate.get("body")
        if raw_body:
            try:
                req_data: Any = json.loads(raw_body)
            except (ValueError, TypeError):
                req_data = raw_body
        else:
            req_data = dict(_test_params())

        print(f"[INFO] webauthn_registration_options: probing {method} {url}", file=sys.stderr)
        for attempt in range(2):
            try:
                api_resp = (
                    await page.context.request.get(url)
                    if method == "GET"
                    else await page.context.request.post(url, data=req_data)
                )
                resp_status = api_resp.status
                resp_headers = dict(api_resp.headers)
                resp_text = await api_resp.text()
                try:
                    resp_body = json.loads(resp_text)
                except Exception:
                    resp_body = None

                confirmed = isinstance(resp_body, dict) and required <= resp_body.keys()

                # On first attempt: check for a validation error and retry with enriched body.
                if not confirmed and attempt == 0 and resp_status == 400 and isinstance(resp_body, dict):
                    if any(isinstance(v, list) for v in resp_body.values()):
                        enriched = {**req_data}
                        for field in resp_body:
                            if field not in enriched and field in _WEBAUTHN_FIELD_DEFAULTS:
                                enriched[field] = _WEBAUTHN_FIELD_DEFAULTS[field]
                        if enriched != req_data:
                            print(
                                f"[INFO] webauthn_registration_options: 400 validation error — "
                                f"retrying with enriched body (added: "
                                f"{sorted(set(enriched) - set(req_data))})",
                                file=sys.stderr,
                            )
                            req_data = enriched
                            continue  # retry

                if confirmed:
                    evidence = sorted(required | (resp_body.keys() & {"challenge", "attestation", "timeout"}))
                    print(f"[INFO] webauthn_registration_options: confirmed at {url}", file=sys.stderr)
                else:
                    evidence = []
                    print(
                        f"[INFO] webauthn_registration_options: {url} responded {resp_status} (not confirmed)",
                        file=sys.stderr,
                    )

                body_str = req_data if isinstance(req_data, str) else json.dumps(req_data)
                findings.append({
                    "url": url,
                    "confirmed": confirmed,
                    "evidence": evidence,
                    "request": {"method": method, "body": body_str},
                    "response": {"status": resp_status, "headers": resp_headers, "body": resp_text},
                })
                break  # done with this candidate (confirmed or exhausted retries)

            except Exception as exc:
                print(f"[WARN] webauthn_registration_options: request to {url} failed: {exc}", file=sys.stderr)
                break

    print(f"[INFO] webauthn_registration_options: {len(findings)} finding(s)", file=sys.stderr)
    return {"webauthn_registration_options": findings}


async def webauthn_registration_create(
    target_url: str,
    prior_results: Dict[str, Any] | None = None,
    cache_dir: Path | None = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Complete the WebAuthn registration ceremony using a virtual authenticator.

    Requires a confirmed attestation_options result from webauthn_registration_options.
    Installs a CTAP2 virtual authenticator so navigator.credentials.create() succeeds,
    then simulates user registration to capture the full attestation_result request and
    response. Extracts the generated credential — including private key — for use in
    subsequent authentication flows.

    Args:
        page: The Playwright page object.
        referenced_urls: Unused; kept for pipeline signature.
        json_responses: Unused; kept for pipeline signature.
        prior_results: Must contain confirmed webauthn_registration_options findings.

    Returns:
        Dict with "webauthn_registration_create" key mapping to findings:
        [{username, attestation_result: {url, request, response}, credential: {...}}]
    """
    options_findings = (prior_results or {}).get("webauthn_registration_options", [])
    if not any(f.get("confirmed") for f in options_findings):
        print("[INFO] webauthn_registration_create: no confirmed options endpoint, skipping", file=sys.stderr)
        return {"webauthn_registration_create": []}

    username_input = await page.query_selector(
        'input[type="text"], input[type="email"], '
        'input[name*="user" i], input[placeholder*="user" i], input[id*="user" i]'
    )
    if not username_input:
        print("[INFO] webauthn_registration_create: no username input found", file=sys.stderr)
        return {"webauthn_registration_create": []}

    register_btn = None
    for sel in [
        'button:has-text("Register")',
        'button:has-text("Sign Up")',
        'button:has-text("Create")',
        'input[type="submit"][value*="Register" i]',
    ]:
        register_btn = await page.query_selector(sel)
        if register_btn:
            break
    if not register_btn:
        print("[INFO] webauthn_registration_create: no register button found", file=sys.stderr)
        return {"webauthn_registration_create": []}

    # Identify known attestation_result URLs from discovery for later matching.
    pr = prior_results or {}
    result_urls = {
        urljoin(page.url, c["url"])
        for src in (
            pr.get("webauthn_registration_discovery1", [])
            + pr.get("webauthn_registration_discovery2", [])
        )
        if src.get("function") == "attestation_result"
        for c in [src]
    }

    # Install virtual authenticator via CDP — Playwright Python bindings don't
    # expose add_virtual_authenticator() directly; use the WebAuthn CDP domain.
    print("[INFO] webauthn_registration_create: installing virtual authenticator", file=sys.stderr)
    cdp = await page.context.new_cdp_session(page)
    await cdp.send("WebAuthn.enable", {"enableUI": False})
    va_result = await cdp.send("WebAuthn.addVirtualAuthenticator", {
        "options": {
            "protocol": "ctap2",
            "transport": "internal",
            "hasResidentKey": True,
            "hasUserVerification": True,
            "automaticPresenceSimulation": True,
            "isUserVerified": True,
        }
    })
    authenticator_id = va_result["authenticatorId"]

    # Capture all non-static POST responses during the ceremony.
    captured: List[Dict[str, Any]] = []

    async def on_response(response) -> None:
        if response.request.method not in ("GET", "HEAD"):
            url = response.url
            if not any(skip in url for skip in (".js", ".css", ".png", ".svg", "/static/")):
                try:
                    resp_text = await response.text()
                except Exception:
                    resp_text = ""
                captured.append({
                    "url": url,
                    "request": {
                        "method": response.request.method,
                        "headers": dict(response.request.headers),
                        "body": response.request.post_data,
                    },
                    "response": {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "body": resp_text,
                    },
                })
                print(f"[INFO] webauthn_registration_create: captured response from {url}", file=sys.stderr)

    page.on("response", on_response)
    raw_credentials: List[Dict[str, Any]] = []
    try:
        await username_input.fill(_test_params()["username"])
        await register_btn.click()
        await page.wait_for_timeout(5000)
        creds_result = await cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator_id})
        raw_credentials = creds_result.get("credentials", [])
    except Exception as exc:
        print(f"[WARN] webauthn_registration_create: ceremony error: {exc}", file=sys.stderr)
    finally:
        page.remove_listener("response", on_response)
        try:
            await cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator_id})
        except Exception:
            pass

    # Identify the attestation_result exchange — prefer known URLs, fall back to
    # any captured POST whose path matches result keywords.
    attestation_result = next(
        (r for r in captured if r["url"] in result_urls),
        next((r for r in captured if _VERIFICATION_SEGMENT_RE.search(r["url"])), None),
    )
    if attestation_result:
        print(f"[INFO] webauthn_registration_create: attestation_result at {attestation_result['url']}", file=sys.stderr)
    else:
        print("[WARN] webauthn_registration_create: attestation_result not captured", file=sys.stderr)

    # CDP returns credentials as dicts; credentialId/privateKey/userHandle are
    # already base64-encoded strings.
    credentials = [
        {
            "credential_id": c.get("credentialId"),
            "private_key_pkcs8": c.get("privateKey"),
            "rp_id": c.get("rpId"),
            "sign_count": c.get("signCount"),
            "is_resident_key": c.get("isResidentCredential"),
            "user_handle": c.get("userHandle") or None,
        }
        for c in raw_credentials
    ]

    print(f"[INFO] webauthn_registration_create: {len(credentials)} credential(s) captured", file=sys.stderr)
    finding = {
        "username": _test_params()["username"],
        "attestation_result": attestation_result,
        "credentials": credentials,
    }
    return {"webauthn_registration_create": [finding] if credentials else []}


async def webauthn_authentication(
    target_url: str,
    prior_results: Dict[str, Any] | None = None,
    cache_dir: Path | None = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Detect the authentication options endpoint via JSON response body inspection.

    Looks for responses containing the PublicKeyCredentialRequestOptions fields
    (challenge plus allowCredentials or rpId). Skips if webauthn_javascript found
    no credentials.get calls (unless no prior JS results exist).

    Args:
        page: The Playwright page object (unused, kept for pipeline signature).
        referenced_urls: List of URLs referenced by the page (unused).
        json_responses: JSON responses buffered during page load.
        prior_results: Accumulated results from earlier pipeline functions.

    Returns:
        Dict with "webauthn_authentication" key mapping to list of findings.
    """
    js_calls = _js_calls_found(prior_results)
    if js_calls and "navigator.credentials.get" not in js_calls:
        print("[INFO] webauthn_authentication: skipping (no credentials.get in JS)", file=sys.stderr)
        return {"webauthn_authentication": []}

    findings = []
    for entry in json_responses or []:
        body = entry.get("body")
        if not isinstance(body, dict):
            continue
        if "challenge" in body and ("allowCredentials" in body or "rpId" in body):
            evidence = sorted({"challenge"} | ({"allowCredentials", "rpId"} & body.keys()))
            findings.append({"url": entry["url"], "evidence": evidence})
            print(
                f"[INFO] webauthn_authentication: found options at {entry['url']}", file=sys.stderr
            )

    print(
        f"[INFO] webauthn_authentication: found {len(findings)} authentication options endpoint(s)",
        file=sys.stderr,
    )
    return {"webauthn_authentication": findings}


async def webauthn_deregistration(
    target_url: str,
    prior_results: Dict[str, Any] | None = None,
    cache_dir: Path | None = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Detect deregistration endpoints via URL keyword heuristics.

    No WebAuthn JS API exists for deregistration, so this always runs regardless
    of prior results. A URL matches when it contains at least one flow keyword
    (delete/remove/revoke/deregister/unregister) and at least one shared WebAuthn
    signal (webauthn/passkey/fido/credential/authenticat), OR at least two flow
    keywords.

    Args:
        page: The Playwright page object (unused, kept for pipeline signature).
        referenced_urls: List of URLs referenced by the page.
        json_responses: JSON responses buffered during page load (unused).
        prior_results: Accumulated results from earlier pipeline functions (unused).

    Returns:
        Dict with "webauthn_deregistration" key mapping to list of findings.
    """
    flow_keywords = {"delete", "remove", "revoke", "deregister", "unregister"}
    shared_keywords = {"webauthn", "passkey", "fido", "credential", "authenticat"}

    # Scan referenced_urls from all crawled pages (deregistration endpoints can appear anywhere).
    all_refs: List[str] = []
    for entry in (prior_results or {}).get("http_crawl", {}).get("inside_urls", []):
        all_refs.extend(entry.get("referenced_urls", []))

    seen_urls: Set[str] = set()
    findings = []
    for url in all_refs:
        if url in seen_urls:
            continue
        seen_urls.add(url)
        url_lower = url.lower()
        flow_hits = {kw for kw in flow_keywords if kw in url_lower}
        shared_hits = {kw for kw in shared_keywords if kw in url_lower}
        if (flow_hits and shared_hits) or len(flow_hits) >= 2:
            matched = sorted(flow_hits | shared_hits)
            findings.append({"url": url, "matched_keywords": matched})
            print(f"[INFO] webauthn_deregistration: matched {url}", file=sys.stderr)

    print(
        f"[INFO] webauthn_deregistration: found {len(findings)} candidate deregistration endpoint(s)",
        file=sys.stderr,
    )
    return {"webauthn_deregistration": findings}


_RESULT_CACHE_FILE = "result.pkl"


async def query_webpage(
    target_url: str,
    search_methods: List[Callable] = [http_crawl],  # noqa: B006
    cache_dir: Path | None = None,
    no_cache: List[str] | None = None,
    no_run: List[str] | None = None,
) -> Dict[str, Any]:
    """Run a pipeline of discovery functions against a URL.

    Each method is called with (target_url, prior_results, cache_dir) and receives
    the accumulated results from all prior methods. Methods are responsible for their
    own browser or HTTP sessions.

    If result.pkl exists in a method's cache subdirectory, that cached result is
    loaded into search_results before the method is called, so the method can
    inspect its own prior result via prior_results and resume incremental work.
    After all methods run, each method's result is saved to result.pkl.

    Args:
        target_url: The URL to query.
        search_methods: Ordered list of discovery functions to run. Each must accept
            (target_url: str, prior_results: Dict | None, cache_dir: Path | None).
        cache_dir: Root cache directory for this run. Each method receives a
            subdirectory named after itself; the directory is created before the call.
        no_cache: Function names for which cached results are ignored — they run
            without seeing any prior cached result; any cached result is overwritten.
        no_run: Function names that are not called — cached result is loaded if
            available results are written back to cache as they may be modified by
            downstream functions; if no cache exists, or no_cache is also specified,
            then no result is produced for the function (skipped).

    Returns:
        search_results dict keyed by method name.
    """
    print(f"[INFO] Starting webpage query for: {target_url}", file=sys.stderr)
    search_results: Dict[str, Any] = {}
    timings: List[tuple[str, float]] = []
    method_cache_dirs: Dict[str, Path] = {}
    no_cache_set: set[str] = set(no_cache) if no_cache else set()
    no_run_set: set[str] = set(no_run) if no_run else set()
    pipeline_start = time.monotonic()

    for method in search_methods:
        method_cache_dir: Path | None = None
        if cache_dir is not None:
            method_cache_dir = cache_dir / method.__name__
            method_cache_dir.mkdir(parents=True, exist_ok=True)
            method_cache_dirs[method.__name__] = method_cache_dir

        result_cache = method_cache_dir / _RESULT_CACHE_FILE if method_cache_dir else None
        ignore_cache = method.__name__ in no_cache_set
        ignore_run = method.__name__ in no_run_set

        # Load cache if available and not suppressed.
        load_elapsed: float | None = None
        cached_summary = ""
        if not ignore_cache and result_cache and result_cache.exists():
            t_load = time.monotonic()
            cached = pickle.loads(result_cache.read_bytes())
            load_elapsed = time.monotonic() - t_load
            search_results.update(cached)
            cached_data = cached.get(method.__name__, {})
            cached_summary = cached_data.get("summary", "") if isinstance(cached_data, dict) else ""

        # Skip running if ignore_run; cache was already loaded above if present.
        if ignore_run:
            label = f"cache loaded: {cached_summary}" if load_elapsed is not None else "no cache"
            print(f"\n[INFO] {method.__name__} (no-run, {label})", file=sys.stderr)
            continue

        # Run the function.
        if load_elapsed is not None:
            print(f"\n[INFO] Running {method.__name__} (cache pre-loaded): {cached_summary}", file=sys.stderr)
        else:
            print(f"\n[INFO] Running {method.__name__}...", file=sys.stderr)
        t0 = time.monotonic()
        result = await method(target_url, search_results, method_cache_dir)
        elapsed = time.monotonic() - t0
        timings.append((method.__name__, elapsed, load_elapsed))
        search_results.update(result)

    for method_name, method_cache_dir in method_cache_dirs.items():
        if method_name not in search_results:
            continue
        result_cache = method_cache_dir / _RESULT_CACHE_FILE
        result_cache.write_bytes(pickle.dumps({method_name: search_results[method_name]}))

    total_elapsed = time.monotonic() - pipeline_start

    print("\n[INFO] ===== SEARCH RESULTS =====", file=sys.stderr)
    for method_name, elapsed, load_elapsed in timings:
        findings = search_results.get(method_name, {})
        if isinstance(findings, dict):
            summary = findings.get("summary", "")
        else:
            summary = f"{len(findings)} finding(s)"
        timing_str = f"{elapsed:.1f}s"
        if load_elapsed is not None:
            timing_str = f"load={load_elapsed:.2f}s run={elapsed:.1f}s"
        print(f"[INFO]   {method_name} ({timing_str})  {summary}", file=sys.stderr)
    print(f"[INFO] Total: {total_elapsed:.1f}s", file=sys.stderr)

    return search_results


def _find_latest_cache(url_slug: str) -> Path | None:
    """Return the most recent cache directory for the given URL slug, or None.

    Scans OUTPUT_DIR/.cache/ for subdirectories whose names end with _{url_slug},
    sorts lexicographically (YYYYMMDD_HHmmss prefix orders correctly), and returns
    the last entry.
    """
    cache_root = OUTPUT_DIR / ".cache"
    if not cache_root.is_dir():
        return None
    suffix = f"_{url_slug}"
    candidates = sorted(p for p in cache_root.iterdir() if p.is_dir() and p.name.endswith(suffix))
    return candidates[-1] if candidates else None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Query a webpage for WebAuthn signals.")
    parser.add_argument("url", help="Target URL to query.")
    parser.add_argument(
        "--use-cache",
        nargs="?",
        const="auto",
        default=None,
        metavar="PATH",
        help=(
            "Reuse a prior cache instead of creating a new one. "
            "Without a value, auto-selects the most recent cache for the given URL. "
            "With a PATH, uses that directory directly."
        ),
    )
    parser.add_argument(
        "--no-cache",
        action="append",
        default=None,
        metavar="FUNCTION",
        help=(
            "Ignore cached results for FUNCTION. "
            "The function runs without seeing any prior cached result and its "
            "result.pkl is overwritten. May be repeated."
        ),
    )
    parser.add_argument(
        "--no-run",
        action="append",
        default=None,
        metavar="FUNCTION",
        help=(
            "Do not call FUNCTION. Cached result is loaded if available, "
            "but the function does no work and result.pkl is not written. May be repeated."
        ),
    )
    parser.add_argument(
        "--skip",
        action="append",
        default=None,
        metavar="FUNCTION",
        help="Alias for --no-cache FUNCTION --no-run FUNCTION. May be repeated.",
    )
    args = parser.parse_args()

    target_url = args.url
    start_ts = datetime.now(timezone.utc)

    ts = start_ts.strftime("%Y%m%d_%H%M%S")
    url_slug = re.sub(r'^https?://', '', target_url)
    url_slug = re.sub(r'[^a-zA-Z0-9._-]', '_', url_slug)
    url_slug = re.sub(r'_+', '_', url_slug).strip('_')
    output_stem = f"{ts}_{url_slug}"
    output_path = OUTPUT_DIR / f"{output_stem}.json"

    if args.use_cache is None:
        run_cache_dir: Path = OUTPUT_DIR / ".cache" / output_stem
    elif args.use_cache == "auto":
        found = _find_latest_cache(url_slug)
        if found is None:
            print(f"[ERROR] --use-cache: no cached run found for {target_url!r}", file=sys.stderr)
            sys.exit(1)
        run_cache_dir = found
        print(f"[INFO] Using cache: {run_cache_dir}", file=sys.stderr)
    else:
        run_cache_dir = Path(args.use_cache)
        print(f"[INFO] Using cache: {run_cache_dir}", file=sys.stderr)

    if args.use_cache is not None and not run_cache_dir.is_dir():
        print(f"[ERROR] --use-cache: directory does not exist: {run_cache_dir}", file=sys.stderr)
        sys.exit(1)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    results = asyncio.run(
        query_webpage(
            target_url,
            search_methods=[
                http_redirect,
                http_sitemap,
                http_crawl,
                http_crawl2,
                http_crawl3,
                webauthn_javascript,
                # webauthn_registration_discovery1,
                # webauthn_registration_discovery2,
                # webauthn_registration_options,
                # webauthn_registration_create,
                # webauthn_authentication,
                # webauthn_deregistration,
            ],
            cache_dir=run_cache_dir,
            no_cache=(args.no_cache or []) + (args.skip or []),
            no_run=(args.no_run or []) + (args.skip or []),
        )
    )

    output = {
        "target_url": target_url,
        "search_results": results,
    }

    output_path.write_text(json.dumps(_strip_transient_keys(output), indent=2))
    print(f"[INFO] Results written to {output_path}", file=sys.stderr)
