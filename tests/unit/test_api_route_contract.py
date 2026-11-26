"""Guardrails keeping the SDK route union and API docs aligned with mounted routes."""

import re
from pathlib import Path

from src.api.main import create_app

ROOT = Path(__file__).resolve().parents[2]
PROTECTED_PREFIXES = ("/pilot/", "/wallet/ownership/")


def _iter_routes(routes):
    for route in routes:
        if hasattr(route, "original_router"):
            yield from _iter_routes(route.original_router.routes)
        elif hasattr(route, "routes"):
            yield from _iter_routes(route.routes)
        else:
            yield route


def _mounted_routes() -> set[tuple[str, str]]:
    mounted = set()
    for route in _iter_routes(create_app().routes):
        path = getattr(route, "path", "")
        if not path.startswith(PROTECTED_PREFIXES):
            continue
        for method in getattr(route, "methods", ()) or ():
            if method in ("GET", "POST"):
                mounted.add((method, path))
    return mounted


def _sdk_routes() -> set[str]:
    source = (ROOT / "packages/proof/src/api-client.ts").read_text()
    block = re.search(r"export const PILOT_AND_WALLET_ROUTES = \[(.*?)\] as const;", source, re.S)
    assert block is not None
    return set(re.findall(r"'([^']+)'", block.group(1)))


def _documented_routes() -> set[tuple[str, str]]:
    page = (ROOT / "apps/docs/app/docs/api/page.mdx").read_text()
    documented = set()
    for line in page.splitlines():
        method = None
        previous = None
        for token in re.findall(r"`([^`]+)`", line):
            if token.startswith(("GET ", "POST ")):
                method, path = token.split(" ", 1)
            elif token.startswith("/") and method:
                # A combined cell continues from the previous path's parent.
                path = token if token.startswith(PROTECTED_PREFIXES) else previous.rsplit("/", 1)[0] + token
            else:
                continue
            previous = path
            if path.startswith(PROTECTED_PREFIXES):
                documented.add((method, path))
    return documented


def test_sdk_route_union_lists_every_pilot_and_wallet_route():
    mounted = _mounted_routes()
    assert mounted
    assert _sdk_routes() == {path for _, path in mounted}


def test_docs_route_tables_match_mounted_pilot_and_wallet_routes():
    assert _documented_routes() == _mounted_routes()
