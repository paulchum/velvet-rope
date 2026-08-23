from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
PAGE = SITE / "src" / "pages" / "index.astro"
REPLAY = SITE / "src" / "scripts" / "replay.ts"


def test_product_site_is_an_astro_cloudflare_project() -> None:
    package = json.loads((SITE / "package.json").read_text(encoding="utf-8"))
    config = (SITE / "wrangler.jsonc").read_text(encoding="utf-8")
    page = PAGE.read_text(encoding="utf-8")

    assert package["devDependencies"]["astro"].startswith("^7.")
    assert "next" not in package.get("dependencies", {})
    assert "vinext" not in package.get("devDependencies", {})
    assert '"pattern": "shadowpath.coriolislabs.ca"' in config
    assert '"custom_domain": true' in config
    assert '"run_worker_first": ["/api/*"]' in config
    assert "https://shadowpath.coriolislabs.ca" in page
    assert "chatgpt.site" not in page


def test_product_site_public_assets_exist() -> None:
    page = PAGE.read_text(encoding="utf-8")
    references = re.findall(r'(?:href|content)="(/[a-zA-Z0-9_.-]+)"', page)

    assert references
    for reference in references:
        assert (SITE / "public" / reference.removeprefix("/")).is_file(), reference


def test_product_site_replay_matches_committed_shadowpath_routes() -> None:
    fixture = json.loads(
        (
            ROOT
            / "benchmarks"
            / "agent_authorization"
            / "shadowpath"
            / "results"
            / "v0.4.0--shadowpath.json"
        ).read_text(encoding="utf-8")
    )
    expected = [item["route"]["route_id"] for item in fixture["route_results"]]
    javascript = REPLAY.read_text(encoding="utf-8")
    actual = re.findall(r'\{ id: "([a-z0-9_]+)", ingress:', javascript)

    assert actual == expected


def test_product_site_preserves_claim_and_privacy_boundaries() -> None:
    page = PAGE.read_text(encoding="utf-8")
    worker = (SITE / "worker" / "index.ts").read_text(encoding="utf-8")

    assert "Illustrative UI using the implemented portfolio schema." in page
    assert "Velvet is currently local and self-hosted." in page
    assert "No vendor claims" in page
    assert "invented customer" not in page.lower()
    assert "ALLOWED_EVENTS" in worker
    assert "arbitrary properties" in worker
    assert "request.headers" not in worker
