from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"


class _AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = dict(attrs)
        if tag == "link" and values.get("href"):
            self.assets.append(str(values["href"]))
        if tag == "script" and values.get("src"):
            self.assets.append(str(values["src"]))


def test_product_site_local_assets_exist() -> None:
    parser = _AssetParser()
    parser.feed((SITE / "index.html").read_text(encoding="utf-8"))

    assert parser.assets
    for reference in parser.assets:
        if reference.startswith(("http://", "https://", "#")):
            continue
        assert (SITE / reference).resolve().is_file(), reference


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
    javascript = (SITE / "app.js").read_text(encoding="utf-8")
    actual = re.findall(r'\{ id: "([a-z0-9_]+)", ingress:', javascript)

    assert actual == expected


def test_product_site_preserves_claim_boundaries() -> None:
    html = (SITE / "index.html").read_text(encoding="utf-8")

    assert "Illustrative UI using the implemented portfolio schema." in html
    assert "Velvet is currently local and self-hosted." in html
    assert "No vendor claims" in html
    assert "invented customer" not in html.lower()
