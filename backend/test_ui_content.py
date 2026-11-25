"""Tests for Python-hosted bilingual UI bundles (/api/i18n) and SVG share cards (/api/share-card)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from api_router import handle_api_request  # noqa: E402
from ui_content import UI_BUNDLES, get_ui_content, render_share_card_svg  # noqa: E402


def _collect_key_paths(obj: dict, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    for key, value in obj.items():
        full = f"{prefix}.{key}" if prefix else key
        paths.add(full)
        if isinstance(value, dict):
            paths.update(_collect_key_paths(value, full))
    return paths


class UiContentTests(unittest.TestCase):
    def test_ar_and_en_bundles_have_identical_key_structure(self) -> None:
        bundles = get_ui_content()
        self.assertIn("ar", bundles)
        self.assertIn("en", bundles)

        ar_keys = _collect_key_paths(bundles["ar"])
        en_keys = _collect_key_paths(bundles["en"])
        self.assertEqual(ar_keys, en_keys)

        self.assertEqual(len(bundles["ar"]["hero"]["examples"]), 3)
        self.assertEqual(len(bundles["en"]["hero"]["examples"]), 3)
        self.assertEqual(len(bundles["ar"]["learn"]["items"]), 5)
        self.assertEqual(len(bundles["en"]["learn"]["items"]), 5)
        self.assertTrue(bundles["ar"]["dlp"]["sampleLeak"])
        self.assertTrue(bundles["en"]["academic"]["samples"]["human"])

    def test_api_router_serves_i18n_and_svg_share_card(self) -> None:
        all_bundles = handle_api_request("GET", "/api/i18n", {}, {}, "127.0.0.1")
        self.assertEqual(set(all_bundles.keys()), {"ar", "en"})  # type: ignore[union-attr]

        en_only = handle_api_request("GET", "/api/i18n", {"lang": "en"}, {}, "127.0.0.1")
        self.assertEqual(en_only["brandEn"], UI_BUNDLES["en"]["brandEn"])  # type: ignore[index]

        card = handle_api_request(
            "POST",
            "/api/share-card",
            {},
            {"score": 88, "verdict": "dangerous", "category": "phishing_bank", "lang": "en"},
            "127.0.0.1",
        )
        self.assertIn("<svg", card["svg"])  # type: ignore[index]
        self.assertIn("88", card["svg"])  # type: ignore[index]
        self.assertIn("#dc2626", card["svg"])  # type: ignore[index]
        self.assertEqual(card["filename"], "kashf-verdict-88.png")  # type: ignore[index]

    def test_share_card_clamps_score_and_handles_zero(self) -> None:
        card = render_share_card_svg(score=-10, verdict="safe", category="other", lang="ar")
        self.assertIn(">0<", card["svg"])
        self.assertIn("#16a34a", card["svg"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
