"""
Tests for Cisco Docs AI ext `ask` endpoint.

Live tests require a key in the environment (same names as the app); never commit secrets.
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import requests

import app

DOCS_AI_EXT_ASK_URL = "https://docs-ai-ext.cloudapps.cisco.com/api/v1/docs/ask"


def _docs_ai_key_present() -> bool:
    return bool(
        app._env_pick_first(
            "DOC_AI_KEY",
            "DOCS_AI_API_KEY",
            "DOCS_AI_KEY",
            "doc_AI_key",
        )
    )


class TestDocsAiExtAskUrl(unittest.TestCase):
    def test_default_ask_url_matches_ext(self) -> None:
        self.assertEqual(app._DEFAULT_DOCS_AI_ASK_URL, DOCS_AI_EXT_ASK_URL)

    def test_rewrite_legacy_netloc_to_ext(self) -> None:
        legacy = "https://docs-ai.cloudapps.cisco.com/api/v1/docs/ask"
        out = app._rewrite_legacy_docs_ai_netloc_to_ext(legacy)
        self.assertEqual(out, DOCS_AI_EXT_ASK_URL)

    def test_resolve_post_url_prefers_ext_when_env_unset(self) -> None:
        with patch.dict(
            os.environ,
            {k: "" for k in app._DOCS_AI_POST_URL_ENV_KEYS},
            clear=False,
        ):
            url, env_key, raw = app._resolve_docs_ai_post_url()
        self.assertIsNone(env_key)
        self.assertIsNone(raw)
        self.assertEqual(url, DOCS_AI_EXT_ASK_URL)

    def test_resolve_post_url_rewrites_legacy_do_docs_ai_url(self) -> None:
        legacy = "https://docs-ai.cloudapps.cisco.com/api/v1/docs/ask"
        with patch.dict(os.environ, {"DOCS_AI_URL": legacy}, clear=False):
            url, env_key, raw = app._resolve_docs_ai_post_url()
        self.assertEqual(env_key, "DOCS_AI_URL")
        self.assertEqual(raw, legacy)
        self.assertEqual(url, DOCS_AI_EXT_ASK_URL)


@unittest.skipUnless(_docs_ai_key_present(), "Set DOC_AI_KEY or DOCS_AI_API_KEY (or DOCS_AI_KEY / doc_AI_key)")
class TestDocsAiExtAskLive(unittest.TestCase):
    def test_post_ask_ext_returns_success_or_auth_error(self) -> None:
        """POST to docs-ai-ext ask API; 200 = OK, 401/403 = bad/expired key but host reachable."""
        token = app.get_docs_ai_key()
        resp = requests.post(
            DOCS_AI_EXT_ASK_URL,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            json={"question": "How to configure ACI?"},
            timeout=float(os.environ.get("DOCS_AI_TIMEOUT_SEC", "120")),
        )
        self.assertLess(
            resp.status_code,
            500,
            msg=(resp.text or "")[:4000],
        )
        self.assertIn(
            resp.status_code,
            (200, 401, 403, 422),
            msg=f"status={resp.status_code} body={(resp.text or '')[:2000]}",
        )
        if resp.status_code == 200:
            self.assertTrue(
                (resp.headers.get("Content-Type") or "").lower().startswith("application/json"),
                msg=resp.headers.get("Content-Type"),
            )
            body = resp.json()
            self.assertIsInstance(body, dict)


if __name__ == "__main__":
    unittest.main()
