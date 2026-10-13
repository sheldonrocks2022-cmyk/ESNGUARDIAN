"""Offline tests for ESNG AI multi-source safeguards and model regression."""
import unittest
from unittest.mock import AsyncMock, patch
from esn_guardian.esng_multisource import valid_url, research_many, PublicResolver
from esn_guardian.esng_minilm import ESNGMiniLM

class MultiSourceTests(unittest.IsolatedAsyncioTestCase):
    def test_valid_urls(self):
        self.assertTrue(valid_url("https://example.org/article"))
        self.assertFalse(valid_url("http://example.org"))
        self.assertFalse(valid_url("https://user:pass@example.org/"))
        self.assertFalse(valid_url("https://example.org:8080/"))
        self.assertFalse(valid_url("https://localhost.local/"))

    async def test_requires_multiple(self):
        self.assertIn("2",await research_many("question",["https://example.org"]))

    async def test_rejects_duplicate_urls(self):
        self.assertIn("different",await research_many("question",["https://example.org","https://example.org"]))

    async def test_synthesis_without_network(self):
        with patch("esn_guardian.esng_multisource.fetch_public_text",new_callable=AsyncMock) as fetch:
            fetch.side_effect=[
                "Python supports modules and reusable functions for organizing programs.",
                "Python supports extensive libraries for scientific analysis and data processing."
            ]
            result=await research_many("What does Python support?",["https://example.org/a","https://example.org/b"])
            self.assertIn("https://example.org/",result)
            self.assertEqual(fetch.await_count,2)

    async def test_resolver_rejects_private(self):
        with patch("esn_guardian.esng_multisource.socket.getaddrinfo",return_value=[(2,1,6,"",("127.0.0.1",443))]):
            with self.assertRaises(OSError):
                await PublicResolver().resolve("example.org",443)

class ModelTests(unittest.TestCase):
    def test_expanded_corpus(self):
        model=ESNGMiniLM()
        self.assertIn("version control",model.reply("what is git?"))
        self.assertIn("trigram",model.reply("model status"))
        self.assertIsNone(model.reply("what is the quantum spaghetti emperor?"))

if __name__=="__main__":
    unittest.main()
