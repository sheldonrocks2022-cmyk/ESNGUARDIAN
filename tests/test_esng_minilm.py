"""Tests for ESNG's local statistical language model."""
import unittest
from esn_guardian.esng_minilm import ESNGMiniLM, CORPUS

class MiniLMTests(unittest.TestCase):
    def setUp(self):
        self.model = ESNGMiniLM()

    def test_corpus(self):
        self.assertGreaterEqual(len(CORPUS), 25)

    def test_local_status(self):
        self.assertIn("trigram", self.model.reply("model status"))

    def test_known_question(self):
        self.assertIn("programming language", self.model.reply("what is python?"))

    def test_unknown_question_does_not_hallucinate(self):
        self.assertIsNone(self.model.reply("what is the secret moon dragon password?"))

    def test_deterministic_generation(self):
        self.assertEqual(self.model.generate("hello"), self.model.generate("hello"))

    def test_generation_is_bounded(self):
        self.assertLessEqual(len(self.model.generate("hello", 999)), 500)

    def test_explicit_generation(self):
        self.assertIn("Experimental", self.model.reply("ai generate: hello"))

if __name__ == "__main__":
    unittest.main()
