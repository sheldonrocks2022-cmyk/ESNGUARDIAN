"""Regression checks for ESNG scientific math and extractive research."""
import unittest
from esn_guardian.esng_capabilities import calculate
from esn_guardian.esng_research import extractive_answer

class ScientificTests(unittest.TestCase):
    def test_powers(self):
        self.assertEqual(calculate("2 ** 10"), 1024)
    def test_unicode(self):
        self.assertEqual(calculate("(125 × 48) + (936 ÷ 12) − 357"), 5721)
    def test_sqrt(self):
        self.assertEqual(calculate("sqrt(144) + 2 ** 10"), 1036)
    def test_reject_code(self):
        with self.assertRaises((ValueError,SyntaxError)):
            calculate("__import__('os').system('echo no')")
    def test_reject_huge_power(self):
        with self.assertRaises(ValueError):
            calculate("999999999 ** 999999")
    def test_research(self):
        answer=extractive_answer("What is Python?",["Python is a programming language used for scripting and automation. JavaScript is a separate programming language used on the web."],"https://example.org")
        self.assertIn("Python is a programming language",answer)
        self.assertIn("https://example.org",answer)

if __name__=="__main__":
    unittest.main()
