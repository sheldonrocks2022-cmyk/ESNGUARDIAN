"""Regression coverage for new ESNG AI-only skills."""
import unittest
from esn_guardian.esng_skills import answer_skill

class TestESNGSkills(unittest.TestCase):
    def test_conversion(self):
        self.assertIn("1000 m",answer_skill("convert 1 km to m"))
    def test_temperature(self):
        self.assertIn("32 f",answer_skill("convert 0 c to f"))
    def test_statistics(self):
        self.assertIn("Mean: 3",answer_skill("stats: 1, 3, 5"))
    def test_quadratic(self):
        self.assertIn("Real roots: 3, 2",answer_skill("quadratic: 1, -5, 6"))
    def test_percentage(self):
        self.assertIn("= 40",answer_skill("percentage 20 of 200"))
    def test_words(self):
        self.assertIn("Words: 3",answer_skill("word count: one two three"))
    def test_nonmatching(self):
        self.assertIsNone(answer_skill("hello"))

if __name__=="__main__":
    unittest.main()
