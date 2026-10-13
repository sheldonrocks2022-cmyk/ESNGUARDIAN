"""ESNG extended skill regression checks."""
import unittest
from esn_guardian.esng_extended import extended_skill

class ExtendedSkillTests(unittest.TestCase):
    def test_linear(self):
        self.assertIn("x = 2",extended_skill("linear: 2, -4"))
    def test_gcd(self):
        self.assertIn("6",extended_skill("gcd: 54, 24"))
    def test_lcm(self):
        self.assertIn("12",extended_skill("lcm: 4, 6"))
    def test_combinations(self):
        self.assertIn("10",extended_skill("combinations: 5, 2"))
    def test_permutations(self):
        self.assertIn("20",extended_skill("permutations: 5, 2"))
    def test_circle(self):
        self.assertIn("12.566",extended_skill("circle area: 2"))
    def test_rectangle(self):
        self.assertIn("12",extended_skill("rectangle area: 3, 4"))
    def test_probability(self):
        self.assertIn("25%",extended_skill("probability: 1, 4"))
    def test_sort(self):
        self.assertIn("1, 2, 3",extended_skill("sort: 3, 1, 2"))
    def test_days(self):
        self.assertIn("9",extended_skill("days between: 2026-01-01, 2026-01-10"))
    def test_unmatched(self):
        self.assertIsNone(extended_skill("hello there"))

if __name__=="__main__":
    unittest.main()
